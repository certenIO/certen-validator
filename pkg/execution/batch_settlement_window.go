package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Settlement windows — who settles an attested on-demand member, and until when
// =============================================================================
//
// Once a member's anchor is attested, its leaf can be spent by a settlement that anyone sends. The
// validator that attested it settles it - unless it died. Deciding who takes over from a dead
// settler with a timer or a local lock is not sound: local state is lost to a restart, and two
// validators can each believe it is their turn. So the decision is made from chain facts only.
//
//   - T is the block time of the anchor's attestation (its ProofExecuted transaction): one value,
//     read identically by every validator.
//   - Window j is [T + j*W, T + (j+1)*W). Window 0 belongs to the attester; each later window to the
//     next validator in the chain-bound roster (the configured set the anchor's validator-set root
//     commits to), wrapping around.
//   - A settlement sent in window j carries expiresAt = T + (j+1)*W - margin. The account refuses a
//     settlement mined after its expiresAt (CertenAccountV7: block.timestamp <= proof.expiresAt), so
//     no settlement from window j can execute after window j - whoever broadcasts it, and however
//     long it sat in a mempool.
//   - Window j's settler acts only once a FINALIZED block is later than window j-1's fence. At that
//     block, every earlier window's settlement has executed (the leaf reads spent), reverted, or can
//     no longer execute. The leaf is read after that, so the handoff cannot race an earlier settler.
//   - Before settling, the taker looks for an earlier settler's attempt: it asks its peers for the
//     hashes of their settlements of the member and checks each on chain. One that was mined - a
//     revert the target caused - is that validator's outcome, recorded by it. Nothing is taken on a
//     peer's word: an attempt counts only if the chain shows it.
//
// A revert caused by the timing fields, not by the intent (mined after its expiresAt, or before its
// timestamp) is not the member's failure: it is never recorded as one, and settlement continues.

const (
	// SettlementWindow is W: how long each settler has.
	//
	// Window j's settler may act only once a finalized block is past window j-1's fence, so it acts
	// about (finality lag) into its window, and must still have settlementMinLanding left before its
	// own fence. W therefore has to exceed the finality lag plus the margins, or no taker could ever
	// act inside its window. Measured 2026-09-21: finalized lagged head by 17m48s on Sepolia, 20m38s
	// on Base Sepolia and 19m13s on Arbitrum Sepolia. 30 minutes clears that with room; a dead
	// attester's member is taken over roughly 50 minutes after its attestation.
	SettlementWindow = 30 * time.Minute
	// settlementFenceMargin puts the fence this far before the window's end.
	settlementFenceMargin = 2 * time.Minute
	// settlementMinLanding is the least time a settlement is sent with before its fence. Less
	// than this and it would most likely be mined after its expiresAt and revert.
	settlementMinLanding = 2 * time.Minute
)

// settlementWindows is one attested member's schedule of settlers.
type settlementWindows struct {
	start  time.Time
	width  time.Duration
	margin time.Duration
	roster []common.Address
	base   int
}

// newSettlementWindows builds the schedule from the attestation's block time and sender. An attester
// outside the roster (the anchor's attest call is open to anyone) starts the rotation at the member's
// election index instead, which every validator derives identically.
func newSettlementWindows(start time.Time, roster []common.Address, attester common.Address,
	chainID int64, opID [32]byte) (settlementWindows, error) {
	if start.IsZero() {
		return settlementWindows{}, fmt.Errorf("attestation time unknown")
	}
	if len(roster) == 0 {
		return settlementWindows{}, fmt.Errorf("empty settlement roster")
	}
	base := -1
	for i, a := range roster {
		if a == attester {
			base = i
			break
		}
	}
	if base < 0 {
		base = onDemandLeaderIndex(chainID, opID, len(roster))
	}
	return settlementWindows{start: start, width: SettlementWindow, margin: settlementFenceMargin,
		roster: append([]common.Address(nil), roster...), base: base}, nil
}

// index is the window chain time t falls in.
func (w settlementWindows) index(t time.Time) int {
	if !t.After(w.start) {
		return 0
	}
	return int(t.Sub(w.start) / w.width)
}

// settler is window j's settler.
func (w settlementWindows) settler(j int) common.Address {
	return w.roster[(w.base+j)%len(w.roster)]
}

// fence is the latest expiresAt a settlement sent in window j may carry.
func (w settlementWindows) fence(j int) time.Time {
	return w.start.Add(time.Duration(j+1)*w.width - w.margin)
}

// earlierSettlers is every validator that held a window before j, once each, except me.
func (w settlementWindows) earlierSettlers(j int, me common.Address) []common.Address {
	seen := map[common.Address]bool{me: true}
	var out []common.Address
	for k := 0; k < j; k++ {
		s := w.settler(k)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// isCallVerdict reports whether a failed contract call is the contract's answer - it reverted, or
// returned data that does not decode as the expected result - rather than a failed read.
func isCallVerdict(err error) bool {
	if err == nil {
		return false
	}
	var de rpc.DataError
	if errors.As(err, &de) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "execution reverted") || strings.HasPrefix(msg, "abi:") ||
		strings.Contains(msg, "no contract code at given address")
}

// OnDemandAnchorAttested reports whether member's one-member anchor is already attested. Read-only:
// the submitter uses it to let an attested member's settlement windows, rather than the
// pre-attestation leader rotation, decide who acts on it.
func (o *BatchOrchestrator) OnDemandAnchorAttested(ctx context.Context, member *PendingBatchIntent) (bool, error) {
	in, err := member.LeafInput()
	if err != nil {
		return false, err
	}
	tree, err := BuildBatchTree(member.ChainID, []BatchLeafInput{in}, member.CommitHeight)
	if err != nil {
		return false, err
	}
	return o.chainOps().anchorAlreadyAttested(ctx, tree.BundleID)
}

// anchorAttestation is the transaction that attested an anchor.
type anchorAttestation struct {
	Tx   string
	From common.Address
	Time time.Time
}

// decideSettlementWindow decides whether THIS validator may settle an attested member now, and with
// which fence. It returns true when the outcome is decided (Deferred or Released); false means settle,
// with out.fence set.
func (o *BatchOrchestrator) decideSettlementWindow(
	ctx context.Context,
	chain onDemandChain,
	member *PendingBatchIntent,
	tree *BatchTree,
	out *OnDemandOutcome,
) bool {
	deferf := func(format string, a ...interface{}) bool {
		out.Deferred = true
		o.logf("[OD] intent=%s anchor 0x%x: "+format, append([]interface{}{member.IntentID, tree.BundleID[:8]}, a...)...)
		return true
	}
	att, found, err := chain.anchorAttestation(ctx, tree.BundleID, member.AnchorBlock)
	if err != nil || !found {
		return deferf("attested, but its attestation is not in view (found=%t err=%v) — deferring", found, err)
	}
	roster, err := chain.settlementRoster(ctx)
	if err != nil {
		return deferf("settlement roster unavailable (%v) — deferring", err)
	}
	win, err := newSettlementWindows(att.Time, roster, att.From, member.ChainID, member.OperationID)
	if err != nil {
		return deferf("no settlement schedule (%v) — deferring", err)
	}
	head, finalized, err := chain.chainTimes(ctx)
	if err != nil {
		return deferf("chain time unreadable (%v) — deferring", err)
	}
	j := win.index(head)
	me := chain.ownAddress()
	if s := win.settler(j); s != me {
		return deferf("settlement window %d (to %s) belongs to %s", j,
			win.fence(j).UTC().Format(time.RFC3339), s.Hex())
	}
	if j > 0 {
		if !finalized.After(win.fence(j - 1)) {
			return deferf("window %d is this validator's; waiting for a finalized block past window %d's fence %s "+
				"(finalized %s)", j, j-1, win.fence(j-1).UTC().Format(time.RFC3339), finalized.UTC().Format(time.RFC3339))
		}
		tx, from, found, perr := chain.priorSettlementAttempt(ctx, member, tree, win.earlierSettlers(j, me))
		if perr != nil {
			return deferf("earlier settlers' attempts unreadable (%v) — deferring", perr)
		}
		if found {
			out.Released = true
			o.logf("[OD] intent=%s anchor 0x%x: %s already settled it in its window (%s, mined); releasing — "+
				"that transaction is its outcome and its sender records it", member.IntentID, tree.BundleID[:8], from.Hex(), tx)
			return true
		}
		o.logf("[OD] intent=%s anchor 0x%x: no earlier settler's attempt is on chain; taking over in window %d",
			member.IntentID, tree.BundleID[:8], j)
	}
	fence := win.fence(j)
	if !head.Add(settlementMinLanding).Before(fence) {
		return deferf("window %d ends at %s, too soon to land a settlement — deferring", j,
			fence.UTC().Format(time.RFC3339))
	}
	out.fence = fence
	return false
}

// =============================================================================
// Chain reads behind the schedule
// =============================================================================

func (o *BatchOrchestrator) anchorAttestation(ctx context.Context, bundleID [32]byte, floor uint64) (anchorAttestation, bool, error) {
	if floor == 0 {
		f, err := o.anchorFloor(ctx, bundleID)
		if err != nil {
			return anchorAttestation{}, false, err
		}
		floor = f
	}
	l, err := o.scanForward(ctx, o.anchorV7, [][]common.Hash{{proofExecutedTopic}, {common.Hash(bundleID)}}, floor)
	if err != nil || l == nil {
		return anchorAttestation{}, false, err
	}
	from, err := o.logSender(ctx, l)
	if err != nil {
		return anchorAttestation{}, false, err
	}
	h, err := o.ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(l.BlockNumber))
	if err != nil {
		return anchorAttestation{}, false, readErr(fmt.Errorf("reading block %d: %w", l.BlockNumber, err))
	}
	return anchorAttestation{Tx: l.TxHash.Hex(), From: from, Time: time.Unix(int64(h.Time), 0)}, true, nil
}

// chainTimes is the head's and the finalized block's timestamps.
func (o *BatchOrchestrator) chainTimes(ctx context.Context) (head, finalized time.Time, err error) {
	h, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return time.Time{}, time.Time{}, readErr(fmt.Errorf("reading head: %w", err))
	}
	f, err := o.ecm.client.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return time.Time{}, time.Time{}, readErr(fmt.Errorf("reading finalized block: %w", err))
	}
	return time.Unix(int64(h.Time), 0), time.Unix(int64(f.Time), 0), nil
}

const validatorSetRootABIJSON = `[{"type":"function","name":"currentValidatorSetRoot","inputs":[],` +
	`"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"}]`

// settlementRoster is the configured validator roster, used only after checking it is the roster the
// anchor's currentValidatorSetRoot commits to. Cached once confirmed: a roster change needs a restart.
func (o *BatchOrchestrator) settlementRoster(ctx context.Context) ([]common.Address, error) {
	o.rosterMu.Lock()
	defer o.rosterMu.Unlock()
	if o.roster != nil {
		return o.roster, nil
	}
	addrs, _, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		return nil, err
	}
	want, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return nil, err
	}
	parsed, err := abiFromJSON(validatorSetRootABIJSON)
	if err != nil {
		return nil, err
	}
	bound := bind.NewBoundContract(o.anchorV7, parsed, o.ecm.client, o.ecm.client, o.ecm.client)
	var res []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &res, "currentValidatorSetRoot"); err != nil {
		return nil, readErr(fmt.Errorf("reading currentValidatorSetRoot: %w", err))
	}
	if len(res) != 1 {
		return nil, fmt.Errorf("currentValidatorSetRoot returned %d values", len(res))
	}
	got, ok := res[0].([32]byte)
	if !ok || got != want {
		return nil, fmt.Errorf("the configured validator roster is not the one anchor %s commits to "+
			"(root 0x%x, configured 0x%x)", o.anchorV7.Hex(), got[:8], want[:8])
	}
	o.roster = append([]common.Address(nil), addrs...)
	return o.roster, nil
}

// settlementProofOf decodes the account proof a settlement transaction carries.
func settlementProofOf(input []byte) (contracts.AccountProofV7, bool) {
	if len(input) < 4 || certenAccountV7ABIErr != nil {
		return contracts.AccountProofV7{}, false
	}
	m, err := certenAccountV7ABI.MethodById(input[:4])
	if err != nil || (m.Name != "executeGovernanceProofDirect" && m.Name != "batchExecuteGovernanceProofDirect") {
		return contracts.AccountProofV7{}, false
	}
	args, err := m.Inputs.Unpack(input[4:])
	if err != nil || len(args) == 0 {
		return contracts.AccountProofV7{}, false
	}
	var p contracts.AccountProofV7
	if err := convertABIValue(args[len(args)-1], &p); err != nil {
		return contracts.AccountProofV7{}, false
	}
	return p, true
}

func convertABIValue(v interface{}, dst *contracts.AccountProofV7) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("proof tuple does not convert: %v", r)
		}
	}()
	*dst = *abi.ConvertType(v, new(contracts.AccountProofV7)).(*contracts.AccountProofV7)
	return nil
}

// timingRevert reports whether a settlement mined at blockTime reverted because of its own timing
// fields rather than the intent: mined after its expiresAt, or before its timestamp.
func timingRevert(p contracts.AccountProofV7, blockTime uint64) (bool, string) {
	bt := new(big.Int).SetUint64(blockTime)
	if p.ExpiresAt != nil && bt.Cmp(p.ExpiresAt) > 0 {
		return true, fmt.Sprintf("mined at %d, after its expiresAt %s", blockTime, p.ExpiresAt)
	}
	if p.Timestamp != nil && bt.Cmp(p.Timestamp) < 0 {
		return true, fmt.Sprintf("mined at %d, before its timestamp %s", blockTime, p.Timestamp)
	}
	return false, ""
}

// settlementRevertCause reports whether a mined, reverted settlement reverted on its timing fields -
// not the member's failure - and why.
func (o *BatchOrchestrator) settlementRevertCause(ctx context.Context, txHash string) (bool, string, error) {
	h := common.HexToHash(txHash)
	tx, _, err := o.ecm.client.TransactionByHash(ctx, h)
	if err != nil {
		return false, "", readErr(fmt.Errorf("reading transaction %s: %w", txHash, err))
	}
	rcpt, err := o.ecm.client.TransactionReceipt(ctx, h)
	if err != nil {
		return false, "", readErr(fmt.Errorf("reading receipt %s: %w", txHash, err))
	}
	hdr, err := o.ecm.client.HeaderByNumber(ctx, rcpt.BlockNumber)
	if err != nil {
		return false, "", readErr(fmt.Errorf("reading block %s: %w", rcpt.BlockNumber, err))
	}
	p, ok := settlementProofOf(tx.Data())
	if !ok {
		return false, "", nil
	}
	infra, why := timingRevert(p, hdr.Time)
	return infra, why, nil
}

// priorSettlementAttempt looks for a settlement of member under tree's anchor, sent by one of
// settlers and MINED - a success, or a revert the intent caused. Candidates come from the peers; the
// verdict comes from the chain alone.
func (o *BatchOrchestrator) priorSettlementAttempt(
	ctx context.Context,
	member *PendingBatchIntent,
	tree *BatchTree,
	settlers []common.Address,
) (string, common.Address, bool, error) {
	if len(settlers) == 0 {
		return "", common.Address{}, false, nil
	}
	hashes := collectSettlementEvidence(ctx, o.evidencePeers(), &SettlementEvidenceRequest{
		ChainID: member.ChainID, OperationID: "0x" + common.Bytes2Hex(member.OperationID[:]),
	}, o.logf)
	for _, hash := range hashes {
		from, ok, err := o.verifyPriorAttempt(ctx, member, tree, settlers, hash)
		if err != nil {
			return "", common.Address{}, false, err
		}
		if ok {
			return hash, from, true, nil
		}
	}
	return "", common.Address{}, false, nil
}

func (o *BatchOrchestrator) evidencePeers() []string {
	if o.peersFn != nil {
		return o.peersFn()
	}
	return BatchAttestationPeersFromEnv()
}

// verifyPriorAttempt checks one candidate hash: a mined transaction from one of settlers to the
// member's account, carrying a settlement proof for this anchor and this operation, which did not
// revert on its own timing fields.
func (o *BatchOrchestrator) verifyPriorAttempt(
	ctx context.Context,
	member *PendingBatchIntent,
	tree *BatchTree,
	settlers []common.Address,
	hash string,
) (common.Address, bool, error) {
	if !IsTransactionHash(hash) {
		return common.Address{}, false, nil
	}
	h := common.HexToHash(hash)
	tx, pending, err := o.ecm.client.TransactionByHash(ctx, h)
	if errors.Is(err, ethereum.NotFound) {
		return common.Address{}, false, nil
	}
	if err != nil {
		return common.Address{}, false, readErr(fmt.Errorf("reading transaction %s: %w", hash, err))
	}
	if pending || tx.To() == nil || *tx.To() != member.Account {
		return common.Address{}, false, nil
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		return common.Address{}, false, nil
	}
	isSettler := false
	for _, s := range settlers {
		if s == from {
			isSettler = true
			break
		}
	}
	if !isSettler {
		return common.Address{}, false, nil
	}
	p, ok := settlementProofOf(tx.Data())
	if !ok || p.AnchorId != tree.BundleID || p.OperationID != member.OperationID {
		return common.Address{}, false, nil
	}
	rcpt, err := o.ecm.client.TransactionReceipt(ctx, h)
	if errors.Is(err, ethereum.NotFound) {
		return common.Address{}, false, nil
	}
	if err != nil {
		return common.Address{}, false, readErr(fmt.Errorf("reading receipt %s: %w", hash, err))
	}
	if rcpt.Status == types.ReceiptStatusFailed {
		hdr, err := o.ecm.client.HeaderByNumber(ctx, rcpt.BlockNumber)
		if err != nil {
			return common.Address{}, false, readErr(fmt.Errorf("reading block %s: %w", rcpt.BlockNumber, err))
		}
		if infra, _ := timingRevert(p, hdr.Time); infra {
			return common.Address{}, false, nil
		}
	}
	return from, true, nil
}

// =============================================================================
// Settlement evidence — what each validator sent for a member
// =============================================================================

// SettlementEvidenceEndpoint is the peer path answering which settlement transactions a validator
// broadcast for an on-demand member. The answer is only a list of candidates: the asker verifies
// every one on chain, so the endpoint needs no authentication.
const SettlementEvidenceEndpoint = "/api/batch/ondemand/settlement-evidence"

// SettlementEvidenceRequest names one member.
type SettlementEvidenceRequest struct {
	ChainID     int64  `json:"chainId"`
	OperationID string `json:"operationId"`
}

// SettlementEvidenceResponse lists the hashes this validator broadcast for the member's settlement.
type SettlementEvidenceResponse struct {
	Hashes []string `json:"hashes"`
	Error  string   `json:"error,omitempty"`
}

// HandleSettlementEvidenceRequest answers from this validator's durable outbox, which keeps every
// hash a settlement went out under, resolved or not, for its retention period.
func (s *BatchStack) HandleSettlementEvidenceRequest(req *SettlementEvidenceRequest) *SettlementEvidenceResponse {
	if req == nil {
		return &SettlementEvidenceResponse{Error: "empty request"}
	}
	opBytes := common.FromHex(req.OperationID)
	if len(opBytes) != 32 {
		return &SettlementEvidenceResponse{Error: "operationId must be 32 bytes"}
	}
	var op [32]byte
	copy(op[:], opBytes)
	orch, err := s.OrchestratorFor(req.ChainID)
	if err != nil {
		return &SettlementEvidenceResponse{Error: err.Error()}
	}
	sender, err := orch.ecm.batchSender()
	if err != nil || sender == nil {
		return &SettlementEvidenceResponse{Error: "sender unavailable"}
	}
	return &SettlementEvidenceResponse{
		Hashes: sender.outbox.hashesForOwner("settle:" + memberWorkKey(req.ChainID, op)),
	}
}

// collectSettlementEvidence asks every peer and returns the distinct hashes they name. A peer that
// is down or refuses contributes nothing - which only ever leads to settling, never to a false record.
func collectSettlementEvidence(ctx context.Context, peers []string, req *SettlementEvidenceRequest,
	logf func(string, ...interface{})) []string {
	body, err := json.Marshal(req)
	if err != nil || len(peers) == 0 {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var (
		mu   sync.Mutex
		seen = map[string]bool{}
		out  []string
		wg   sync.WaitGroup
	)
	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, peer+SettlementEvidenceEndpoint, bytes.NewReader(body))
			if err != nil {
				return
			}
			hreq.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(hreq)
			if err != nil {
				logf("[OD] settlement evidence: %s unreachable: %v", peer, err)
				return
			}
			defer resp.Body.Close()
			var r SettlementEvidenceResponse
			if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, h := range r.Hashes {
				k := strings.ToLower(h)
				if !seen[k] {
					seen[k] = true
					out = append(out, h)
				}
			}
		}(peer)
	}
	wg.Wait()
	return out
}
