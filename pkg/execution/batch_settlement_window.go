package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
//     next validator in the chain-bound roster (the set the anchor's validator-set root commits to,
//     sorted by address as the contract sorts it), wrapping around.
//   - A settlement sent in window j carries expiresAt = T + (j+1)*W - margin. The account refuses a
//     settlement mined after its expiresAt (CertenAccountV7: block.timestamp <= proof.expiresAt), so
//     no settlement from window j can execute after window j - whoever broadcasts it, and however
//     long it sat in a mempool.
//   - Window j's settler acts only once a FINALIZED block is later than window j-1's fence (plus a
//     reorg margin). Every settlement an earlier window's settler sent has then executed (the leaf
//     reads spent), reverted, or can never execute, and each of those is fixed in finalized blocks.
//   - Before settling, the taker scans those finalized blocks - from the attestation to window j-1's
//     fence - for a transaction a roster validator sent to the member's account. One that is an
//     honest settlement of this member under this anchor and reverted is a tried-and-failed outcome:
//     its sender records it (or, if the sender is this validator, it records it now), and nobody
//     settles again. The chain is the only evidence taken: a reverted transaction leaves no log, but
//     it is in its block.
//
// A revert caused by the timing fields, not by the intent (mined after its expiresAt, or before its
// timestamp) is not the member's failure: it is never recorded as one, and settlement continues.

const (
	// SettlementWindow is W: how long each settler has.
	//
	// Window j's settler may act only once a finalized block is past window j-1's fence (and the reorg
	// margin), so it acts about (finality lag) into its window, and must still have
	// settlementMinLanding left before its own fence. W therefore has to exceed the finality lag plus
	// the margins, or no taker could ever act inside its window. Measured 2026-09-21: finalized lagged
	// head by 17m48s on Sepolia, 20m38s on Base Sepolia and 19m13s on Arbitrum Sepolia. 30 minutes
	// clears that with room; a dead attester's member is taken over roughly 50 minutes after its
	// attestation.
	SettlementWindow = 30 * time.Minute
	// settlementFenceMargin puts the fence this far before the window's end.
	settlementFenceMargin = 2 * time.Minute
	// settlementMinLanding is the least time a settlement is sent with before its fence. Less
	// than this and it would most likely be mined after its expiresAt and revert.
	settlementMinLanding = 2 * time.Minute
	// settlementReorgMargin is how far past the previous fence finality must be before a taker acts.
	// The attester reads T straight after its attestation mines; a reorg that re-mines the
	// attestation a few slots earlier moves every fence earlier for the takers than for it. The
	// margin keeps the attester's own fence behind the takers' view of it.
	settlementReorgMargin = 2 * time.Minute
	// settlementScanBatch is how many blocks one JSON-RPC batch fetches while scanning a window; small
	// enough that a public endpoint's rate limit rarely refuses it.
	settlementScanBatch = 20
	// settlementScanRetries is how often a refused batch is retried, with doubling backoff, before the
	// member is deferred. Progress is kept either way: finalized blocks never need scanning twice.
	settlementScanRetries = 3
	// settlementScanPerPass bounds the blocks one pass scans. The scan runs while this validator holds its
	// key's nonce sequence, which the period lane waits on; a long window (thousands of Arbitrum blocks)
	// is covered over several passes instead, resuming from its saved progress.
	settlementScanPerPass = 400
	// settlementPrescanPerPass bounds a pre-scan, which holds no lock: the next window's settler scans
	// the current window's blocks as they finalize, so its own turn finds only a short tail left.
	settlementPrescanPerPass = 2000
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

// isCallVerdict reports whether a failed contract call is the contract's own answer - it reverted -
// rather than a failed read. Only an explicit revert counts: go-ethereum gives every JSON-RPC error
// body an ErrorData, so "has data" would also match "header not found", a rate limit or an internal
// error. An empty result on an address known to hold code (bind's "no contract code" or an abi
// unmarshal of nothing) is a lagging backend, not a verdict.
func isCallVerdict(err error) bool {
	if err == nil {
		return false
	}
	var re rpc.Error
	if errors.As(err, &re) && re.ErrorCode() == 3 {
		return true
	}
	return strings.Contains(err.Error(), "execution reverted")
}

// OnDemandMemberNeedsThisValidator reports whether this validator should act on a member it is not
// the anchoring leader for: its anchor is attested, and either the leaf is spent (this validator
// releases its copy) or the current settlement window is this validator's. Cheap reads only, so the
// validators that have nothing to do for a member do not pin their key's nonce sequence for it.
//
// A member whose anchor is attested is marked as such: it is held past the memory-backstop prune,
// because this validator may yet hold a settlement window for it.
func (o *BatchOrchestrator) OnDemandMemberNeedsThisValidator(ctx context.Context, member *PendingBatchIntent) (bool, error) {
	in, err := member.LeafInput()
	if err != nil {
		return false, err
	}
	tree, err := BuildBatchTree(member.ChainID, []BatchLeafInput{in}, member.CommitHeight)
	if err != nil {
		return false, err
	}
	chain := o.chainOps()
	attested, err := chain.anchorAlreadyAttested(ctx, tree.BundleID)
	if err != nil || !attested {
		return false, err
	}
	if !member.AttestedSeen {
		o.noteOnDemandProgress(member, func(p *PendingBatchIntent) { p.AttestedSeen = true })
	}
	consumed, err := chain.memberLeafConsumed(ctx, member)
	if err != nil {
		return false, err
	}
	if consumed {
		return true, nil
	}
	att, found, err := chain.anchorAttestation(ctx, tree.BundleID, member.AnchorBlock)
	if err != nil || !found {
		return false, err
	}
	roster, err := chain.settlementRoster(ctx)
	if err != nil {
		return false, err
	}
	win, err := newSettlementWindows(att.Time, roster, att.From, member.ChainID, member.OperationID)
	if err != nil {
		return false, err
	}
	head, err := chain.headTime(ctx)
	if err != nil {
		return false, err
	}
	j, me := win.index(head), chain.ownAddress()
	if win.settler(j+1) == me || (j > 0 && win.settler(j) == me) {
		// This validator takes over next (or now): scan what has finalized of the earlier windows
		// ahead of its turn. Best effort; the turn itself scans whatever is left.
		if fin, ferr := chain.finalizedTime(ctx); ferr == nil {
			until := fin
			if f := win.fence(j); until.After(f) {
				until = f
			}
			chain.prescanEarlierWindows(ctx, member, tree, att, until, roster)
		}
	}
	return win.settler(j) == me, nil
}

// anchorAttestation is the transaction that attested an anchor.
type anchorAttestation struct {
	Tx    string
	From  common.Address
	Block uint64
	Time  time.Time
}

// priorAttempt is a settlement of a member that an earlier window's settler sent and that was mined.
type priorAttempt struct {
	Tx       string
	From     common.Address
	Reverted bool
}

// decideSettlementWindow decides whether THIS validator may settle an attested member now, and with
// which fence. It returns true when the outcome is decided (Deferred, Released or Reverted); false
// means settle, with out.fence set.
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
	if !member.AttestedSeen {
		o.noteOnDemandProgress(member, func(p *PendingBatchIntent) { p.AttestedSeen = true })
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
	head, err := chain.headTime(ctx)
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
		finalized, ferr := chain.finalizedTime(ctx)
		if ferr != nil {
			return deferf("finalized block unreadable (%v) — deferring", ferr)
		}
		prevFence := win.fence(j - 1)
		if !finalized.After(prevFence.Add(settlementReorgMargin)) {
			return deferf("window %d is this validator's; waiting for a finalized block past window %d's fence %s "+
				"(finalized %s)", j, j-1, prevFence.UTC().Format(time.RFC3339), finalized.UTC().Format(time.RFC3339))
		}
		prior, pfound, perr := chain.priorSettlementAttempt(ctx, member, tree, att, prevFence, roster)
		if perr != nil {
			return deferf("earlier windows unreadable (%v) — deferring", perr)
		}
		if pfound {
			if prior.From == me {
				// This validator's own attempt, which its record lost. Recording it is this node's job.
				if prior.Reverted {
					o.markReverted(ctx, chain, member, prior.Tx, out)
				} else {
					o.markOwnSettled(ctx, chain, member, prior.Tx, out)
				}
				return true
			}
			out.Released = true
			o.logf("[OD] intent=%s anchor 0x%x: %s already settled it in its window (%s, mined); releasing — "+
				"that transaction is its outcome and its sender records it", member.IntentID, tree.BundleID[:8], prior.From.Hex(), prior.Tx)
			return true
		}
		o.logf("[OD] intent=%s anchor 0x%x: no earlier window's settlement is in the finalized chain; taking over in window %d",
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
	return anchorAttestation{Tx: l.TxHash.Hex(), From: from, Block: l.BlockNumber, Time: time.Unix(int64(h.Time), 0)}, true, nil
}

// headTime is the chain head's timestamp.
func (o *BatchOrchestrator) headTime(ctx context.Context) (time.Time, error) {
	h, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return time.Time{}, readErr(fmt.Errorf("reading head: %w", err))
	}
	return time.Unix(int64(h.Time), 0), nil
}

// finalizedTime is the finalized block's timestamp.
func (o *BatchOrchestrator) finalizedTime(ctx context.Context) (time.Time, error) {
	f, err := o.ecm.client.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return time.Time{}, readErr(fmt.Errorf("reading finalized block: %w", err))
	}
	return time.Unix(int64(f.Time), 0), nil
}

const validatorSetRootABIJSON = `[{"type":"function","name":"currentValidatorSetRoot","inputs":[],` +
	`"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"}]`

// settlementRoster is the validator roster, sorted by address ascending, used only after checking it
// is the set the anchor's currentValidatorSetRoot commits to. The root binds the SET (the contract
// sorts it), not the order the addresses are configured in, so the schedule must not depend on that
// order: every validator sorts, and every validator gets the same rotation. Cached once confirmed: a
// roster change needs a restart.
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
	o.roster = sortedRoster(addrs)
	return o.roster, nil
}

// sortedRoster is addrs in ascending address order - the order the anchor's set root uses.
func sortedRoster(addrs []common.Address) []common.Address {
	out := append([]common.Address(nil), addrs...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
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

// =============================================================================
// Earlier windows' attempts, from the finalized chain
// =============================================================================

// scanTx is the part of a block's transaction the scan reads, taken from the raw JSON so transaction
// types go-ethereum cannot decode (an OP-stack deposit, an Arbitrum system transaction) never stop it.
type scanTx struct {
	Hash common.Hash     `json:"hash"`
	From common.Address  `json:"from"`
	To   *common.Address `json:"to"`
}

type scanBlock struct {
	Number       hexutil.Uint64 `json:"number"`
	Transactions []scanTx       `json:"transactions"`
}

// settlementCandidates picks the transactions a roster validator sent to account.
func settlementCandidates(txs []scanTx, account common.Address, roster []common.Address) []scanTx {
	var out []scanTx
	for _, tx := range txs {
		if tx.To == nil || *tx.To != account {
			continue
		}
		for _, r := range roster {
			if tx.From == r {
				out = append(out, tx)
				break
			}
		}
	}
	return out
}

// priorSettlementAttempt looks, in the finalized blocks from the attestation to until, for a mined
// settlement of member under tree's anchor sent by a roster validator: a success, or a revert the
// intent caused (an attempt the account would have authorised, shaped as an honest settlement, whose
// execution reverted). Timing reverts, crafted or starved calls, and transactions for other members or
// anchors do not count. The first found, in chain order, is returned.
func (o *BatchOrchestrator) priorSettlementAttempt(
	ctx context.Context,
	member *PendingBatchIntent,
	tree *BatchTree,
	att anchorAttestation,
	until time.Time,
	roster []common.Address,
) (priorAttempt, bool, error) {
	return o.scanEarlierWindows(ctx, member, tree, att, until, roster, settlementScanPerPass)
}

// prescanEarlierWindows advances the scan of the earlier windows without deciding anything; its
// progress is what the settler's own turn resumes from.
func (o *BatchOrchestrator) prescanEarlierWindows(ctx context.Context, member *PendingBatchIntent, tree *BatchTree,
	att anchorAttestation, until time.Time, roster []common.Address) {
	_, _, _ = o.scanEarlierWindows(ctx, member, tree, att, until, roster, settlementPrescanPerPass)
}

// scanEarlierWindows is priorSettlementAttempt's search, covering at most perPass blocks per call.
func (o *BatchOrchestrator) scanEarlierWindows(
	ctx context.Context,
	member *PendingBatchIntent,
	tree *BatchTree,
	att anchorAttestation,
	until time.Time,
	roster []common.Address,
	perPass uint64,
) (priorAttempt, bool, error) {
	last, err := o.blockAtOrBefore(ctx, uint64(until.Unix()))
	if err != nil {
		return priorAttempt{}, false, err
	}
	rpcClient := o.ecm.client.Client()
	start := att.Block
	o.scanMu.Lock()
	if done, ok := o.scanned[tree.BundleID]; ok && done+1 > start {
		start = done + 1
	}
	o.scanMu.Unlock()
	stop := last
	if start+perPass-1 < stop {
		stop = start + perPass - 1
	}
	for from := start; from <= stop; from += settlementScanBatch {
		to := from + settlementScanBatch - 1
		if to > stop {
			to = stop
		}
		batch := make([]rpc.BatchElem, 0, to-from+1)
		blocks := make([]scanBlock, to-from+1)
		for n := from; n <= to; n++ {
			batch = append(batch, rpc.BatchElem{
				Method: "eth_getBlockByNumber",
				Args:   []interface{}{hexutil.EncodeUint64(n), true},
				Result: &blocks[n-from],
			})
		}
		if err := fetchBatch(ctx, rpcClient, batch); err != nil {
			return priorAttempt{}, false, readErr(fmt.Errorf("reading blocks %d-%d: %w", from, to, err))
		}
		for i := range batch {
			for _, c := range settlementCandidates(blocks[i].Transactions, member.Account, roster) {
				pa, ok, err := o.checkPriorAttempt(ctx, member, tree, c)
				if err != nil {
					return priorAttempt{}, false, err
				}
				if ok {
					return pa, true, nil
				}
			}
		}
		o.scanMu.Lock()
		if o.scanned == nil {
			o.scanned = make(map[[32]byte]uint64)
		}
		o.scanned[tree.BundleID] = to
		o.scanMu.Unlock()
	}
	if stop < last {
		// Not a verdict: the rest of the earlier windows is scanned on the next passes.
		return priorAttempt{}, false, readErr(fmt.Errorf("earlier windows scanned to block %d of %d; continuing next pass", stop, last))
	}
	return priorAttempt{}, false, nil
}

// fetchBatch runs one JSON-RPC batch, retrying a refused one with doubling backoff.
func fetchBatch(ctx context.Context, c *rpc.Client, batch []rpc.BatchElem) error {
	wait := time.Second
	var err error
	for attempt := 0; ; attempt++ {
		err = c.BatchCallContext(ctx, batch)
		if err == nil {
			for _, el := range batch {
				if el.Error != nil {
					err = el.Error
					break
				}
			}
		}
		if err == nil || attempt == settlementScanRetries {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
		for i := range batch {
			batch[i].Error = nil
		}
	}
}

// checkPriorAttempt judges one candidate: a settlement of this member (its calls, its operation) under
// this anchor that succeeded, or reverted as an authorised, honestly shaped attempt.
func (o *BatchOrchestrator) checkPriorAttempt(ctx context.Context, member *PendingBatchIntent, tree *BatchTree, c scanTx) (priorAttempt, bool, error) {
	tx, _, err := o.ecm.client.TransactionByHash(ctx, c.Hash)
	if errors.Is(err, types.ErrTxTypeNotSupported) {
		return priorAttempt{}, false, nil
	}
	if err != nil {
		return priorAttempt{}, false, readErr(fmt.Errorf("reading transaction %s: %w", c.Hash.Hex(), err))
	}
	p, ok := settlementProofOf(tx.Data())
	if !ok || p.AnchorId != tree.BundleID || p.OperationID != member.OperationID {
		return priorAttempt{}, false, nil
	}
	exec, err := decodeAccountExecution(tx.Data())
	if err != nil {
		return priorAttempt{}, false, nil
	}
	committed := make([]CommittedCall, 0, len(member.Legs))
	for _, l := range member.Legs {
		committed = append(committed, CommittedCall{Target: l.Target, Value: l.Value, Data: l.Data})
	}
	if matchCommittedCalls(exec.Calls, committed) != nil {
		return priorAttempt{}, false, nil
	}
	rcpt, err := o.ecm.client.TransactionReceipt(ctx, c.Hash)
	if errors.Is(err, ethereum.NotFound) {
		return priorAttempt{}, false, nil
	}
	if err != nil {
		return priorAttempt{}, false, readErr(fmt.Errorf("reading receipt %s: %w", c.Hash.Hex(), err))
	}
	if rcpt.Status == types.ReceiptStatusSuccessful {
		return priorAttempt{Tx: c.Hash.Hex(), From: c.From}, true, nil
	}
	if err := checkAuthorizedAttempt(ctx, o.ecm.client, tx, rcpt, exec, member.Account); err != nil {
		if IsChainReadError(err) {
			return priorAttempt{}, false, err
		}
		// Not an attempt the intent could have failed: timing, a crafted or starved call.
		return priorAttempt{}, false, nil
	}
	return priorAttempt{Tx: c.Hash.Hex(), From: c.From, Reverted: true}, true, nil
}
