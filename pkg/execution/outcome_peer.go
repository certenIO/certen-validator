package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Outcome attestation - the peer side (RB5 D4)
// =============================================================================
//
// The recorder asks each peer to co-sign a batch anchor's outcome root. A peer signs ONLY a root it derives itself:
//
//	FROM ITS OWN KEPT TREE (the members as it signed them) AND ITS OWN AGREED READS OF THE CHAIN.
//
// The request names the anchor and the root it proposes - for comparison, never to build from - and offers hints:
// reverted attempts the recorder knows of. A hint is only a transaction to look at; the peer verifies each on the chain
// before it can enter a leaf, exactly as it verifies its own.
//
// Before deriving, the peer checks the anchor on the chain IS the tree it kept: valid, its proof executed, the same
// batch root, leaf count, Accumulate set root and incarnation. It signs the registry's message, which commits the
// anchor's currentValidatorSetRoot at the time of recording: the peer refuses unless that is the CERTEN set it signs
// for, so its partial can only count under the set the anchor will check it against.

// OutcomeRequestEndpoint is the peer path the outcome recorder posts to.
const OutcomeRequestEndpoint = "/api/batch/outcome/request"

// DefaultOutcomeRequestTimeout bounds one peer's derivation and signature: a peer reads every member's settlement,
// receipt and effects from independent providers before it signs.
const DefaultOutcomeRequestTimeout = 4 * time.Minute

// Outcome refusal codes, beside the attestation codes a peer reuses (member_not_held, not_ready, config_mismatch,
// refused).
const (
	// CodeOutcomeNotFinal: a member's outcome is not final, or not agreed, yet on this validator's view. Retryable.
	CodeOutcomeNotFinal AttestationRefusalCode = "outcome_not_final"
	// CodeOutcomeMismatch: this validator derives a different outcome root. Never signed.
	CodeOutcomeMismatch AttestationRefusalCode = "outcome_mismatch"
	// CodeAnchorMismatch: the anchor on the chain is not the tree this validator kept for it. Never signed.
	CodeAnchorMismatch AttestationRefusalCode = "anchor_mismatch"
	// CodeSetRootDrift: the anchor's currentValidatorSetRoot is not the CERTEN set this validator signs for.
	CodeSetRootDrift AttestationRefusalCode = "set_root_drift"
	// CodeOutcomeRecorded: the registry already holds an outcome for the anchor.
	CodeOutcomeRecorded AttestationRefusalCode = "outcome_recorded"
)

// OutcomeRequest asks a peer to co-sign an anchor's outcome root.
type OutcomeRequest struct {
	ChainID  int64  `json:"chain_id"`
	BundleID string `json:"bundle_id"`
	// OutcomeRoot is what the recorder derived, for comparison ONLY.
	OutcomeRoot string `json:"outcome_root"`
	ProposerID  string `json:"proposer_id"`
	// Members are hints: candidate reverted attempts per member. Each is verified on the chain before it is used.
	Members []OutcomeMemberHint `json:"members,omitempty"`
}

// OutcomeMemberHint is one member's candidate reverted attempts, 0x-hex.
type OutcomeMemberHint struct {
	OperationID string   `json:"operation_id"`
	Attempts    []string `json:"reverted_attempts,omitempty"`
}

// OutcomeResponse is a peer's partial signature over the outcome message, or a refusal.
type OutcomeResponse struct {
	ValidatorID  string `json:"validator_id"`
	EVMAddress   string `json:"evm_address"`
	SignatureHex string `json:"signature_hex,omitempty"`
	PublicKeyHex string `json:"public_key_hex,omitempty"`
	BundleID     string `json:"bundle_id"`
	// OutcomeRoot is what THIS peer derived; MessageHash the outcome message it signed (or would have).
	OutcomeRoot string `json:"outcome_root,omitempty"`
	MessageHash string `json:"message_hash,omitempty"`
	// SetRoot is the CERTEN validator set root the message commits.
	SetRoot string                 `json:"set_root,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Code    AttestationRefusalCode `json:"code,omitempty"`
	// LeafHashes are this peer's outcome leaves, in tree order, and Attempts the reverted attempts it considered: on a
	// mismatch they say where it differs, and let the recorder offer the attempts it did not know of.
	LeafHashes []string            `json:"leaf_hashes,omitempty"`
	Attempts   []OutcomeMemberHint `json:"attempts,omitempty"`
}

// OutcomeAttemptSource names reverted attempts of a member this validator knows of - candidates only, each verified on
// the chain before it is named in a leaf.
type OutcomeAttemptSource interface {
	AttemptsFor(ctx context.Context, chainID int64, m OutcomeTreeMember) ([]common.Hash, error)
}

// StackAttemptSource reads a member's attempts from what this validator holds: its own settlement broadcasts (the
// mempool, while it keeps the member) and the member's recorded outcome's settlement transaction (the shared database).
type StackAttemptSource struct{ Stack *BatchStack }

func (s StackAttemptSource) AttemptsFor(ctx context.Context, chainID int64, m OutcomeTreeMember) ([]common.Hash, error) {
	if s.Stack == nil {
		return nil, fmt.Errorf("no batch stack to read attempts from")
	}
	var out []common.Hash
	if s.Stack.Mempool != nil {
		if p, ok := s.Stack.Mempool.FindMember(chainID, m.OperationID); ok {
			for _, h := range p.settlementHashes() {
				if IsTransactionHash(h) {
					out = append(out, common.HexToHash(h))
				}
			}
		}
	}
	if s.Stack.MemberOutcomes != nil && m.IntentID != "" {
		o, err := s.Stack.MemberOutcomes.MemberOutcomeOf(ctx, m.IntentID, chainID)
		if err != nil {
			return nil, readErr(fmt.Errorf("the recorded outcome of intent %s on chain %d: %w", m.IntentID, chainID, err))
		}
		if o != nil && IsTransactionHash(o.SettlementTx) {
			out = append(out, common.HexToHash(o.SettlementTx))
		}
	}
	return out, nil
}

// OutcomePeer answers outcome requests.
type OutcomePeer struct {
	Trees    *OutcomeTreeStore
	Chains   map[int64]OutcomeChainReader
	Attempts OutcomeAttemptSource
	// Key is this validator's BLS key; nil reads the key manager main initialises.
	Key func() *bls.PrivateKey
	// SetRoot is the CERTEN validator set root this validator signs for; nil reads contracts.GetV6_1ValidatorSetRoot.
	SetRoot func() ([32]byte, error)
}

func (p *OutcomePeer) key() *bls.PrivateKey {
	if p.Key != nil {
		return p.Key()
	}
	km := bls.GetValidatorBLSKey()
	if km == nil {
		return nil
	}
	return km.PrivateKey()
}

func (p *OutcomePeer) setRoot() ([32]byte, error) {
	if p.SetRoot != nil {
		return p.SetRoot()
	}
	return contracts.GetV6_1ValidatorSetRoot()
}

// attemptHints merges the request's hints with this validator's own, per operation id.
func attemptHints(ctx context.Context, src OutcomeAttemptSource, t *OutcomeTree, hints []OutcomeMemberHint) (map[[32]byte][]common.Hash, error) {
	out := map[[32]byte][]common.Hash{}
	for _, h := range hints {
		op, err := parseHex32(h.OperationID)
		if err != nil {
			continue // a malformed hint names nothing
		}
		for _, a := range h.Attempts {
			if IsTransactionHash(a) {
				out[op] = append(out[op], common.HexToHash(a))
			}
		}
	}
	if src != nil {
		for _, m := range t.Members {
			own, err := src.AttemptsFor(ctx, t.ChainID, m)
			if err != nil {
				return nil, err
			}
			out[m.OperationID] = append(out[m.OperationID], own...)
		}
	}
	return out, nil
}

// hintsOf renders attempts per operation as hints, ascending by operation.
func hintsOf(attempts map[[32]byte][]common.Hash) []OutcomeMemberHint {
	var out []OutcomeMemberHint
	for op, hs := range attempts {
		h := OutcomeMemberHint{OperationID: "0x" + hex.EncodeToString(op[:])}
		for _, x := range uniqueHashes(hs) {
			h.Attempts = append(h.Attempts, strings.ToLower(x.Hex()))
		}
		if len(h.Attempts) > 0 {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OperationID < out[j].OperationID })
	return out
}

// checkAnchorIsTree refuses an anchor that is not the kept tree's.
func checkAnchorIsTree(v *OutcomeAnchorView, t *OutcomeTree) error {
	a := v.Anchor
	switch {
	case a == nil || !a.Valid:
		return fmt.Errorf("anchor 0x%x is not a valid anchor on chain %d", t.BundleID[:8], t.ChainID)
	case a.Version != contracts.BatchAnchorV8_2:
		return fmt.Errorf("anchor 0x%x is a %s anchor, not V8.2", t.BundleID[:8], a.Version)
	case a.MerkleRoot != t.Root:
		return fmt.Errorf("anchor 0x%x commits root 0x%x, the kept tree 0x%x", t.BundleID[:8], a.MerkleRoot[:8], t.Root[:8])
	case v.LeafCount != uint64(len(t.Members)):
		return fmt.Errorf("anchor 0x%x commits %d leaves, the kept tree %d", t.BundleID[:8], v.LeafCount, len(t.Members))
	case a.AccumulateSetRoot != t.AccumulateSetRoot || a.Incarnation != t.Incarnation:
		return fmt.Errorf("anchor 0x%x commits Accumulate set 0x%x under incarnation 0x%x, the kept tree 0x%x under 0x%x",
			t.BundleID[:8], a.AccumulateSetRoot[:8], a.Incarnation[:8], t.AccumulateSetRoot[:8], t.Incarnation[:8])
	}
	return nil
}

// HandleOutcomeRequest is the peer-side handler. Refusing is always safe: the recorder retries, and an outcome that
// never reaches quorum is never recorded.
func (p *OutcomePeer) HandleOutcomeRequest(ctx context.Context, req *OutcomeRequest, me BatchAttesterIdentity) *OutcomeResponse {
	resp := &OutcomeResponse{ValidatorID: me.ValidatorID, EVMAddress: me.EVMAddress}
	refuse := func(code AttestationRefusalCode, format string, a ...interface{}) *OutcomeResponse {
		resp.Error, resp.Code = fmt.Sprintf(format, a...), code
		resp.SignatureHex, resp.PublicKeyHex = "", ""
		return resp
	}
	switch {
	case req == nil:
		return refuse(CodeRefused, "nil request")
	case p == nil || p.Trees == nil:
		return refuse(CodeNotReady, "the outcome peer is not ready: no kept trees")
	case me.EVMAddress == "":
		return refuse(CodeNotReady, "attester has no EVM identity; its signature could not be attributed")
	}
	bundle, err := parseHex32(req.BundleID)
	if err != nil {
		return refuse(CodeRefused, "malformed bundle id: %v", err)
	}
	want, err := parseHex32(req.OutcomeRoot)
	if err != nil || want == ([32]byte{}) {
		return refuse(CodeRefused, "malformed or zero outcome root %q", req.OutcomeRoot)
	}
	resp.BundleID = "0x" + hex.EncodeToString(bundle[:])
	c := p.Chains[req.ChainID]
	if c == nil {
		return refuse(CodeConfigMismatch, "chain %d is not a settlement chain with an outcome registry here", req.ChainID)
	}

	// ---- The tree THIS validator kept: never the request's ------------------------
	tree, err := p.Trees.Load(req.ChainID, bundle)
	if errors.Is(err, ErrOutcomeTreeNotHeld) {
		return refuse(CodeMemberNotHeld, "this validator holds no tree for anchor %s on chain %d: it neither signed nor proved it",
			shortHex(req.BundleID), req.ChainID)
	}
	if err != nil {
		return refuse(CodeRefused, "the tree kept for anchor %s: %v", shortHex(req.BundleID), err)
	}

	// ---- The anchor on the chain is that tree, and its outcome is not recorded ------
	view, err := c.AnchorView(ctx, bundle)
	if err != nil {
		return refuse(CodeOutcomeNotFinal, "reading anchor %s and its registry: %v", shortHex(req.BundleID), err)
	}
	if err := checkAnchorIsTree(view, tree); err != nil {
		return refuse(CodeAnchorMismatch, "%v", err)
	}
	if !view.Anchor.ProofExecuted {
		return refuse(CodeOutcomeNotFinal, "anchor %s's proof has not executed at block %d", shortHex(req.BundleID), view.At.Number.Uint64())
	}
	if view.RecordedRoot != ([32]byte{}) {
		rel := "the same root"
		if view.RecordedRoot != want {
			rel = fmt.Sprintf("a DIFFERENT root 0x%x", view.RecordedRoot[:8])
		}
		return refuse(CodeOutcomeRecorded, "the registry already records %s for anchor %s (block %d)", rel, shortHex(req.BundleID), view.RecordedIn)
	}
	setRoot, err := p.setRoot()
	if err != nil {
		return refuse(CodeNotReady, "validator-set root: %v", err)
	}
	resp.SetRoot = "0x" + hex.EncodeToString(setRoot[:])
	if view.CurrentSetRoot != setRoot {
		return refuse(CodeSetRootDrift, "anchor's currentValidatorSetRoot 0x%x is not the CERTEN set 0x%x this validator signs for: "+
			"the registry would check this partial against another set", view.CurrentSetRoot[:8], setRoot[:8])
	}

	// ---- Derive every member from the chain ------------------------------------------
	hints, err := attemptHints(ctx, p.Attempts, tree, req.Members)
	if err != nil {
		return refuse(CodeOutcomeNotFinal, "this validator's own attempts: %v", err)
	}
	derived, err := DeriveOutcome(ctx, c, tree, hints)
	if err != nil {
		if IsOutcomeRetryable(err) {
			return refuse(CodeOutcomeNotFinal, "%v", err)
		}
		return refuse(CodeRefused, "%v", err)
	}
	resp.OutcomeRoot = "0x" + hex.EncodeToString(derived.Root[:])
	for _, l := range derived.Leaves {
		h, _ := l.Hash()
		resp.LeafHashes = append(resp.LeafHashes, "0x"+hex.EncodeToString(h[:]))
	}
	resp.Attempts = hintsOf(hints)
	if derived.Root != want {
		return refuse(CodeOutcomeMismatch, "outcome mismatch for anchor %s: the recorder proposes 0x%x, this validator derives 0x%x - "+
			"refusing to certify an outcome it did not reproduce", shortHex(req.BundleID), want[:8], derived.Root[:8])
	}

	// ---- The registry's own message, and the signature --------------------------------
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(req.ChainID, bundle, derived.Root, setRoot, tree.AccumulateSetRoot, tree.Incarnation)
	onChain, err := c.OutcomeMessage(ctx, bundle, derived.Root, view.At)
	if err != nil {
		return refuse(CodeOutcomeNotFinal, "reading the registry's outcome message: %v", err)
	}
	if onChain != msg {
		return refuse(CodeRefused, "the registry signs outcome message 0x%x, this validator computes 0x%x", onChain[:8], msg[:8])
	}
	resp.MessageHash = "0x" + hex.EncodeToString(msg[:])
	sk := p.key()
	if sk == nil {
		return refuse(CodeNotReady, "validator BLS private key not loaded")
	}
	sig, err := consensus.SignBatchAttestation(sk, msg)
	if err != nil {
		return refuse(CodeRefused, "signing: %v", err)
	}
	resp.SignatureHex, resp.PublicKeyHex = sig, sk.PublicKey().Hex()
	return resp
}

// OutcomeCollectResult is what the recorder's round of outcome requests gathered.
type OutcomeCollectResult struct {
	Responses []*OutcomeResponse // agreeing partials
	Refusals  map[AttestationRefusalCode]int
	// Attempts are the reverted attempts peers reported considering, for the next round's hints.
	Attempts []OutcomeMemberHint
	// Unreachable counts peers that did not answer.
	Unreachable int
}

// Retryable reports whether a short quorum may still form by waiting: nobody disagreed with the root.
func (r OutcomeCollectResult) Retryable() bool {
	return r.Refusals[CodeOutcomeMismatch] == 0 && r.Refusals[CodeAnchorMismatch] == 0 && r.Refusals[CodeRefused] == 0
}

// CollectOutcomeAttestations asks every peer to co-sign the outcome and keeps the partials over exactly msgHash for
// exactly the proposed root. Refusals are counted by code; nothing a peer says is folded in unless it agrees.
func CollectOutcomeAttestations(ctx context.Context, logger *log.Logger, peers []string, req *OutcomeRequest, msgHash [32]byte,
	timeout time.Duration) OutcomeCollectResult {
	res := OutcomeCollectResult{Refusals: map[AttestationRefusalCode]int{}}
	if req == nil || len(peers) == 0 {
		return res
	}
	if timeout <= 0 {
		timeout = DefaultOutcomeRequestTimeout
	}
	logf := func(format string, a ...interface{}) {
		if logger != nil {
			logger.Printf(format, a...)
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		logf("⚠️ [OUTCOME] encoding request: %v", err)
		return res
	}
	wantMsg := "0x" + hex.EncodeToString(msgHash[:])
	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{Timeout: timeout}
	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			hreq, err := http.NewRequestWithContext(rctx, http.MethodPost, peer+OutcomeRequestEndpoint, bytes.NewReader(body))
			if err != nil {
				return
			}
			hreq.Header.Set("Content-Type", "application/json")
			hresp, err := client.Do(hreq)
			if err != nil || hresp.StatusCode != http.StatusOK {
				if hresp != nil {
					hresp.Body.Close()
				}
				logf("⚠️ [OUTCOME] %s: unreachable or HTTP error: %v", peer, err)
				mu.Lock()
				res.Unreachable++
				mu.Unlock()
				return
			}
			defer hresp.Body.Close()
			var out OutcomeResponse
			if err := json.NewDecoder(hresp.Body).Decode(&out); err != nil {
				logf("⚠️ [OUTCOME] %s: decoding: %v", peer, err)
				mu.Lock()
				res.Unreachable++
				mu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			res.Attempts = append(res.Attempts, out.Attempts...)
			if out.Error != "" {
				res.Refusals[out.Code]++
				logf("↩️  [OUTCOME] %s declined (%s): %s", peer, out.Code, out.Error)
				return
			}
			if out.SignatureHex == "" || out.EVMAddress == "" || !strings.EqualFold(out.BundleID, req.BundleID) ||
				!strings.EqualFold(out.OutcomeRoot, req.OutcomeRoot) || !strings.EqualFold(out.MessageHash, wantMsg) {
				res.Refusals[CodeRefused]++
				logf("⚠️ [OUTCOME] %s signed something other than the proposed outcome - discarding", peer)
				return
			}
			res.Responses = append(res.Responses, &out)
			logf("✅ [OUTCOME] %s certified", peer)
		}(peer)
	}
	wg.Wait()
	return res
}
