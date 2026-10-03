package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Backfilling the kept trees of anchors attested before trees were kept (RB5 D4)
// =============================================================================
//
// A validator keeps the tree of every anchor it signs from now on (outcome_retention.go). The V8.2 anchors attested
// before that have no kept tree anywhere, so nobody could certify their outcome. This rebuilds them - on each
// validator, into its own store - from:
//
//   - the shared database, used ONLY AS HINTS: which members an anchor had, in which order, each member's operation
//     id, governance commitment, certified intent message, intent id, ADI, account and Accumulate transaction, and the
//     key page CERTEN's quorum certified for it;
//   - the user-signed intent read from Accumulate: the member's committed calls, effects and deadlines, and the
//     consensus time of the block it executed in.
//
// None of that is believed. A tree is kept only when it rebuilds EXACTLY the anchor on the chain, read through
// independent providers that agree: every member's leaf recomputed from its signed intent, the batch root, the leaf
// count, the batch operation id and the bundle id. The bundle id commits all of them, so a hint that is wrong in any
// way - a leaf, the order, an operation id, a governance commitment, a certified message, the key page - yields
// another bundle id and the tree is refused by name. Nothing is ever kept partially.

// OutcomeTreeBackfilled: this validator rebuilt the tree from hints and the signed intents, verified against the anchor.
const OutcomeTreeBackfilled OutcomeTreeRole = "backfilled"

// ErrBackfillRefused is wrapped by every refusal to keep a rebuilt tree.
var ErrBackfillRefused = errors.New("outcome tree backfill refused")

// AnchorHints is what the shared database says about an anchor's members.
type AnchorHints = database.AnchorMemberHints

// OutcomeBackfillHints reads the database's hints.
type OutcomeBackfillHints interface {
	AttestedAnchorsWithoutOutcome(ctx context.Context, chainID int64, limit int) ([]string, error)
	AnchorMemberHints(ctx context.Context, chainID int64, bundleID string) (*database.AnchorMemberHints, error)
	// CertifiedAuthority is the key page and key book CERTEN's quorum certified for an operation ("" when none).
	CertifiedAuthority(ctx context.Context, operationID string) (keyPage, keyBook string, err error)
}

// SignedIntentSource reads a user-signed intent from Accumulate: its four blobs, and the consensus time of the block
// it executed in on its partition.
type SignedIntentSource interface {
	SignedIntent(ctx context.Context, txHash, principal string) (blobs [][]byte, executedAt time.Time, err error)
}

// OutcomeBackfill rebuilds and keeps the trees of attested anchors whose outcome is not recorded.
type OutcomeBackfill struct {
	Chains  map[int64]OutcomeChainReader
	Hints   OutcomeBackfillHints
	Intents SignedIntentSource
	Trees   *OutcomeTreeStore
	Apply   bool
	Logf    func(string, ...interface{})
}

// OutcomeBackfillResult is what the backfill did with one anchor.
type OutcomeBackfillResult struct {
	ChainID  int64
	BundleID string
	// Outcome: "kept" (written, or merged with the tree already kept), "would-keep" (dry run), "held" (already kept and
	// equal), "recorded" (its outcome is on chain: nothing to certify), "not-attested", or "refused" with Reason.
	Outcome string
	Reason  string
}

// Run backfills every attested anchor of every chain that the database lists without an outcome. It returns one
// result per anchor; refusals are results, not errors - an error is a failure to run at all.
func (b *OutcomeBackfill) Run(ctx context.Context) ([]OutcomeBackfillResult, error) {
	if b.Hints == nil || b.Intents == nil || b.Trees == nil || len(b.Chains) == 0 {
		return nil, fmt.Errorf("outcome backfill: missing hints, intents, store or chains")
	}
	ids := make([]int64, 0, len(b.Chains))
	for id := range b.Chains {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var out []OutcomeBackfillResult
	for _, id := range ids {
		bundles, err := b.Hints.AttestedAnchorsWithoutOutcome(ctx, id, 100000)
		if err != nil {
			return out, fmt.Errorf("chain %d: listing attested anchors: %w", id, err)
		}
		for _, bundle := range bundles {
			r := b.One(ctx, id, bundle)
			if b.Logf != nil {
				b.Logf("[OUTCOME-BACKFILL] chain %d anchor %s: %s %s", id, bundle, r.Outcome, r.Reason)
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// One backfills one anchor.
func (b *OutcomeBackfill) One(ctx context.Context, chainID int64, bundleHex string) OutcomeBackfillResult {
	res := OutcomeBackfillResult{ChainID: chainID, BundleID: strings.ToLower(bundleHex)}
	refuse := func(format string, a ...interface{}) OutcomeBackfillResult {
		res.Outcome, res.Reason = "refused", fmt.Sprintf(format, a...)
		return res
	}
	bundle, err := parseHex32(bundleHex)
	if err != nil {
		return refuse("bundle id %q: %v", bundleHex, err)
	}
	c := b.Chains[chainID]
	if c == nil {
		return refuse("chain %d is not a settlement chain here", chainID)
	}
	view, err := c.AnchorView(ctx, bundle)
	if err != nil {
		return refuse("reading the anchor: %v", err)
	}
	a := view.Anchor
	switch {
	case a == nil || !a.Valid:
		return refuse("no valid anchor on chain")
	case a.Version != contracts.BatchAnchorV8_2:
		return refuse("the anchor is %s, not V8.2", a.Version)
	case !a.ProofExecuted:
		res.Outcome = "not-attested"
		return res
	case view.RecordedRoot != ([32]byte{}):
		res.Outcome = "recorded"
		return res
	}
	t, err := b.Rebuild(ctx, chainID, bundle, view)
	if err != nil {
		return refuse("%v", err)
	}
	if kept, err := b.Trees.Load(chainID, bundle); err == nil {
		if !kept.sameMembers(t) {
			return refuse("%v: the tree already kept for this anchor states other members", ErrOutcomeTreeContradiction)
		}
		if hasRole(kept.Roles, OutcomeTreeBackfilled) || !b.Apply {
			res.Outcome = "held"
			return res
		}
	} else if !errors.Is(err, ErrOutcomeTreeNotHeld) {
		return refuse("the tree kept for this anchor: %v", err)
	}
	if !b.Apply {
		res.Outcome = "would-keep"
		return res
	}
	if err := b.Trees.Retain(t); err != nil {
		return refuse("%v", err)
	}
	res.Outcome = "kept"
	return res
}

// Rebuild is the anchor's tree from the database's hints and the signed intents, refused unless it rebuilds the anchor
// on the chain exactly.
func (b *OutcomeBackfill) Rebuild(ctx context.Context, chainID int64, bundle [32]byte, view *OutcomeAnchorView) (*OutcomeTree, error) {
	bundleHex := "0x" + common.Bytes2Hex(bundle[:])
	hints, err := b.Hints.AnchorMemberHints(ctx, chainID, bundleHex)
	if err != nil {
		return nil, fmt.Errorf("%w: the database's members of anchor %s: %v", ErrBackfillRefused, bundleHex, err)
	}
	if hints == nil || len(hints.Members) == 0 {
		return nil, fmt.Errorf("%w: the database names no members for anchor %s", ErrBackfillRefused, bundleHex)
	}
	if uint64(len(hints.Members)) != view.LeafCount {
		return nil, fmt.Errorf("%w: the database names %d members, the anchor commits %d leaves", ErrBackfillRefused,
			len(hints.Members), view.LeafCount)
	}
	sort.Slice(hints.Members, func(i, j int) bool { return hints.Members[i].TreeIndex < hints.Members[j].TreeIndex })
	// The anchor does not commit every order of its leaves: its pairs are hashed sorted, so swapping the two leaves of a
	// pair, or two whole subtrees, keeps the root and the bundle id. The order is the one the validators formed the tree
	// in - by commit height, then intent id (BatchMempool.selectForPeriodLocked) - and the rows must state exactly it.
	if err := canonicalMemberOrder(hints.Members); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackfillRefused, err)
	}
	inputs := make([]BatchLeafInput, 0, len(hints.Members))
	members := make([]OutcomeTreeMember, 0, len(hints.Members))
	for i, h := range hints.Members {
		if h.TreeIndex != i {
			return nil, fmt.Errorf("%w: the database's member %d is at tree index %d; the indices must be 0..%d", ErrBackfillRefused,
				i, h.TreeIndex, len(hints.Members)-1)
		}
		in, m, err := b.rebuildMember(ctx, chainID, view, h, hints.BatchOperationIDVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: member %d (intent %s): %v", ErrBackfillRefused, i, h.IntentID, err)
		}
		inputs = append(inputs, in)
		members = append(members, m)
	}
	a := view.Anchor
	tree, err := BuildBatchTree(chainID, inputs, a.AccumulateBlockHeight.Uint64(), a.Incarnation)
	if err != nil {
		return nil, fmt.Errorf("%w: the members do not form a tree: %v", ErrBackfillRefused, err)
	}
	switch {
	case tree.Root != a.MerkleRoot:
		return nil, fmt.Errorf("%w: the rebuilt root 0x%x is not the anchor's 0x%x", ErrBackfillRefused, tree.Root[:8], a.MerkleRoot[:8])
	case uint64(tree.Size()) != view.LeafCount:
		return nil, fmt.Errorf("%w: the rebuilt tree has %d leaves, the anchor %d", ErrBackfillRefused, tree.Size(), view.LeafCount)
	case tree.BatchOperationID != a.OperationID:
		return nil, fmt.Errorf("%w: the rebuilt batch operation id 0x%x is not the anchor's 0x%x", ErrBackfillRefused,
			tree.BatchOperationID[:8], a.OperationID[:8])
	case tree.BundleID != bundle:
		return nil, fmt.Errorf("%w: the rebuilt bundle id 0x%x is not the anchor's 0x%x", ErrBackfillRefused, tree.BundleID[:8], bundle[:8])
	case tree.AccumulateSetRoot != a.AccumulateSetRoot:
		return nil, fmt.Errorf("%w: the rebuilt Accumulate set root is not the anchor's", ErrBackfillRefused)
	}
	for i := range members {
		members[i].Leaf, members[i].LeafIndex = tree.Leaves[i], uint64(i)
		if l := hints.Members[i].Leaf; len(l) > 0 && !bytes.Equal(l, tree.Leaves[i][:]) {
			return nil, fmt.Errorf("%w: the database's leaf of member %d is 0x%x, its signed intent's 0x%x", ErrBackfillRefused,
				i, l[:min(8, len(l))], tree.Leaves[i][:8])
		}
	}
	ot := &OutcomeTree{ChainID: chainID, BundleID: tree.BundleID, Root: tree.Root, BatchOperationID: tree.BatchOperationID,
		BatchOperationIDVersion: tree.BatchOperationIDVersion, BlockHeight: tree.BlockHeight, AccumulateSetRoot: tree.AccumulateSetRoot,
		Incarnation: tree.Incarnation, LeafVersion: keptLeafVersion(tree.LeafVersion), Members: members, Roles: []OutcomeTreeRole{OutcomeTreeBackfilled}, RetainedAt: time.Now().UTC()}
	if err := ot.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackfillRefused, err)
	}
	return ot, nil
}

// rebuildMember is one member from its hints and its signed intent.
func (b *OutcomeBackfill) rebuildMember(ctx context.Context, chainID int64, view *OutcomeAnchorView, h database.AnchorMemberHint,
	opVersion string) (BatchLeafInput, OutcomeTreeMember, error) {
	var in BatchLeafInput
	var m OutcomeTreeMember
	op, err := parseHex32(h.OperationID)
	if err != nil {
		return in, m, fmt.Errorf("the database's operation id %q: %v", h.OperationID, err)
	}
	if h.ADIURL == "" || h.IntentID == "" {
		return in, m, fmt.Errorf("the database names no ADI or intent id")
	}
	var blobs [][]byte
	var executedAt time.Time
	var tried []string
	for _, tx := range uniqueStrings(h.AccumTxHash, h.LifecycleAccumTxHash) {
		for _, principal := range []string{strings.TrimSuffix(h.ADIURL, "/") + "/data", h.ADIURL} {
			blobs, executedAt, err = b.Intents.SignedIntent(ctx, tx, principal)
			if err == nil {
				break
			}
			tried = append(tried, fmt.Sprintf("%s@%s: %v", tx, principal, err))
		}
		if blobs != nil {
			break
		}
	}
	if blobs == nil {
		return in, m, fmt.Errorf("its signed intent cannot be read from Accumulate (%s)", strings.Join(tried, "; "))
	}
	ci := &consensus.CertenIntent{IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}
	if got := intentIDFromBlob(blobs[0]); got != h.IntentID {
		return in, m, fmt.Errorf("the signed intent read is intent %q, the database names %q", got, h.IntentID)
	}
	batchLegs, legChain, account, opID, err := consensus.MemberLegsForChain(ci, chainID)
	if err != nil {
		return in, m, fmt.Errorf("the signed intent's member on chain %d: %v", chainID, err)
	}
	if legChain != chainID || opID != op {
		return in, m, fmt.Errorf("the signed intent's operation id is 0x%x, the database names 0x%x", opID[:8], op[:8])
	}
	if h.Account != "" && !strings.EqualFold(common.Address(account).Hex(), common.HexToAddress(h.Account).Hex()) {
		return in, m, fmt.Errorf("the signed intent's account is %s, the database names %s", common.Address(account).Hex(), h.Account)
	}
	legs, _, _, err := memberLegsFromSignedIntent(blobs, chainID)
	if err != nil {
		return in, m, err
	}
	// The member as the mempool held it: its legs with their signed deadlines, its commit time, its place in a declared
	// cross-chain order - so its deadline is the one every validator computed (PendingBatchIntent.Deadline).
	p := &PendingBatchIntent{IntentID: h.IntentID, ADIURL: h.ADIURL, ChainID: chainID, Account: common.Address(account),
		OperationID: op, CommitTime: executedAt.UTC()}
	for _, l := range batchLegs {
		p.Legs = append(p.Legs, LegExecution{ChainID: chainID, Target: common.Address(l.Target), Value: l.Value, Data: l.Data,
			Deadline: l.Deadline})
	}
	order, err := consensus.DeclaredCrossChainOrder(ci)
	if err != nil {
		return in, m, fmt.Errorf("the signed intent's declared order: %v", err)
	}
	if order != nil {
		pos := -1
		for i, ch := range order.Chains {
			if ch == chainID {
				pos = i
			}
		}
		if pos < 0 {
			return in, m, fmt.Errorf("the signed intent's declared order does not name chain %d", chainID)
		}
		p.SequencePosition = pos
	}
	deadline, ok := p.Deadline()
	if !ok {
		return in, m, fmt.Errorf("no deadline can be stated")
	}
	exec, err := p.ExecutionCommitment()
	if err != nil {
		return in, m, err
	}
	in = BatchLeafInput{ADIURL: h.ADIURL, ExecutionCommitment: exec, OperationID: op, AccumulateSetRoot: view.Anchor.AccumulateSetRoot,
		IntentID: h.IntentID}
	switch {
	case h.GovernanceCommitment == "" && opVersion == BatchOperationIDV1:
		in.LegacyNoGovernance = true
	case h.GovernanceCommitment == "":
		return in, m, fmt.Errorf("the database names no governance commitment for a %s batch", opVersion)
	default:
		if in.GovernanceCommitment, err = parseHex32(h.GovernanceCommitment); err != nil {
			return in, m, fmt.Errorf("the database's governance commitment: %v", err)
		}
	}
	if h.CertifiedIntentMessage != "" {
		if in.IntentMessage, err = parseHex32(h.CertifiedIntentMessage); err != nil {
			return in, m, fmt.Errorf("the database's certified intent message: %v", err)
		}
	}
	page, book, err := b.Hints.CertifiedAuthority(ctx, h.OperationID)
	if err != nil {
		return in, m, fmt.Errorf("the certified key page: %v", err)
	}
	if page == "" || book == "" {
		return in, m, fmt.Errorf("the database holds no certified key page for operation %s", h.OperationID)
	}
	if in.AuthorityBook, in.AuthorityPage, err = AuthorityOf(page, book); err != nil {
		return in, m, err
	}
	// The leaf of the account generation the chain is on (RB5-F57): a v4 leaf binds the window the mempool member had -
	// its commit time (the signed intent's Accumulate execution time) to its deadline - rebuilt here from the same facts.
	version, err := AccountLeafVersionOf(chainID)
	if err != nil {
		return in, m, err
	}
	if version == AccountLeafV4 {
		if in.NotBefore, in.NotAfter, err = p.Window(); err != nil {
			return in, m, err
		}
	}
	m = OutcomeTreeMember{OperationID: op, IntentID: h.IntentID, ADIURL: h.ADIURL, Account: common.Address(account),
		AuthorityBook: in.AuthorityBook, AuthorityPage: in.AuthorityPage, GovernanceCommitment: in.GovernanceCommitment,
		IntentMessage: in.IntentMessage, LegacyNoGovernance: in.LegacyNoGovernance, Deadline: deadline.Unix(),
		NotBefore: int64(in.NotBefore), SearchFrom: executedAt.Add(-leafSpendMargin).Unix()}
	for _, l := range legs {
		tl := OutcomeTreeLeg{Target: l.Call.Target, Value: (*hexutil.Big)(callValue(l.Call.Value)), Data: append(hexutil.Bytes(nil), l.Call.Data...),
			State: append([]ExpectedStateSlot(nil), l.State...)}
		for _, e := range l.Events {
			tl.Events = append(tl.Events, outcomeTreeEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash})
		}
		m.Legs = append(m.Legs, tl)
	}
	return in, m, nil
}

func uniqueStrings(xs ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		x = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(x)), "0x")
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// AccumulateIntentSource reads signed intents from an Accumulate v3 endpoint.
type AccumulateIntentSource struct {
	Adapter *accumulate.LiteClientAdapter
	// URL is the endpoint's base (…/v3 is appended).
	URL    string
	Client *http.Client
}

// SignedIntent reads the intent's writeData blobs, and the consensus time of the block its principal's main chain
// recorded the transaction in - the block it executed in, which admission took as its commit time (RB4-F74).
func (s AccumulateIntentSource) SignedIntent(ctx context.Context, txHash, principal string) ([][]byte, time.Time, error) {
	if s.Adapter == nil {
		return nil, time.Time{}, fmt.Errorf("no Accumulate client")
	}
	blobs, err := s.Adapter.GetIntentBlobs(ctx, txHash, principal)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(blobs) < 4 {
		return nil, time.Time{}, fmt.Errorf("the signed intent has %d blobs", len(blobs))
	}
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "query", "params": map[string]interface{}{
		"scope": principal, "query": map[string]interface{}{"queryType": "chain", "name": "main", "entry": txHash, "includeReceipt": true}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(strings.TrimSuffix(s.URL, "/"), "/v3")+"/v3", bytes.NewReader(body))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	cl := s.Client
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Entry   string `json:"entry"`
			Receipt struct {
				LocalBlock     uint64    `json:"localBlock"`
				LocalBlockTime time.Time `json:"localBlockTime"`
			} `json:"receipt"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, time.Time{}, fmt.Errorf("the chain entry of %s on %s: %w", txHash, principal, err)
	}
	if out.Error != nil {
		return nil, time.Time{}, fmt.Errorf("the chain entry of %s on %s: %s", txHash, principal, out.Error.Message)
	}
	if !strings.EqualFold(out.Result.Entry, strings.TrimPrefix(txHash, "0x")) || out.Result.Receipt.LocalBlockTime.IsZero() {
		return nil, time.Time{}, fmt.Errorf("the chain entry of %s on %s names no block time", txHash, principal)
	}
	return blobs, out.Result.Receipt.LocalBlockTime, nil
}

// canonicalMemberOrder refuses members not in the order a tree is formed in: ascending commit height, then intent id.
// A one-member tree has no order to state.
func canonicalMemberOrder(ms []database.AnchorMemberHint) error {
	if len(ms) < 2 {
		return nil
	}
	for i, m := range ms {
		if m.CommitHeight <= 0 {
			return fmt.Errorf("member %d (intent %s) has no recorded commit height, so its place in the tree cannot be confirmed", i, m.IntentID)
		}
		if i == 0 {
			continue
		}
		p := ms[i-1]
		if m.CommitHeight < p.CommitHeight || (m.CommitHeight == p.CommitHeight && m.IntentID <= p.IntentID) {
			return fmt.Errorf("members %d and %d (intents %s at %d, %s at %d) are not in the order a tree is formed in",
				i-1, i, p.IntentID, p.CommitHeight, m.IntentID, m.CommitHeight)
		}
	}
	return nil
}
