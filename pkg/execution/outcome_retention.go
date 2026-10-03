package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// =============================================================================
// The batch trees this validator signed or proved, kept for their outcome (RB5 D4)
// =============================================================================
//
// A batch anchor's outcome is certified by the same quorum that authorized it: each validator states, from the chain
// itself, what every member of a tree it signed DID, and signs the root over those outcomes only when its own
// derivation reproduces it (outcome_derivation.go, outcome_peer.go).
//
// For that a validator needs the tree it signed - every member's leaf, operation, account, committed calls and
// effects, and deadline - long after the batch was formed. The validators share one database, so a database row is
// a hint, never a source: it is the very thing a dishonest or mistaken peer could have written. The mempool is no
// source either, because a member is pruned from it once its outcome is recorded in that shared database. So each
// validator keeps its OWN copy, on its own disk, written at the moment it signs or proves a tree - the same data it
// signed from - and deletes it only once the chain's finalized state records that anchor's outcome.
//
// A tree is written once. A second write of the same bundle must state exactly the same tree: anything else is two
// different member records under one anchor, which is refused by name, never resolved by overwriting.

// ErrOutcomeTreeNotHeld: this validator holds no tree for the anchor (it neither signed nor proved it).
var ErrOutcomeTreeNotHeld = errors.New("this validator holds no batch tree for the anchor")

// ErrOutcomeTreeContradiction: a tree written for an anchor differs from the one already kept for it.
var ErrOutcomeTreeContradiction = errors.New("a batch tree contradicts the one kept for its anchor")

// OutcomeTreeRole says how this validator came to hold a tree.
type OutcomeTreeRole string

const (
	// OutcomeTreeSigned: this validator co-signed the tree's anchor as a peer.
	OutcomeTreeSigned OutcomeTreeRole = "signed"
	// OutcomeTreeProved: this validator proved the tree's anchor as its leader.
	OutcomeTreeProved OutcomeTreeRole = "proved"
)

// OutcomeTree is a batch tree as this validator signed it, with what stating each member's outcome needs.
type OutcomeTree struct {
	ChainID          int64       `json:"chain_id"`
	BundleID         common.Hash `json:"bundle_id"`
	Root             common.Hash `json:"root"`
	BatchOperationID common.Hash `json:"batch_operation_id"`
	// BatchOperationIDVersion is how BatchOperationID was derived (BatchTree.BatchOperationIDVersion).
	BatchOperationIDVersion string      `json:"batch_operation_id_version"`
	BlockHeight             uint64      `json:"accumulate_block_height"`
	AccumulateSetRoot       common.Hash `json:"accumulate_set_root"`
	Incarnation             common.Hash `json:"incarnation"`
	// LeafVersion is the account leaf version the tree's leaves are of (RB5-F57), so the tree re-derives with the leaves
	// it was formed with even after its chain moves to another version. Absent is v3: every tree kept before F57 was
	// formed with v3 leaves, and a v3 tree is still written without it, byte for byte as before.
	LeafVersion AccountLeafVersion  `json:"leaf_version,omitempty"`
	Members     []OutcomeTreeMember `json:"members"`
	// Roles is every way this validator came to hold the tree, ascending; RetainedAt is the first write.
	Roles      []OutcomeTreeRole `json:"roles"`
	RetainedAt time.Time         `json:"retained_at"`
}

// OutcomeTreeMember is one member, at its leaf's index.
type OutcomeTreeMember struct {
	LeafIndex   uint64         `json:"leaf_index"`
	Leaf        common.Hash    `json:"leaf"`
	OperationID common.Hash    `json:"operation_id"`
	IntentID    string         `json:"intent_id"`
	ADIURL      string         `json:"adi_url"`
	Account     common.Address `json:"account"`
	// The leaf's other inputs, so the kept tree re-derives its own leaves, root and bundle id (Verify).
	AuthorityBook        common.Hash `json:"authority_book"`
	AuthorityPage        uint64      `json:"authority_page"`
	GovernanceCommitment common.Hash `json:"governance_commitment"`
	IntentMessage        common.Hash `json:"intent_message"`
	LegacyNoGovernance   bool        `json:"legacy_no_governance,omitempty"`
	// Legs are the member's committed calls with the effects each committed, as the user-signed intent states them.
	Legs []OutcomeTreeLeg `json:"legs"`
	// Deadline is the latest time the member may execute (PendingBatchIntent.Deadline), unix seconds. On a v4 chain it is
	// also the notAfter the member's leaf binds (RB5-F57).
	Deadline int64 `json:"deadline"`
	// NotBefore is the notBefore a v4 leaf binds - the member's Accumulate commit time - unix seconds (RB5-F57). Zero, and
	// absent, on a v3 chain, whose leaf binds no window.
	NotBefore int64 `json:"not_before,omitempty"`
	// SearchFrom is the earliest time the member's leaf could have been consumed - its Accumulate commit, or this
	// validator's first sighting, less leafSpendMargin - unix seconds. Where a search for the consumption starts; it is
	// never a fact.
	SearchFrom int64 `json:"search_from"`
}

// OutcomeTreeLeg is one committed leg.
type OutcomeTreeLeg struct {
	Target common.Address      `json:"target"`
	Value  *hexutil.Big        `json:"value"`
	Data   hexutil.Bytes       `json:"data"`
	Events []outcomeTreeEvent  `json:"events,omitempty"`
	State  []ExpectedStateSlot `json:"state,omitempty"`
}

type outcomeTreeEvent struct {
	Contract common.Address `json:"contract"`
	Topic0   common.Hash    `json:"topic0"`
	DataHash common.Hash    `json:"data_hash"`
}

// CommittedLegs are the member's legs as the settlement verifiers take them.
func (m OutcomeTreeMember) CommittedLegs() []CommittedLeg {
	out := make([]CommittedLeg, 0, len(m.Legs))
	for _, l := range m.Legs {
		cl := CommittedLeg{Call: CommittedCall{Target: l.Target, Value: new(big.Int).Set(l.Value.ToInt()), Data: append([]byte(nil), l.Data...)}}
		for _, e := range l.Events {
			cl.Events = append(cl.Events, ExpectedEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash})
		}
		cl.State = append(cl.State, l.State...)
		out = append(out, cl)
	}
	return out
}

// signedIntentHolder is a member's round snapshot as retention reads it: the user-signed intent it admitted.
type signedIntentHolder interface {
	SignedIntentBlobs() ([][]byte, error)
}

// NewOutcomeTree is the kept form of tree, whose members are byOperation (each member of the tree, keyed by its
// operation id). Every member must carry its user-signed intent, and the legs that intent commits on the tree's chain
// must be exactly the calls the member's leaf commits: the effects kept are then the ones the leaf's account executes.
func NewOutcomeTree(tree *BatchTree, byOperation map[[32]byte]*PendingBatchIntent, role OutcomeTreeRole) (*OutcomeTree, error) {
	if tree == nil {
		return nil, fmt.Errorf("%w: nil tree", ErrOutcome)
	}
	if len(tree.Inputs) != len(tree.Leaves) || len(tree.Leaves) == 0 {
		return nil, fmt.Errorf("%w: tree 0x%x has %d inputs for %d leaves", ErrOutcome, tree.BundleID[:8], len(tree.Inputs), len(tree.Leaves))
	}
	ot := &OutcomeTree{
		ChainID: tree.ChainID, BundleID: tree.BundleID, Root: tree.Root, BatchOperationID: tree.BatchOperationID,
		BatchOperationIDVersion: tree.BatchOperationIDVersion, BlockHeight: tree.BlockHeight,
		AccumulateSetRoot: tree.AccumulateSetRoot, Incarnation: tree.Incarnation, LeafVersion: keptLeafVersion(tree.LeafVersion),
		Roles: []OutcomeTreeRole{role}, RetainedAt: time.Now().UTC(),
	}
	for i, in := range tree.Inputs {
		p := byOperation[in.OperationID]
		if p == nil {
			return nil, fmt.Errorf("%w: tree 0x%x: member %d (operation %x) is not held here", ErrOutcome, tree.BundleID[:8], i, in.OperationID[:8])
		}
		m, err := outcomeTreeMember(tree, i, in, p)
		if err != nil {
			return nil, fmt.Errorf("tree 0x%x: %w", tree.BundleID[:8], err)
		}
		ot.Members = append(ot.Members, m)
	}
	if err := ot.Verify(); err != nil {
		return nil, err
	}
	return ot, nil
}

func outcomeTreeMember(tree *BatchTree, i int, in BatchLeafInput, p *PendingBatchIntent) (OutcomeTreeMember, error) {
	var none OutcomeTreeMember
	holder, ok := p.Attestation.(signedIntentHolder)
	if !ok || p.Attestation == nil {
		return none, fmt.Errorf("%w: member %s carries no user-signed intent (%T); its committed effects cannot be kept",
			ErrOutcome, p.IntentID, p.Attestation)
	}
	blobs, err := holder.SignedIntentBlobs()
	if err != nil {
		return none, fmt.Errorf("%w: member %s: %v", ErrOutcome, p.IntentID, err)
	}
	legs, account, opID, err := memberLegsFromSignedIntent(blobs, tree.ChainID)
	if err != nil {
		return none, fmt.Errorf("%w: member %s: %v", ErrOutcome, p.IntentID, err)
	}
	if opID != p.OperationID || account != p.Account {
		return none, fmt.Errorf("%w: member %s: its signed intent names operation %x on account %s, the member operation %x on "+
			"account %s", ErrOutcome, p.IntentID, opID[:8], account.Hex(), p.OperationID[:8], p.Account.Hex())
	}
	calls := make([]CommittedCall, 0, len(p.Legs))
	for _, l := range p.Legs {
		calls = append(calls, CommittedCall{Target: l.Target, Value: l.Value, Data: l.Data})
	}
	if err := matchCommittedCalls(calls, committedCalls(legs)); err != nil {
		return none, fmt.Errorf("%w: member %s: the calls its leaf commits are not the calls its signed intent commits: %v",
			ErrOutcome, p.IntentID, err)
	}
	deadline, ok := p.Deadline()
	if !ok {
		return none, fmt.Errorf("%w: member %s on chain %d has no deadline yet; its non-settlement could never be final",
			ErrOutcomeNotYet, p.IntentID, p.ChainID)
	}
	from := p.FirstSeen
	if from.IsZero() || (!p.CommitTime.IsZero() && p.CommitTime.Before(from)) {
		from = p.CommitTime
	}
	if from.IsZero() {
		from = p.EnqueuedAt
	}
	if from.IsZero() {
		return none, fmt.Errorf("%w: member %s has no commit time or sighting to search its chain from", ErrOutcome, p.IntentID)
	}
	// A v4 leaf binds the window (RB5-F57): its notAfter IS the deadline the member's non-settlement is judged at.
	if in.NotAfter != 0 && int64(in.NotAfter) != deadline.Unix() {
		return none, fmt.Errorf("%w: member %s: its leaf binds notAfter %d, its deadline is %d", ErrOutcome, p.IntentID,
			in.NotAfter, deadline.Unix())
	}
	m := OutcomeTreeMember{
		LeafIndex: uint64(i), Leaf: tree.Leaves[i], OperationID: in.OperationID, IntentID: p.IntentID, ADIURL: in.ADIURL,
		Account: p.Account, AuthorityBook: in.AuthorityBook, AuthorityPage: in.AuthorityPage,
		GovernanceCommitment: in.GovernanceCommitment, IntentMessage: in.IntentMessage, LegacyNoGovernance: in.LegacyNoGovernance,
		Deadline: deadline.Unix(), NotBefore: int64(in.NotBefore), SearchFrom: from.Add(-leafSpendMargin).Unix(),
	}
	for _, l := range legs {
		tl := OutcomeTreeLeg{Target: l.Call.Target, Value: (*hexutil.Big)(new(big.Int).Set(callValue(l.Call.Value))),
			Data: append(hexutil.Bytes(nil), l.Call.Data...), State: append([]ExpectedStateSlot(nil), l.State...)}
		for _, e := range l.Events {
			tl.Events = append(tl.Events, outcomeTreeEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash})
		}
		m.Legs = append(m.Legs, tl)
	}
	return m, nil
}

// Verify re-derives the kept tree's leaves, root and bundle id from its own members: a kept tree that does not
// reproduce its anchor is refused, whatever wrote it.
func (t *OutcomeTree) Verify() error {
	if t == nil || len(t.Members) == 0 {
		return fmt.Errorf("%w: an empty kept tree", ErrOutcome)
	}
	// The leaves are re-derived as the version the tree was formed with (RB5-F57), never another.
	version, err := t.leafVersion()
	if err != nil {
		return fmt.Errorf("%w: kept tree 0x%x: %v", ErrOutcome, t.BundleID[:8], err)
	}
	inputs := make([]BatchLeafInput, 0, len(t.Members))
	for i, m := range t.Members {
		if m.LeafIndex != uint64(i) {
			return fmt.Errorf("%w: kept tree 0x%x: member %d is at leaf %d", ErrOutcome, t.BundleID[:8], i, m.LeafIndex)
		}
		if len(m.Legs) == 0 || m.Deadline <= 0 || m.Account == (common.Address{}) {
			return fmt.Errorf("%w: kept tree 0x%x: member %d lacks its legs, deadline or account", ErrOutcome, t.BundleID[:8], i)
		}
		calls := make([]BatchCall, 0, len(m.Legs))
		for _, l := range m.Legs {
			if l.Value == nil {
				return fmt.Errorf("%w: kept tree 0x%x: member %d has a leg without a value", ErrOutcome, t.BundleID[:8], i)
			}
			calls = append(calls, BatchCall{Target: l.Target, Value: l.Value.ToInt(), Data: l.Data})
		}
		var exec [32]byte
		if len(calls) == 1 {
			exec = computeExecutionCommitment(t.ChainID, calls[0].Target, calls[0].Value, calls[0].Data)
		} else {
			exec = computeBatchExecutionCommitment(t.ChainID, calls)
		}
		in := BatchLeafInput{
			ADIURL: m.ADIURL, ExecutionCommitment: exec, OperationID: m.OperationID, AuthorityBook: m.AuthorityBook,
			AuthorityPage: m.AuthorityPage, GovernanceCommitment: m.GovernanceCommitment, LegacyNoGovernance: m.LegacyNoGovernance,
			AccumulateSetRoot: t.AccumulateSetRoot, IntentMessage: m.IntentMessage, IntentID: m.IntentID,
		}
		// A v4 leaf binds [notBefore, deadline] (RB5-F57); a v3 leaf binds no window.
		switch {
		case version == AccountLeafV4 && m.NotBefore <= 0:
			return fmt.Errorf("%w: kept tree 0x%x: member %d of a v4 tree lacks the notBefore its leaf binds", ErrOutcome,
				t.BundleID[:8], i)
		case version == AccountLeafV4:
			in.NotBefore, in.NotAfter = uint64(m.NotBefore), uint64(m.Deadline)
		case m.NotBefore != 0:
			return fmt.Errorf("%w: kept tree 0x%x: member %d states a window, and a %s leaf binds none", ErrOutcome,
				t.BundleID[:8], i, version)
		}
		inputs = append(inputs, in)
	}
	rebuilt, err := buildBatchTreeAs(version, t.ChainID, inputs, t.BlockHeight, t.Incarnation)
	if err != nil {
		return fmt.Errorf("%w: kept tree 0x%x does not rebuild: %v", ErrOutcome, t.BundleID[:8], err)
	}
	if rebuilt.BundleID != t.BundleID || rebuilt.Root != t.Root || rebuilt.BatchOperationID != t.BatchOperationID {
		return fmt.Errorf("%w: kept tree 0x%x rebuilds as bundle 0x%x (root 0x%x)", ErrOutcome, t.BundleID[:8], rebuilt.BundleID[:8], rebuilt.Root[:8])
	}
	for i, l := range rebuilt.Leaves {
		if t.Members[i].Leaf != l {
			return fmt.Errorf("%w: kept tree 0x%x: member %d's leaf does not rebuild", ErrOutcome, t.BundleID[:8], i)
		}
	}
	return nil
}

// keptLeafVersion is how a kept tree records the leaf version it was formed with: v3 absent, as every tree kept before
// RB5-F57 was written, any other version by name.
func keptLeafVersion(v AccountLeafVersion) AccountLeafVersion {
	if v == AccountLeafV3 {
		return ""
	}
	return v
}

// leafVersion is the account leaf version the kept tree's leaves are of (LeafVersion; absent is v3).
func (t *OutcomeTree) leafVersion() (AccountLeafVersion, error) {
	if t.LeafVersion == "" {
		return AccountLeafV3, nil
	}
	return ParseAccountLeafVersion(string(t.LeafVersion))
}

// sameMembers reports whether two kept trees state the same members - roles, write time and each member's search floor
// aside: the floor is where a search starts, not a fact, and a tree rebuilt from Accumulate starts it at the commit time
// where a validator that queued the member started it at its first sighting.
func (t *OutcomeTree) sameMembers(o *OutcomeTree) bool {
	a, b := *t, *o
	a.Roles, b.Roles, a.RetainedAt, b.RetainedAt = nil, nil, time.Time{}, time.Time{}
	a.Members = append([]OutcomeTreeMember(nil), a.Members...)
	b.Members = append([]OutcomeTreeMember(nil), b.Members...)
	for i := range a.Members {
		a.Members[i].SearchFrom = 0
	}
	for i := range b.Members {
		b.Members[i].SearchFrom = 0
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// OutcomeTreeStore keeps this validator's batch trees as files in its own data directory.
type OutcomeTreeStore struct {
	dir string
	mu  sync.Mutex
}

// OutcomeTreeDirEnv overrides where the trees are kept.
const OutcomeTreeDirEnv = "CERTEN_OUTCOME_TREE_DIR"

// OutcomeTreeDir is where the trees are kept: CERTEN_OUTCOME_TREE_DIR, or data/outcome_trees beside the validator's
// other durable state.
func OutcomeTreeDir() string {
	if d := strings.TrimSpace(os.Getenv(OutcomeTreeDirEnv)); d != "" {
		return d
	}
	return filepath.Join("data", "outcome_trees")
}

// NewOutcomeTreeStore opens the directory, creating it, and reads every tree in it: a tree that cannot be read stops the
// store from opening, and is left in place for the operator - a validator that silently forgot a tree could no longer
// certify that anchor's outcome.
func NewOutcomeTreeStore(dir string) (*OutcomeTreeStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("outcome tree store: no directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("outcome tree store %s: %w", dir, err)
	}
	s := &OutcomeTreeStore{dir: dir}
	if _, err := s.List(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir is the store's directory.
func (s *OutcomeTreeStore) Dir() string { return s.dir }

func (s *OutcomeTreeStore) path(chainID int64, bundle [32]byte) string {
	return filepath.Join(s.dir, fmt.Sprintf("%d_%x.json", chainID, bundle))
}

// Retain keeps t: written once, durably (a temporary file renamed over), before the caller signs. A tree already kept
// for the anchor must state the same members (ErrOutcomeTreeContradiction otherwise); its roles are merged.
func (s *OutcomeTreeStore) Retain(t *OutcomeTree) error {
	if s == nil {
		return fmt.Errorf("%w: no outcome tree store", ErrOutcome)
	}
	if err := t.Verify(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept, err := s.loadLocked(t.ChainID, t.BundleID)
	switch {
	case errors.Is(err, ErrOutcomeTreeNotHeld):
		return s.writeLocked(t)
	case err != nil:
		return err
	}
	if !kept.sameMembers(t) {
		return fmt.Errorf("%w: chain %d anchor 0x%x: the tree kept at %s and the one being signed now state different members",
			ErrOutcomeTreeContradiction, t.ChainID, t.BundleID[:8], kept.RetainedAt.Format(time.RFC3339))
	}
	for _, r := range t.Roles {
		if !hasRole(kept.Roles, r) {
			kept.Roles = append(kept.Roles, r)
			sort.Slice(kept.Roles, func(i, j int) bool { return kept.Roles[i] < kept.Roles[j] })
			if err := s.writeLocked(kept); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasRole(rs []OutcomeTreeRole, r OutcomeTreeRole) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func (s *OutcomeTreeStore) writeLocked(t *OutcomeTree) error {
	blob, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("outcome tree 0x%x: %w", t.BundleID[:8], err)
	}
	p := s.path(t.ChainID, t.BundleID)
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("outcome tree %s: %w", p, err)
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return fmt.Errorf("outcome tree %s: %w", p, err)
	}
	// Synced before the rename: the tree must be on disk before the signature it backs leaves this validator.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("outcome tree %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("outcome tree %s: %w", p, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("outcome tree %s: %w", p, err)
	}
	return nil
}

// Load returns the tree kept for the anchor, ErrOutcomeTreeNotHeld when there is none.
func (s *OutcomeTreeStore) Load(chainID int64, bundle [32]byte) (*OutcomeTree, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: no outcome tree store", ErrOutcome)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(chainID, bundle)
}

func (s *OutcomeTreeStore) loadLocked(chainID int64, bundle [32]byte) (*OutcomeTree, error) {
	blob, err := os.ReadFile(s.path(chainID, bundle))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: chain %d anchor 0x%x", ErrOutcomeTreeNotHeld, chainID, bundle[:8])
	}
	if err != nil {
		return nil, fmt.Errorf("outcome tree %s: %w", s.path(chainID, bundle), err)
	}
	return decodeOutcomeTree(blob, s.path(chainID, bundle), chainID, bundle)
}

func decodeOutcomeTree(blob []byte, path string, chainID int64, bundle [32]byte) (*OutcomeTree, error) {
	var t OutcomeTree
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("outcome tree %s does not decode: %w", path, err)
	}
	if t.ChainID != chainID || t.BundleID != bundle {
		return nil, fmt.Errorf("outcome tree %s holds chain %d anchor 0x%x", path, t.ChainID, t.BundleID[:8])
	}
	if err := t.Verify(); err != nil {
		return nil, fmt.Errorf("outcome tree %s: %w", path, err)
	}
	return &t, nil
}

// List returns every kept tree, ordered by chain and bundle. A file that does not read as the tree its name says is an
// error naming it.
func (s *OutcomeTreeStore) List() ([]*OutcomeTree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("outcome tree store %s: %w", s.dir, err)
	}
	var out []*OutcomeTree
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		chainPart, bundlePart, ok := strings.Cut(strings.TrimSuffix(name, ".json"), "_")
		chainID, cerr := strconv.ParseInt(chainPart, 10, 64)
		bundle, berr := parseHex32(bundlePart)
		if !ok || cerr != nil || berr != nil {
			return nil, fmt.Errorf("outcome tree store %s: %s is not a kept tree's name", s.dir, name)
		}
		t, err := s.loadLocked(chainID, bundle)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChainID != out[j].ChainID {
			return out[i].ChainID < out[j].ChainID
		}
		return bytes.Compare(out[i].BundleID[:], out[j].BundleID[:]) < 0
	})
	return out, nil
}

// Release deletes the kept tree of an anchor whose outcome the chain's finalized state records (the caller has read
// it there): nothing about that anchor remains for this validator to certify.
func (s *OutcomeTreeStore) Release(chainID int64, bundle [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(chainID, bundle)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("outcome tree %s: %w", s.path(chainID, bundle), err)
	}
	return nil
}

// ErrOutcomeNotYet: an outcome fact is not final, or not agreed, yet. Retryable: it is never a verdict.
var ErrOutcomeNotYet = errors.New("batch outcome not final yet")

// OutcomeTreeRetainer keeps the trees this validator proves (the leader's side of retention).
type OutcomeTreeRetainer interface {
	RetainTree(tree *BatchTree, role OutcomeTreeRole) error
}

// RetainTree keeps tree, whose members this validator holds in its mempool, before it signs or proves it.
func (s *BatchStack) RetainTree(tree *BatchTree, role OutcomeTreeRole) error {
	if s == nil || s.Mempool == nil {
		return fmt.Errorf("%w: batch stack not ready", ErrOutcome)
	}
	if tree == nil {
		return fmt.Errorf("%w: nil tree", ErrOutcome)
	}
	byOp := make(map[[32]byte]*PendingBatchIntent, len(tree.Inputs))
	for _, in := range tree.Inputs {
		p, ok := s.Mempool.FindMember(tree.ChainID, in.OperationID)
		if !ok || p == nil {
			return fmt.Errorf("%w: tree 0x%x: member operation %x is not held here", ErrOutcomeTreeNotHeld, tree.BundleID[:8], in.OperationID[:8])
		}
		byOp[in.OperationID] = p
	}
	return s.retainMembers(tree, byOp, role)
}

// retainMembers keeps tree with its members as this validator holds them.
func (s *BatchStack) retainMembers(tree *BatchTree, byOp map[[32]byte]*PendingBatchIntent, role OutcomeTreeRole) error {
	if s.OutcomeTrees == nil {
		return fmt.Errorf("%w: no outcome tree store is wired, so this validator could not later certify the outcome of "+
			"what it signs", ErrOutcome)
	}
	t, err := NewOutcomeTree(tree, byOp, role)
	if err != nil {
		return err
	}
	return s.OutcomeTrees.Retain(t)
}

// retentionRefusalCode classifies a failure to keep a tree for an attestation refusal: retryable unless the tree itself
// cannot be stated (a member without its signed intent, a contradiction with the kept tree).
func retentionRefusalCode(err error) AttestationRefusalCode {
	switch {
	case errors.Is(err, ErrOutcomeTreeNotHeld):
		return CodeMemberNotHeld
	case errors.Is(err, ErrOutcomeNotYet):
		return CodeNotReady
	case errors.Is(err, ErrOutcomeTreeContradiction), errors.Is(err, ErrOutcome):
		return CodeRefused
	default:
		return CodeNotReady // the disk: retryable
	}
}
