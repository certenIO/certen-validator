package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/database"
)

// These tests pin the fix for the 2026-09-15 testnet incident: Commit rewrote every cached
// ValidatorBlock to Postgres and ran a never-matching anchor_batches lookup per cached block, taking
// 14-16 s, which made every concurrent BroadcastTxSync time out. See consensus_persistence.go.

var persistQuietLog = log.New(io.Discard, "", 0)

// ─── fakes ──────────────────────────────────────────────────────────────────────────────────────────

type fakeRecordStore struct {
	mu        sync.Mutex
	watermark int64
	found     bool
	loadErrs  int           // LoadPersistedHeight fails this many times first
	failN     int           // PersistCommittedBlock fails this many times first
	gate      chan struct{} // when non-nil, PersistCommittedBlock waits for it to close
	writes    []database.CommittedConsensusRecords
	reject    []database.RejectedRecord // returned as content rejections by every write
	resets    []int64
	hang      bool // PersistCommittedBlock blocks until its context ends (a hung connection)
	calls     atomic.Int64
}

func (s *fakeRecordStore) PersistCommittedBlock(ctx context.Context, writerID string, rec *database.CommittedConsensusRecords) ([]database.RejectedRecord, error) {
	s.calls.Add(1)
	if g := s.gate; g != nil {
		select {
		case <-g:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	hang := s.hang
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failN > 0 {
		s.failN--
		return nil, errors.New("fictional: database unavailable")
	}
	s.writes = append(s.writes, *rec)
	if rec.Height > s.watermark {
		s.watermark = rec.Height
	}
	s.found = true
	return s.reject, nil
}

func (s *fakeRecordStore) LoadPersistedHeight(ctx context.Context, writerID string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErrs > 0 {
		s.loadErrs--
		return 0, false, errors.New("fictional: database unavailable")
	}
	return s.watermark, s.found, nil
}

func (s *fakeRecordStore) ResetPersistedHeight(ctx context.Context, writerID string, height int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watermark = height
	s.found = true
	s.resets = append(s.resets, height)
	return nil
}

func (s *fakeRecordStore) EnsurePersistenceProgressTable(ctx context.Context) error { return nil }

func (s *fakeRecordStore) heights() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int64, len(s.writes))
	for i, w := range s.writes {
		out[i] = w.Height
	}
	return out
}

func (s *fakeRecordStore) byHeight() map[int64]database.CommittedConsensusRecords {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int64]database.CommittedConsensusRecords{}
	for _, w := range s.writes {
		out[w.Height] = w
	}
	return out
}

type fakeBlockSource struct {
	mu          sync.Mutex
	blocks      map[int64]*committedBlock
	unavailable map[int64]bool
	asked       []int64
}

func (f *fakeBlockSource) CommittedValidatorBlocks(ctx context.Context, height int64) (*committedBlock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, height)
	if f.unavailable[height] {
		return nil, fmt.Errorf("%w: fictional pruned height %d", errCommittedBlockUnavailable, height)
	}
	if b, ok := f.blocks[height]; ok {
		return b, nil
	}
	return &committedBlock{height: height}, nil
}

// fakeBlockReader serves blocks the way CometBFT's block store does, recorded from real FinalizeBlock runs.
type fakeBlockReader struct {
	mu      sync.Mutex
	blocks  map[int64]*coretypes.ResultBlock
	results map[int64]*coretypes.ResultBlockResults
	errs    map[int64]error
}

func newFakeBlockReader() *fakeBlockReader {
	return &fakeBlockReader{blocks: map[int64]*coretypes.ResultBlock{}, results: map[int64]*coretypes.ResultBlockResults{}, errs: map[int64]error{}}
}

func (r *fakeBlockReader) record(height int64, t time.Time, txs [][]byte, res []*abcitypes.ExecTxResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	blk := &cmttypes.Block{}
	blk.Header.Height = height
	blk.Header.Time = t
	for _, tx := range txs {
		blk.Data.Txs = append(blk.Data.Txs, cmttypes.Tx(tx))
	}
	r.blocks[height] = &coretypes.ResultBlock{Block: blk}
	r.results[height] = &coretypes.ResultBlockResults{Height: height, TxsResults: res}
}

func (r *fakeBlockReader) Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.errs[*height]; err != nil {
		return nil, err
	}
	b, ok := r.blocks[*height]
	if !ok {
		return nil, fmt.Errorf("height %d must be less than or equal to the current blockchain height 0", *height)
	}
	return b, nil
}

func (r *fakeBlockReader) BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, ok := r.results[*height]
	if !ok {
		return nil, fmt.Errorf("could not find results for height #%d", *height)
	}
	return res, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────────────────────────────

func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func startTestPersister(t *testing.T, store consensusRecordStore, queueCap int) *consensusPersister {
	t.Helper()
	p := newConsensusPersister(store, "validator-test", persistQuietLog)
	if queueCap > 0 {
		p.queue = make(chan persistJob, queueCap)
	}
	p.retryBase = time.Millisecond
	p.retryMax = 5 * time.Millisecond
	p.idleCheck = 2 * time.Millisecond
	p.start()
	t.Cleanup(p.stop)
	return p
}

// persistTestBlockJSON builds a ValidatorBlock that passes VerifyValidatorBlockInvariants (same derivation
// as invariantValidBlockJSON) with a unique operation, real hex BLS fields and a governance level.
func persistTestBlockJSON(t *testing.T, op, level, validatorID string) []byte {
	t.Helper()
	vb := ValidatorBlock{
		ValidatorID:         validatorID,
		OperationCommitment: op,
		Timestamp:           time.Unix(gateNow, 0).UTC().Format(time.RFC3339),
		BlockHeight:         1,
		GovernanceProof: GovernanceProof{
			OrganizationADI: "acc://fictional-payer.acme",
			GovernanceLevel: level,
			AuthorizationLeaves: []AuthorizationLeaf{{
				KeyPage: "acc://fictional-payer.acme/book/1", KeyHash: "0xkh-" + op,
				Role: "DEFAULT_SIGNER", Signature: "0xleafsig",
			}},
			BLSAggregateSignature: "0x" + strings.Repeat("ab", 48),
			BLSValidatorSetPubKey: "0x" + strings.Repeat("cd", 48),
		},
		CrossChainProof: CrossChainProof{
			OperationID:          op,
			CrossChainCommitment: "0xcc",
			ChainTargets: []ChainTarget{{
				Chain:           "ethereum-sepolia",
				ContractAddress: "0xcontract",
				Commitment:      "0xtargetcommit",
				Expiry:          time.Unix(gateNow+3600, 0).UTC().Format(time.RFC3339),
			}},
		},
		ExecutionProof: ExecutionProof{
			Stage:               ExecutionStagePre,
			ValidatorSignatures: []string{"0xvsig"},
		},
		AccumulateAnchorReference: AccumulateAnchorReference{
			AccountURL:  "acc://fictional-payer.acme",
			TxHash:      "0xtx-" + op,
			BlockHeight: 1,
		},
	}
	leaves := make([]interface{}, len(vb.GovernanceProof.AuthorizationLeaves))
	for i, l := range vb.GovernanceProof.AuthorizationLeaves {
		leaves[i] = l
	}
	root, err := commitment.ComputeGovernanceMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	vb.GovernanceProof.MerkleRoot = root
	bundleID, err := commitment.ComputeBundleID(vb.GovernanceProof, vb.CrossChainProof)
	if err != nil {
		t.Fatal(err)
	}
	vb.BundleID = bundleID
	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bundleOf(t *testing.T, tx []byte) string {
	t.Helper()
	var vb ValidatorBlock
	if err := json.Unmarshal(tx, &vb); err != nil {
		t.Fatal(err)
	}
	return vb.BundleID
}

func newPersistTestApp(t *testing.T) *ValidatorApp {
	t.Helper()
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "")
	app := NewValidatorApp(newInMemLedger(), "certen-fictional-test")
	app.logger = persistQuietLog
	app.validatorCount = 7
	return app
}

// seedCache fills the Query cache the way three days of uptime did, with blocks from other heights.
func seedCache(app *ValidatorApp, n int) {
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("0xcached%058d", i)
		app.validatorBlocks[id] = &ValidatorBlock{BundleID: id, BlockHeight: uint64(100000 + i),
			GovernanceProof: GovernanceProof{MerkleRoot: "0x" + strings.Repeat("11", 32)}}
	}
}

// commitBlock runs FinalizeBlock + Commit for one block and records it in reader (if non-nil).
func commitBlock(t *testing.T, app *ValidatorApp, reader *fakeBlockReader, height int64, blockTime time.Time, txs ...[]byte) (time.Duration, *abcitypes.ResponseFinalizeBlock) {
	t.Helper()
	ctx := context.Background()
	fb, err := app.FinalizeBlock(ctx, &abcitypes.RequestFinalizeBlock{Height: height, Time: blockTime, Hash: bytes.Repeat([]byte{byte(height)}, 32), Txs: txs})
	if err != nil {
		t.Fatalf("FinalizeBlock %d: %v", height, err)
	}
	if reader != nil {
		reader.record(height, blockTime, txs, fb.TxResults)
	}
	start := time.Now()
	if _, err := app.Commit(ctx, &abcitypes.RequestCommit{}); err != nil {
		t.Fatalf("Commit %d: %v", height, err)
	}
	return time.Since(start), fb
}

// ─── Commit path ────────────────────────────────────────────────────────────────────────────────────

// Commit hands off exactly the ValidatorBlocks FinalizeBlock accepted for THIS block — never the cache —
// and every height, including empty blocks, so the watermark advances contiguously.
func TestCommitHandsOffOnlyThisBlocksAcceptedValidatorBlocks(t *testing.T) {
	app := newPersistTestApp(t)
	seedCache(app, 1000)
	store := &fakeRecordStore{}
	app.persister = startTestPersister(t, store, 0)

	base := time.Unix(gateNow, 0).UTC()
	a, b, c := persistTestBlockJSON(t, "op-a", "G2", "validator-1"), persistTestBlockJSON(t, "op-b", "G1", "validator-2"), persistTestBlockJSON(t, "op-c", "G0", "")
	invalid := []byte(`{"bundle_id":"not-a-valid-block"}`)

	_, fb1 := commitBlock(t, app, nil, 1, base, a, invalid, b)
	if fb1.TxResults[1].Code == 0 || fb1.TxResults[0].Code != 0 || fb1.TxResults[2].Code != 0 {
		t.Fatalf("fixture: want a,b accepted and the invalid tx rejected, got codes %d,%d,%d",
			fb1.TxResults[0].Code, fb1.TxResults[1].Code, fb1.TxResults[2].Code)
	}
	commitBlock(t, app, nil, 2, base.Add(time.Second), c)
	commitBlock(t, app, nil, 3, base.Add(2*time.Second))

	waitUntil(t, "three heights persisted", 2*time.Second, func() bool { return len(store.heights()) == 3 })
	if got := store.heights(); !reflect.DeepEqual(got, []int64{1, 2, 3}) {
		t.Fatalf("persisted heights = %v, want [1 2 3]", got)
	}
	w := store.byHeight()

	ids := func(r database.CommittedConsensusRecords) []uuid.UUID {
		var out []uuid.UUID
		for _, e := range r.Entries {
			out = append(out, e.BatchID)
		}
		return out
	}
	batch := func(tx []byte) uuid.UUID { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(bundleOf(t, tx))) }

	if got, want := ids(w[1]), []uuid.UUID{batch(a), batch(b)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("height 1 entries = %v, want %v (only the accepted blocks of height 1)", got, want)
	}
	if got, want := ids(w[2]), []uuid.UUID{batch(c)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("height 2 entries = %v, want %v", got, want)
	}
	if len(w[3].Entries) != 0 || len(w[3].Attestations) != 0 {
		t.Fatalf("empty height 3 persisted records: %+v", w[3])
	}

	// ABCI metadata and deterministic columns.
	e1 := w[1].Entries[0]
	if e1.BlockNumber != 1 || !e1.StartTime.Equal(base) || e1.State != "completed" || e1.CompletedAt == nil || !e1.CompletedAt.Equal(base) {
		t.Fatalf("height 1 entry metadata wrong: block=%d start=%v state=%s completed=%v", e1.BlockNumber, e1.StartTime, e1.State, e1.CompletedAt)
	}
	if w[1].Entries[1].State != "quorum_met" || w[2].Entries[0].State != "collecting" || w[2].Entries[0].CompletedAt != nil {
		t.Fatalf("governance level -> state mapping changed")
	}
	if len(w[1].Attestations) != 2 || w[2].Attestations[0].ValidatorID != "certen-fictional-test" {
		t.Fatalf("attestations: got %d at height 1; height 2 validator id %q (want chain id default)",
			len(w[1].Attestations), w[2].Attestations[0].ValidatorID)
	}
	for _, r := range w {
		for _, e := range r.Entries {
			if strings.HasPrefix(uuidToBundleHint(e.ResultJSON), "0xcached") {
				t.Fatalf("a cached block from another height was persisted: %v", e.ResultJSON)
			}
		}
	}
	if len(app.validatorBlocks) < 900 {
		t.Fatalf("Query cache unexpectedly emptied: %d", len(app.validatorBlocks))
	}
}

func uuidToBundleHint(resultJSON interface{}) string {
	m, _ := resultJSON.(map[string]interface{})
	s, _ := m["bundle_id"].(string)
	return s
}

// The incident, reproduced: a database that never answers (and a full cache) must not slow Commit, and
// the heights that could not be handed off are rebuilt from the block store afterwards — identical to a
// run where nothing was dropped.
func TestCommitNeverWaitsOnTheDatabaseAndDroppedHeightsAreRebuilt(t *testing.T) {
	base := time.Unix(gateNow, 0).UTC()
	const heights = 40
	txsFor := func(h int64) [][]byte {
		if h%3 == 0 {
			return nil // empty block
		}
		out := [][]byte{persistTestBlockJSON(t, fmt.Sprintf("op-%d-a", h), "G2", "validator-1")}
		if h%2 == 0 {
			out = append(out, persistTestBlockJSON(t, fmt.Sprintf("op-%d-b", h), "G0", "validator-3"))
		}
		return out
	}

	// Control: a responsive database, nothing dropped.
	controlApp := newPersistTestApp(t)
	controlStore := &fakeRecordStore{}
	controlApp.persister = startTestPersister(t, controlStore, 0)
	for h := int64(1); h <= heights; h++ {
		commitBlock(t, controlApp, nil, h, base.Add(time.Duration(h)*time.Second), txsFor(h)...)
	}
	waitUntil(t, "control persisted", 5*time.Second, func() bool { return len(controlStore.heights()) == heights })

	// Incident: the database blocks every write; the hand-off queue holds only 4 blocks.
	var debugBuf syncBuffer
	app := newPersistTestApp(t)
	seedCache(app, 1000)
	reader := newFakeBlockReader()
	store := &fakeRecordStore{gate: make(chan struct{})}
	p := newConsensusPersister(store, "validator-test", log.New(&debugBuf, "", 0))
	p.queue = make(chan persistJob, 4)
	p.retryBase, p.retryMax, p.idleCheck = time.Millisecond, 5*time.Millisecond, 2*time.Millisecond
	p.setSource(&rpcCommittedBlockSource{reader: reader, chainID: app.chainID})
	p.start()
	t.Cleanup(p.stop)
	app.persister = p

	var worst time.Duration
	for h := int64(1); h <= heights; h++ {
		d, _ := commitBlock(t, app, reader, h, base.Add(time.Duration(h)*time.Second), txsFor(h)...)
		if d > worst {
			worst = d
		}
	}
	if worst > 250*time.Millisecond {
		t.Fatalf("Commit took %v with a blocked database; it must not wait on persistence", worst)
	}
	if p.dropped.Load() == 0 {
		t.Fatal("fixture: expected hand-offs to be refused while the database was blocked")
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("persister log:\n%s\nheights=%v dropped=%d persisted=%d",
				tail(debugBuf.String(), 3000), store.heights(), p.dropped.Load(), p.persisted.Load())
		}
	})
	// The database recovers and NO further block is committed (this chain only produces blocks for real
	// work): the writer must rebuild the dropped tail on its own.
	close(store.gate)
	waitUntil(t, "all heights persisted after recovery", 5*time.Second, func() bool {
		return len(store.heights()) >= heights
	})
	time.Sleep(50 * time.Millisecond) // nothing more may be written

	got := store.byHeight()
	want := controlStore.byHeight()
	for h := int64(1); h <= heights; h++ {
		g, w := got[h], want[h]
		if !recordsEqualIgnoringNothing(g, w) {
			t.Fatalf("height %d rebuilt/handed-off records differ from the control run:\n got=%+v\nwant=%+v", h, g, w)
		}
	}
	if hs := store.heights(); !sort.SliceIsSorted(hs, func(i, j int) bool { return hs[i] < hs[j] }) || len(hs) != heights {
		t.Fatalf("heights persisted out of order or more than once: %v", hs)
	}
}

func recordsEqualIgnoringNothing(a, b database.CommittedConsensusRecords) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// ─── persister ──────────────────────────────────────────────────────────────────────────────────────

func TestPersisterResumesFromItsWatermarkAndIgnoresReplays(t *testing.T) {
	store := &fakeRecordStore{watermark: 10, found: true}
	source := &fakeBlockSource{blocks: map[int64]*committedBlock{}}
	p := newConsensusPersister(store, "validator-test", persistQuietLog)
	p.retryBase, p.retryMax, p.idleCheck = time.Millisecond, time.Millisecond, 2*time.Millisecond
	p.setSource(source)
	p.start()
	t.Cleanup(p.stop)

	p.enqueue(committedBlock{height: 13}, 7)
	waitUntil(t, "heights 11-13", time.Second, func() bool { return len(store.heights()) == 3 })
	p.enqueue(committedBlock{height: 12}, 7) // replay below the watermark
	p.enqueue(committedBlock{height: 14}, 7)
	waitUntil(t, "height 14", time.Second, func() bool { return len(store.heights()) == 4 })

	if got := store.heights(); !reflect.DeepEqual(got, []int64{11, 12, 13, 14}) {
		t.Fatalf("heights = %v, want [11 12 13 14]", got)
	}
	if !reflect.DeepEqual(source.asked, []int64{11, 12}) {
		t.Fatalf("rebuilt heights = %v, want [11 12]", source.asked)
	}
}

// A writer that has never persisted anything starts at the first block it is handed; history before it
// was written by earlier binaries.
func TestPersisterFirstRunDoesNotRebuildHistory(t *testing.T) {
	store := &fakeRecordStore{}
	source := &fakeBlockSource{}
	p := startTestPersister(t, store, 0)
	p.setSource(source)
	p.enqueue(committedBlock{height: 500}, 7)
	waitUntil(t, "height 500", time.Second, func() bool { return len(store.heights()) == 1 })
	if len(source.asked) != 0 {
		t.Fatalf("rebuilt history on first run: %v", source.asked)
	}
}

func TestPersisterRetriesUntilTheDatabaseRecovers(t *testing.T) {
	store := &fakeRecordStore{loadErrs: 2, failN: 3}
	p := startTestPersister(t, store, 0)
	p.enqueue(committedBlock{height: 7}, 7)
	waitUntil(t, "height 7 persisted", 2*time.Second, func() bool { return len(store.heights()) == 1 })
	if got := store.calls.Load(); got != 4 {
		t.Fatalf("PersistCommittedBlock calls = %d, want 4 (3 failures + 1 success)", got)
	}
	if p.persisted.Load() != 7 {
		t.Fatalf("persisted = %d, want 7", p.persisted.Load())
	}
}

func TestPersisterAdvancesPastHeightsTheBlockStoreNoLongerHas(t *testing.T) {
	store := &fakeRecordStore{watermark: 10, found: true}
	source := &fakeBlockSource{unavailable: map[int64]bool{11: true}}
	p := startTestPersister(t, store, 0)
	p.setSource(source)
	p.enqueue(committedBlock{height: 12}, 7)
	waitUntil(t, "heights 11-12", time.Second, func() bool { return len(store.heights()) == 2 })
	w := store.byHeight()
	if len(w[11].Entries) != 0 || p.gaps.Load() != 1 {
		t.Fatalf("unavailable height 11: entries=%d gaps=%d, want 0 and 1", len(w[11].Entries), p.gaps.Load())
	}
}

func TestPersisterWithoutASourceRecordsGapsInsteadOfStalling(t *testing.T) {
	store := &fakeRecordStore{watermark: 3, found: true}
	p := startTestPersister(t, store, 0)
	p.enqueue(committedBlock{height: 6}, 7)
	waitUntil(t, "heights 4-6", time.Second, func() bool { return len(store.heights()) == 3 })
	if p.gaps.Load() != 2 {
		t.Fatalf("gaps = %d, want 2", p.gaps.Load())
	}
}

func TestEnqueueNeverBlocks(t *testing.T) {
	store := &fakeRecordStore{gate: make(chan struct{})}
	p := startTestPersister(t, store, 1)
	t.Cleanup(func() { close(store.gate) })
	done := make(chan struct{})
	go func() {
		for h := int64(1); h <= 1000; h++ {
			p.enqueue(committedBlock{height: h}, 7)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enqueue blocked on a full queue")
	}
	if p.dropped.Load() == 0 {
		t.Fatal("expected refused hand-offs")
	}
}

// ─── records ────────────────────────────────────────────────────────────────────────────────────────

func TestConsensusRecordsForIsDeterministicAndKeepsTheOriginalMapping(t *testing.T) {
	bt := time.Unix(gateNow, 0).UTC()
	good := func(id, level string) ValidatorBlock {
		return ValidatorBlock{BundleID: id, ValidatorID: "validator-9", BlockHeight: 42, Timestamp: bt.Format(time.RFC3339),
			GovernanceProof: GovernanceProof{GovernanceLevel: level, MerkleRoot: "0x" + strings.Repeat("aa", 32),
				BLSAggregateSignature: "0x" + strings.Repeat("bb", 48), BLSValidatorSetPubKey: "0x" + strings.Repeat("cc", 48)}}
	}
	noRoot := good("no-root", "G2")
	noRoot.GovernanceProof.MerkleRoot = ""
	badRoot := good("bad-root", "G2")
	badRoot.GovernanceProof.MerkleRoot = "0xzz"
	noSig := good("no-sig", "G1")
	noSig.GovernanceProof.BLSAggregateSignature = ""

	blk := &committedBlock{height: 42, time: bt, blocks: []ValidatorBlock{good("g2", "G2"), noRoot, badRoot, noSig, good("g0", "G0")}}
	r1 := consensusRecordsFor(blk, 7, persistQuietLog)
	time.Sleep(5 * time.Millisecond)
	r2 := consensusRecordsFor(blk, 7, persistQuietLog)
	if !recordsEqualIgnoringNothing(*r1, *r2) {
		t.Fatal("records depend on when they are derived (wall clock leaked in)")
	}
	if len(r1.Entries) != 5 {
		t.Fatalf("entries = %d, want 5 (one per accepted ValidatorBlock, as before)", len(r1.Entries))
	}
	if len(r1.Entries[1].MerkleRoot) != 0 || len(r1.Entries[2].MerkleRoot) != 0 {
		t.Fatal("an absent or undecodable merkle root must be stored as empty bytes, as before")
	}
	if len(r1.Attestations) != 4 {
		t.Fatalf("attestations = %d, want 4 (every block with a BLS signature, as before)", len(r1.Attestations))
	}
	if e := r1.Entries[0]; e.CompletedAt == nil || !e.CompletedAt.Equal(bt) || e.RequiredCount != 5 || e.QuorumFraction != 1.0/7 {
		t.Fatalf("G2 entry: completed=%v required=%d fraction=%v", e.CompletedAt, e.RequiredCount, e.QuorumFraction)
	}
	if r1.Entries[4].CompletedAt != nil {
		t.Fatal("G0 entry must not be completed")
	}
}

// ─── block-store source ─────────────────────────────────────────────────────────────────────────────

func TestRPCCommittedBlockSourceMatchesWhatFinalizeBlockAccepted(t *testing.T) {
	bt := time.Unix(gateNow, 0).UTC()
	accepted := persistTestBlockJSON(t, "op-src-a", "G2", "")
	rejected := persistTestBlockJSON(t, "op-src-r", "G2", "validator-2")
	policy := []byte(fmt.Sprintf(`{"kind":%q}`, PolicyUpdateKind))
	reader := newFakeBlockReader()
	reader.record(5, bt, [][]byte{accepted, rejected, policy, []byte("not json")},
		[]*abcitypes.ExecTxResult{{Code: 0}, {Code: 4}, {Code: 0}, {Code: 0}})

	src := &rpcCommittedBlockSource{reader: reader, chainID: "certen-fictional-test"}
	blk, err := src.CommittedValidatorBlocks(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(blk.blocks) != 1 || blk.blocks[0].BundleID != bundleOf(t, accepted) {
		t.Fatalf("rebuilt blocks = %v, want only the accepted ValidatorBlock", blk)
	}
	vb := blk.blocks[0]
	if vb.BlockHeight != 5 || vb.Timestamp != bt.Format(time.RFC3339) || vb.ValidatorID != "certen-fictional-test" || !blk.time.Equal(bt) {
		t.Fatalf("commit metadata not applied: height=%d ts=%s validator=%q", vb.BlockHeight, vb.Timestamp, vb.ValidatorID)
	}

	// Pruned heights and missing results are unavailable (not retried); other errors are retried.
	reader.errs[6] = errors.New("height 6 is not available, lowest height is 9")
	if _, err := src.CommittedValidatorBlocks(context.Background(), 6); !errors.Is(err, errCommittedBlockUnavailable) {
		t.Fatalf("pruned height: %v, want unavailable", err)
	}
	reader.record(7, bt, [][]byte{accepted}, nil)
	if _, err := src.CommittedValidatorBlocks(context.Background(), 7); !errors.Is(err, errCommittedBlockUnavailable) {
		t.Fatalf("results/txs mismatch: %v, want unavailable", err)
	}
	reader.mu.Lock()
	delete(reader.results, 7)
	reader.mu.Unlock()
	if _, err := src.CommittedValidatorBlocks(context.Background(), 7); !errors.Is(err, errCommittedBlockUnavailable) {
		t.Fatalf("discarded results: %v, want unavailable", err)
	}
	reader.errs[8] = errors.New("post failed: connection refused")
	if _, err := src.CommittedValidatorBlocks(context.Background(), 8); err == nil || errors.Is(err, errCommittedBlockUnavailable) {
		t.Fatalf("transport error: %v, want retryable", err)
	}
}

// ─── app wiring and cache ───────────────────────────────────────────────────────────────────────────

func TestStopConsensusPersistenceDetachesTheWriter(t *testing.T) {
	app := newPersistTestApp(t)
	store := &fakeRecordStore{}
	app.persister = startTestPersister(t, store, 0)
	app.StopConsensusPersistence()
	commitBlock(t, app, nil, 1, time.Unix(gateNow, 0).UTC()) // must not panic or block
	if app.persister != nil {
		t.Fatal("persister still attached")
	}
}

func TestEnableConsensusPersistenceWithoutConsensusRepositoryIsANoOp(t *testing.T) {
	app := newPersistTestApp(t)
	app.EnableConsensusPersistence(nil, "validator-test", nil)
	app.EnableConsensusPersistence(&database.Repositories{}, "validator-test", nil)
	if app.persister != nil {
		t.Fatal("a persister started without a consensus repository")
	}
}

// Heights are uint64: below the eviction margin the old subtraction wrapped to a huge value and evicted
// the entire Query cache.
func TestCacheEvictionDoesNotWrapBelowTheMargin(t *testing.T) {
	app := newPersistTestApp(t)
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("0xlow%061d", i)
		app.validatorBlocks[id] = &ValidatorBlock{BundleID: id, BlockHeight: 3}
	}
	commitBlock(t, app, nil, 5, time.Unix(gateNow, 0).UTC(), persistTestBlockJSON(t, "op-evict", "G2", "validator-1"))
	if n := len(app.validatorBlocks); n < 900 {
		t.Fatalf("cache size after eviction = %d; the height subtraction wrapped and evicted everything", n)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// A row the database refuses on content is skipped and counted; the writer moves on instead of retrying a
// block that can never be written.
func TestPersisterSkipsContentRejectionsInsteadOfStalling(t *testing.T) {
	store := &fakeRecordStore{reject: []database.RejectedRecord{{Table: "consensus_entries", Err: errors.New("fictional: value too long for type character varying(66)")}}}
	p := startTestPersister(t, store, 0)
	p.enqueue(committedBlock{height: 1}, 7)
	p.enqueue(committedBlock{height: 2}, 7)
	waitUntil(t, "heights 1-2", time.Second, func() bool { return len(store.heights()) == 2 })
	if got := store.calls.Load(); got != 2 || p.rejected.Load() != 2 {
		t.Fatalf("calls=%d rejected=%d, want 2 and 2 (no retries for content rejections)", got, p.rejected.Load())
	}
}

// A CometBFT data reset with the database kept leaves the watermark far ahead of the new chain. The writer
// must rewind and persist the new chain, not silently skip every height up to the old watermark.
func TestPersisterRewindsAWatermarkAheadOfTheChain(t *testing.T) {
	store := &fakeRecordStore{watermark: 5000, found: true}
	p := startTestPersister(t, store, 0)
	for h := int64(1); h <= 50; h++ {
		p.enqueue(committedBlock{height: h}, 7)
	}
	waitUntil(t, "the new chain persisted", 2*time.Second, func() bool { return len(store.heights()) == 50 })
	if got := store.heights(); got[0] != 1 || got[49] != 50 {
		t.Fatalf("heights = %v", got)
	}
	store.mu.Lock()
	resets := append([]int64(nil), store.resets...)
	store.mu.Unlock()
	if len(resets) != 1 || resets[0] != 0 || p.rewinds.Load() != 1 {
		t.Fatalf("resets=%v rewinds=%d, want one rewind to 0", resets, p.rewinds.Load())
	}
}

// A normal restart (watermark below the first committed height) must not rewind.
func TestPersisterDoesNotRewindOnANormalRestart(t *testing.T) {
	store := &fakeRecordStore{watermark: 99, found: true}
	p := startTestPersister(t, store, 0)
	p.enqueue(committedBlock{height: 100}, 7)
	waitUntil(t, "height 100", time.Second, func() bool { return len(store.heights()) == 1 })
	if p.rewinds.Load() != 0 || len(store.resets) != 0 {
		t.Fatalf("rewound on a normal restart: rewinds=%d resets=%v", p.rewinds.Load(), store.resets)
	}
}

// A hung database call is bounded and retried, not a silent permanent stall.
func TestPersisterBoundsHungDatabaseCalls(t *testing.T) {
	store := &fakeRecordStore{hang: true}
	p := newConsensusPersister(store, "validator-test", persistQuietLog)
	p.retryBase, p.retryMax, p.idleCheck, p.callTimeout = time.Millisecond, 2*time.Millisecond, 2*time.Millisecond, 10*time.Millisecond
	p.start()
	t.Cleanup(p.stop)
	p.enqueue(committedBlock{height: 1}, 7)
	waitUntil(t, "several bounded attempts", 2*time.Second, func() bool { return store.calls.Load() >= 3 })
	store.mu.Lock()
	store.hang = false
	store.mu.Unlock()
	waitUntil(t, "height 1 after the connection recovers", 2*time.Second, func() bool { return len(store.heights()) == 1 })
}

// Blocks the handshake replays before the database is wired are never handed off; the writer rebuilds them.
func TestEnablingPersistenceRebuildsBlocksCommittedBeforeIt(t *testing.T) {
	app := newPersistTestApp(t)
	if _, err := app.Info(context.Background(), &abcitypes.RequestInfo{}); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(gateNow, 0).UTC()
	reader := newFakeBlockReader()
	early := persistTestBlockJSON(t, "op-replayed", "G2", "validator-1")
	commitBlock(t, app, reader, 1, base, early) // committed before persistence exists
	commitBlock(t, app, reader, 2, base.Add(time.Second))

	store := &fakeRecordStore{}
	p := newConsensusPersister(store, "validator-test", persistQuietLog)
	p.retryBase, p.retryMax, p.idleCheck = time.Millisecond, 2*time.Millisecond, 2*time.Millisecond
	p.setSource(&rpcCommittedBlockSource{reader: reader, chainID: app.chainID})
	p.seedCommitted(app.startHeight, app.latestHeight)
	p.start()
	t.Cleanup(p.stop)
	app.persister = p

	commitBlock(t, app, reader, 3, base.Add(2*time.Second))
	waitUntil(t, "heights 1-3", 2*time.Second, func() bool { return len(store.heights()) == 3 })
	if got := store.heights(); !reflect.DeepEqual(got, []int64{1, 2, 3}) {
		t.Fatalf("heights = %v, want [1 2 3]", got)
	}
	if w := store.byHeight()[1]; len(w.Entries) != 1 || w.Entries[0].BatchID != uuid.NewSHA1(uuid.NameSpaceOID, []byte(bundleOf(t, early))) {
		t.Fatalf("replayed height 1 not rebuilt: %+v", w)
	}
}
