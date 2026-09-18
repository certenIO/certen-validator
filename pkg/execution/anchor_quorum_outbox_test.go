// Copyright 2026 Certen Protocol
//
// The outbox exists so that proven evidence survives the database being unavailable. These tests plant
// each way it used to be lost and require it to come back.

package execution

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

func newTestOutbox(t *testing.T) *FileAnchorQuorumOutbox {
	t.Helper()
	o, err := NewFileAnchorQuorumOutbox(t.TempDir())
	if err != nil {
		t.Fatalf("opening outbox: %v", err)
	}
	return o
}

func recordFixture() *database.AnchorQuorumRecord {
	return AnchorQuorumRecordFrom(evidenceFixture())
}

// ─── storage ────────────────────────────────────────────────────────────────────────────────────────

// Everything RecordAnchorQuorum needs has to survive the round trip. A record that comes back missing its
// aggregate or its voting power would be written as a DIFFERENT anchor and read as a conflict.
func TestOutboxRoundTripPreservesTheWholeRecord(t *testing.T) {
	o := newTestOutbox(t)
	want := recordFixture()
	if err := o.Put(want); err != nil {
		t.Fatalf("put: %v", err)
	}

	entries, err := o.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	got := entries[0].Record
	if got == nil {
		t.Fatal("entry decoded to nil")
	}

	switch {
	case got.ChainID != want.ChainID:
		t.Fatalf("chain id = %d, want %d", got.ChainID, want.ChainID)
	case got.BundleID != want.BundleID:
		t.Fatalf("bundle = %s, want %s", got.BundleID, want.BundleID)
	case string(got.Root) != string(want.Root):
		t.Fatalf("root = %x, want %x", got.Root, want.Root)
	case string(got.AggregateSignature) != string(want.AggregateSignature):
		t.Fatalf("aggregate signature = %x, want %x", got.AggregateSignature, want.AggregateSignature)
	case string(got.AggregatePubKey) != string(want.AggregatePubKey):
		t.Fatalf("aggregate pubkey = %x, want %x", got.AggregatePubKey, want.AggregatePubKey)
	case got.EvidenceSource != "live":
		t.Fatalf("evidence source = %q, want live", got.EvidenceSource)
	case got.VerifyTx != want.VerifyTx:
		t.Fatalf("verify tx = %s", got.VerifyTx)
	case !got.VerifiedAt.Equal(want.VerifiedAt):
		t.Fatalf("verified at = %v, want %v", got.VerifiedAt, want.VerifiedAt)
	case len(got.Members) != len(want.Members):
		t.Fatalf("members = %d, want %d", len(got.Members), len(want.Members))
	case len(got.Signers) != len(want.Signers):
		t.Fatalf("signers = %d, want %d", len(got.Signers), len(want.Signers))
	}

	// Voting power is a 256-bit value carried as *big.Int. JSON is where that quietly becomes a float.
	if got.SignedVotingPower == nil || got.SignedVotingPower.Cmp(want.SignedVotingPower) != 0 {
		t.Fatalf("signed voting power = %v, want %v", got.SignedVotingPower, want.SignedVotingPower)
	}
	if got.TotalVotingPower == nil || got.TotalVotingPower.Cmp(want.TotalVotingPower) != 0 {
		t.Fatalf("total voting power = %v, want %v", got.TotalVotingPower, want.TotalVotingPower)
	}
	for i := range got.Signers {
		if got.Signers[i].Address != want.Signers[i].Address {
			t.Fatalf("signer %d address = %s", i, got.Signers[i].Address)
		}
		if got.Signers[i].VotingPower.Cmp(want.Signers[i].VotingPower) != 0 {
			t.Fatalf("signer %d power = %v", i, got.Signers[i].VotingPower)
		}
	}
	m, wm := got.Members[0], want.Members[0]
	if m.IntentID != wm.IntentID || m.AccumTxHash != wm.AccumTxHash || m.LeafIndex != wm.LeafIndex {
		t.Fatalf("member provenance not preserved: %+v", m)
	}
	if len(m.Branch) != len(wm.Branch) || (len(m.Branch) > 0 && m.Branch[0].Hash != wm.Branch[0].Hash) {
		t.Fatalf("member branch not preserved: %+v", m.Branch)
	}
}

// A 256-bit voting power must not be rounded. json.Number-vs-float64 is the classic way this breaks, and it
// would turn a correct record into a conflicting one.
func TestOutboxKeepsLargeVotingPowerExact(t *testing.T) {
	o := newTestOutbox(t)
	huge, ok := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	if !ok {
		t.Fatal("test fixture is not a number")
	}
	rec := recordFixture()
	rec.TotalVotingPower = huge
	rec.Signers[0].VotingPower = new(big.Int).Sub(huge, big.NewInt(1))
	if err := o.Put(rec); err != nil {
		t.Fatal(err)
	}

	entries, err := o.List()
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[0].Record.TotalVotingPower; got.Cmp(huge) != 0 {
		t.Fatalf("total voting power came back as %v, want %v", got, huge)
	}
	if got := entries[0].Record.Signers[0].VotingPower; got.Cmp(new(big.Int).Sub(huge, big.NewInt(1))) != 0 {
		t.Fatalf("signer power came back as %v", got)
	}
}

// The same anchor offered twice is ONE pending anchor. Without a deterministic key a flapping database
// would grow an entry per retry and the reconciler would write the same row over and over.
func TestOutboxKeepsOneEntryPerAnchor(t *testing.T) {
	o := newTestOutbox(t)
	for i := 0; i < 5; i++ {
		if err := o.Put(recordFixture()); err != nil {
			t.Fatal(err)
		}
	}
	depth, err := o.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("depth = %d after 5 puts of one anchor, want 1", depth)
	}
}

func TestOutboxSeparatesDistinctAnchors(t *testing.T) {
	o := newTestOutbox(t)
	a := recordFixture()
	b := recordFixture()
	b.BundleID = "0x" + strings.Repeat("bb", 32)
	c := recordFixture()
	c.ChainID = 11155111 // same bundle id, different chain: a different anchor

	for _, rec := range []*database.AnchorQuorumRecord{a, b, c} {
		if err := o.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	depth, err := o.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 3 {
		t.Fatalf("depth = %d, want 3 — (chain_id, bundle_id) is the identity", depth)
	}
}

func TestOutboxRemoveClearsTheEntry(t *testing.T) {
	o := newTestOutbox(t)
	rec := recordFixture()
	if err := o.Put(rec); err != nil {
		t.Fatal(err)
	}
	id := AnchorQuorumOutboxID(rec.ChainID, rec.BundleID)
	if err := o.Remove(id); err != nil {
		t.Fatal(err)
	}
	if depth, _ := o.Depth(); depth != 0 {
		t.Fatalf("depth = %d after remove", depth)
	}
	// Removing what is not there is not an error: the reconciler may race itself across a restart.
	if err := o.Remove(id); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// Quarantine must PRESERVE the evidence. It is the only local copy of a record the database disagrees
// with, which is exactly the thing an operator needs to look at.
func TestOutboxQuarantineKeepsTheEvidenceOutOfTheQueue(t *testing.T) {
	o := newTestOutbox(t)
	rec := recordFixture()
	if err := o.Put(rec); err != nil {
		t.Fatal(err)
	}
	id := AnchorQuorumOutboxID(rec.ChainID, rec.BundleID)
	if err := o.Quarantine(id, "stored root disagrees"); err != nil {
		t.Fatal(err)
	}

	if depth, _ := o.Depth(); depth != 0 {
		t.Fatalf("depth = %d; a quarantined entry must not be retried", depth)
	}
	kept := filepath.Join(o.Dir(), anchorQuorumQuarantineSubdir, id+anchorQuorumOutboxSuffix)
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("quarantined evidence was not kept: %v", err)
	}
	reason, err := os.ReadFile(filepath.Join(o.Dir(), anchorQuorumQuarantineSubdir, id+".reason.txt"))
	if err != nil || !strings.Contains(string(reason), "disagrees") {
		t.Fatalf("quarantine reason not recorded: %v %q", err, reason)
	}
}

// One unreadable file must not stall every healthy entry behind it.
func TestOutboxReportsAnUnreadableEntryWithoutFailingTheListing(t *testing.T) {
	o := newTestOutbox(t)
	good := recordFixture()
	if err := o.Put(good); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(o.Dir(), strings.Repeat("ab", 32)+anchorQuorumOutboxSuffix)
	if err := os.WriteFile(junk, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := o.List()
	if err != nil {
		t.Fatalf("one corrupt entry failed the whole listing: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	var decoded, nils int
	for _, e := range entries {
		if e.Record == nil {
			nils++
		} else {
			decoded++
		}
	}
	if decoded != 1 || nils != 1 {
		t.Fatalf("decoded=%d undecodable=%d, want 1 and 1", decoded, nils)
	}
}

// An entry id reaches the filesystem. It must never be able to name anything outside the outbox.
func TestOutboxRefusesAnIdThatIsNotAHash(t *testing.T) {
	o := newTestOutbox(t)
	for _, bad := range []string{"", "..", "../../etc/passwd", "nothex" + strings.Repeat("z", 58), strings.Repeat("ab", 10)} {
		if err := o.Remove(bad); err == nil {
			t.Fatalf("Remove accepted %q", bad)
		}
		if err := o.Quarantine(bad, "x"); err == nil {
			t.Fatalf("Quarantine accepted %q", bad)
		}
	}
}

// Temporary files from an interrupted write must never be mistaken for entries.
func TestOutboxIgnoresPartialWrites(t *testing.T) {
	o := newTestOutbox(t)
	if err := os.WriteFile(filepath.Join(o.Dir(), "deadbeef.1234.tmp"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if depth, err := o.Depth(); err != nil || depth != 0 {
		t.Fatalf("depth = %d (err %v); a .tmp file is not an entry", depth, err)
	}
}

// ─── writer spill ───────────────────────────────────────────────────────────────────────────────────

// The case that used to lose evidence outright: the queue is full because the database cannot keep up.
func TestWriterSpillsToTheOutboxInsteadOfDroppingWhenSaturated(t *testing.T) {
	store := &fakeQuorumStore{gate: make(chan struct{})} // never answers
	o := newTestOutbox(t)
	w := startWriter(t, store, 1)
	w.SetOutbox(o)
	t.Cleanup(func() { close(store.gate) })

	hook := w.Hook()
	for i := 0; i < 50; i++ {
		ev := evidenceFixture()
		ev.BundleID[0] = byte(i) // distinct anchors, so each spill is its own entry
		hook(context.Background(), ev)
	}

	_, _, _, dropped, _ := w.Stats()
	if dropped != 0 {
		t.Fatalf("dropped = %d; with an outbox installed nothing proven may be dropped", dropped)
	}
	depth, err := o.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth == 0 {
		t.Fatal("the outbox is empty; saturated hand-offs were lost")
	}
	if got := w.Spilled(); got != uint64(depth) {
		t.Fatalf("spilled = %d but outbox holds %d", got, depth)
	}
}

// Shutting down while the database is down must not discard what was already proven.
func TestWriterSpillsQueuedEvidenceOnShutdown(t *testing.T) {
	store := &fakeQuorumStore{gate: make(chan struct{})} // never answers
	o := newTestOutbox(t)
	w := NewAnchorQuorumWriter(store, nil)
	w.queue = make(chan *database.AnchorQuorumRecord, 16)
	w.retryBase, w.retryMax, w.callTimeout = time.Millisecond, 2*time.Millisecond, time.Second
	w.SetOutbox(o)
	w.Start()

	hook := w.Hook()
	for i := 0; i < 8; i++ {
		ev := evidenceFixture()
		ev.BundleID[0] = byte(i)
		hook(context.Background(), ev)
	}
	w.Stop() // the database never answered; everything is still in flight
	close(store.gate)

	depth, err := o.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 8 {
		t.Fatalf("outbox depth = %d after shutdown, want 8 — proven evidence was discarded", depth)
	}
}

// ─── reconciler ─────────────────────────────────────────────────────────────────────────────────────

func TestReconcilerRecordsEverythingTheOutboxHeld(t *testing.T) {
	o := newTestOutbox(t)
	for i := 0; i < 4; i++ {
		rec := recordFixture()
		rec.BundleID = "0x" + strings.Repeat(string("0123"[i]), 64)
		if err := o.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	store := &fakeQuorumStore{}
	r := &AnchorQuorumReconciler{Outbox: o, Store: store}

	rep, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recorded != 4 || rep.Remaining != 0 {
		t.Fatalf("recorded=%d remaining=%d, want 4 and 0", rep.Recorded, rep.Remaining)
	}
	if len(store.records) != 4 {
		t.Fatalf("store holds %d records", len(store.records))
	}
}

// The whole point: a record that could not be written survives the process that proved it.
func TestEvidenceSurvivesADatabaseOutageAcrossARestart(t *testing.T) {
	dir := t.TempDir()

	// Process 1: the database is down for the entire life of the writer.
	down := &fakeQuorumStore{gate: make(chan struct{})}
	o1, err := NewFileAnchorQuorumOutbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := NewAnchorQuorumWriter(down, nil)
	w.queue = make(chan *database.AnchorQuorumRecord, 4)
	w.retryBase, w.retryMax, w.callTimeout = time.Millisecond, 2*time.Millisecond, 50*time.Millisecond
	w.SetOutbox(o1)
	w.Start()
	w.Hook()(context.Background(), evidenceFixture())
	w.Stop()
	close(down.gate)

	if depth, _ := o1.Depth(); depth != 1 {
		t.Fatalf("outbox depth = %d at shutdown, want 1", depth)
	}

	// Process 2: a fresh outbox over the same directory, and a database that now answers.
	o2, err := NewFileAnchorQuorumOutbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	up := &fakeQuorumStore{}
	rep, err := (&AnchorQuorumReconciler{Outbox: o2, Store: up}).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recorded != 1 {
		t.Fatalf("recorded = %d after restart, want 1", rep.Recorded)
	}
	if len(up.records) != 1 {
		t.Fatalf("store holds %d records after restart", len(up.records))
	}
	got := up.records[0]
	want := AnchorQuorumRecordFrom(evidenceFixture())
	if got.BundleID != want.BundleID || string(got.Root) != string(want.Root) {
		t.Fatalf("recovered record is not the one that was proven: %s / %x", got.BundleID, got.Root)
	}
	if string(got.AggregateSignature) != string(want.AggregateSignature) {
		t.Fatal("the recovered record lost its aggregate signature")
	}
	if depth, _ := o2.Depth(); depth != 0 {
		t.Fatalf("depth = %d after a successful replay", depth)
	}
}

// A conflict is never resolved by retrying, and the evidence is never thrown away.
func TestReconcilerQuarantinesAConflictAndStopsRetryingIt(t *testing.T) {
	o := newTestOutbox(t)
	rec := recordFixture()
	if err := o.Put(rec); err != nil {
		t.Fatal(err)
	}
	store := &fakeQuorumStore{conflict: true}
	r := &AnchorQuorumReconciler{Outbox: o, Store: store}

	rep, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Quarantined != 1 || rep.Recorded != 0 {
		t.Fatalf("quarantined=%d recorded=%d, want 1 and 0", rep.Quarantined, rep.Recorded)
	}
	if len(store.records) != 0 {
		t.Fatal("a conflict must not write a row")
	}

	// A second pass must not touch it again.
	before := store.count()
	rep2, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Pending != 0 {
		t.Fatalf("pending = %d on the second pass; a conflict is being retried for ever", rep2.Pending)
	}
	if store.count() != before {
		t.Fatalf("the store was called again for a quarantined conflict")
	}

	id := AnchorQuorumOutboxID(rec.ChainID, rec.BundleID)
	if _, err := os.Stat(filepath.Join(o.Dir(), anchorQuorumQuarantineSubdir, id+anchorQuorumOutboxSuffix)); err != nil {
		t.Fatalf("conflicting evidence was not preserved: %v", err)
	}
}

// A transient failure must NOT retire the entry — that is the difference between a retry and a loss.
func TestReconcilerKeepsAnEntryTheDatabaseCouldNotTakeYet(t *testing.T) {
	o := newTestOutbox(t)
	if err := o.Put(recordFixture()); err != nil {
		t.Fatal(err)
	}
	store := &fakeQuorumStore{failN: 1}
	r := &AnchorQuorumReconciler{Outbox: o, Store: store}

	rep, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Deferred != 1 || rep.Recorded != 0 || rep.Quarantined != 0 {
		t.Fatalf("deferred=%d recorded=%d quarantined=%d, want 1/0/0", rep.Deferred, rep.Recorded, rep.Quarantined)
	}
	if depth, _ := o.Depth(); depth != 1 {
		t.Fatalf("depth = %d; a deferred entry must stay pending", depth)
	}

	// Next pass, the database is healthy again.
	rep2, err := r.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Recorded != 1 {
		t.Fatalf("recorded = %d on the retry pass", rep2.Recorded)
	}
	if depth, _ := o.Depth(); depth != 0 {
		t.Fatalf("depth = %d after a successful retry", depth)
	}
}

// A row another validator already wrote is not an error and not a conflict: the entry is simply retired.
func TestReconcilerRetiresAnEntryAnotherValidatorAlreadyRecorded(t *testing.T) {
	o := newTestOutbox(t)
	if err := o.Put(recordFixture()); err != nil {
		t.Fatal(err)
	}
	store := &fakeQuorumStore{alreadyHeld: true}
	rep, err := (&AnchorQuorumReconciler{Outbox: o, Store: store}).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.AlreadyHeld != 1 || rep.Recorded != 0 {
		t.Fatalf("already-held=%d recorded=%d, want 1 and 0", rep.AlreadyHeld, rep.Recorded)
	}
	if depth, _ := o.Depth(); depth != 0 {
		t.Fatalf("depth = %d; an anchor already recorded needs no further replay", depth)
	}
}

func TestReconcilerQuarantinesAnEntryItCannotDecode(t *testing.T) {
	o := newTestOutbox(t)
	junkID := strings.Repeat("cd", 32)
	if err := os.WriteFile(filepath.Join(o.Dir(), junkID+anchorQuorumOutboxSuffix), []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := &fakeQuorumStore{}
	rep, err := (&AnchorQuorumReconciler{Outbox: o, Store: store}).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Quarantined != 1 {
		t.Fatalf("quarantined = %d, want 1", rep.Quarantined)
	}
	if store.count() != 0 {
		t.Fatal("an undecodable entry must never reach the database")
	}
	if _, err := os.Stat(filepath.Join(o.Dir(), anchorQuorumQuarantineSubdir, junkID+anchorQuorumOutboxSuffix)); err != nil {
		t.Fatalf("the undecodable entry was deleted rather than kept: %v", err)
	}
}

// Start must replay immediately rather than waiting out an interval: the commonest reason for a non-empty
// outbox is the shutdown that just happened.
func TestReconcilerReplaysAtStartupBeforeTheFirstTick(t *testing.T) {
	o := newTestOutbox(t)
	if err := o.Put(recordFixture()); err != nil {
		t.Fatal(err)
	}
	store := &fakeQuorumStore{}
	r := &AnchorQuorumReconciler{Outbox: o, Store: store, Interval: time.Hour}
	r.Start(context.Background())
	t.Cleanup(r.Stop)

	waitForQuorum(t, "the startup replay", 2*time.Second, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.records) == 1
	})
}

func TestReconcilerNeedsBothAnOutboxAndAStore(t *testing.T) {
	if _, err := (&AnchorQuorumReconciler{}).RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce accepted a reconciler with nothing wired")
	}
}
