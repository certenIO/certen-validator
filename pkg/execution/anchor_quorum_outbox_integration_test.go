// Copyright 2026 Certen Protocol
//
// The outbox against a REAL database, through the real repository.
//
// Every other reconciler test drives a fake store, which proves the control flow and nothing about the
// write. This one proves the thing the outbox exists to promise: evidence proven while the database was
// unreachable is still in the database afterwards, written by the same write-once repository the live
// path uses, and identical to what would have been written had the database never been down.

package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/database"
)

func outboxTestDB(t *testing.T) *database.BatchRepository {
	t.Helper()
	conn := openMigratedTestDB(t, "the anchor quorum outbox")
	return database.NewBatchRepository(database.NewClientFromDB(conn))
}

// integrationRunNonce makes every bundle id distinct per RUN as well as per case.
//
// The canonical row is deliberately write-once and this database persists between runs, so a fixed bundle
// id passes the first time and then measures its own first run for ever after — the exact defect this file
// was written to catch in evidence_monitor_test.go.
var integrationRunNonce = uuid.New()

func integrationBundle(n int) string {
	nonce := strings.ReplaceAll(integrationRunNonce.String(), "-", "") // 32 hex chars
	return fmt.Sprintf("0x%s%s%08x", nonce, nonce[:24], n)             // 32 + 24 + 8 = 64
}

func TestOutboxRecoversIntoTheRealDatabaseAfterAnOutage(t *testing.T) {
	repo := outboxTestDB(t)
	dir := t.TempDir()
	ctx := context.Background()

	// A record that is valid for the real repository: distinct bundle, real 32-byte root.
	rec := recordFixture()
	rec.ChainID = 84532
	rec.BundleID = integrationBundle(1)
	rec.Root = make([]byte, 32)
	for i := range rec.Root {
		rec.Root[i] = 0xe0
	}
	rec.VerifiedAt = time.Now().UTC().Truncate(time.Second)

	// ── the outage: the writer cannot reach the database and is then shut down ──────────────────────
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
	w.queue <- rec // straight onto the queue, so the exact record above is the one that must survive
	w.Stop()
	close(down.gate)

	if depth, _ := o1.Depth(); depth != 1 {
		t.Fatalf("outbox depth = %d after the outage, want 1", depth)
	}

	// Nothing reached the database.
	existing, err := repo.GetAnchorQuorum(ctx, rec.ChainID, rec.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	if existing != nil {
		t.Fatal("a row exists before the outbox was ever replayed")
	}

	// ── recovery: a new process, the same directory, a database that answers ────────────────────────
	o2, err := NewFileAnchorQuorumOutbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := (&AnchorQuorumReconciler{Outbox: o2, Store: repo}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recorded != 1 {
		t.Fatalf("recorded = %d (deferred=%d quarantined=%d), want 1", rep.Recorded, rep.Deferred, rep.Quarantined)
	}

	// ── the row is there, and it is the evidence that was proven ───────────────────────────────────
	got, err := repo.GetAnchorQuorum(ctx, rec.ChainID, rec.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("the reconciler reported a write but the database has no row")
	}
	switch {
	case !got.QuorumReached:
		t.Fatal("the recovered row does not record a quorum")
	case string(got.Root) != string(rec.Root):
		t.Fatalf("root = %x, want %x", got.Root, rec.Root)
	case got.EvidenceSource != "live":
		t.Fatalf("evidence_source = %q; a recovered row is still LIVE evidence, not a reconstruction",
			got.EvidenceSource)
	case got.AttestationCount != len(rec.Signers):
		t.Fatalf("attestation_count = %d, want %d", got.AttestationCount, len(rec.Signers))
	case got.AnchorCreateTx == "" && rec.AnchorCreateTx != "":
		t.Fatal("the recovered row lost its anchor-create transaction")
	}
	if got.SignedVotingPower != rec.SignedVotingPower.String() {
		t.Fatalf("signed voting power = %s, want %s", got.SignedVotingPower, rec.SignedVotingPower.String())
	}

	if depth, _ := o2.Depth(); depth != 0 {
		t.Fatalf("outbox depth = %d after a successful replay", depth)
	}

	// Replaying again must be a no-op, not a second row or a conflict.
	again, err := (&AnchorQuorumReconciler{Outbox: o2, Store: repo}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Pending != 0 {
		t.Fatalf("pending = %d on a second pass over a drained outbox", again.Pending)
	}
}

// The real repository reports a genuine disagreement as a conflict, and the reconciler must preserve that
// evidence rather than overwrite the stored row — against the real write-once implementation, not a fake.
func TestOutboxReplayNeverOverwritesADisagreeingRowInTheRealDatabase(t *testing.T) {
	repo := outboxTestDB(t)
	dir := t.TempDir()
	ctx := context.Background()

	chainID := int64(84532)
	bundleID := integrationBundle(2)

	// What the fleet already recorded.
	stored := recordFixture()
	stored.ChainID, stored.BundleID = chainID, bundleID
	stored.Root = make([]byte, 32)
	for i := range stored.Root {
		stored.Root[i] = 0x11
	}
	stored.AggregateSignature = []byte{0x01, 0x02}
	stored.SignedVotingPower = big.NewInt(700)
	stored.TotalVotingPower = big.NewInt(700)
	if written, err := repo.RecordAnchorQuorum(ctx, stored); err != nil || !written {
		t.Fatalf("seeding the stored row: written=%t err=%v", written, err)
	}

	// A different account of the SAME anchor, held in the outbox.
	rival := recordFixture()
	rival.ChainID, rival.BundleID = chainID, bundleID
	rival.Root = make([]byte, 32)
	for i := range rival.Root {
		rival.Root[i] = 0xd2 // the shadow-root shape
	}
	rival.AggregateSignature = []byte{0x09, 0x09}

	o, err := NewFileAnchorQuorumOutbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Put(rival); err != nil {
		t.Fatal(err)
	}

	rep, err := (&AnchorQuorumReconciler{Outbox: o, Store: repo}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Quarantined != 1 || rep.Recorded != 0 {
		t.Fatalf("quarantined=%d recorded=%d, want 1 and 0", rep.Quarantined, rep.Recorded)
	}

	// The stored row is untouched. This is the property the whole design turns on: the chain is the
	// source of truth and the database is a projection, so a disagreement is reported, never resolved.
	after, err := repo.GetAnchorQuorum(ctx, chainID, bundleID)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil {
		t.Fatal("the stored row disappeared")
	}
	if string(after.Root) != string(stored.Root) {
		t.Fatalf("the stored root was overwritten: %x, want %x", after.Root, stored.Root)
	}
}
