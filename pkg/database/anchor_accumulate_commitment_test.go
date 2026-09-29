package database

import (
	"context"
	"strings"
	"testing"
)

// A V8.2 anchor's row keeps everything its bundle id derives from and its quorum signed (RB5-F9, migration 00018).
func TestAnchorRowKeepsTheAccumulateCommitment(t *testing.T) {
	repo := anchorRepoForTest(t)
	ctx := context.Background()
	rec := anchorRecordForTest(84532, bundleHex(18001), 0x18)
	if written, err := repo.RecordAnchorQuorum(ctx, rec); err != nil || !written {
		t.Fatalf("write: %v %v", written, err)
	}
	var version, certen, acc, inc string
	var height int64
	if err := testDB.QueryRowContext(ctx, `SELECT anchor_version, accumulate_block_height, certen_validator_set_root,
	        accumulate_set_root, accumulate_incarnation FROM anchor_batches WHERE chain_id = $1 AND bundle_id = $2`,
		rec.ChainID, rec.BundleID).Scan(&version, &height, &certen, &acc, &inc); err != nil {
		t.Fatal(err)
	}
	if version != "v8_2" || height != rec.AccumulateBlockHeight || !strings.EqualFold(certen, rec.CertenSetRoot) ||
		!strings.EqualFold(acc, rec.AccumulateSetRoot) || !strings.EqualFold(inc, rec.AccumulateIncarnation) {
		t.Fatalf("stored %s %d %s %s %s", version, height, certen, acc, inc)
	}

	// The same anchor stated with another Accumulate set is an anchor the chain did not create: refused, never
	// overwritten.
	other := anchorRecordForTest(84532, rec.BundleID, 0x18)
	other.AccumulateSetRoot = bundleHex(18002)
	if _, err := repo.RecordAnchorQuorum(ctx, other); err == nil || !strings.Contains(err.Error(), "Accumulate set") {
		t.Fatalf("a different Accumulate set was accepted for a stored anchor: %v", err)
	}
	otherInc := anchorRecordForTest(84532, rec.BundleID, 0x18)
	otherInc.AccumulateIncarnation = bundleHex(18003)
	if _, err := repo.RecordAnchorQuorum(ctx, otherInc); err == nil {
		t.Fatal("a different incarnation was accepted for a stored anchor")
	}
	if err := testDB.QueryRowContext(ctx, `SELECT accumulate_set_root FROM anchor_batches WHERE chain_id = $1 AND bundle_id = $2`,
		rec.ChainID, rec.BundleID).Scan(&acc); err != nil || !strings.EqualFold(acc, rec.AccumulateSetRoot) {
		t.Fatalf("the stored set moved: %s %v", acc, err)
	}
}

func TestAnchorRecordMustStateItsCommitment(t *testing.T) {
	repo := anchorRepoForTest(t)
	zero := "0x" + strings.Repeat("0", 64)
	for name, mut := range map[string]func(r *AnchorQuorumRecord){
		"no generation":              func(r *AnchorQuorumRecord) { r.AnchorVersion = "" },
		"unknown generation":         func(r *AnchorQuorumRecord) { r.AnchorVersion = "v9" },
		"v8.2 without a set":         func(r *AnchorQuorumRecord) { r.AccumulateSetRoot = "" },
		"v8.2 without incarnation":   func(r *AnchorQuorumRecord) { r.AccumulateIncarnation = "" },
		"v8.2 with a zero set":       func(r *AnchorQuorumRecord) { r.AccumulateSetRoot = zero },
		"v8.2 with zero incarnation": func(r *AnchorQuorumRecord) { r.AccumulateIncarnation = zero },
		"v8.1 claiming a set":        func(r *AnchorQuorumRecord) { r.AnchorVersion = "v8_1" },
	} {
		rec := anchorRecordForTest(84532, bundleHex(18100+len(name)), 0x19)
		mut(rec)
		if written, err := repo.RecordAnchorQuorum(context.Background(), rec); err == nil || written {
			t.Errorf("%s: accepted", name)
		}
	}
}
