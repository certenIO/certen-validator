package proofv2_test

import (
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// V-J J2 (V-E F-VE-1): the set check's checkpoint is bounded like the certification's. A document that names a fresh checkpoint for the
// certification and a checkpoint more than CheckpointLag behind the newest for the set check is the stale-key attack (keys that were in
// force at the old checkpoint sign the set check's hops and the state tree it binds), so it is refused by the same name with the stale value.
func TestCheckpointStaleBoundsTheSetChecksCheckpointToo(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Final: xworld.ChainItem{Anchored: true}})
	g, set, err := proofv2.AcceptSpineGenesis(b.Inputs, b.Pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := proofv2.ExtendSpine(l, b.Archive.Majors, 2)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	// The chain goes on to major 6: copies of the first checkpoint stand for the later majors (the stale check is about the counts, before any
	// checkpoint is read).
	for n := uint64(2); n <= 6; n++ {
		c := cps[0]
		c.Major = n
		l.Checkpoints = append(l.Checkpoints, c)
	}
	newest := uint64(len(l.Checkpoints))
	for _, c := range []struct {
		name          string
		majors, check uint64
		stale         bool
		field         string
	}{
		{"fresh certification, set check CheckpointLag behind", newest, newest - proofv2.CheckpointLag, false, ""},
		{"fresh certification, set check one past the lag", newest, newest - proofv2.CheckpointLag - 1, true, "3"},
		{"fresh certification, set check at the first checkpoint", newest, 1, true, "1"},
		{"both stale: the certification's is the one named", newest - proofv2.CheckpointLag - 1, 1, true, "3"},
	} {
		ev := *b.Evidence
		ev.Majors, ev.Check.Majors = c.majors, c.check
		ev.Check.Hops = append([]string(nil), ev.Certify...) // a set check with runs of its own: the equality of the two counts is not what refuses it
		_, err := proofv2.VerifyEvidence21FromSpine(&ev, l, b.Pin)
		if c.stale {
			wantCertifyState(t, err, proofv2.StateCheckpointStale, c.field, "6", "2")
			continue
		}
		if err == nil {
			t.Fatalf("%s: a document that names no real hops for the checkpoint was verified", c.name)
		}
		var cs *proofv2.CertifyState
		if errors.As(err, &cs) && cs.Code == proofv2.StateCheckpointStale {
			t.Fatalf("%s: refused as stale (%v), the edge of the lag is judged on its merits", c.name, err)
		}
	}
	// 2.0 is judged as ever: the same shape under evidence 2.0 is not a stale refusal.
	ev := *b.Evidence
	ev.Version = proofv2.Version
	ev.Majors, ev.Check.Majors = newest, 1
	ev.Check.Hops = append([]string(nil), ev.Certify...)
	if _, err := proofv2.VerifyFromSpine(&ev, l, b.Pin); err != nil {
		var cs *proofv2.CertifyState
		if errors.As(err, &cs) && cs.Code == proofv2.StateCheckpointStale {
			t.Fatalf("evidence 2.0 was refused as stale: %v", err)
		}
	}
}
