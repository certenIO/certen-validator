// Copyright 2026 Certen Protocol

package ethl1

import (
	"encoding/binary"
	"testing"
)

// Tests added for the survivors of the mutation gate (pv2mut) over the production files of this package: each states a boundary or a
// ordering that no published vector pins and that a wrong implementation could break.

func v2Case(t *testing.T, id string) (Pins, LC) {
	t.Helper()
	useSet(t, vectorDirV2)
	c, ok := cases(t)[id]
	if !ok {
		t.Fatalf("case %s is not in the v2 set", id)
	}
	return loadPins(t, c.Pins), loadLC(t, c)
}

func asFault(t *testing.T, err error) *Fault {
	t.Helper()
	f, ok := err.(*Fault)
	if !ok || f == nil {
		t.Fatalf("not a fault: %v", err)
	}
	return f
}

// TestMaxLinksIsInclusive: a container with exactly max_links links verifies; one more is finality_evidence_too_large; max_links 0
// admits no link at all.
func TestMaxLinksIsInclusive(t *testing.T) {
	p, lc := v2Case(t, "synth_valid_link_then_final") // exactly one link
	if len(lc.Links) != 1 {
		t.Fatalf("the case has %d links", len(lc.Links))
	}
	p.MaxLinks = 1
	if _, err := VerifyFinalizedHead(p, lc); err != nil {
		t.Fatalf("one link against max_links 1: %v", err)
	}
	p.MaxLinks = 0
	f := asFault(t, func() error { _, err := VerifyFinalizedHead(p, lc); return err }())
	if f.Code != CodeEvidenceTooLarge || f.Fields["count"] != 1 || f.Fields["limit"] != 0 {
		t.Fatalf("one link against max_links 0: %s", f.CanonicalJSON())
	}
}

// TestBootstrapAndLinkForkChecks: the fork of the bootstrap's and of every link's attested slot must carry the layout the blob was parsed
// by, and is judged before the anchor (spec 3.2 b): a Gloas-shaped bootstrap or link with a Fulu-era slot is finality_fork_unsupported.
func TestBootstrapAndLinkForkChecks(t *testing.T) {
	fuluSlot := uint64(352768 * 32) // first slot of the Fulu epoch 352768, 256*1378
	p, lc := v2Case(t, "valid_k2_k0")
	b := append([]byte(nil), lc.AnchorBody.SSZ...)
	binary.LittleEndian.PutUint64(b[0:8], fuluSlot)
	lc.AnchorBody.SSZ = b
	f := asFault(t, func() error { _, err := VerifyFinalizedHead(p, lc); return err }())
	if f.Code != CodeForkUnsupported || f.Fields["slot"] != fuluSlot || f.Fields["layout"] != "gloas" {
		t.Fatalf("bootstrap with a Fulu-era slot: %s", f.CanonicalJSON())
	}

	p, lc = v2Case(t, "valid_k1_short")
	l := append([]byte(nil), lc.Links[0].SSZ...)
	binary.LittleEndian.PutUint64(l[0:8], fuluSlot)
	lc.Links[0].SSZ = l
	f = asFault(t, func() error { _, err := VerifyFinalizedHead(p, lc); return err }())
	if f.Code != CodeForkUnsupported || f.Fields["slot"] != fuluSlot || f.Fields["layout"] != "gloas" {
		t.Fatalf("link with a Fulu-era attested slot: %s", f.CanonicalJSON())
	}
}
