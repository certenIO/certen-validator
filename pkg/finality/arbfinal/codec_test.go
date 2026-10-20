// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func boundsOf(t *testing.T, w *synthworld.World) arbfinal.Bounds {
	t.Helper()
	p, err := finality.ParsePinsOverride(w.Pins)
	if err != nil {
		t.Fatal(err)
	}
	l1p, err := arbfinal.EthL1Pins(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := arbfinal.LoadPins(p)
	if err != nil {
		t.Fatal(err)
	}
	return arbfinal.Bounds{Limits: finality.DefaultLimits(), MaxLinks: l1p.MaxLinks, MaxSpineHeaders: l1p.MaxSpineHeaders, MaxHeaderChain: a.MaxHeaderChain}
}

// encode(decode(x)) == x for the valid world; every strict-decoding refusal is a named state, never a panic.
func TestBodyRoundTripAndStrictness(t *testing.T) {
	w := synthworld.Assemble(synthworld.NewParts("codec"))
	c, err := finality.DecodeContainer(w.Container, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b := boundsOf(t, w)
	e, err := arbfinal.Decode(c.Body, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.Encode(), c.Body) {
		t.Fatal("encode(decode(x)) != x")
	}
	// trailing byte
	if _, err := arbfinal.Decode(append(append([]byte(nil), c.Body...), 0), b); err == nil {
		t.Fatal("a trailing byte was accepted")
	}
	// every truncation of the body is a named state
	for _, n := range []int{0, 1, 5, 40, 300, len(c.Body) / 3, len(c.Body) / 2, len(c.Body) - 50, len(c.Body) - 5, len(c.Body) - 1} {
		_, err := arbfinal.Decode(c.Body[:n], b)
		if err == nil {
			t.Fatalf("a body truncated to %d bytes was accepted", n)
		}
		if _, ok := finality.AsNamed(err); !ok {
			t.Fatalf("truncation to %d: %v is not a named state", n, err)
		}
	}
	// the l2Spine count is judged against max_header_chain before anything is allocated
	small := b
	small.MaxHeaderChain = 2
	_, err = arbfinal.Decode(c.Body, small)
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != arbfinal.CodeHeaderChainExceeds {
		t.Fatalf("got %v, want header_chain_exceeds_bound", err)
	}
	if s.Fields["needed"] != uint64(len(e.L2Spine)) || s.Fields["max"] != uint64(2) {
		t.Fatalf("fields %v", s.Fields)
	}
	// a hostile l2Spine count that cannot fit in the remaining bytes is malformed, not an allocation
	hostile := append([]byte(nil), c.Body...)
	off := bytes.Index(hostile, e.L2Spine[0]) - 4 - 4
	if off < 0 {
		t.Fatal("cannot locate the l2Spine count")
	}
	hostile[off], hostile[off+1], hostile[off+2], hostile[off+3] = 0x00, 0x00, 0x7f, 0xff
	if _, err := arbfinal.Decode(hostile, b); err == nil {
		t.Fatal("a count of 32767 headers in a few KB was accepted")
	}
}

// The level-2 container of the same leg and the other chain's evidence are never taken for this kind.
func TestKindChainAndLevelAreChecked(t *testing.T) {
	w := synthworld.Assemble(synthworld.NewParts("kind"))
	k := arbfinal.New()
	if k.Name() != "arb-sepolia/finalized/v1" || k.Chain() != finality.ChainArbitrumSepolia || k.Level() != finality.LevelFinalized {
		t.Fatal("identity of the kind")
	}
	p, err := finality.ParsePinsOverride(w.Pins)
	if err != nil {
		t.Fatal(err)
	}
	other := finality.BlockRef{Chain: w.Leg.Chain, Number: w.Leg.Number + 1, Hash: w.Leg.Hash, HeaderRLP: w.Leg.HeaderRLP}
	if _, err := k.Verify(p, other, w.Container); err == nil {
		t.Fatal("evidence of another block was accepted")
	}
}

// A body cut exactly at the start of each field is refused as truncated at THAT field (so a decoder that lost one of its error
// checks would report a later field, or accept).
func TestTruncationAtEveryFieldNamesTheField(t *testing.T) {
	w := synthworld.Assemble(synthworld.NewParts("trunc"))
	c, err := finality.DecodeContainer(w.Container, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b := boundsOf(t, w)
	e := w.Evidence
	off := len(ethl1.EncodeLC(e.LC))
	spine := 4
	for _, h := range e.L1Spine {
		spine += 4 + len(h)
	}
	type field struct {
		part string
		size int
	}
	fields := []field{
		{"l1Spine.count", spine}, {"stateBlock", 8}, {"confBlock", 8}, {"parentAssertionHash", 32},
		{"afterState.blockHash", 32}, {"afterState.sendRoot", 32}, {"afterState.inboxPosition", 8}, {"afterState.positionInMessage", 8},
		{"afterState.machineStatus", 1}, {"afterState.endHistoryRoot", 32}, {"sequencerBatchAcc", 32},
		{"parentConfig.wasmModuleRoot", 32}, {"parentConfig.requiredStake", 32}, {"parentConfig.challengeManager", 20},
		{"parentConfig.confirmPeriodBlocks", 8}, {"parentConfig.nextInboxPosition", 8},
	}
	l2 := 4
	for _, h := range e.L2Spine {
		l2 += 4 + len(h)
	}
	fields = append(fields, field{"l2Spine.count", l2}, field{"confTxIndex", 4}, field{"confTxRaw.len", 4 + len(e.ConfTxRaw)}, field{"confReceiptRaw.len", 4 + len(e.ConfReceiptRaw)})
	for _, f := range fields {
		cut := c.Body[:off]
		_, err := arbfinal.Decode(cut, b)
		s, ok := finality.AsNamed(err)
		want := f.part
		if !ok || s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != want {
			t.Errorf("cut at the start of %s (offset %d): got %v", want, off, err)
		}
		off += f.size
	}
	// the nodes set is the last field: cut at its start
	_, err = arbfinal.Decode(c.Body[:off], b)
	if s, ok := finality.AsNamed(err); !ok || s.Fields["part"] != "nodes.count" {
		t.Errorf("cut at the start of nodes: %v", err)
	}
}

// A cut inside the LC part names the LC field it falls in, and a cut inside a length-prefixed value reports the value as too long
// for what remains.
func TestTruncationInsideTheLCNamesTheField(t *testing.T) {
	w := synthworld.Assemble(synthworld.NewParts("lc-trunc"))
	c, err := finality.DecodeContainer(w.Container, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b := boundsOf(t, w)
	prof := 4 + len(ethl1.ProfileLC)
	bodyLen := 4 + len(w.Evidence.LC.AnchorBody.SSZ)
	steps := []struct {
		part string
		size int
	}{
		{"lc.profile.len", prof}, {"lc.anchorKind", 1}, {"lc.anchorPeriod", 8}, {"lc.anchorRoot", 32}, {"lc.anchorBody.layout", 1},
		{"lc.anchorBody.len", bodyLen}, {"lc.links.count", 4}, {"lc.finalUpdate.layout", 1},
	}
	off := 0
	for _, s := range steps {
		_, err := arbfinal.Decode(c.Body[:off], b)
		st, ok := finality.AsNamed(err)
		if !ok || st.Code != finality.CodeEvidenceMalformed || st.Fields["part"] != s.part {
			t.Errorf("cut at %d (start of %s): got %v", off, s.part, err)
		}
		off += s.size
	}
	// a length that exceeds what remains: the profile string cut after its length word, and the committee cut in the middle
	for _, c2 := range []struct {
		at   int
		part string
	}{{4 + 2, "lc.profile"}, {prof + 1 + 8 + 32 + 1 + 4 + 100, "lc.anchorBody"}} {
		_, err := arbfinal.Decode(c.Body[:c2.at], b)
		st, ok := finality.AsNamed(err)
		if !ok || st.Fields["part"] != c2.part || st.Fields["reason"] != finality.ReasonLengthExceedsRemaining {
			t.Errorf("cut at %d: got %v", c2.at, err)
		}
	}
}

// The l2Spine count bound and the count-against-remaining guard are exact: a count equal to max_header_chain passes (and one above
// is refused), and a count whose minimum size equals the bytes that remain passes the guard (the body then ends at the next field).
func TestL2SpineCountBoundariesAreExact(t *testing.T) {
	w := synthworld.Assemble(synthworld.NewParts("l2-bounds"))
	c, err := finality.DecodeContainer(w.Container, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b := boundsOf(t, w)
	n := len(w.Evidence.L2Spine)
	b.MaxHeaderChain = n
	if _, err := arbfinal.Decode(c.Body, b); err != nil {
		t.Fatalf("a spine of exactly max_header_chain headers: %v", err)
	}
	b.MaxHeaderChain = n - 1
	if _, err := arbfinal.Decode(c.Body, b); err == nil {
		t.Fatal("a spine of max_header_chain+1 headers was accepted")
	}
	// locate the l2Spine count: the body up to it is everything before the first L2 header's length word
	idx := bytes.Index(c.Body, w.Evidence.L2Spine[0])
	if idx < 8 {
		t.Fatal("cannot locate the l2Spine")
	}
	prefix := c.Body[:idx-8]
	b.MaxHeaderChain = 32768
	for _, tc := range []struct {
		count     uint32
		zeroWords int
		part      string
		reason    finality.EvidenceReason
	}{
		{3, 3, "confTxIndex", ""},                               // 3*4 bytes remain: the guard passes, the next field is missing
		{3, 2, "l2Spine", finality.ReasonCountExceedsRemaining}, // 3*4 > 8 remaining
		{1, 1, "confTxIndex", ""},                               // one zero-length header, then nothing
	} {
		body := append([]byte(nil), prefix...)
		body = append(body, byte(tc.count>>24), byte(tc.count>>16), byte(tc.count>>8), byte(tc.count))
		for i := 0; i < tc.zeroWords; i++ {
			body = append(body, 0, 0, 0, 0)
		}
		_, err := arbfinal.Decode(body, b)
		st, ok := finality.AsNamed(err)
		if !ok || st.Fields["part"] != tc.part {
			t.Errorf("count %d with %d zero words: got %v, want part %s", tc.count, tc.zeroWords, err, tc.part)
			continue
		}
		if tc.reason != "" && st.Fields["reason"] != tc.reason {
			t.Errorf("count %d with %d zero words: reason %v", tc.count, tc.zeroWords, st.Fields["reason"])
		}
	}
}
