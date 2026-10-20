// Copyright 2026 Certen Protocol

package arbposted

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// A cut of the container body at ANY byte is refused by the field the cut falls in. The expected `part` is derived here from the
// grammar of V2_SPEC_S7 3.3 (field order and widths), not from the decoder, so a decoder that skips a check and fails later (naming
// another part) is caught: the final refusal alone would hide it.
type cutField struct {
	name string
	typ  int // 0 fixed, 1 length-prefixed, 2 count
	n    int // fixed width, or the length of the lp data, or the element count
	min  int // minimum element width of a count
}

func (c cutField) size() int {
	switch c.typ {
	case 1:
		return 4 + c.n
	case 2:
		return 4
	}
	return c.n
}

func cutFields(e Evidence) []cutField {
	var f []cutField
	fixed := func(name string, n int) { f = append(f, cutField{name, 0, n, 0}) }
	lp := func(name string, data []byte) { f = append(f, cutField{name, 1, len(data), 0}) }
	count := func(name string, n, min int) { f = append(f, cutField{name, 2, n, min}) }
	lb := func(name string, b ethl1.LB) { fixed(name+".layout", 1); lp(name, b.SSZ) }

	lp("lc.profile", []byte(e.LC.Profile))
	fixed("lc.anchorKind", 1)
	fixed("lc.anchorPeriod", 8)
	fixed("lc.anchorRoot", 32)
	lb("lc.anchorBody", e.LC.AnchorBody)
	count("lc.links", len(e.LC.Links), 5)
	for _, l := range e.LC.Links {
		lb("lc.link", l)
	}
	lb("lc.finalUpdate", e.LC.FinalUpdate)
	count("l1Spine", len(e.L1Spine), 4)
	for _, h := range e.L1Spine {
		lp("l1Spine", h)
	}
	fixed("stateBlock", 8)
	count("blockTxs", len(e.BlockTxs), 4)
	for _, t := range e.BlockTxs {
		lp("blockTxs", t)
	}
	fixed("batchSeq", 8)
	for range e.Header40 {
		fixed("header40", 8)
	}
	fixed("beforeAcc", 32)
	fixed("delayedAcc", 32)
	fixed("dataKind", 1)
	switch e.DataKind {
	case DataBlobs:
		count("versionedHashes", len(e.VersionedHashes), 32)
		for range e.VersionedHashes {
			fixed("versionedHashes", 32)
		}
		count("blobs", len(e.Blobs), 4+BlobBytes+96)
		for _, b := range e.Blobs {
			lp("blobs.raw", b.Raw)
			fixed("blobs.commitment", 48)
			fixed("blobs.proof", 48)
		}
	case DataCalldata:
		lp("calldata", e.Calldata)
	}
	fixed("delayedFlag", 1)
	if e.Delayed != nil {
		fixed("delayed.msgKind", 1)
		fixed("delayed.sender", 20)
		fixed("delayed.msgBlockNumber", 8)
		fixed("delayed.msgTimestamp", 8)
		fixed("delayed.baseFeeL1", 32)
		lp("delayed.data", e.Delayed.Data)
		fixed("delayed.k", 8)
	}
	nodes := finality.EncodeNodes(e.Nodes)
	count("nodes", len(nodes), 4)
	for _, n := range nodes {
		lp("nodes", n)
	}
	return f
}

// wantPart is the part and reason the decoder must name for the body cut to cut bytes, "" when the cut is the whole body.
func wantPart(fields []cutField, cut int) (part, reason string) {
	pos := 0
	for _, f := range fields {
		switch f.typ {
		case 0:
			if cut < pos+f.n {
				return f.name, "truncated"
			}
			pos += f.n
		case 1:
			if cut < pos+4 {
				return f.name + ".len", "truncated"
			}
			if cut < pos+4+f.n {
				return f.name, "length_exceeds_remaining"
			}
			pos += 4 + f.n
		case 2:
			if cut < pos+4 {
				return f.name + ".count", "truncated"
			}
			pos += 4
			if f.n*f.min > cut-pos {
				return f.name, "count_exceeds_remaining"
			}
		}
	}
	return "", ""
}

func partOf(err error) (part, reason string) {
	if s, ok := finality.AsNamed(err); ok {
		p, _ := s.Fields["part"].(string)
		r := ""
		if v, ok := s.Fields["reason"]; ok {
			r = fmt.Sprint(v)
		}
		if p == "" {
			p = "<" + s.Code + ">"
		}
		return p, r
	}
	return fmt.Sprintf("<%v>", err), ""
}

func cutEvidence(mode string) Evidence {
	e := Evidence{LC: ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: 5, AnchorBody: ethl1.LB{SSZ: []byte{1, 2}},
		Links: []ethl1.LB{{Layout: ethl1.LayoutGloas, SSZ: []byte{3, 3}}, {Layout: ethl1.LayoutGloas, SSZ: []byte{4}}}, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: []byte{5, 5, 5}}},
		L1Spine: [][]byte{{1, 2, 3}, {4}}, StateBlock: 7, BlockTxs: [][]byte{{5}, {6, 6}}, BatchSeq: 8, Header40: [5]uint64{1, 2, 3, 4, 5},
		Nodes: [][]byte{{0xc0}, {0xc1, 0x80}, {0xc2, 0x80, 0x80}}}
	switch mode {
	case "calldata":
		e.DataKind, e.Calldata = DataCalldata, []byte{9, 9, 9}
		e.Delayed = &Delayed{MsgKind: 12, K: 3, Data: []byte{1, 2}}
	case "blobs":
		e.DataKind = DataBlobs
		e.VersionedHashes = [][32]byte{{1}, {2}}
		e.Blobs = []Blob{{Raw: make([]byte, BlobBytes)}, {Raw: make([]byte, BlobBytes)}}
	case "none":
		e.DataKind = DataNone
	}
	return e
}

func TestACutAtAnyByteIsRefusedByTheFieldItFallsIn(t *testing.T) {
	b := DefaultBounds()
	for _, mode := range []string{"calldata", "none", "blobs"} {
		e := cutEvidence(mode)
		body := e.Encode()
		fields := cutFields(e)
		total := 0
		for _, f := range fields {
			total += f.size()
		}
		if total != len(body) {
			t.Fatalf("%s: the grammar walk covers %d bytes, the encoding is %d", mode, total, len(body))
		}
		cuts := make([]int, 0, len(body))
		if mode == "blobs" {
			// the two 128 KiB blobs: every cut near a field boundary, and a seeded sample of the interior
			pos := 0
			for _, f := range fields {
				for d := -3; d <= 3; d++ {
					if c := pos + d; c >= 0 && c < len(body) {
						cuts = append(cuts, c)
					}
				}
				pos += f.size()
			}
			rnd := rand.New(rand.NewSource(13))
			for i := 0; i < 40; i++ {
				cuts = append(cuts, rnd.Intn(len(body)))
			}
		} else {
			for i := 0; i < len(body); i++ {
				cuts = append(cuts, i)
			}
		}
		for _, c := range cuts {
			_, err := Decode(body[:c], b)
			gp, gr := partOf(err)
			wp, wr := wantPart(fields, c)
			if gp != wp || gr != wr {
				t.Fatalf("%s: a body cut to %d of %d bytes is refused in part %q (%s), the grammar says %q (%s)", mode, c, len(body), gp, gr, wp, wr)
			}
		}
		if _, err := Decode(body, b); err != nil {
			t.Fatalf("%s: the whole body: %v", mode, err)
		}
	}
}

// A blob whose length prefix is not the blob size is refused in its own part: a huge prefix by the bound, a short one as truncated.
func TestABlobLengthPrefixThatIsNotTheBlobSizeIsRefused(t *testing.T) {
	e := cutEvidence("blobs")
	e.Blobs = e.Blobs[:1]
	e.VersionedHashes = e.VersionedHashes[:1]
	body := e.Encode()
	pos := 0
	for _, f := range cutFields(e) {
		if f.name == "blobs.raw" {
			break
		}
		pos += f.size()
	}
	for name, c := range map[string]struct {
		size   uint32
		code   string
		reason string
	}{
		"4 GiB":     {0xffffffff, "finality_evidence_too_large", ""},
		"one over":  {BlobBytes + 1, "finality_evidence_too_large", ""},
		"one under": {BlobBytes - 1, "finality_evidence_malformed", "truncated"},
		"zero":      {0, "finality_evidence_malformed", "truncated"},
	} {
		mut := append([]byte(nil), body...)
		mut[pos], mut[pos+1], mut[pos+2], mut[pos+3] = byte(c.size>>24), byte(c.size>>16), byte(c.size>>8), byte(c.size)
		_, err := Decode(mut, DefaultBounds())
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != c.code || s.Fields["part"] != "blobs.raw" {
			t.Errorf("%s: %v", name, err)
			continue
		}
		r := ""
		if v, ok := s.Fields["reason"]; ok {
			r = fmt.Sprint(v)
		}
		if r != c.reason {
			t.Errorf("%s: reason %q, want %q", name, r, c.reason)
		}
	}
}
