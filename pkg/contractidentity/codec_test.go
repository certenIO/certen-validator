// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// ---- an independent writer that records, for every byte, which read of the grammar consumes it ----

type seg struct {
	start, end int
	part       string
}

type rec struct {
	b     []byte
	segs  []seg
	marks map[string]int
}

func newRec() *rec { return &rec{marks: map[string]int{}} }

func (r *rec) mark(name string) { r.marks[name] = len(r.b) }
func (r *rec) fixed(part string, v []byte) {
	s := len(r.b)
	r.b = append(r.b, v...)
	if len(v) > 0 {
		r.segs = append(r.segs, seg{s, len(r.b), part})
	}
}
func u32b(n int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }
func u64b(n uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, n)
}
func (r *rec) lp(part string, v []byte) { r.fixed(part, u32b(len(v))); r.fixed(part, v) }
func (r *rec) str(part, s string)       { r.lp(part, []byte(s)) }
func (r *rec) u8(part string, v uint8)  { r.fixed(part, []byte{v}) }

// record writes c by the grammar of item 1a, independently of codec.go, and records the part each byte belongs to when it is not read.
func record(c *Container) *rec {
	r := newRec()
	r.fixed(PartMagic, []byte(Magic))
	r.str(PartKind, Kind)
	r.fixed(PartContainer, u64b(c.Chain))
	r.fixed(PartContainer, u64b(c.Leg.Number))
	r.fixed(PartContainer, c.Leg.Hash[:])
	r.fixed(PartCodes, u32b(len(c.Codes)))
	for _, code := range c.Codes {
		r.fixed(PartCodes, code.Address[:])
		r.lp(PartCodes, code.Runtime)
	}
	for _, pp := range []struct {
		name string
		p    Part
	}{{PartSettle, c.Settle}, {PartAttest, c.Attest}} {
		r.mark(pp.name + "Tag")
		r.u8(pp.name, uint8(pp.p.Tag))
		switch pp.p.Tag {
		case TagStated:
			s := pp.p.Stated
			r.str(pp.name, s.State)
			r.str(pp.name, s.Reason)
			r.fixed(pp.name, u64b(s.JudgedBlock))
			r.fixed(pp.name, s.JudgedHash[:])
			r.fixed(PartFailures, u32b(len(s.Failures)))
			for _, f := range s.Failures {
				r.str(pp.name, f.Host)
				r.str(pp.name, f.Error)
			}
			r.str(pp.name, s.Detail)
		case TagCaptured:
			if pp.name == PartAttest {
				a := pp.p.Attest
				r.mark("link")
				r.u8(PartAttest, a.Link)
				r.lp(PartAttest, a.HeaderV)
				r.lp(PartAttest, a.HeaderVParent)
				if a.Link == LinkHops {
					r.fixed(PartHopHeaders, u32b(len(a.HopHeaders)))
					for _, h := range a.HopHeaders {
						r.lp(PartHopHeaders, h)
					}
				}
				if a.Link == LinkSpine {
					r.fixed(PartSpine, u32b(len(a.Spine)))
					for _, h := range a.Spine {
						r.lp(PartSpine, h)
					}
				}
				r.fixed(PartAttest, u32b(int(a.TxIndex)))
				r.lp(PartAttest, a.TxLeaf)
				r.lp(PartAttest, a.ReceiptLeaf)
				r.fixed(PartBlockTxs, u32b(len(a.BlockTxs)))
				for _, t := range a.BlockTxs {
					r.lp(PartBlockTxs, t)
				}
			}
		}
	}
	r.mark("nodesCount")
	r.fixed(PartNodes, u32b(len(c.Nodes)))
	for _, n := range c.Nodes {
		r.lp(PartNodes, n)
	}
	return r
}

func wantState(t *testing.T, err error, want *StateError) {
	t.Helper()
	got, ok := AsState(err)
	if !ok {
		t.Fatalf("error %v is not a named state", err)
	}
	if err := Validate(got); err != nil {
		t.Fatalf("state %s is not a registry state: %v", got, err)
	}
	if !bytes.Equal(got.Canonical(), want.Canonical()) {
		t.Fatalf("state\n got %s\nwant %s", got.Canonical(), want.Canonical())
	}
}

func mustDecodeErr(t *testing.T, raw []byte) error {
	t.Helper()
	c, err := Decode(raw, DefaultLimits())
	if err == nil {
		t.Fatalf("decode accepted %x (%+v)", raw, c)
	}
	return err
}

func TestRecorderAgreesWithEncoder(t *testing.T) {
	for _, c := range []*Container{g1Container(), g2Container()} {
		want, err := Encode(c, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if got := record(c).b; !bytes.Equal(got, want) {
			t.Fatalf("recorder and encoder disagree\n rec %x\n enc %x", got, want)
		}
	}
}

// Truncation at every byte of both golden containers is evidence_malformed{truncated} at the part that the next read belongs to, with the
// offset where that read started and the bytes present / wanted (fuzz-style, every field boundary AND every byte inside a field).
func TestTruncationAtEveryByteIsTruncated(t *testing.T) {
	for _, c := range []*Container{g1Container(), g2Container(), richContainer(), statedAttestContainer()} {
		r := record(c)
		full, err := Encode(c, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		for l := 0; l < len(full); l++ {
			var hit *seg
			for i := range r.segs {
				if r.segs[i].start <= l && l < r.segs[i].end {
					hit = &r.segs[i]
					break
				}
			}
			if hit == nil {
				t.Fatalf("no segment covers byte %d", l)
			}
			_, err := Decode(full[:l], DefaultLimits())
			wantState(t, err, Malformed(hit.part, MalformedTruncated, hit.start, l-hit.start, hit.end-hit.start))
		}
	}
}

// richContainer has captured link 2 (spine), a code, all optional lists non-empty.
func richContainer() *Container {
	c := g2Container()
	c.Attest.Attest.Link = LinkSpine
	c.Attest.Attest.HopHeaders = nil
	c.Attest.Attest.Spine = [][]byte{[]byte("s-2"), []byte("s-1"), []byte("s-0")}
	c.Settle = Part{Tag: TagStated, Stated: &Stated{State: StatedState, Reason: "state_unavailable", JudgedBlock: 5, JudgedHash: bytes32(0x07),
		Failures: []ProviderFailure{{Host: "a.example", Error: "e1"}, {Host: "b.example", Error: ""}}, Detail: "bytes=1;limit=2"}}
	return c
}

func statedAttestContainer() *Container {
	c := g2Container()
	c.Attest = Part{Tag: TagStated, Stated: &Stated{State: StatedState, Reason: "block_too_large", JudgedBlock: 9, JudgedHash: bytes32(0x09), Detail: "bytes=2097152;limit=1048576"}}
	c.Attest.Stated.Failures = nil
	c.Codes = nil
	return c
}

func TestVS8_010_BadMagic(t *testing.T) {
	raw, _ := Encode(g2Container(), DefaultLimits())
	bad := append([]byte("CIE2"), raw[4:]...)
	wantState(t, mustDecodeErr(t, bad), Malformed(PartMagic, MalformedBadMagic, 0, 0, 0))
}

func TestVS8_011_UnknownKind(t *testing.T) {
	var b []byte
	b = append(b, Magic...)
	b = append(b, u32b(len("contract-identity/v9"))...)
	b = append(b, "contract-identity/v9"...)
	b = append(b, make([]byte, 64)...)
	wantState(t, mustDecodeErr(t, b), Unrecognised("contract-identity/v9"))
	if st, _ := AsState(mustDecodeErr(t, b)); st.Fields["version"] != "v9" {
		t.Fatalf("version = %v", st.Fields["version"])
	}
}

func TestVS8_012_TrailingByte(t *testing.T) {
	raw, _ := Encode(g2Container(), DefaultLimits())
	for _, extra := range []int{1, 2, 17} {
		bad := append(append([]byte(nil), raw...), make([]byte, extra)...)
		wantState(t, mustDecodeErr(t, bad), Malformed(PartContainer, MalformedTrailingBytes, len(raw), extra, 0))
	}
}

func TestVS8_013_Ordering(t *testing.T) {
	g2 := g2Container()
	rev := func(n [][]byte) [][]byte {
		o := append([][]byte(nil), n...)
		for i, j := 0, len(o)-1; i < j; i, j = i+1, j-1 {
			o[i], o[j] = o[j], o[i]
		}
		return o
	}
	c := *g2
	c.Nodes = rev(g2.Nodes)
	wantState(t, mustDecodeErr(t, EncodeUnvalidated(&c)), Malformed(PartNodes, MalformedNodesNotAscending, 1, 0, 0))
	c = *g2
	c.Nodes = [][]byte{g2.Nodes[0], g2.Nodes[0]}
	wantState(t, mustDecodeErr(t, EncodeUnvalidated(&c)), Malformed(PartNodes, MalformedNodesDuplicate, 1, 0, 0))
	c = *g2
	c.Nodes = [][]byte{g2.Nodes[0], g2.Nodes[1], g2.Nodes[1]}
	wantState(t, mustDecodeErr(t, EncodeUnvalidated(&c)), Malformed(PartNodes, MalformedNodesDuplicate, 2, 0, 0))
	c = *g2
	c.Codes = []Code{g2.Codes[1], g2.Codes[0]} // address 0x01.. before 0x00..02
	wantState(t, mustDecodeErr(t, EncodeUnvalidated(&c)), Malformed(PartCodes, MalformedCodesNotAscending, 1, 0, 0))
	c = *g2
	c.Codes = []Code{g2.Codes[0], g2.Codes[0]}
	wantState(t, mustDecodeErr(t, EncodeUnvalidated(&c)), Malformed(PartCodes, MalformedCodesDuplicate, 1, 0, 0))
	// Encode refuses the same constructions with the same states
	for _, bad := range []*Container{{Chain: 1, Nodes: rev(g2.Nodes), Settle: Part{Tag: TagCaptured}, Attest: g2.Attest}} {
		_, err := Encode(bad, DefaultLimits())
		wantState(t, err, Malformed(PartNodes, MalformedNodesNotAscending, 1, 0, 0))
	}
}

func TestVS8_014_TagsLinksStatedStrings(t *testing.T) {
	g2 := g2Container()
	r := record(g2)
	raw := r.b
	set := func(off int, v byte) []byte { b := append([]byte(nil), raw...); b[off] = v; return b }
	wantState(t, mustDecodeErr(t, set(r.marks["settleTag"], 3)), Malformed(PartSettle, MalformedUnknownPartTag, r.marks["settleTag"]+1, 0, 0))
	wantState(t, mustDecodeErr(t, set(r.marks["attestTag"], 0)), Malformed(PartAttest, MalformedUnknownPartTag, r.marks["attestTag"]+1, 0, 0))
	wantState(t, mustDecodeErr(t, set(r.marks["link"], 3)), Malformed(PartAttest, MalformedUnknownLink, r.marks["link"]+1, 0, 0))

	g1 := g1Container()
	mod := func(f func(s *Stated)) *Container {
		c := g1Container()
		f(c.Settle.Stated)
		return c
	}
	_ = g1
	enc := func(c *Container) []byte { return EncodeUnvalidated(c) }
	// the offset after the offending STR is derived from the recorder of the modified container
	offAfterStr := func(c *Container, which string) int {
		rr := record(c)
		base := rr.marks[PartSettle+"Tag"] + 1
		n := len(c.Settle.Stated.State)
		if which == "state" {
			return base + 4 + n
		}
		return base + 4 + n + 4 + len(c.Settle.Stated.Reason)
	}
	c := mod(func(s *Stated) { s.State = "contract_identity_verified" })
	wantState(t, mustDecodeErr(t, enc(c)), Malformed(PartSettle, MalformedBadStatedState, offAfterStr(c, "state"), 0, 0))
	c = mod(func(s *Stated) { s.Reason = "Upper_Case" })
	wantState(t, mustDecodeErr(t, enc(c)), Malformed(PartSettle, MalformedBadStatedReason, offAfterStr(c, "reason"), 0, 0))
	c = mod(func(s *Stated) { s.Reason = "" })
	wantState(t, mustDecodeErr(t, enc(c)), Malformed(PartSettle, MalformedBadStatedReason, offAfterStr(c, "reason"), 0, 0))
	c = mod(func(s *Stated) { s.Reason = strings.Repeat("a", 65) })
	wantState(t, mustDecodeErr(t, enc(c)), Malformed(PartSettle, MalformedBadStatedReason, offAfterStr(c, "reason"), 0, 0))
	// non-ASCII and NUL in a STR: the kind, a Stated string
	for _, bad := range []string{"caf\xc3\xa9", "nul\x00byte"} {
		c = mod(func(s *Stated) { s.Failures[0].Host = bad })
		rr := record(c)
		// host is the first string after the failures count
		hostEnd := rr.marks[PartSettle+"Tag"] + 1 + 4 + len(StatedState) + 4 + len(c.Settle.Stated.Reason) + 8 + 32 + 4 + 4 + len(bad)
		wantState(t, mustDecodeErr(t, enc(c)), Malformed(PartSettle, MalformedStringNotAscii, hostEnd, 0, 0))
	}
	kindBad := append(append(append([]byte(Magic), u32b(4)...), "k\x00nd"...), make([]byte, 40)...)
	wantState(t, mustDecodeErr(t, kindBad), Malformed(PartKind, MalformedStringNotAscii, 4+4+4, 0, 0))
}

// ---- caps: N passes, N+1 fails with evidence_too_large{part,count,limit} ----

// minimal is a valid container with captured parts, link 0, and nothing optional.
func minimal() *Container {
	return &Container{Chain: chain0, Leg: leg0, Settle: Part{Tag: TagCaptured},
		Attest: Part{Tag: TagCaptured, Attest: &AttestProof{Link: LinkSameBlock, HeaderV: []byte{1}, HeaderVParent: []byte{2}, TxLeaf: []byte{3}, ReceiptLeaf: []byte{4}}}}
}

func sortedNodes(n int, size int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		b := make([]byte, size)
		binary.BigEndian.PutUint32(b, uint32(i)+1)
		out[i] = b
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := crypto.Keccak256Hash(out[i]), crypto.Keccak256Hash(out[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	return out
}

func ascCodes(n, size int) []Code {
	out := make([]Code, n)
	for i := range out {
		out[i].Address[18], out[i].Address[19] = byte(i>>8), byte(i)
		out[i].Address[0] = 1
		out[i].Runtime = make([]byte, size)
	}
	return out
}

type capCase struct {
	name  string
	part  string
	limit int
	build func(n int) *Container
	count func(n int) uint64 // the count the refusal reports for n (default n)
}

func TestCapsAreExactBoundaries(t *testing.T) {
	lim := DefaultLimits()
	cases := []capCase{
		{"codes", PartCodes, lim.MaxCodes, func(n int) *Container { c := minimal(); c.Codes = ascCodes(n, 1); return c }, nil},
		{"code bytes", PartCodes, lim.MaxCodeBytes, func(n int) *Container { c := minimal(); c.Codes = ascCodes(1, n); return c }, nil},
		{"nodes", PartNodes, lim.MaxNodes, func(n int) *Container { c := minimal(); c.Nodes = sortedNodes(n, 4); return c }, nil},
		{"node bytes", PartNodes, lim.MaxNodeBytes, func(n int) *Container { c := minimal(); c.Nodes = sortedNodes(1, n); return c }, nil},
		{"headerV bytes", PartAttest, lim.MaxHeaderBytes, func(n int) *Container { c := minimal(); c.Attest.Attest.HeaderV = make([]byte, n); return c }, nil},
		{"headerVParent bytes", PartAttest, lim.MaxHeaderBytes, func(n int) *Container { c := minimal(); c.Attest.Attest.HeaderVParent = make([]byte, n); return c }, nil},
		{"hop headers", PartHopHeaders, lim.MaxAttestHops, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.Link = LinkHops
			c.Attest.Attest.HopHeaders = make([][]byte, n)
			return c
		}, nil},
		{"hop header bytes", PartHopHeaders, lim.MaxHeaderBytes, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.Link = LinkHops
			c.Attest.Attest.HopHeaders = [][]byte{make([]byte, n)}
			return c
		}, nil},
		{"spine headers", PartSpine, lim.MaxAttestSpine, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.Link = LinkSpine
			c.Attest.Attest.Spine = make([][]byte, n)
			return c
		}, nil},
		{"spine header bytes", PartSpine, lim.MaxHeaderBytes, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.Link = LinkSpine
			c.Attest.Attest.Spine = [][]byte{make([]byte, n)}
			return c
		}, nil},
		{"txLeaf bytes", PartAttest, lim.MaxLeafBytes, func(n int) *Container { c := minimal(); c.Attest.Attest.TxLeaf = make([]byte, n); return c }, nil},
		{"receiptLeaf bytes", PartAttest, lim.MaxLeafBytes, func(n int) *Container { c := minimal(); c.Attest.Attest.ReceiptLeaf = make([]byte, n); return c }, nil},
		{"block txs", PartBlockTxs, lim.MaxBlockTxs, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.BlockTxs = make([][]byte, n)
			return c
		}, nil},
		{"one block tx bytes", PartBlockTxs, lim.MaxBlockTxsBytes, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.BlockTxs = [][]byte{make([]byte, n)}
			return c
		}, nil},
		{"block txs total bytes", PartBlockTxs, lim.MaxBlockTxsBytes, func(n int) *Container {
			c := minimal()
			c.Attest.Attest.BlockTxs = [][]byte{make([]byte, n-1), make([]byte, 1)}
			return c
		}, nil},
		{"failures", PartFailures, lim.MaxFailures, func(n int) *Container {
			c := g1Container()
			c.Settle.Stated.Failures = make([]ProviderFailure, n)
			return c
		}, nil},
		{"stated host bytes", PartFailures, lim.MaxText, func(n int) *Container {
			c := g1Container()
			c.Settle.Stated.Failures = []ProviderFailure{{Host: strings.Repeat("h", n)}}
			return c
		}, nil},
		{"stated error bytes", PartFailures, lim.MaxText, func(n int) *Container {
			c := g1Container()
			c.Attest.Stated.Failures = []ProviderFailure{{Error: strings.Repeat("e", n)}}
			return c
		}, nil},
		{"stated detail bytes", PartFailures, lim.MaxText, func(n int) *Container {
			c := g1Container()
			c.Attest.Stated.Detail = strings.Repeat("d", n)
			return c
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, n := range []int{tc.limit, tc.limit + 1} {
				c := tc.build(n)
				raw := EncodeUnvalidated(c)
				got, err := Decode(raw, lim)
				if n == tc.limit {
					if err != nil {
						t.Fatalf("N=%d must pass: %v", n, err)
					}
					// and the checked encoder agrees: the same container encodes, and decoding it again gives the same bytes
					if enc, err := Encode(got, lim); err != nil || !bytes.Equal(enc, raw) {
						t.Fatalf("N=%d: re-encode: %v", n, err)
					}
					continue
				}
				wantState(t, err, TooLarge(tc.part, uint64(n), uint64(tc.limit)))
				// Encode refuses the same container with the same state
				_, err = Encode(c, lim)
				wantState(t, err, TooLarge(tc.part, uint64(n), uint64(tc.limit)))
			}
		})
	}
}

func TestKindCapBoundary(t *testing.T) {
	mk := func(n int) []byte {
		k := strings.Repeat("k", n)
		return append(append(append([]byte(Magic), u32b(n)...), k...), make([]byte, 64)...)
	}
	lim := DefaultLimits()
	wantState(t, mustDecodeErr(t, mk(lim.MaxKindBytes)), Unrecognised(strings.Repeat("k", lim.MaxKindBytes)))
	wantState(t, mustDecodeErr(t, mk(lim.MaxKindBytes+1)), TooLarge(PartKind, uint64(lim.MaxKindBytes+1), uint64(lim.MaxKindBytes)))
}

func TestContainerSizeCapIsExact(t *testing.T) {
	lim := DefaultLimits()
	// 31 full nodes plus one node sized so that the container is exactly MaxContainerBytes
	full := sortedNodes(31, lim.MaxNodeBytes)
	for i := range full { // distinct, not-all-zero contents
		full[i][len(full[i])-1] = byte(i + 1)
	}
	build := func(size int) *Container {
		c := minimal()
		last := make([]byte, size)
		binary.BigEndian.PutUint32(last, 0xfeedface)
		nodes := append(append([][]byte(nil), full...), last)
		sort.Slice(nodes, func(i, j int) bool {
			a, b := crypto.Keccak256Hash(nodes[i]), crypto.Keccak256Hash(nodes[j])
			return bytes.Compare(a[:], b[:]) < 0
		})
		c.Nodes = nodes
		return c
	}
	probe := EncodeUnvalidated(build(8))
	size := 8 + lim.MaxContainerBytes - len(probe)
	if size <= 8 || size > lim.MaxNodeBytes {
		t.Fatalf("test construction: tuned node size %d", size)
	}
	c := build(size)
	raw := EncodeUnvalidated(c)
	if len(raw) != lim.MaxContainerBytes {
		t.Fatalf("constructed %d bytes, want %d", len(raw), lim.MaxContainerBytes)
	}
	got, err := Decode(raw, lim)
	if err != nil {
		t.Fatalf("a container of exactly %d bytes must decode: %v", lim.MaxContainerBytes, err)
	}
	if enc, err := Encode(got, lim); err != nil || !bytes.Equal(enc, raw) {
		t.Fatalf("re-encode at the cap: %v", err)
	}
	over := EncodeUnvalidated(build(size + 1))
	if len(over) != lim.MaxContainerBytes+1 {
		t.Fatalf("constructed %d bytes", len(over))
	}
	wantState(t, mustDecodeErr(t, over), TooLarge(PartContainer, uint64(lim.MaxContainerBytes+1), uint64(lim.MaxContainerBytes)))
	_, err = Encode(build(size+1), lim)
	wantState(t, err, TooLarge(PartContainer, uint64(lim.MaxContainerBytes+1), uint64(lim.MaxContainerBytes)))
}

// VS8-017: no non-canonical encoding is accepted. A length prefix longer than the content and a count prefix with extra bytes behind it
// are evidence_malformed; the width of the integers is fixed so there is no other degree of freedom.
func TestVS8_017_NonCanonicalEncodings(t *testing.T) {
	g2 := g2Container()
	g2.Nodes = g2.Nodes[:1] // a single node: the length arithmetic below cannot trip the node ordering rule first
	r := record(g2)
	raw := r.b
	// count of nodes lowered by one: one whole node is left over
	lower := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(lower[r.marks["nodesCount"]:], 0)
	last := g2.Nodes[len(g2.Nodes)-1]
	st := mustDecodeErr(t, lower)
	wantState(t, st, Malformed(PartContainer, MalformedTrailingBytes, len(raw)-4-len(last), 4+len(last), 0))
	// count of nodes raised by one: the next node is missing
	higher := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(higher[r.marks["nodesCount"]:], uint32(len(g2.Nodes)+1))
	wantState(t, mustDecodeErr(t, higher), Malformed(PartNodes, MalformedTruncated, len(raw), 0, 4))
	// the last node's length prefix claims more than remains
	longer := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(longer[len(raw)-len(last)-4:], uint32(len(last)+1))
	wantState(t, mustDecodeErr(t, longer), Malformed(PartNodes, MalformedTruncated, len(raw)-len(last), len(last), len(last)+1))
	// the last node's length prefix claims less than it holds: the remainder is not a valid next element
	shorter := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(shorter[len(raw)-len(last)-4:], uint32(len(last)-1))
	wantState(t, mustDecodeErr(t, shorter), Malformed(PartContainer, MalformedTrailingBytes, len(raw)-1, 1, 0))
}

// ---- properties ----

func randBytes(r *rand.Rand, max int) []byte {
	b := make([]byte, r.Intn(max+1))
	r.Read(b)
	return b
}

func randomContainer(r *rand.Rand) *Container {
	c := &Container{Chain: r.Uint64(), Leg: BlockRef{Number: r.Uint64()}}
	r.Read(c.Leg.Hash[:])
	nc := r.Intn(5)
	c.Codes = ascCodes(nc, 0)
	for i := range c.Codes {
		c.Codes[i].Address[0] = byte(i*40 + r.Intn(30))
		c.Codes[i].Runtime = randBytes(r, 40)
	}
	rr := func(n int) string { return strings.Repeat("a", 1+r.Intn(n)) }
	stated := func() Part {
		s := &Stated{State: StatedState, Reason: rr(60), JudgedBlock: r.Uint64(), Detail: strings.Repeat("d", r.Intn(30))}
		r.Read(s.JudgedHash[:])
		for i := r.Intn(4); i > 0; i-- {
			s.Failures = append(s.Failures, ProviderFailure{Host: rr(20), Error: strings.Repeat("e", r.Intn(30))})
		}
		return Part{Tag: TagStated, Stated: s}
	}
	if r.Intn(3) == 0 {
		c.Settle = stated()
	} else {
		c.Settle = Part{Tag: TagCaptured}
	}
	if r.Intn(3) == 0 {
		c.Attest = stated()
	} else {
		a := &AttestProof{Link: uint8(r.Intn(3)), HeaderV: randBytes(r, 50), HeaderVParent: randBytes(r, 50), TxIndex: r.Uint32(), TxLeaf: randBytes(r, 60), ReceiptLeaf: randBytes(r, 60)}
		list := func() (out [][]byte) {
			for i := r.Intn(5); i > 0; i-- {
				out = append(out, randBytes(r, 30))
			}
			return
		}
		switch a.Link {
		case LinkHops:
			a.HopHeaders = list()
		case LinkSpine:
			a.Spine = list()
		}
		a.BlockTxs = list()
		c.Attest = Part{Tag: TagCaptured, Attest: a}
	}
	var nodes [][]byte
	for i := r.Intn(8); i > 0; i-- {
		nodes = append(nodes, randBytes(r, 40))
	}
	c.Nodes = sortedUnique(nodes)
	return c
}

func sortedUnique(n [][]byte) [][]byte {
	seen := map[[32]byte]bool{}
	var out [][]byte
	for _, x := range n {
		h := crypto.Keccak256Hash(x)
		if !seen[h] {
			seen[h] = true
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := crypto.Keccak256Hash(out[i]), crypto.Keccak256Hash(out[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	return out
}

func TestRoundTripRandomContainers(t *testing.T) {
	r := rand.New(rand.NewSource(8))
	for i := 0; i < 400; i++ {
		c := randomContainer(r)
		raw, err := Encode(c, DefaultLimits())
		if err != nil {
			t.Fatalf("case %d: encode: %v", i, err)
		}
		got, err := Decode(raw, DefaultLimits())
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !containersEqual(got, c) {
			t.Fatalf("case %d: decode(encode(c)) != c", i)
		}
		again, err := Encode(got, DefaultLimits())
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("case %d: encode(decode(x)) != x (%v)", i, err)
		}
	}
}

// For every accepted byte string x, encode(decode(x)) == x; every refused one is a registered evidence_ state. The inputs are every single
// byte of the goldens changed in three ways, and random garbage.
func TestMutationsAreAcceptedCanonicallyOrRefusedByName(t *testing.T) {
	check := func(raw []byte) {
		c, err := Decode(raw, DefaultLimits())
		if err != nil {
			st, ok := AsState(err)
			if !ok || !strings.HasPrefix(st.Code, Prefix+"evidence_") {
				t.Fatalf("refusal %v of %x is not an evidence_ state", err, raw)
			}
			if verr := Validate(st); verr != nil {
				t.Fatalf("refusal %v of %x is not a registry state: %v", err, raw, verr)
			}
			return
		}
		again, err := Encode(c, DefaultLimits())
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("accepted %x but encode(decode(x)) = %x (%v)", raw, again, err)
		}
	}
	r := rand.New(rand.NewSource(17))
	for _, c := range []*Container{g1Container(), g2Container(), richContainer(), statedAttestContainer()} {
		raw, _ := Encode(c, DefaultLimits())
		for i := range raw {
			for _, f := range []func(byte) byte{func(b byte) byte { return b ^ 0x01 }, func(b byte) byte { return ^b }, func(byte) byte { return 0 }} {
				m := append([]byte(nil), raw...)
				m[i] = f(m[i])
				check(m)
			}
		}
		for i := 0; i < 300; i++ {
			m := append([]byte(nil), raw...)
			for k := r.Intn(4) + 1; k > 0; k-- {
				m[r.Intn(len(m))] = byte(r.Intn(256))
			}
			if r.Intn(4) == 0 {
				m = m[:r.Intn(len(m))]
			}
			check(m)
		}
	}
	for i := 0; i < 500; i++ {
		check(randBytes(r, 300))
	}
}

// A container that EncodeUnvalidated writes and Encode refuses is refused by Decode too: the unvalidated writer is not a way to put a
// container on the wire that a verifier would accept.
func TestEncodeUnvalidatedIsOnlyForVectors(t *testing.T) {
	lim := DefaultLimits()
	bad := []*Container{}
	c := g2Container()
	asc := sortedUnique([][]byte{[]byte("a"), []byte("b")})
	c.Nodes = [][]byte{asc[1], asc[0]} // descending by keccak256
	bad = append(bad, c)
	d := g2Container()
	d.Attest.Attest.HeaderV = make([]byte, lim.MaxHeaderBytes+1)
	bad = append(bad, d)
	e := g1Container()
	e.Settle.Stated.State = "verified"
	bad = append(bad, e)
	f := g2Container()
	f.Settle.Tag = 3
	bad = append(bad, f)
	g := g2Container()
	g.Attest.Attest.Link = 5
	bad = append(bad, g)
	for i, x := range bad {
		if _, err := Encode(x, lim); err == nil {
			t.Fatalf("case %d: Encode accepted an invalid container", i)
		}
		if _, err := Decode(EncodeUnvalidated(x), lim); err == nil {
			t.Fatalf("case %d: Decode accepted what Encode refuses", i)
		}
	}
}

// Encode of a link that disagrees with the hop and spine lists, and of a Part whose body is in the wrong place, is refused.
func TestEncodeRefusesInconsistentParts(t *testing.T) {
	lim := DefaultLimits()
	c := g2Container()
	c.Attest.Attest.Spine = [][]byte{[]byte("x")} // link 1 carries no spine
	if _, err := Encode(c, lim); err == nil {
		t.Fatal("link 1 with a spine accepted")
	}
	c = g2Container()
	c.Attest.Attest.Link = LinkSameBlock // link 0 carries no hop headers
	if _, err := Encode(c, lim); err == nil {
		t.Fatal("link 0 with hop headers accepted")
	}
	c = g2Container()
	c.Settle.Attest = c.Attest.Attest // a captured settle part has an empty body
	if _, err := Encode(c, lim); err == nil {
		t.Fatal("captured settle with a body accepted")
	}
	c = g2Container()
	c.Attest.Attest = nil
	if _, err := Encode(c, lim); err == nil {
		t.Fatal("captured attest without a body accepted")
	}
	if _, err := Encode(nil, lim); err == nil {
		t.Fatal("nil container accepted")
	}
}
