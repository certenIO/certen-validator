package intentcert

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// rawVoteLeaf is the leaf govRoot v4 commits for one vote, written out byte by byte from the layout of the design (docs/proof/
// G1_CROSS_PARTITION.md D4 / govroot_v4.go EncodeVoteV4) without calling any of the production encoder: sha256("certen:g1:v4:vote:" ‖
// fields), strings and bytes length-prefixed by a 4-byte big-endian length, integers 8 bytes big-endian, optional members behind a 1-byte
// flag, URLs in lower case without a trailing slash, hex members as the bytes they encode.
func rawVoteLeaf(v proofv2.Vote) [32]byte {
	var b []byte
	str := func(s string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	canonURL := func(s string) { str(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/")) }
	hexb := func(s string) {
		raw, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(raw)))
		b = append(b, raw...)
	}
	flag := func(f bool) {
		if f {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	idx := func(p proofv2.IndexProof) {
		b = binary.BigEndian.AppendUint64(b, p.Position)
		hexb(p.Entry)
		hexb(p.Receipt)
	}
	arr := func(a proofv2.Arrival) {
		flag(a.Before != nil)
		if a.Before != nil {
			idx(*a.Before)
		}
		idx(a.At)
	}
	hops := func(hs []proofv2.VoteHop) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(hs)))
		for _, h := range hs {
			canonURL(h.Page)
			hexb(h.Message)
			hexb(h.Signature)
			b = binary.BigEndian.AppendUint64(b, h.Block)
			hexb(h.Receipt)
			flag(h.Arrival != nil)
			if h.Arrival != nil {
				arr(*h.Arrival)
			}
		}
	}
	canonURL(v.Authority)
	canonURL(v.Origin)
	str(v.Vote)
	canonURL(v.Cause)
	str(v.Transport.Kind)
	canonURL(v.Transport.Source)
	canonURL(v.Transport.Destination)
	b = binary.BigEndian.AppendUint64(b, v.Transport.Number)
	hexb(v.Message)
	hexb(v.Receipt)
	hops(v.Hops)
	hops(v.Counted)
	flag(v.Produced != nil)
	if p := v.Produced; p != nil {
		canonURL(p.Account)
		str(p.Chain)
		hexb(p.Message)
		hexb(p.Receipt)
		arr(p.Arrival)
	}
	return sha256.Sum256(append([]byte("certen:g1:v4:vote:"), b...))
}

// rawVotesRoot is the merkle root over the leaves sorted by (authority, origin, message) in canonical spelling.
func rawVotesRoot(votes []proofv2.Vote) [32]byte {
	type l struct {
		key  string
		leaf [32]byte
	}
	var ls []l
	for _, v := range votes {
		c := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/") }
		ls = append(ls, l{c(v.Authority) + "\x00" + c(v.Origin) + "\x00" + strings.ToLower(v.Message), rawVoteLeaf(v)})
	}
	sort.SliceStable(ls, func(i, j int) bool { return ls[i].key < ls[j].key })
	var h merkle.Hasher
	for _, x := range ls {
		h.AddHash2(x.leaf)
	}
	var out [32]byte
	copy(out[:], h.MerkleHash())
	return out
}

func twoHopVote() proofv2.Vote {
	v := x21Vote()
	second := v.Hops[0]
	second.Page, second.Message, second.Block = xDelPage, hx32(30), second.Block-1
	v.Hops = append(v.Hops, second)
	return v
}

// The votes root recomputed from the explicit byte layout - no production encoder, no JSON - over votes with every member populated (a
// hop and a counted signature with arrivals and a production), and over a bare vote whose optional members are all absent.
func TestVotesRootV4_IndependentRecomputation(t *testing.T) {
	full := twoHopVote()
	bare := proofv2.Vote{Authority: xHdrBook, Origin: xHdrPage, Vote: "accept", Message: hx32(40), Receipt: "01",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}}
	for name, votes := range map[string][]proofv2.Vote{"full": {full}, "bare": {bare}, "both": {full, bare}, "both, reversed": {bare, full}} {
		got, err := VotesRootV4(votes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := rawVotesRoot(votes); got != want {
			t.Errorf("%s: production %x, independent %x", name, got, want)
		}
	}
}

// Every member of a vote is committed, in a fixed order: a change to any of them - or swapping two hops, or moving a signature between
// hops and counted - changes the root.
func TestVotesRootV4_EveryMemberAndTheirOrderChangeTheRoot(t *testing.T) {
	base, err := VotesRootV4([]proofv2.Vote{twoHopVote()})
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(v *proofv2.Vote){
		"authority":             func(v *proofv2.Vote) { v.Authority = xHdrBook },
		"origin":                func(v *proofv2.Vote) { v.Origin = xBook1 },
		"vote":                  func(v *proofv2.Vote) { v.Vote = "reject" },
		"cause":                 func(v *proofv2.Vote) { v.Cause += "x" },
		"transport kind":        func(v *proofv2.Vote) { v.Transport.Kind = proofv2.TransportInline },
		"transport source":      func(v *proofv2.Vote) { v.Transport.Source = partBVN3 },
		"transport destination": func(v *proofv2.Vote) { v.Transport.Destination = partBVN3 },
		"transport number":      func(v *proofv2.Vote) { v.Transport.Number++ },
		"message":               func(v *proofv2.Vote) { v.Message = hx32(99) },
		"receipt":               func(v *proofv2.Vote) { v.Receipt = "0a0c" },
		"swap two hops":         func(v *proofv2.Vote) { v.Hops[0], v.Hops[1] = v.Hops[1], v.Hops[0] },
		"drop a hop":            func(v *proofv2.Vote) { v.Hops = v.Hops[:1] },
		"hop page":              func(v *proofv2.Vote) { v.Hops[0].Page = xBook1 },
		"hop message":           func(v *proofv2.Vote) { v.Hops[0].Message = hx32(98) },
		"hop signature":         func(v *proofv2.Vote) { v.Hops[0].Signature = "0cff" },
		"hop block":             func(v *proofv2.Vote) { v.Hops[0].Block++ },
		"hop receipt":           func(v *proofv2.Vote) { v.Hops[0].Receipt = "0dff" },
		"hop arrival dropped":   func(v *proofv2.Vote) { v.Hops[0].Arrival = nil },
		"hop arrival before dropped": func(v *proofv2.Vote) {
			a := *v.Hops[0].Arrival
			a.Before = nil
			v.Hops[0].Arrival = &a
		},
		"hop arrival before position": func(v *proofv2.Vote) {
			a, b := *v.Hops[0].Arrival, *v.Hops[0].Arrival.Before
			b.Position++
			a.Before = &b
			v.Hops[0].Arrival = &a
		},
		"hop arrival at entry": func(v *proofv2.Vote) {
			a := *v.Hops[0].Arrival
			a.At.Entry = hx32(97)
			v.Hops[0].Arrival = &a
		},
		"hop arrival at receipt": func(v *proofv2.Vote) {
			a := *v.Hops[0].Arrival
			a.At.Receipt = "ff"
			v.Hops[0].Arrival = &a
		},
		"counted dropped":       func(v *proofv2.Vote) { v.Counted = nil },
		"counted block":         func(v *proofv2.Vote) { v.Counted[0].Block++ },
		"counted moved to hops": func(v *proofv2.Vote) { v.Hops, v.Counted = append(v.Hops, v.Counted...), nil },
		"hops moved to counted": func(v *proofv2.Vote) { v.Counted, v.Hops = append(v.Counted, v.Hops[1]), v.Hops[:1] },
		"produced dropped":      func(v *proofv2.Vote) { v.Produced = nil },
		"produced account":      func(v *proofv2.Vote) { p := *v.Produced; p.Account = xBook; v.Produced = &p },
		"produced chain":        func(v *proofv2.Vote) { p := *v.Produced; p.Chain = "main"; v.Produced = &p },
		"produced message":      func(v *proofv2.Vote) { p := *v.Produced; p.Message = hx32(96); v.Produced = &p },
		"produced receipt":      func(v *proofv2.Vote) { p := *v.Produced; p.Receipt = "10ff"; v.Produced = &p },
		"produced arrival":      func(v *proofv2.Vote) { p := *v.Produced; p.Arrival.At.Position++; v.Produced = &p },
		"produced arrival before": func(v *proofv2.Vote) {
			p := *v.Produced
			b := p.Arrival.At
			p.Arrival.Before = &b
			v.Produced = &p
		},
	} {
		v := twoHopVote()
		// Deep copies of the members the mutators edit through pointers.
		a := *v.Hops[0].Arrival
		bf := *a.Before
		a.Before = &bf
		v.Hops[0].Arrival = &a
		v.Hops = append([]proofv2.VoteHop(nil), v.Hops...)
		v.Counted = append([]proofv2.VoteHop(nil), v.Counted...)
		pr := *v.Produced
		v.Produced = &pr
		mut(&v)
		got, err := VotesRootV4([]proofv2.Vote{v})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got == base {
			t.Errorf("%s: the root did not change", name)
		}
	}
}

// Hex members are committed as the bytes they encode and URLs in canonical spelling: the spelling of the same evidence does not change
// the root; a member that is not hex is refused, never committed as something else.
func TestVotesRootV4_SpellingIsNotCommittedButBytesAre(t *testing.T) {
	v := twoHopVote()
	base, err := VotesRootV4([]proofv2.Vote{v})
	if err != nil {
		t.Fatal(err)
	}
	w := twoHopVote()
	w.Authority, w.Origin = strings.ToUpper(w.Authority), w.Origin+"/"
	w.Receipt = strings.ToUpper(w.Receipt)
	w.Message = strings.ToUpper(w.Message)
	w.Hops[0].Page = strings.ToUpper(w.Hops[0].Page)
	if got, err := VotesRootV4([]proofv2.Vote{w}); err != nil || got != base {
		t.Fatalf("the spelling of the same evidence changed the root: %x vs %x (%v)", got, base, err)
	}
	for name, mut := range map[string]func(v *proofv2.Vote){
		"message":     func(v *proofv2.Vote) { v.Message = "zz" },
		"receipt":     func(v *proofv2.Vote) { v.Receipt = "0g" },
		"odd length":  func(v *proofv2.Vote) { v.Hops[0].Signature = "abc" },
		"arrival":     func(v *proofv2.Vote) { v.Hops[0].Arrival.At.Entry = "xyz" },
		"production":  func(v *proofv2.Vote) { v.Produced.Receipt = "nothex" },
		"counted hop": func(v *proofv2.Vote) { v.Counted[0].Receipt = "q" },
	} {
		v := twoHopVote()
		a := *v.Hops[0].Arrival
		v.Hops[0].Arrival = &a
		p := *v.Produced
		v.Produced = &p
		mut(&v)
		if _, err := VotesRootV4([]proofv2.Vote{v}); err == nil || !strings.Contains(err.Error(), "not hex") {
			t.Errorf("%s: a member that is not hex gave %v", name, err)
		}
	}
}

// The same facts in any order are one root even when two votes tie on (authority, origin, message): the leaf breaks the tie.
func TestVotesRootV4_TiesAreBrokenByTheLeaf(t *testing.T) {
	a, b := twoHopVote(), twoHopVote()
	b.Transport.Number++
	r1, err1 := VotesRootV4([]proofv2.Vote{a, b})
	r2, err2 := VotesRootV4([]proofv2.Vote{b, a})
	if err1 != nil || err2 != nil || r1 != r2 {
		t.Fatalf("a tie made the root depend on order: %x %v / %x %v", r1, err1, r2, err2)
	}
}

// The commitment is not a serialisation of the Go structs: the file that computes it does not import encoding/json at all.
func TestVoteEncodingV4DoesNotUseJSON(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "govroot_v4.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		if strings.Contains(imp.Path.Value, "json") || strings.Contains(imp.Path.Value, "gob") || strings.Contains(imp.Path.Value, "cbor") {
			t.Fatalf("govroot_v4.go imports %s: the vote encoding must be an explicit field layout", imp.Path.Value)
		}
	}
}
