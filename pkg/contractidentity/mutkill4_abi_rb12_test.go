// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB12 EPSILON stage 2, part A: literal-expectation tests for the surviving mutants of abi.go. Calldata is built by a small encoder written
// here from the Solidity ABI specification (head/tail, offsets relative to the start of the enclosing sequence), not by the decoder under test.

type mk4Val struct {
	kind byte // 'w' word, 'y' bytes or string, 'a' dynamic array, 't' tuple
	w    [32]byte
	b    []byte
	xs   []mk4Val
}

func mk4U(n uint64) []byte {
	out := make([]byte, 32)
	binary.BigEndian.PutUint64(out[24:], n)
	return out
}

func mk4Word(b []byte) mk4Val {
	v := mk4Val{kind: 'w'}
	copy(v.w[:], b)
	return v
}

func mk4N(n uint64) mk4Val { return mk4Word(mk4U(n)) }

func mk4H(seed byte) mk4Val {
	b := bytes.Repeat([]byte{seed}, 32)
	return mk4Word(b)
}

func mk4A(seed byte) (mk4Val, common.Address) {
	var a common.Address
	for i := range a {
		a[i] = seed
	}
	b := make([]byte, 32)
	copy(b[12:], a[:])
	return mk4Word(b), a
}

func mk4Y(b []byte) mk4Val       { return mk4Val{kind: 'y', b: b} }
func mk4Arr(xs ...mk4Val) mk4Val { return mk4Val{kind: 'a', xs: xs} }
func mk4Tup(xs ...mk4Val) mk4Val { return mk4Val{kind: 't', xs: xs} }

func (v mk4Val) dyn() bool {
	switch v.kind {
	case 'y', 'a':
		return true
	case 't':
		for _, x := range v.xs {
			if x.dyn() {
				return true
			}
		}
	}
	return false
}

func (v mk4Val) enc() []byte {
	switch v.kind {
	case 'w':
		return v.w[:]
	case 'y':
		out := mk4U(uint64(len(v.b)))
		out = append(out, v.b...)
		if pad := (32 - len(v.b)%32) % 32; pad > 0 {
			out = append(out, make([]byte, pad)...)
		}
		return out
	case 'a':
		return append(mk4U(uint64(len(v.xs))), mk4Seq(v.xs)...)
	}
	return mk4Seq(v.xs)
}

func mk4Seq(xs []mk4Val) []byte {
	head := 0
	for _, x := range xs {
		if x.dyn() {
			head += 32
		} else {
			head += len(x.enc())
		}
	}
	var h, tl []byte
	for _, x := range xs {
		if x.dyn() {
			h = append(h, mk4U(uint64(head+len(tl)))...)
			tl = append(tl, x.enc()...)
		} else {
			h = append(h, x.enc()...)
		}
	}
	return append(h, tl...)
}

func mk4Call(sig string, xs ...mk4Val) []byte {
	sel := Selector4(sig)
	return append(sel[:], mk4Seq(xs)...)
}

func wantABIErr(t *testing.T, got *ABIError, kind ABIKind, field string, off int, gotN, limit uint64, detail string) {
	t.Helper()
	if got == nil {
		t.Fatalf("no refusal; want %s at %q", kind, field)
	}
	if got.Kind != kind || got.Field != field || got.Offset != off || got.Got != gotN || got.Limit != limit || got.Detail != detail {
		t.Fatalf("refusal\n got %+v\nwant {Kind:%s Field:%q Offset:%d Got:%d Limit:%d Detail:%q}", *got, kind, field, off, gotN, limit, detail)
	}
}

func TestMutKill4ABIErrorStrings(t *testing.T) {
	for _, c := range []struct {
		e    ABIError
		want string
	}{
		{ABIError{Kind: ABICap, Field: "f", Offset: 3, Got: 5, Limit: 4}, `abi cap at "f" (byte 3): 5 against 4`},
		{ABIError{Kind: ABILength, Field: "f", Offset: 3, Got: 7, Limit: 6, Detail: "d"}, `abi length at "f" (byte 3): 7 against 6: d`},
		{ABIError{Kind: ABITruncated, Field: "f", Offset: 1, Detail: "need"}, `abi truncated at "f" (byte 1): need`},
		{ABIError{Kind: ABIWord, Field: "g", Offset: 0}, `abi word at "g" (byte 0)`},
		{ABIError{Kind: ABIShape, Field: "g", Offset: 9, Got: 1, Limit: 2}, `abi shape at "g" (byte 9)`},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("Error() = %q, want %q", got, c.want)
		}
	}
}

func TestMutKill4ABISchemaSizes(t *testing.T) {
	st, dy := tU(8), tBytes()
	for _, c := range []struct {
		name string
		t    *abiT
		dyn  bool
		head int
	}{
		{"uint", st, false, 32},
		{"bytes", dy, true, 32},
		{"fixed static", tFix(st, 3), false, 96},
		{"fixed dynamic", tFix(dy, 2), true, 32},
		{"tuple static", tTup(fd("a", st), fd("b", tAddr())), false, 64},
		{"tuple static nested", tTup(fd("a", st), fd("b", tFix(st, 2))), false, 96},
		{"tuple dynamic", tTup(fd("a", st), fd("b", dy)), true, 32},
		{"tuple dynamic first", tTup(fd("a", dy), fd("b", st)), true, 32},
		{"array", tArr(st, 0), true, 32},
	} {
		if c.t.dynamic() != c.dyn || c.t.headSize() != c.head {
			t.Errorf("%s: dynamic %v head %d, want %v %d", c.name, c.t.dynamic(), c.t.headSize(), c.dyn, c.head)
		}
	}
}

func TestMutKill4ABIWordBounds(t *testing.T) {
	d := &abiDec{buf: make([]byte, 40)}
	for i := range d.buf {
		d.buf[i] = byte(i + 1)
	}
	w, err := d.word(0, "f")
	if err != nil || w[0] != 1 || w[31] != 32 {
		t.Fatalf("word(0): %v %v", w, err)
	}
	w, err = d.word(8, "f")
	if err != nil || w[0] != 9 || w[31] != 40 {
		t.Fatalf("word(8): %v %v", w, err)
	}
	_, err = d.word(9, "f")
	wantABIErr(t, err, ABITruncated, "f", 9, 0, 0, "need 32 bytes, 31 remain")
	_, err = d.word(100, "f")
	wantABIErr(t, err, ABITruncated, "f", 100, 0, 0, "need 32 bytes, 0 remain")
	if _, err = d.word(-1, "f"); err == nil || err.Kind != ABITruncated {
		t.Fatalf("word(-1): %v", err)
	}
}

func TestMutKill4ABILengthWord(t *testing.T) {
	buf := make([]byte, 64)
	buf[24] = 1 // 2^56: fits 64 bits
	d := &abiDec{buf: buf}
	n, err := d.length(0, "f")
	if err != nil || n != 1<<56 {
		t.Fatalf("length: %d %v", n, err)
	}
	buf[23] = 1 // 2^120: does not fit
	_, err = d.length(0, "f")
	wantABIErr(t, err, ABILength, "f", 0, ^uint64(0), 64, "length does not fit 64 bits")
	_, err = d.length(100, "f")
	wantABIErr(t, err, ABITruncated, "f", 100, 0, 0, "need 32 bytes, 0 remain")
}

func TestMutKill4ABIScalars(t *testing.T) {
	d := &abiDec{buf: make([]byte, 32)}
	if _, err := d.scalar(tU(8), 100, "f"); err == nil || err.Kind != ABITruncated {
		t.Fatalf("scalar beyond the buffer: %v", err)
	}
	set := func(idx int, v byte) *abiDec {
		b := make([]byte, 32)
		b[idx] = v
		return &abiDec{buf: b}
	}
	if _, err := set(30, 1).scalar(tU(8), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("uint8 with a high byte: %v", err)
	}
	if _, err := set(31, 255).scalar(tU(8), 0, "f"); err != nil {
		t.Fatalf("uint8 255: %v", err)
	}
	if _, err := set(0, 1).scalar(tU(256), 0, "f"); err != nil {
		t.Fatalf("uint256 with a high byte: %v", err)
	}
	if _, err := set(11, 1).scalar(tAddr(), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("address with a high byte: %v", err)
	}
	if _, err := set(31, 2).scalar(tBool(), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("bool 2: %v", err)
	}
	if _, err := set(0, 1).scalar(tBool(), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("bool with a high byte: %v", err)
	}
	if _, err := set(31, 4).scalar(tEnum(4), 0, "f"); err != nil {
		t.Fatalf("enum at its maximum: %v", err)
	}
	if _, err := set(31, 5).scalar(tEnum(4), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("enum above its maximum: %v", err)
	}
	if _, err := set(0, 1).scalar(tEnum(4), 0, "f"); err == nil || err.Kind != ABIWord {
		t.Fatalf("enum with a high byte: %v", err)
	}
}

func TestMutKill4ABIDecodeScalarEnd(t *testing.T) {
	d := &abiDec{buf: make([]byte, 128)}
	_, end, err := d.decode(tU(8), 64, "f", ABILimits{})
	if err != nil || end != 96 {
		t.Fatalf("end %d %v", end, err)
	}
}

func TestMutKill4ABIDecodeBytes(t *testing.T) {
	lim := ABILimits{}
	enc := func(prefix int, b []byte, trim int) *abiDec {
		buf := append(make([]byte, prefix), mk4Y(b).enc()...)
		return &abiDec{buf: buf[:len(buf)-trim]}
	}
	capped := func(n int) *abiT { return &abiT{k: 'y', cap: n} }
	// the exact value comes back with the offset after its padded encoding
	v, end, err := enc(32, []byte{1, 2, 3}, 0).decode(tBytes(), 32, "f", lim)
	if err != nil || !bytes.Equal(v.b, []byte{1, 2, 3}) || end != 32+32+32 {
		t.Fatalf("bytes: %x %d %v", v.b, end, err)
	}
	v, end, err = enc(0, make([]byte, 32), 0).decode(tBytes(), 0, "f", lim)
	if err != nil || len(v.b) != 32 || end != 64 {
		t.Fatalf("32 bytes: %d %d %v", len(v.b), end, err)
	}
	// caps: at the cap passes, one above refuses, with the numbers
	if _, _, err = enc(0, []byte{1, 2, 3, 4}, 0).decode(capped(4), 0, "f", lim); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	_, _, err = enc(0, []byte{1, 2, 3, 4, 5}, 0).decode(capped(4), 0, "f", lim)
	wantABIErr(t, err, ABICap, "f", 0, 5, 4, "")
	_, _, err = enc(0, []byte{1, 2}, 0).decode(capped(1), 0, "f", lim)
	wantABIErr(t, err, ABICap, "f", 0, 2, 1, "")
	// a length that reaches past the remaining input
	_, _, err = enc(0, make([]byte, 32), 1).decode(tBytes(), 0, "f", lim)
	wantABIErr(t, err, ABILength, "f", 0, 32, 31, "")
	_, _, err = enc(32, []byte{7}, 31).decode(tBytes(), 32, "f", lim)
	wantABIErr(t, err, ABILength, "f", 32, 1, 1, "")
	// padding must be zero; the refusal names the byte after the data
	bad := enc(32, []byte{1, 2, 3}, 0)
	bad.buf[32+32+5] = 9
	_, _, err = bad.decode(tBytes(), 32, "f", lim)
	wantABIErr(t, err, ABIPadding, "f", 32+32+3, 0, 0, "non-zero padding after 3 bytes")
}

func TestMutKill4ABIDecodeArrays(t *testing.T) {
	lim := ABILimits{}
	enc := func(prefix, claimed, actual, trim int) *abiDec {
		buf := append(make([]byte, prefix), mk4U(uint64(claimed))...)
		for i := 0; i < actual; i++ {
			buf = append(buf, mk4U(uint64(i+1))...)
		}
		return &abiDec{buf: buf[:len(buf)-trim]}
	}
	arr := func(cap int) *abiT { return tArr(tU(256), cap) }
	// exact fit
	v, end, err := enc(32, 3, 3, 0).decode(arr(0), 32, "f", lim)
	if err != nil || len(v.items) != 3 || end != 32+32+96 || v.items[2].u64() != 3 {
		t.Fatalf("exact fit: %+v %d %v", v, end, err)
	}
	// one element claimed beyond the input
	_, _, err = enc(32, 4, 3, 0).decode(arr(0), 32, "f", lim)
	wantABIErr(t, err, ABILength, "f", 32, 4, 3, "")
	_, _, err = enc(32, 5, 3, 0).decode(arr(0), 32, "f", lim)
	wantABIErr(t, err, ABILength, "f", 32, 5, 3, "")
	// the last element is one byte short
	_, _, err = enc(32, 3, 3, 1).decode(arr(0), 32, "f", lim)
	wantABIErr(t, err, ABILength, "f", 32, 3, 2, "")
	// caps
	if _, _, err = enc(0, 3, 3, 0).decode(arr(3), 0, "f", lim); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	_, _, err = enc(0, 4, 4, 0).decode(arr(3), 0, "f", lim)
	wantABIErr(t, err, ABICap, "f", 0, 4, 3, "")
	_, _, err = enc(0, 2, 2, 0).decode(arr(1), 0, "f", lim)
	wantABIErr(t, err, ABICap, "f", 0, 2, 1, "")
	// the count word itself
	_, _, err = (&abiDec{buf: make([]byte, 10)}).decode(arr(0), 0, "f", lim)
	wantABIErr(t, err, ABITruncated, "f", 0, 0, 0, "need 32 bytes, 10 remain")
	// a fixed array of words decodes in place
	d := &abiDec{buf: append(mk4U(7), mk4U(8)...)}
	v, end, err = d.decode(tFix(tU(256), 2), 0, "f", lim)
	if err != nil || len(v.items) != 2 || v.items[0].u64() != 7 || v.items[1].u64() != 8 || end != 64 {
		t.Fatalf("fixed: %+v %d %v", v, end, err)
	}
}

func TestMutKill4ABISequences(t *testing.T) {
	lim := ABILimits{}
	two := []*abiT{tU(8), tU(8)}
	// a head that does not fit: the numbers are relative to base
	d := &abiDec{buf: make([]byte, 32+63)}
	_, _, err := d.seq(two, []string{"a", "b"}, 32, lim)
	wantABIErr(t, err, ABITruncated, "a", 32, 0, 0, "head of 64 bytes, 63 remain")
	d = &abiDec{buf: make([]byte, 32+64)}
	if items, end, err := d.seq(two, []string{"a", "b"}, 32, lim); err != nil || len(items) != 2 || end != 96 {
		t.Fatalf("exact head: %v %d %v", items, end, err)
	}
	// empty names list
	if names0(nil) != "" || names0([]string{"x"}) != "x" || names0([]string{"x", "y"}) != "x" {
		t.Fatal("names0")
	}
	// an offset word that does not fit 64 bits is an impossible offset (and says so)
	bad := make([]byte, 64)
	bad[3] = 1
	_, err = decodeArgs(bad, []abiF{fd("x", tBytes())}, lim)
	wantABIErr(t, err, ABIOffset, "x", 0, ^uint64(0), 64, "length does not fit 64 bits")
	// an offset that points to the end of the input is within it: the refusal is the missing length word
	end32 := mk4U(32)
	_, err = decodeArgs(end32, []abiF{fd("x", tBytes())}, lim)
	wantABIErr(t, err, ABITruncated, "x", 32, 0, 0, "need 32 bytes, 0 remain")
	// an offset past the input
	buf := append(mk4U(100), make([]byte, 32)...)
	_, err = decodeArgs(buf, []abiF{fd("x", tBytes())}, lim)
	wantABIErr(t, err, ABIOffset, "x", 0, 0, 0, "offset 100 points to byte 64, the previous tail ends at 32")
	// an offset inside the input that is not where the previous tail ended
	buf = append(mk4U(64), make([]byte, 96)...)
	_, err = decodeArgs(buf, []abiF{fd("x", tBytes())}, lim)
	wantABIErr(t, err, ABIOffset, "x", 0, 0, 0, "offset 64 points to byte 64, the previous tail ends at 32")
	// trailing bytes
	_, err = decodeArgs(append(mk4U(1), 0), []abiF{fd("x", tU(8))}, lim)
	wantABIErr(t, err, ABITrailing, "", 32, 0, 0, "1 bytes after the encoding")
}

func TestMutKill4ABISelectors(t *testing.T) {
	want := [4]byte{0x0a, 0x0b, 0x0c, 0x0d}
	rest, err := splitSelector([]byte{0x0a, 0x0b, 0x0c, 0x0d}, want)
	if err != nil || len(rest) != 0 {
		t.Fatalf("exactly four bytes: %x %v", rest, err)
	}
	rest, err = splitSelector([]byte{0x0a, 0x0b, 0x0c, 0x0d, 9}, want)
	if err != nil || !bytes.Equal(rest, []byte{9}) {
		t.Fatalf("one argument byte: %x %v", rest, err)
	}
	_, err = splitSelector([]byte{0x0a, 0x0b, 0x0c}, want)
	wantABIErr(t, err, ABITruncated, "selector", 0, 0, 0, "3 bytes")
	_, err = splitSelector([]byte{1, 2, 3, 4, 5}, want)
	wantABIErr(t, err, ABISelector, "selector", 0, 0, 0, "got 0x01020304, want 0x0a0b0c0d")
	// legSelector: the first four bytes of the leg data, zero below four bytes
	if legSelector([]byte{1, 2, 3, 4}) != [4]byte{1, 2, 3, 4} || legSelector([]byte{1, 2, 3, 4, 5, 6}) != [4]byte{1, 2, 3, 4} ||
		legSelector([]byte{1, 2, 3}) != [4]byte{} || legSelector(nil) != [4]byte{} {
		t.Fatal("legSelector")
	}
}

type mk4Proof struct {
	v      mk4Val
	addrs  []common.Address
	voters []common.Address
	gov    common.Address
	target common.Address
}

func mk4ProofValue(nAddrs, nPowers int) mk4Proof {
	var p mk4Proof
	gov, govA := mk4A(0x31)
	tgt, tgtA := mk4A(0x32)
	p.gov, p.target = govA, tgtA
	var addrs, powers []mk4Val
	for i := 0; i < nAddrs; i++ {
		a, aa := mk4A(byte(0x40 + i))
		addrs = append(addrs, a)
		p.addrs = append(p.addrs, aa)
	}
	for i := 0; i < nPowers; i++ {
		powers = append(powers, mk4N(uint64(1000+i)))
	}
	p.v = mk4Tup(
		mk4H(0x11), mk4H(0x12), mk4Arr(mk4H(0x13), mk4H(0x14)), mk4H(0x15),
		mk4Tup(mk4Y([]byte("acc://book")), mk4H(0x16), mk4Arr(mk4H(0x17)), gov, mk4N(3), mk4N(101), mk4N(102), mk4N(103), mk4N(1)),
		mk4Tup(mk4Y([]byte{1, 2, 3}), mk4Arr(addrs...), mk4Arr(powers...), mk4N(201), mk4N(202), mk4N(1), mk4H(0x18)),
		mk4Tup(mk4H(0x19), mk4H(0x1a), mk4H(0x1b), mk4H(0x1c), mk4Y([]byte("ethereum")), mk4N(301), mk4H(0x1d), mk4Y([]byte("arbitrum")), tgt),
		mk4N(401), mk4Y([]byte{9, 9}),
	)
	return p
}

func TestMutKill4ComprehensiveProofFieldByField(t *testing.T) {
	p := mk4ProofValue(2, 2)
	c, err := DecodeComprehensiveProofCall(mk4Call(SigExecuteComprehensiveProof, mk4H(0x10), p.v), DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	h := func(seed byte) [32]byte { var b [32]byte; copy(b[:], bytes.Repeat([]byte{seed}, 32)); return b }
	if c.AnchorID != h(0x10) || c.TransactionHash != h(0x11) || c.MerkleRoot != h(0x12) || c.LeafHash != h(0x15) ||
		len(c.ProofHashes) != 2 || c.ProofHashes[0] != h(0x13) || c.ProofHashes[1] != h(0x14) {
		t.Fatalf("top level: %+v", c)
	}
	g := c.Governance
	if g.KeyBookURL != "acc://book" || g.KeyBookRoot != h(0x16) || len(g.KeyPageProofs) != 1 || g.KeyPageProofs[0] != h(0x17) || g.AuthorityAddress != p.gov ||
		g.AuthorityLevel != 3 || g.Nonce.Int64() != 101 || g.RequiredSignatures.Int64() != 102 || g.ProvidedSignatures.Int64() != 103 || !g.ThresholdMet {
		t.Fatalf("governance: %+v", g)
	}
	b := c.BLS
	if !bytes.Equal(b.AggregateSignature, []byte{1, 2, 3}) || len(b.ValidatorAddresses) != 2 || b.ValidatorAddresses[0] != p.addrs[0] || b.ValidatorAddresses[1] != p.addrs[1] ||
		len(b.VotingPowers) != 2 || b.VotingPowers[0].Int64() != 1000 || b.VotingPowers[1].Int64() != 1001 ||
		b.TotalVotingPower.Int64() != 201 || b.SignedVotingPower.Int64() != 202 || !b.ThresholdMet || b.MessageHash != h(0x18) {
		t.Fatalf("bls: %+v", b)
	}
	m := c.Commitments
	if m.OperationCommitment != h(0x19) || m.CrossChainCommitment != h(0x1a) || m.GovernanceRoot != h(0x1b) || m.ExecutionCommitment != h(0x1c) ||
		m.SourceChain != "ethereum" || m.SourceBlockHeight.Int64() != 301 || m.SourceTxHash != h(0x1d) || m.TargetChain != "arbitrum" || m.TargetAddress != p.target {
		t.Fatalf("commitments: %+v", m)
	}
	if c.ExpirationTime.Int64() != 401 || !bytes.Equal(c.Metadata, []byte{9, 9}) {
		t.Fatalf("tail: %v %x", c.ExpirationTime, c.Metadata)
	}
}

func TestMutKill4ComprehensiveProofArrayLengthMismatch(t *testing.T) {
	for _, c := range []struct{ addrs, powers int }{{3, 1}, {1, 3}, {0, 2}} {
		p := mk4ProofValue(c.addrs, c.powers)
		_, err := DecodeComprehensiveProofCall(mk4Call(SigExecuteComprehensiveProof, mk4H(0x10), p.v), DefaultABILimits())
		ae, ok := err.(*ABIError)
		if !ok {
			t.Fatalf("%d/%d: %v", c.addrs, c.powers, err)
		}
		wantABIErr(t, ae, ABIShape, "proof.blsProof.votingPowers", 0, uint64(c.powers), uint64(c.addrs), "validatorAddresses and votingPowers differ in length")
	}
}

func TestMutKill4ZKBlobWords(t *testing.T) {
	_, err := DecodeZKBlob(make([]byte, 575))
	ae, ok := err.(*ABIError)
	if !ok {
		t.Fatal(err)
	}
	wantABIErr(t, ae, ABITruncated, "aggregateSignature", 0, 575, 576, "blob shorter than 18 words")
	_, err = DecodeZKBlob(nil)
	if ae, ok = err.(*ABIError); !ok || ae.Got != 0 || ae.Limit != 576 {
		t.Fatalf("empty blob: %v", err)
	}
	blob := make([]byte, 580)
	for i := 0; i < 18; i++ {
		copy(blob[i*32:], bytes.Repeat([]byte{byte(i + 1)}, 32))
	}
	copy(blob[14*32:], mk4U(14)) // signed
	copy(blob[15*32:], mk4U(15)) // total
	copy(blob[16*32:], mk4U(16))
	copy(blob[17*32:], mk4U(17))
	z, err := DecodeZKBlob(blob)
	if err != nil || z.Length != 580 || z.MessageHash[0] != 13 || z.PubkeyCommitment[0] != 14 || z.Words[17][31] != 17 ||
		z.SignedVotingPower.Int64() != 14 || z.TotalVotingPower.Int64() != 15 || z.ThresholdNumerator.Int64() != 16 || z.ThresholdDenominator.Int64() != 17 {
		t.Fatalf("blob: %+v %v", z, err)
	}
	if _, err = DecodeZKBlob(blob[:576]); err != nil {
		t.Fatalf("exactly 18 words: %v", err)
	}
}

func mk4GovTuple() mk4Val {
	return mk4Tup(mk4Y([]byte("acc://adi")), mk4H(0x51), mk4Arr(mk4H(0x52), mk4H(0x53)), mk4H(0x54), mk4Y([]byte{0xa1}), mk4Y([]byte{0xa2, 0xa2}), mk4Y([]byte{0xa3}),
		mk4N(61), mk4N(62), mk4Y([]byte{0xa4}), mk4N(63), mk4H(0x55), mk4N(64), mk4N(65), mk4N(66))
}

func TestMutKill4SettlementCallSingleLeg(t *testing.T) {
	tgt, tgtA := mk4A(0x61)
	data := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}
	c, err := DecodeSettlementCall(mk4Call(SigExecuteGovernanceDirect, tgt, mk4N(777), mk4Y(data), mk4GovTuple()), DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	if c.Batch || len(c.Legs) != 1 || c.Legs[0].Target != tgtA || c.Legs[0].Value.Int64() != 777 || !bytes.Equal(c.Legs[0].Data, data) || c.Legs[0].Selector != [4]byte{0xde, 0xad, 0xbe, 0xef} {
		t.Fatalf("leg: %+v", c)
	}
	p := c.Proof
	h := func(seed byte) [32]byte { var b [32]byte; copy(b[:], bytes.Repeat([]byte{seed}, 32)); return b }
	if p.ADIURL != "acc://adi" || p.AnchorID != h(0x51) || len(p.MerkleProof) != 2 || p.MerkleProof[1] != h(0x53) || p.OperationID != h(0x54) ||
		!bytes.Equal(p.KeyBookProof, []byte{0xa1}) || !bytes.Equal(p.RoleProof, []byte{0xa2, 0xa2}) || !bytes.Equal(p.ThresholdProof, []byte{0xa3}) ||
		p.Timestamp.Int64() != 61 || p.ExpiresAt.Int64() != 62 || !bytes.Equal(p.ValidatorSignatures, []byte{0xa4}) || p.Nonce.Int64() != 63 || p.AuthorityBook != h(0x55) ||
		p.AuthorityPage != 64 || p.NotBefore != 65 || p.NotAfter != 66 {
		t.Fatalf("proof: %+v", p)
	}
}

func TestMutKill4SettlementCallSelectorBoundaries(t *testing.T) {
	sel := Selector4(SigExecuteGovernanceDirect)
	_, err := DecodeSettlementCall(sel[:], DefaultABILimits())
	wantABIErr(t, err.(*ABIError), ABITruncated, "target", 0, 0, 0, "head of 128 bytes, 0 remain")
	_, err = DecodeSettlementCall(sel[:3], DefaultABILimits())
	wantABIErr(t, err.(*ABIError), ABITruncated, "selector", 0, 0, 0, "3 bytes")
	_, err = DecodeSettlementCall([]byte{1, 2, 3, 4}, DefaultABILimits())
	wantABIErr(t, err.(*ABIError), ABISelector, "selector", 0, 0, 0, "0x01020304 is not a pinned settlement selector")
}

func TestMutKill4SettlementCallBatchShapes(t *testing.T) {
	addr := func(n int) mk4Val {
		var xs []mk4Val
		for i := 0; i < n; i++ {
			a, _ := mk4A(byte(0x70 + i))
			xs = append(xs, a)
		}
		return mk4Arr(xs...)
	}
	vals := func(n int) mk4Val {
		var xs []mk4Val
		for i := 0; i < n; i++ {
			xs = append(xs, mk4N(uint64(500+i)))
		}
		return mk4Arr(xs...)
	}
	datas := func(n int) mk4Val {
		var xs []mk4Val
		for i := 0; i < n; i++ {
			xs = append(xs, mk4Y([]byte{byte(0x10 + i), 0xaa, 0xbb, 0xcc, 0xdd}))
		}
		return mk4Arr(xs...)
	}
	call := func(nt, nv, nd int) []byte {
		return mk4Call(SigBatchGovernanceDirect, addr(nt), vals(nv), datas(nd), mk4GovTuple())
	}
	c, err := DecodeSettlementCall(call(3, 3, 3), DefaultABILimits())
	if err != nil || !c.Batch || len(c.Legs) != 3 {
		t.Fatalf("batch: %+v %v", c, err)
	}
	for i, l := range c.Legs {
		_, want := mk4A(byte(0x70 + i))
		if l.Target != want || l.Value.Int64() != int64(500+i) || len(l.Data) != 5 || l.Data[0] != byte(0x10+i) || l.Selector != [4]byte{byte(0x10 + i), 0xaa, 0xbb, 0xcc} {
			t.Fatalf("leg %d: %+v", i, l)
		}
	}
	for _, s := range []struct {
		nt, nv, nd int
		got, limit uint64
	}{{3, 1, 2, 1, 3}, {2, 1, 2, 1, 2}, {2, 2, 1, 2, 2}, {3, 2, 3, 2, 3}, {1, 3, 1, 3, 1}} {
		_, err := DecodeSettlementCall(call(s.nt, s.nv, s.nd), DefaultABILimits())
		ae, ok := err.(*ABIError)
		if !ok {
			t.Fatalf("%v: %v", s, err)
		}
		wantABIErr(t, ae, ABIShape, "values", 0, s.got, s.limit, "targets, values and datas differ in length")
	}
	_, err = DecodeSettlementCall(call(0, 0, 0), DefaultABILimits())
	wantABIErr(t, err.(*ABIError), ABIShape, "targets", 0, 0, 0, "empty batch")
	lim := DefaultABILimits()
	lim.MaxLegs = 2
	_, err = DecodeSettlementCall(call(3, 3, 3), lim)
	ae := err.(*ABIError)
	if ae.Kind != ABICap || ae.Got != 3 || ae.Limit != 2 || ae.Field != "targets" {
		t.Fatalf("cap: %+v", ae)
	}
}

func TestMutKill4ProofExecutedDataFlags(t *testing.T) {
	h := mk4H(0x77)
	for _, c := range []struct {
		m, b, g bool
		ts      uint64
	}{{false, true, false, 1}, {true, false, true, 2}, {true, true, true, 1}, {false, false, false, 2}} {
		bit := func(v bool) mk4Val {
			if v {
				return mk4N(1)
			}
			return mk4N(0)
		}
		data := mk4Seq([]mk4Val{h, bit(c.m), bit(c.b), bit(c.g), mk4N(c.ts)})
		l, err := DecodeProofExecutedData(data)
		if err != nil || l.MerkleVerified != c.m || l.BLSVerified != c.b || l.GovernanceVerified != c.g || l.Timestamp.Uint64() != c.ts || l.TransactionHash != h.w {
			t.Fatalf("%v: %+v %v", c, l, err)
		}
	}
	if _, err := DecodeProofExecutedData(make([]byte, 160-1)); err == nil {
		t.Fatal("a short log was accepted")
	}
}

func TestMutKill4SmallLogs(t *testing.T) {
	op, err := DecodeLeafConsumedData(mk4H(0x66).enc())
	if err != nil || op != mk4H(0x66).w {
		t.Fatalf("leaf consumed: %x %v", op, err)
	}
	g, err := DecodeGovernanceOperationData(mk4Seq([]mk4Val{mk4N(11), mk4Y([]byte{1, 2}), mk4N(4)}))
	if err != nil || g.Value.Int64() != 11 || !bytes.Equal(g.Data, []byte{1, 2}) || g.Level != 4 {
		t.Fatalf("operation: %+v %v", g, err)
	}
	if _, err = DecodeGovernanceOperationData(mk4Seq([]mk4Val{mk4N(11), mk4Y(nil), mk4N(5)})); err == nil {
		t.Fatal("a level above the enum was accepted")
	}
	b, err := DecodeGovernanceBatchData(mk4Seq([]mk4Val{mk4N(12), mk4N(3)}))
	if err != nil || b.CallCount.Int64() != 12 || b.Level != 3 {
		t.Fatalf("batch: %+v %v", b, err)
	}
	if _, err = DecodeGovernanceBatchData(mk4Seq([]mk4Val{mk4N(12), mk4N(5)})); err == nil {
		t.Fatal("a level above the enum was accepted")
	}
}
