// Copyright 2026 Certen Protocol

package ethl1

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestFaultBuilderTakesPairsAndIgnoresADanglingKey(t *testing.T) {
	if f := fault("c", "a"); len(f.Fields) != 0 {
		t.Fatalf("a dangling key must be ignored, got %v", f.Fields)
	}
	if f := fault("c"); len(f.Fields) != 0 {
		t.Fatalf("no pairs: %v", f.Fields)
	}
	if f := fault("c", "a", "x", "b", uint64(2)); len(f.Fields) != 2 || f.Fields["a"] != "x" || f.Fields["b"] != uint64(2) {
		t.Fatalf("two pairs: %v", f.Fields)
	}
	if f := fault("c", "a", "x", "b"); len(f.Fields) != 1 {
		t.Fatalf("three kv: %v", f.Fields)
	}
}

func TestFaultCanonicalJSONRendersBoolsAndEveryScalarKind(t *testing.T) {
	f := fault("c", "t", true, "f", false, "u8", uint8(7), "u32", uint32(9), "i64", int64(-5), "bytes", []byte{0xab, 0xcd}, "v", [4]byte{1, 2, 3, 4})
	want := `{"code":"c","fields":{"bytes":"0xabcd","f":false,"i64":"-5","t":true,"u32":"9","u8":"7","v":"0x01020304"}}`
	if got := string(f.CanonicalJSON()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestHeaderContainerAndSigningRootAPI(t *testing.T) {
	hdr := make([]byte, BeaconBlockHeaderSize)
	for i := range hdr {
		hdr[i] = byte(i + 1)
	}
	for _, n := range []int{0, 111, 113} {
		if _, err := HashTreeRootBeaconBlockHeader(make([]byte, n)); err == nil || err.(*Fault).Fields["reason"] != "length" || err.(*Fault).Fields["got_len"] != n {
			t.Fatalf("header of %d bytes: %v", n, err)
		}
		if root, err := SyncCommitteeSigningRoot(make([]byte, n), [4]byte{}, [32]byte{}); err == nil || root != ([32]byte{}) {
			t.Fatalf("signing root of a %d byte header: %x %v", n, root, err)
		}
	}
	// an independent hash_tree_root(BeaconBlockHeader): five 32-byte leaves padded to eight
	var leaf [8][32]byte
	copy(leaf[0][:], hdr[0:8])
	copy(leaf[1][:], hdr[8:16])
	copy(leaf[2][:], hdr[16:48])
	copy(leaf[3][:], hdr[48:80])
	copy(leaf[4][:], hdr[80:112])
	pair := func(a, b [32]byte) [32]byte { return sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...)) }
	objectRoot := pair(pair(pair(leaf[0], leaf[1]), pair(leaf[2], leaf[3])), pair(pair(leaf[4], leaf[5]), pair(leaf[6], leaf[7])))
	got, err := HashTreeRootBeaconBlockHeader(hdr)
	if err != nil || got != objectRoot {
		t.Fatalf("hash_tree_root: %x %v want %x", got, err, objectRoot)
	}
	version, gvr := [4]byte{0xde, 0xad, 0xbe, 0xef}, [32]byte{0x11, 0x22, 0x33}
	var fv [32]byte
	copy(fv[:], version[:])
	forkDataRoot := pair(fv, gvr)
	var domain [32]byte
	domain[0] = 0x07
	copy(domain[4:], forkDataRoot[:28])
	wantSigning := pair(objectRoot, domain)
	if gotSigning, err := SyncCommitteeSigningRoot(hdr, version, gvr); err != nil || gotSigning != wantSigning {
		t.Fatalf("signing root %x %v want %x", gotSigning, err, wantSigning)
	}

	if err := ValidateContainer("Bogus", nil); err == nil || err.(*Fault).Fields["reason"] != "unknown_kind" || err.(*Fault).Fields["part"] != "container" {
		t.Fatalf("unknown kind: %v", err)
	}
	if err := ValidateContainer("", make([]byte, 0)); err == nil || err.(*Fault).Fields["reason"] != "unknown_kind" {
		t.Fatalf("empty kind: %v", err)
	}
	for kind, size := range map[string]int{"BeaconBlockHeader": 112, "LightClientHeader": 496, "SyncCommittee": 24624, "LightClientBootstrap": 25472, "LightClientUpdate": 26424, "LightClientFinalityUpdate": 1448} {
		if err := ValidateContainer(kind, make([]byte, size)); err != nil {
			t.Fatalf("%s of %d bytes: %v", kind, size, err)
		}
		if err := ValidateContainer(kind, make([]byte, size+1)); err == nil || err.(*Fault).Fields["reason"] != "length" || err.(*Fault).Fields["want_len"] != size {
			t.Fatalf("%s of %d bytes: %v", kind, size+1, err)
		}
	}
}

func TestRootFromNormalizedBranchFoldsByTheIndexBits(t *testing.T) {
	sha := func(a, b [32]byte) [32]byte { return sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...)) }
	var leaf, b0, b1, b2, b3, junk0, junk1 [32]byte
	leaf[0], b0[0], b1[0], b2[0], b3[0], junk0[0], junk1[0] = 1, 2, 3, 4, 5, 0xee, 0xef
	// gindex 26 = 0b11010: depth 4, index 0b1010: bits (low to high) 0,1,0,1
	v := sha(leaf, b0)
	v = sha(b1, v)
	v = sha(v, b2)
	want := sha(b3, v)
	if got := RootFromNormalizedBranch(leaf, [][32]byte{b0, b1, b2, b3}, 26); got != want {
		t.Fatalf("gindex 26: %x want %x", got, want)
	}
	// a zero-extended branch carries unused leading entries that must not be read
	if got := RootFromNormalizedBranch(leaf, [][32]byte{junk0, junk1, b0, b1, b2, b3}, 26); got != want {
		t.Fatalf("gindex 26 with a two entry extension: %x want %x", got, want)
	}
	// gindex 11 = 0b1011: depth 3, index 0b011: bits 1,1,0
	w := sha(b0, leaf)
	w = sha(b1, w)
	wantB := sha(w, b2)
	if got := RootFromNormalizedBranch(leaf, [][32]byte{b0, b1, b2}, 11); got != wantB {
		t.Fatalf("gindex 11: %x want %x", got, wantB)
	}
	if got := RootFromNormalizedBranch(leaf, [][32]byte{junk0, b0, b1, b2}, 11); got != wantB {
		t.Fatalf("gindex 11 with a one entry extension: %x want %x", got, wantB)
	}
	// gindex 1 has depth 0: the leaf is the root
	if got := RootFromNormalizedBranch(leaf, nil, 1); got != leaf {
		t.Fatalf("gindex 1: %x", got)
	}
}

func TestForkAtPicksTheLastForkNotAfterTheEpoch(t *testing.T) {
	n := Network{Forks: []Fork{{Name: "a", Epoch: 0}, {Name: "b", Epoch: 100}, {Name: "c", Epoch: 200}}}
	for _, c := range []struct {
		epoch uint64
		name  string
	}{{0, "a"}, {99, "a"}, {100, "b"}, {199, "b"}, {200, "c"}, {1 << 40, "c"}} {
		if f, ok := n.forkAt(c.epoch); !ok || f.Name != c.name {
			t.Fatalf("forkAt(%d) = %+v %v, want %s", c.epoch, f, ok, c.name)
		}
	}
	late := Network{Forks: []Fork{{Name: "x", Epoch: 50}}}
	if f, ok := late.forkAt(49); ok || f.Name != "" {
		t.Fatalf("before the first fork: %+v %v", f, ok)
	}
	if f, ok := late.forkAt(50); !ok || f.Name != "x" {
		t.Fatalf("at the first fork: %+v %v", f, ok)
	}
	if f, ok := (Network{}).forkAt(5); ok || f.Name != "" {
		t.Fatalf("empty schedule: %+v %v", f, ok)
	}
	one := Network{Forks: []Fork{{Name: "z", Epoch: 0}}}
	if f, ok := one.forkAt(0); !ok || f.Name != "z" {
		t.Fatalf("single fork at epoch 0: %+v %v", f, ok)
	}
}

func TestLedgerHeadIsTheLargestPeriodWhateverTheOrder(t *testing.T) {
	mk := func(ps ...uint64) Pins {
		var p Pins
		for _, x := range ps {
			p.Anchors = append(p.Anchors, Anchor{Period: x})
		}
		return p
	}
	for _, c := range []struct {
		in   []uint64
		want uint64
		ok   bool
	}{{nil, 0, false}, {[]uint64{5}, 5, true}, {[]uint64{0}, 0, true}, {[]uint64{3, 9, 5}, 9, true}, {[]uint64{9, 3, 5}, 9, true}, {[]uint64{3, 5, 9}, 9, true}, {[]uint64{9, 3}, 9, true}, {[]uint64{4, 4}, 4, true}} {
		if got, ok := mk(c.in...).ledgerHead(); got != c.want || ok != c.ok {
			t.Fatalf("ledgerHead(%v) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestVerifyBootstrapAnchorJudgesEachStepOfTheKind2Anchor(t *testing.T) {
	good := func() (Pins, LC) { return v2Case(t, "valid_k2_k0") }
	p, lc := good()
	if err := VerifyBootstrapAnchor(p, lc.AnchorPeriod, lc.AnchorBody); err != nil {
		t.Fatalf("the bootstrap of a valid kind-2 evidence: %v", err)
	}
	expect := func(name string, err error, code string) *Fault {
		t.Helper()
		f, ok := err.(*Fault)
		if !ok || f == nil || f.Code != code {
			t.Fatalf("%s: got %v, want %s", name, err, code)
		}
		return f
	}

	p, lc = good()
	p.Network.ChainID++
	expect("wrong chain", VerifyBootstrapAnchor(p, lc.AnchorPeriod, lc.AnchorBody), CodeNetworkMismatch)

	p, lc = good()
	f := expect("period without an anchor", VerifyBootstrapAnchor(p, lc.AnchorPeriod+100000, lc.AnchorBody), CodePinUnknown)
	if f.Fields["kind"] != 2 || f.Fields["period"] != lc.AnchorPeriod+100000 || f.Fields["root"] != ([32]byte{}) {
		t.Fatalf("pin_unknown fields: %s", f.CanonicalJSON())
	}

	p, lc = good()
	for i := range p.Anchors {
		p.Anchors[i].BlockRoot = nil
	}
	expect("anchor without a block root", VerifyBootstrapAnchor(p, lc.AnchorPeriod, lc.AnchorBody), CodePinUnknown)

	p, lc = good()
	short := LB{Layout: lc.AnchorBody.Layout, SSZ: lc.AnchorBody.SSZ[:len(lc.AnchorBody.SSZ)-1]}
	expect("truncated bootstrap", VerifyBootstrapAnchor(p, lc.AnchorPeriod, short), CodeEvidenceMalformed)

	p, lc = good()
	fuluSlot := uint64(352768 * 32)
	b := append([]byte(nil), lc.AnchorBody.SSZ...)
	binary.LittleEndian.PutUint64(b[0:8], fuluSlot)
	f = expect("Fulu-era slot", VerifyBootstrapAnchor(p, lc.AnchorPeriod, LB{Layout: lc.AnchorBody.Layout, SSZ: b}), CodeForkUnsupported)
	if f.Fields["slot"] != fuluSlot {
		t.Fatalf("fork_unsupported fields: %s", f.CanonicalJSON())
	}

	p, lc = good()
	for i := range p.Anchors {
		if p.Anchors[i].Period == lc.AnchorPeriod {
			br := *p.Anchors[i].BlockRoot
			br[0] ^= 0xff
			p.Anchors[i].BlockRoot = &br
		}
	}
	expect("block root pin differs", VerifyBootstrapAnchor(p, lc.AnchorPeriod, lc.AnchorBody), CodePinMismatch)

	p, lc = good()
	for i := range p.Anchors {
		if p.Anchors[i].Period == lc.AnchorPeriod {
			p.Anchors[i].CommitteeRoot[0] ^= 0xff
		}
	}
	f = expect("committee root pin differs", VerifyBootstrapAnchor(p, lc.AnchorPeriod, lc.AnchorBody), CodePinMismatch)
	if f.Fields["period"] != lc.AnchorPeriod {
		t.Fatalf("pin_mismatch fields: %s", f.CanonicalJSON())
	}
}

func TestCommitteeKeyReadsExactlyTheSeatsBytes(t *testing.T) {
	_, _, g1, g2 := bls12381.Generators()
	raw := make([]byte, SyncCommitteeBytes)
	// seat 48 and the seat after it hold the 96-byte UNCOMPRESSED generator: a 48-byte compressed read of seat 48 must refuse it
	unc := g1.RawBytes()
	copy(raw[48*48:], unc[:])
	c := newCommittee(raw, SyncCommitteeSize)
	if _, err := c.key(48); err == nil {
		t.Fatal("an uncompressed key in a 48-byte seat must be refused, whatever follows the seat")
	}
	comp := g1.Bytes()
	copy(raw[7*48:], comp[:])
	c = newCommittee(raw, SyncCommitteeSize)
	k, err := c.key(7)
	if err != nil || !k.Equal(&g1) {
		t.Fatalf("seat 7: %v", err)
	}
	_ = g2
}

func TestFastAggregateVerifyNamesEachRefusal(t *testing.T) {
	_, _, g1, g2 := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1)
	pk, npk, sigGen := g1.Bytes(), negG1.Bytes(), g2.Bytes()
	var msg [32]byte
	msg[0] = 9

	two := make([]byte, SyncCommitteeBytes)
	copy(two[0:], pk[:])
	copy(two[48:], npk[:])
	cmtTwo := newCommittee(two, SyncCommitteeSize)

	bits := func(set ...int) []byte {
		b := make([]byte, SyncCommitteeSize/8)
		for _, i := range set {
			b[i/8] |= 1 << (uint(i) % 8)
		}
		return b
	}
	var infSig [96]byte
	infSig[0] = 0xc0
	cases := []struct {
		name string
		c    *committee
		agg  syncAggregate
		want string
	}{
		{"identity signature", committeeOf(pk), syncAggregate{Bits: bits(0), Signature: infSig}, "identity signature"},
		{"no participants", committeeOf(pk), syncAggregate{Bits: bits(), Signature: sigGen}, "no participants"},
		{"identity aggregate key", cmtTwo, syncAggregate{Bits: bits(0, 1), Signature: sigGen}, "identity aggregate public key"},
		{"wrong signature", committeeOf(pk), syncAggregate{Bits: bits(0), Signature: sigGen}, "aggregate signature does not verify"},
	}
	for _, c := range cases {
		err := fastAggregateVerify(c.c, c.agg, msg)
		if err == nil || err.Error() != c.want {
			t.Fatalf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// exactly one participant with a right signature verifies (a single seat is a participation of one, not of none)
	good := syncAggregate{Bits: bits(5), Signature: signAll(t, 1, msg, 1)}
	if err := fastAggregateVerify(committeeOf(pk), good, msg); err != nil {
		t.Fatalf("one participant: %v", err)
	}
	three := syncAggregate{Bits: bits(1, 2, 300), Signature: signAll(t, 1, msg, 3)}
	if err := fastAggregateVerify(committeeOf(pk), three, msg); err != nil {
		t.Fatalf("three participants: %v", err)
	}
}
