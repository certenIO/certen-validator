// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/finality"
)

func proofNodes(t *testing.T, tr *trie.Trie, key []byte) [][]byte {
	t.Helper()
	var ns proofSink
	if err := tr.Prove(key, &ns); err != nil {
		t.Fatal(err)
	}
	return ns.nodes
}

// nodeDB reads an account and a storage slot as proven present, proven absent or malformed.
func TestNodeDBReadsAccountsAndSlotsAsPresentAbsentOrMalformed(t *testing.T) {
	storage := trie.NewEmpty(nil)
	val := func(raw []byte) []byte { return rlpOf(raw) }
	slotKey := func(n byte) common.Hash { return common.Hash{31: n} }
	thirtyTwo := bytes.Repeat([]byte{0xab}, 32)
	storage.Update(crypto.Keccak256(slotKey(1).Bytes()), val([]byte{1}))               // the value 1 (a single byte below 0x80)
	storage.Update(crypto.Keccak256(slotKey(2).Bytes()), val(thirtyTwo))               // a full word
	storage.Update(crypto.Keccak256(slotKey(3).Bytes()), val(append(thirtyTwo, 0xcd))) // 33 bytes: not a word
	storage.Update(crypto.Keccak256(slotKey(4).Bytes()), rlpOf([]any{}))               // a list, not a string
	storage.Update(crypto.Keccak256(slotKey(5).Bytes()), val(nil))                     // the empty string: zero
	storage.Update(crypto.Keccak256(slotKey(6).Bytes()), val([]byte{0x80, 0x81}))      // two bytes: right-aligned
	storageRoot := storage.Hash()
	var snodes [][]byte
	for n := byte(1); n <= 7; n++ { // slot 7 is absent
		snodes = append(snodes, proofNodes(t, storage, crypto.Keccak256(slotKey(n).Bytes()))...)
	}
	db := newNodeDB(snodes)
	root := [32]byte(storageRoot)
	for _, c := range []struct {
		slot byte
		want string // hex of the word, or "refused"
	}{
		{1, strings.Repeat("00", 31) + "01"},
		{2, hex.EncodeToString(thirtyTwo)},
		{3, "refused"},
		{4, "refused"},
		{5, strings.Repeat("00", 32)},
		{6, strings.Repeat("00", 30) + "8081"},
		{7, strings.Repeat("00", 32)},
	} {
		got, err := db.slot(root, slotKey(c.slot))
		if c.want == "refused" {
			wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "slot"})
			continue
		}
		if err != nil || hex.EncodeToString(got[:]) != c.want {
			t.Errorf("slot %d: %x, %v; want %s", c.slot, got, err, c.want)
		}
	}
	// a slot whose proof is not in the node set is refused, not read as zero
	_, err := newNodeDB(nil).slot(root, slotKey(1))
	wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "slot"})

	accts := trie.NewEmpty(nil)
	okAddr, badAddr, noneAddr := common.Address{1}, common.Address{2}, common.Address{3}
	acc := rlpOf(&types.StateAccount{Nonce: 3, Balance: uint256.NewInt(5), Root: storageRoot, CodeHash: crypto.Keccak256([]byte("code"))})
	accts.Update(crypto.Keccak256(okAddr[:]), acc)
	accts.Update(crypto.Keccak256(badAddr[:]), rlpOf([]byte("not an account")))
	var anodes [][]byte
	for _, a := range []common.Address{okAddr, badAddr, noneAddr} {
		anodes = append(anodes, proofNodes(t, accts, crypto.Keccak256(a[:]))...)
	}
	adb := newNodeDB(anodes)
	aroot := [32]byte(accts.Hash())
	got, err := adb.account(aroot, okAddr)
	if err != nil || got.Nonce != 3 || got.Root != storageRoot || !bytes.Equal(got.CodeHash, crypto.Keccak256([]byte("code"))) {
		t.Fatalf("%+v %v", got, err)
	}
	for name, a := range map[string]common.Address{"junk value": badAddr, "proven absent": noneAddr, "no proof": {9}} {
		_, err := adb.account(aroot, a)
		if _, ok := finality.AsNamed(err); !ok {
			t.Fatalf("%s: %v", name, err)
		}
		wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "account"})
	}
}

func TestKindVerifyNamesAGarbageContainerAsMalformedNotUnrecognised(t *testing.T) {
	set := filepath.Join("testdata", SetName)
	pinsRaw, _ := ReadFile(set, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Kind{}.Verify(pins, finality.BlockRef{Chain: 84532}, []byte{1, 2, 3})
	wantCode(t, err, finality.CodeEvidenceMalformed, nil)
}

// A blob whose versioned hash is not the one the transaction carries is refused on that ground, even when the blob, its commitment
// and its KZG proof are a perfectly valid triple (here: the first blob of another channel).
func TestAValidBlobTripleThatTheTransactionDoesNotCommitToIsABlobMismatch(t *testing.T) {
	set := filepath.Join("testdata", SetName)
	pinsRaw, _ := ReadFile(set, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(set, "legs/a.json")
	var leg Leg
	_ = json.Unmarshal(legRaw, &leg)
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	hdr, _ := hex.DecodeString(strings.TrimPrefix(leg.Header, "0x"))
	hb, _ := hex.DecodeString(strings.TrimPrefix(leg.Hash, "0x"))
	var hash [32]byte
	copy(hash[:], hb)
	ref := finality.BlockRef{Chain: 84532, Number: num, Hash: hash, HeaderRLP: hdr}
	evA, _ := ReadFile(set, "evidence/valid_a.bin")
	evB, _ := ReadFile(set, "evidence/valid_b.bin")
	ca, err := finality.DecodeContainer(evA, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	cb, err := finality.DecodeContainer(evB, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bodyA, err := DecodeBody(ca.Body, finality.DefaultLimits(), EthL1Pins(pins), 32)
	if err != nil {
		t.Fatal(err)
	}
	bodyB, err := DecodeBody(cb.Body, finality.DefaultLimits(), EthL1Pins(pins), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(bodyA.Frames[0].Blobs) == 0 || len(bodyB.Frames[0].Blobs) == 0 || bodyA.Frames[0].Blobs[0].Commitment == bodyB.Frames[0].Blobs[0].Commitment {
		t.Fatal("test assumption: both evidences carry distinct blobs in their first frame")
	}
	swapped := bodyA
	swapped.Frames = append([]FrameTx(nil), bodyA.Frames...)
	f0 := swapped.Frames[0]
	f0.Blobs = append([]Blob(nil), f0.Blobs...)
	f0.Blobs[0] = bodyB.Frames[0].Blobs[0]
	swapped.Frames[0] = f0
	ev, err := finality.Container{Header: ca.Header, Body: EncodeBody(swapped)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Kind{}.Verify(pins, ref, ev)
	wantCode(t, err, CodeBlobMismatch, nil)
}

func TestFrameTransactionsOrderTheChannelAndAreDecodedBeforeTheyAreUsed(t *testing.T) {
	synth := func(o synthOpts) *synth {
		o.compression, o.calldata = "zlib", true
		return makeSynth(t, o)
	}
	// frames in descending L1 blocks, numbered 0 and 1 in that order: the order of the L1 blocks alone refuses them
	rev := synth(synthOpts{nFrames: 2, frameBlocks: []uint64{1001, 1000}})
	_, err := rev.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)
	// two frames of one block are in transaction order: the same index twice is refused, ascending indices are accepted
	same := synth(synthOpts{nFrames: 2, frameBlocks: []uint64{1000, 1000}})
	mustOK(t, same)
	dup := synth(synthOpts{nFrames: 2, frameBlocks: []uint64{1000, 1000}})
	dup.body.Frames[1].TxIndex = dup.body.Frames[0].TxIndex
	_, err = dup.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)
	// the first frame is not compared with a predecessor: a frame in L1 block 0 at index 0 is judged on its other merits (its batch
	// is outside the sequencing window of its epoch)
	zero := synth(synthOpts{frameBlocks: []uint64{0}})
	_, err = zero.verify()
	wantCode(t, err, CodeBatchOutsideWindow, nil)
	// a spine entry that is not a header
	junk := synth(synthOpts{})
	junk.body.L1Spine[0] = []byte{1, 2}
	_, err = junk.verify()
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "header"})
	// a transaction in the block trie that is not a transaction
	gt := synth(synthOpts{garbageTx: []byte{0x02, 0xc0}})
	_, err = gt.verify()
	wantCode(t, err, CodeL1TxProofInvalid, nil)
	// calldata that is not a frame stream
	bad := synth(synthOpts{txData: []byte{0xff}})
	_, err = bad.verify()
	wantCode(t, err, CodeChannelMalformed, nil)
	// no frame of the channel the body names
	other := synth(synthOpts{})
	other.body.ChannelID[0] ^= 1
	_, err = other.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)
}

func TestBatchTypesThisVerifierDoesNotDecodeAreNamedWithTheirType(t *testing.T) {
	// a batch type 7 in the channel stream
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, rawStream: rlpOf([]byte{7, 1})})
	_, err := s.verify()
	wantCode(t, err, CodeBatchFormat, map[string]string{"type": "7"})
	// a span batch carrying a transaction of type 3
	head := rawPayload(uvs(0, 9), spanParent, spanOrigin)
	three := rawPayload(head, uvs(1), []byte{0}, uvs(1), []byte{0}, []byte{0}, make([]byte, 64), addrA.Bytes(), []byte{3}, rlpOf([]any{uint64(1)}), uvs(1), uvs(1))
	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true, rawStream: rlpOf(append([]byte{1}, three...))})
	_, err = s.verify()
	wantCode(t, err, CodeBatchFormat, map[string]string{"type": "3"})
}

func TestTheL1InfoDepositMustBeThereAType0x7eTransactionWithTheEpochInItsLastItem(t *testing.T) {
	good := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	mustOK(t, good)
	for name, dep := range map[string][][]byte{
		"no deposits":               nil,
		"an empty first deposit":    {{}},
		"another deposit type":      {append([]byte{0x7f}, good.body.Deposits[0][1:]...)},
		"a type byte and nothing":   {{0x7e}},
		"a type byte and junk list": {{0x7e, 0xc1, 0x01}},
	} {
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
		s.body.Deposits = dep
		_, err := s.verify()
		if _, ok := finality.AsNamed(err); !ok {
			t.Fatalf("%s: %v", name, err)
		}
		wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "l1_info_deposit"})
	}
}

func TestL1InfoReadsTheEpochNumberAndHashFromTheLastOfEightItems(t *testing.T) {
	hash := [32]byte(crypto.Keccak256Hash([]byte("epoch")))
	calldata := func(n int) []byte {
		d := make([]byte, n)
		for i := range d {
			d[i] = byte(i + 1)
		}
		binary.BigEndian.PutUint64(d[28:36], 0x0102030405060708)
		copy(d[100:], hash[:])
		return d
	}
	dep := func(items ...any) []byte { return append([]byte{0x7e}, rlpOf(items)...) }
	eight := func(last any) []any {
		return []any{common.Hash{1}, common.Address{0xde}, common.Address{0x42}, big.NewInt(0), big.NewInt(0), uint64(1_000_000), false, last}
	}
	num, h, ok := l1Info(dep(eight(calldata(164))...))
	if !ok || num != 0x0102030405060708 || h != hash {
		t.Fatalf("%x %x %v", num, h, ok)
	}
	if _, _, ok := l1Info(dep(eight(calldata(132))...)); !ok {
		t.Fatal("a last item of exactly 132 bytes carries the epoch")
	}
	for name, d := range map[string][]byte{
		"a last item of 131 bytes":           dep(eight(calldata(131))...),
		"seven items":                        dep(eight(calldata(164))[:7]...),
		"nine items, the ninth one byte":     dep(append(eight(calldata(164)), uint64(1))...),
		"nine items":                         dep(append(eight(calldata(164)), []byte{1, 2})...),
		"a list as the eighth item":          dep(eight([]any{calldata(164)})...),
		"a string instead of a list":         append([]byte{0x7e}, rlpOf(calldata(164))...),
		"bytes after the list":               append(dep(eight(calldata(164))...), 0x00),
		"a truncated item":                   {0x7e, 0xc8, 0x01, 0x83, 0x01},
		"an empty deposit body":              {0x7e},
		"a list whose item header is broken": {0x7e, 0xc2, 0xb8, 0x01},
	} {
		if _, _, ok := l1Info(d); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPrefixEqAndDistinctSortedBoundaries(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i], b[i] = byte(i+1), byte(i+1)
	}
	b[20] ^= 0xff
	for _, c := range []struct {
		n    int
		want bool
	}{{-1, false}, {0, false}, {1, true}, {20, true}, {21, false}, {32, false}, {33, false}} {
		if got := prefixEq(a, c.n, b); got != c.want {
			t.Errorf("n=%d: %v, want %v", c.n, got, c.want)
		}
	}
	b = a
	if !prefixEq(a, 32, b) || prefixEq(a, 33, b) || prefixEq(a, 0, b) || !prefixEq(a, 1, b) {
		t.Error("equal arrays")
	}
	in := []uint64{9, 3, 3, 7, 1, 9, 5, 1, 8, 2, 6, 4, 4, 0, 11, 10, 12, 12}
	got := distinctSorted(in)
	want := []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	if len(got) != len(want) || !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}
