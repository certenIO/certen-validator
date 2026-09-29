package contracts

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func u256(v uint64) []byte { w := make([]byte, 32); new(big.Int).SetUint64(v).FillBytes(w); return w }

// v81Call is a self-consistent V8.1 createBatchAnchor call: its bundle id is the one its arguments derive.
func v81Call(chainID int64, root [32]byte, leafCount uint64, opID [32]byte, height uint64) []byte {
	bundle := DeriveV8_1BatchBundleID(chainID, root, leafCount, opID, height)
	d := append([]byte{}, CreateBatchAnchorV8_1Selector[:]...)
	for _, w := range [][]byte{bundle[:], root[:], u256(leafCount), opID[:], u256(height)} {
		d = append(d, w...)
	}
	return d
}

func v82Call(chainID int64, root [32]byte, leafCount uint64, opID [32]byte, height uint64, acc, inc [32]byte) []byte {
	bundle := DeriveV8_2BatchBundleID(chainID, root, leafCount, opID, height, acc, inc)
	d := append([]byte{}, CreateBatchAnchorV8_2Selector[:]...)
	for _, w := range [][]byte{bundle[:], root[:], u256(leafCount), opID[:], u256(height), acc[:], inc[:]} {
		d = append(d, w...)
	}
	return d
}

func b32h(s string) (o [32]byte) { b, _ := hex.DecodeString(s); copy(o[:], b); return }

func TestCreateBatchAnchorSelectors(t *testing.T) {
	if hex.EncodeToString(CreateBatchAnchorV8_1Selector[:]) != "34597e5a" || hex.EncodeToString(CreateBatchAnchorV8_2Selector[:]) != "5d22872b" {
		t.Fatalf("selectors %x %x", CreateBatchAnchorV8_1Selector, CreateBatchAnchorV8_2Selector)
	}
}

// The root of Phase C's ethereum member (tx 0xcde94ba3… on sepolia, 2026-09-29, a V8.1 anchor) in a V8.1 call, and the
// same batch as a V8.2 call committing Kermit's set and incarnation: both decode, and name their generation.
func TestDecodeCreateBatchAnchor_BothGenerations(t *testing.T) {
	root := b32h("4c84c233a475390a0f70c05479b6efb9e2bbb88a6c85c6cae9823e3baccb40b1")
	var op [32]byte
	op[31] = 0xee
	c, err := DecodeCreateBatchAnchor(11155111, v81Call(11155111, root, 1, op, 100))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != BatchAnchorV8_1 || c.Root != root || c.LeafCount != 1 || c.Height != 100 || c.BatchOperationID != op ||
		c.AccumulateSetRoot != ([32]byte{}) || c.Incarnation != ([32]byte{}) {
		t.Fatalf("%+v", c)
	}
	acc := b32h("afa6bd344b04b6ff9645c97b09254af9c25a214991e0b442538e9084d4136bf5")
	inc := b32h("cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0")
	c, err = DecodeCreateBatchAnchor(84532, v82Call(84532, root, 3, op, 42, acc, inc))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != BatchAnchorV8_2 || c.AccumulateSetRoot != acc || c.Incarnation != inc || c.LeafCount != 3 || c.Height != 42 {
		t.Fatalf("%+v", c)
	}
}

// Nothing the anchor would not have accepted decodes.
func TestDecodeCreateBatchAnchor_Refusals(t *testing.T) {
	root := b32h("4c84c233a475390a0f70c05479b6efb9e2bbb88a6c85c6cae9823e3baccb40b1")
	var op, acc, inc [32]byte
	op[0], acc[1], inc[2] = 1, 2, 3
	good81 := v81Call(11155111, root, 1, op, 100)
	good82 := v82Call(11155111, root, 1, op, 100, acc, inc)
	tamper := func(d []byte, at int) []byte { c := append([]byte{}, d...); c[at] ^= 1; return c }
	for name, tc := range map[string]struct {
		chain int64
		data  []byte
		want  string
	}{
		"another function":        {11155111, append([]byte{0xde, 0xad, 0xbe, 0xef}, good81[4:]...), "not createBatchAnchor"},
		"truncated":               {11155111, good81[:40], "bytes"},
		"v8.2 shape, v8.1 length": {11155111, good82[:4+5*32], "bytes"},
		"bundle not derived":      {11155111, tamper(good81, 4), "derive"},
		"root changed":            {11155111, tamper(good81, 4+32+5), "derive"},
		"set root changed":        {11155111, tamper(good82, 4+5*32+1), "derive"},
		"incarnation changed":     {11155111, tamper(good82, 4+6*32+1), "derive"},
		"another chain":           {84532, good82, "derive"},
		"count over 64 bits":      {11155111, tamper(good81, 4+2*32+3), "64 bits"},
		"empty":                   {11155111, nil, "bytes"},
	} {
		if _, err := DecodeCreateBatchAnchor(tc.chain, tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
