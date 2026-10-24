// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// rawList is a DerivableList over wire encodings: go-ethereum's own DeriveSha (an independent trie implementation) is the oracle.
type rawList [][]byte

func (l rawList) Len() int                           { return len(l) }
func (l rawList) EncodeIndex(i int, w *bytes.Buffer) { w.Write(l[i]) }

func oracleRoot(txs [][]byte) common.Hash {
	return types.DeriveSha(rawList(txs), trie.NewListHasher())
}

func wantTx(t *testing.T, err error, kind TxKind) *TxError {
	t.Helper()
	var te *TxError
	if !errors.As(err, &te) || te.Kind != kind {
		t.Fatalf("want %s, got %v", kind, err)
	}
	return te
}

func realTxs(t *testing.T) [][]byte {
	t.Helper()
	to := common.HexToAddress("0xb4Ea0cDA7b4755751293cb6d9b8D6027E05077BA")
	mk := func(tx *types.Transaction) []byte {
		b, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return [][]byte{
		mk(types.NewTx(&types.LegacyTx{Nonce: 1, GasPrice: big.NewInt(7), Gas: 21000, To: &to, Value: big.NewInt(1), Data: []byte{1, 2}})),
		mk(types.NewTx(&types.AccessListTx{ChainID: big.NewInt(11155111), Nonce: 2, GasPrice: big.NewInt(7), Gas: 30000, To: &to, Value: big.NewInt(0), Data: []byte{3},
			AccessList: types.AccessList{{Address: to, StorageKeys: []common.Hash{{1}}}}})),
		mk(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(9), Gas: 50000, To: &to, Value: big.NewInt(5), Data: []byte{4, 5, 6}})),
	}
}

// synthTx builds a wire encoding of the given type with a payload of n distinguishing bytes (a list for the standard types).
func synthTx(ty byte, i int) []byte {
	body, _ := rlp.EncodeToBytes([]any{uint64(i), []byte{byte(i), byte(i >> 8)}, "x"})
	switch {
	case ty == 0:
		return body
	case ty <= 4:
		return append([]byte{ty}, body...)
	default: // L2 and unknown types: an opaque payload, not necessarily a list
		return append([]byte{ty}, byte(i), byte(i>>8), 0x99)
	}
}

func TestRebuildTxRootEqualsGethDeriveShaAtEveryIndexEdge(t *testing.T) {
	if got := RebuildTxRoot(nil); got != types.EmptyTxsHash || oracleRoot(nil) != types.EmptyTxsHash {
		t.Fatalf("empty block: %s", got.Hex())
	}
	// the real transaction types
	real := realTxs(t)
	if got, want := RebuildTxRoot(real), types.DeriveSha(types.Transactions{}, trie.NewListHasher()); got == want {
		t.Fatal("non-empty list has the empty root")
	}
	var typed types.Transactions
	for _, raw := range real {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		typed = append(typed, &tx)
	}
	if got, want := RebuildTxRoot(real), types.DeriveSha(typed, trie.NewListHasher()); got != want {
		t.Fatalf("real txs: %s vs geth %s", got.Hex(), want.Hex())
	}
	// counts around the RLP index encoding edges (rlp(0)=0x80, rlp(127)=0x7f, rlp(128)=0x8180, rlp(255)=0x81ff, rlp(256)=0x820100)
	kinds := []byte{0, 1, 2, 3, 4, 0x7e, 0x64, 0x6a, 0x78, 0x7f}
	for _, n := range []int{1, 2, 3, 126, 127, 128, 129, 130, 255, 256, 257, 300} {
		txs := make([][]byte, n)
		for i := range txs {
			txs[i] = synthTx(kinds[i%len(kinds)], i)
		}
		if got, want := RebuildTxRoot(txs), oracleRoot(txs); got != want {
			t.Fatalf("%d txs: %s vs geth %s", n, got.Hex(), want.Hex())
		}
	}
}

func TestClassifyTxEnvelope(t *testing.T) {
	legacy := synthTx(0, 3)
	for ty := byte(1); ty <= 4; ty++ {
		info, err := ClassifyTx(synthTx(ty, 3))
		if err != nil || info.Type != ty || !info.Typed || !info.Standard || !bytes.Equal(info.Payload, synthTx(0, 3)) {
			t.Fatalf("type %d: %+v %v", ty, info, err)
		}
	}
	if info, err := ClassifyTx(legacy); err != nil || info.Type != 0 || info.Typed || !info.Standard || !bytes.Equal(info.Payload, legacy) {
		t.Fatalf("legacy: %+v %v", info, err)
	}
	// L2 and unknown type bytes are returned as they are, payload undecoded (even when it is not RLP)
	l2 := []byte{0x7e, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x78, 0x05, 0x7f}
	for _, ty := range l2 {
		raw := synthTx(ty, 9)
		info, err := ClassifyTx(raw)
		if err != nil || info.Type != ty || !info.Typed || info.Standard || !bytes.Equal(info.Payload, raw[1:]) {
			t.Fatalf("type 0x%02x: %+v %v", ty, info, err)
		}
	}
	// refusals
	_, err := ClassifyTx(nil)
	wantTx(t, err, TxEmpty)
	for _, first := range []byte{0x80, 0x81, 0xb7, 0xbf} {
		_, err := ClassifyTx([]byte{first, 1, 2, 3})
		wantTx(t, err, TxBadEnvelope)
	}
	_, err = ClassifyTx([]byte{0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9}) // a long-list prefix whose length does not fit
	wantTx(t, err, TxBadEnvelope)
	_, err = ClassifyTx(append(legacy, 0)) // trailing byte after the legacy list
	wantTx(t, err, TxBadEnvelope)
	_, err = ClassifyTx(append(synthTx(2, 1), 0))
	wantTx(t, err, TxBadEnvelope)
	_, err = ClassifyTx([]byte{0x02, 0x83, 1, 2, 3}) // type 2 whose payload is an RLP string
	wantTx(t, err, TxBadEnvelope)
	_, err = ClassifyTx([]byte{0x00, 0xc0}) // a 0x00 prefix is no envelope
	wantTx(t, err, TxBadEnvelope)
	_, err = ClassifyTx([]byte{0x03}) // type 3 without payload
	wantTx(t, err, TxBadEnvelope)
	// a truncated legacy list
	_, err = ClassifyTx(legacy[:len(legacy)-1])
	wantTx(t, err, TxBadEnvelope)
}

func TestVerifyBlockTxsCensusAndMutations(t *testing.T) {
	lim := DefaultLimits()
	txs := append(realTxs(t), synthTx(3, 1), synthTx(4, 2), synthTx(0x7e, 3), synthTx(0x6a, 4), synthTx(0x7f, 5))
	root := oracleRoot(txs)
	c, err := VerifyBlockTxs(root, txs, 2, txs[2], lim)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Types, []byte{0, 1, 2, 3, 4, 0x7e, 0x6a, 0x7f}) || !bytes.Equal(c.Distinct, []byte{0, 1, 2, 3, 4, 0x6a, 0x7e, 0x7f}) || c.Root != root || len(c.Infos) != 8 {
		t.Fatalf("census %+v", c)
	}
	total := 0
	for _, x := range txs {
		total += len(x)
	}
	if c.TotalBytes != total {
		t.Fatalf("total %d want %d", c.TotalBytes, total)
	}
	// a mutated transaction byte, a reordered pair, a dropped and an extra transaction: the header root no longer matches
	mut := append([][]byte{}, txs...)
	mut[2] = append([]byte{}, txs[2]...)
	mut[2][len(mut[2])-1] ^= 1
	_, err = VerifyBlockTxs(root, mut, 2, mut[2], lim)
	wantTx(t, err, TxRootMismatch)
	swapped := append([][]byte{}, txs...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	_, err = VerifyBlockTxs(root, swapped, 2, swapped[2], lim)
	wantTx(t, err, TxRootMismatch)
	_, err = VerifyBlockTxs(root, txs[:7], 2, txs[2], lim)
	wantTx(t, err, TxRootMismatch)
	_, err = VerifyBlockTxs(root, append(append([][]byte{}, txs...), synthTx(2, 99)), 2, txs[2], lim)
	wantTx(t, err, TxRootMismatch)
	// the leaf of the attestation transaction must be the list entry at its index; the index must exist
	_, err = VerifyBlockTxs(root, txs, 2, txs[3], lim)
	wantTx(t, err, TxLeafMismatch)
	te := func() *TxError {
		_, e := VerifyBlockTxs(root, txs, len(txs), txs[2], lim)
		return wantTx(t, e, TxIndexOutOfList)
	}()
	if te.Index != len(txs) {
		t.Fatal("index not carried")
	}
	_, err = VerifyBlockTxs(root, txs, -1, txs[2], lim)
	wantTx(t, err, TxIndexOutOfList)
	// a malformed entry is named with its index before the root is compared
	bad := append([][]byte{}, txs...)
	bad[5] = []byte{0x85, 1, 2}
	if te := wantTx(t, func() error { _, e := VerifyBlockTxs(root, bad, 2, txs[2], lim); return e }(), TxBadEnvelope); te.Index != 5 {
		t.Fatalf("index %d", te.Index)
	}
	// the empty block
	if c, err := VerifyBlockTxs(types.EmptyTxsHash, nil, 0, nil, lim); err == nil || c != nil {
		t.Fatal("an empty block has no attestation transaction")
	} else {
		wantTx(t, err, TxIndexOutOfList)
	}
}

func TestVerifyBlockTxsBoundsAreExact(t *testing.T) {
	lim := DefaultLimits()
	// count: 4096 passes, 4097 fails, before any classification
	mk := func(n int) [][]byte {
		txs := make([][]byte, n)
		for i := range txs {
			txs[i] = []byte{0x7f, byte(i)}
		}
		return txs
	}
	txs := mk(lim.MaxBlockTxs)
	if _, err := VerifyBlockTxs(oracleRoot(txs), txs, 0, txs[0], lim); err != nil {
		t.Fatalf("%d txs: %v", lim.MaxBlockTxs, err)
	}
	te := wantTx(t, func() error {
		_, e := VerifyBlockTxs(common.Hash{}, mk(lim.MaxBlockTxs+1), 0, nil, lim)
		return e
	}(), TxTooMany)
	if te.Got != 4097 || te.Limit != 4096 {
		t.Fatalf("%+v", te)
	}
	// total bytes: 1048576 passes, 1048577 fails
	big1 := func(n int) [][]byte {
		a := append([]byte{0x7e}, bytes.Repeat([]byte{1}, n-1)...)
		return [][]byte{a}
	}
	one := big1(lim.MaxBlockTxsBytes)
	if _, err := VerifyBlockTxs(oracleRoot(one), one, 0, one[0], lim); err != nil {
		t.Fatalf("%d bytes: %v", lim.MaxBlockTxsBytes, err)
	}
	te = wantTx(t, func() error {
		_, e := VerifyBlockTxs(common.Hash{}, big1(lim.MaxBlockTxsBytes+1), 0, nil, lim)
		return e
	}(), TxTooLarge)
	if te.Got != 1048577 || te.Limit != 1048576 {
		t.Fatalf("%+v", te)
	}
	_ = crypto.Keccak256
}
