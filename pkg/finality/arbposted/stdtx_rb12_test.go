// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"testing"
)

// The block's signed standard transactions are the types 0-4 (legacy, access list, dynamic fee, blob, set-code); the Arbitrum internal, retry and
// delayed-origin types are not.
func TestRB12ArbStandardTxsAreTheSignedTypes(t *testing.T) {
	var txs [][]byte
	var want [][]byte
	for _, ty := range []byte{0x6a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x68, 0x64, 0x65, 0x66, 0x69} {
		tx := append([]byte{ty}, 0xc0)
		txs = append(txs, tx)
		if ty >= 1 && ty <= 4 {
			want = append(want, tx)
		}
	}
	legacy := ixTx(5) // an RLP list: type 0
	txs = append(txs, legacy)
	want = append(want, legacy)
	got := standardTxs(txs)
	if len(got) != len(want) {
		t.Fatalf("%d standard transactions, want %d", len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("standard transaction %d differs", i)
		}
	}
}
