package execution

import (
	"encoding/hex"
	"testing"
)

// The anchor-create calldata of Phase C's ethereum member (tx 0xcde94ba3… on sepolia, 2026-09-29) decodes to its
// root, and a call that is not createBatchAnchor is refused.
func TestF66_CreateBatchAnchorCalldataDecodes(t *testing.T) {
	data := append([]byte{}, createBatchAnchorSelector...)
	word := func(b byte) []byte { w := make([]byte, 32); w[31] = b; return w }
	root, _ := hex.DecodeString("4c84c233a475390a0f70c05479b6efb9e2bbb88a6c85c6cae9823e3baccb40b1")
	data = append(data, word(0xcc)...)
	data = append(data, root...)
	data = append(data, word(1)...)
	data = append(data, word(0xee)...)
	data = append(data, word(100)...)
	c, err := decodeCreateBatchAnchor(data)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(c.root[:]) != hex.EncodeToString(root) || c.leafCount != 1 || c.height != 100 || c.batchOpID[31] != 0xee {
		t.Fatalf("%+v", c)
	}
	bad := append([]byte{0xde, 0xad, 0xbe, 0xef}, data[4:]...)
	if _, err := decodeCreateBatchAnchor(bad); err == nil {
		t.Fatal("another function's calldata was taken as createBatchAnchor")
	}
	if _, err := decodeCreateBatchAnchor(data[:40]); err == nil {
		t.Fatal("truncated calldata was decoded")
	}
}
