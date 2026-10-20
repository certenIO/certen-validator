// Copyright 2026 Certen Protocol

package arbfinal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

const forceDir = "testdata/finality_arb_force1"

type forceFixture struct {
	K struct {
		Number       uint64 `json:"number"`
		Hash         string `json:"hash"`
		TxRoot       string `json:"transactions_root"`
		ReceiptsRoot string `json:"receipts_root"`
	} `json:"k"`
	TxIndex uint32 `json:"tx_index"`
	TxHash  string `json:"tx_hash"`
	Expect  string `json:"expect"`
}

func readNodes(t *testing.T, b []byte) [][]byte {
	t.Helper()
	n := int(binary.BigEndian.Uint32(b))
	off := 4
	var out [][]byte
	for i := 0; i < n; i++ {
		l := int(binary.BigEndian.Uint32(b[off:]))
		off += 4
		out = append(out, b[off:off+l])
		off += l
	}
	if off != len(b) {
		t.Fatal("nodes.bin: trailing bytes")
	}
	return out
}

func h32(t *testing.T, s string) common.Hash {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hash %q", s)
	}
	return common.BytesToHash(b)
}

// The real owner force-confirmation of 2025-10-13 (tx 0x350518a9..., Sepolia block 9404699): proven under the block's roots with
// the carried nodes and classified as confirmed_by_owner_force{force}, byte for byte the fixture's literal.
func TestRealOwnerForceConfirmationIsClassifiedByItsLog(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(forceDir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx forceFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	m, err := os.ReadFile(filepath.Join(forceDir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(m, &man); err != nil {
		t.Fatal(err)
	}
	for name, want := range man.Files {
		b, err := os.ReadFile(filepath.Join(forceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != want {
			t.Errorf("%s hashes to %x, manifest says %s", name, s, want)
		}
	}
	tx, _ := os.ReadFile(filepath.Join(forceDir, "tx.bin"))
	rc, _ := os.ReadFile(filepath.Join(forceDir, "receipt.bin"))
	nb, _ := os.ReadFile(filepath.Join(forceDir, "nodes.bin"))
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	arb, err := LoadPins(pins)
	if err != nil {
		t.Fatal(err)
	}
	// the assertion is the Rollup's AssertionConfirmed log topic1 of the real receipt
	var r types.Receipt
	if err := r.UnmarshalBinary(rc); err != nil {
		t.Fatal(err)
	}
	var assertion [32]byte
	var forced bool
	for _, l := range r.Logs {
		if l.Address == arb.Rollup && l.Topics[0] == arb.Topic.Confirmed {
			assertion = l.Topics[1]
		}
		if l.Address == arb.Rollup && l.Topics[0] == arb.Topic.ForceConfirmed {
			forced = true
		}
	}
	if assertion == ([32]byte{}) || !forced {
		t.Fatalf("the real receipt lacks the Rollup AssertionConfirmed (%x) or AssertionForceConfirmed (%v) log", assertion, forced)
	}
	var stx types.Transaction
	if err := stx.UnmarshalBinary(tx); err != nil {
		t.Fatal(err)
	}
	if stx.To() != nil && *stx.To() == arb.Rollup {
		t.Fatal("the real force transaction was sent to the Rollup directly; the fixture is not the owner-path shape")
	}
	kh := finality.HeaderFields{TransactionRoot: h32(t, fx.K.TxRoot), ReceiptsRoot: h32(t, fx.K.ReceiptsRoot), Number: fx.K.Number}
	kb := ethl1.L1Block{Hash: h32(t, fx.K.Hash), Number: fx.K.Number}
	e := Evidence{ConfTxIndex: fx.TxIndex, ConfTxRaw: tx, ConfReceiptRaw: rc, Nodes: readNodes(t, nb)}
	_, err = classifyConfirmation(arb, kb, kh, nil, assertion, e)
	s, ok := finality.AsNamed(err)
	if !ok {
		t.Fatalf("got %v, want confirmed_by_owner_force", err)
	}
	if got := string(s.Canonical()); got != fx.Expect {
		t.Fatalf("got  %s\nwant %s", got, fx.Expect)
	}
	if s.Fields["tx"] != [32]byte(h32(t, fx.TxHash)) {
		t.Fatalf("tx %v", s.Fields["tx"])
	}
	// a proof for another index, another root, or another assertion is not accepted as the same fact
	e2 := e
	e2.ConfTxIndex++
	if _, err := classifyConfirmation(arb, kb, kh, nil, assertion, e2); err == nil || !strings.Contains(err.Error(), CodeTxProofInvalid) {
		t.Fatalf("another index: %v", err)
	}
	kh2 := kh
	kh2.ReceiptsRoot[0] ^= 1
	if _, err := classifyConfirmation(arb, kb, kh2, nil, assertion, e); err == nil || !strings.Contains(err.Error(), CodeTxProofInvalid) {
		t.Fatalf("another receipts root: %v", err)
	}
	other := assertion
	other[0] ^= 1
	if _, err := classifyConfirmation(arb, kb, kh, nil, other, e); err == nil || !strings.Contains(err.Error(), string(ConfirmLogMissing)) {
		t.Fatalf("another assertion: %v", err)
	}
}
