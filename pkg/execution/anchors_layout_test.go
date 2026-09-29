//go:build live

// Behind the live build tag rather than a skip (00_STANDARD §2, RB3-F83): without the tag it is not
// compiled; with it, a missing input is a failure, never a pass.

package execution

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// ReadAnchorState decodes the `anchors` struct getter positionally, by generation (fifteen fields on V8.1, seventeen
// on V8.2). If a future anchor reordered the Anchor struct, a position would silently become some other 32 bytes, so
// this asserts the layout against a DEPLOYED contract rather than a fixture.
//
// Live test. Set all three to run it:
//
//	CERTEN_TEST_RPC_11155111  — a Sepolia RPC URL
//	CERTEN_TEST_ANCHOR        — a deployed CertenAnchorV8_1 or CertenAnchorV8_2 address
//	CERTEN_TEST_BATCH_BUNDLE  — a known batch anchor bundleId on it
func TestAnchorsTupleLayoutMatchesDeployedContract(t *testing.T) {
	rpc, anchor := os.Getenv("CERTEN_TEST_RPC_11155111"), os.Getenv("CERTEN_TEST_ANCHOR")
	bundleHex := os.Getenv("CERTEN_TEST_BATCH_BUNDLE")
	if rpc == "" || !common.IsHexAddress(anchor) || bundleHex == "" {
		t.Fatal("the live build requires CERTEN_TEST_RPC_11155111, CERTEN_TEST_ANCHOR and CERTEN_TEST_BATCH_BUNDLE")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(bundleHex, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("CERTEN_TEST_BATCH_BUNDLE must be 32 bytes of hex, got %q", bundleHex)
	}
	var bundleID [32]byte
	copy(bundleID[:], raw)

	client, err := ethclient.Dial(rpc)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	st, err := ReadAnchorState(context.Background(), client, common.HexToAddress(anchor), bundleID, nil)
	if err != nil {
		t.Fatalf("anchors(): %v", err)
	}
	// Field 0 echoes the key: the cheapest position to catch a reordered struct.
	if st.BundleID != bundleID {
		t.Fatalf("field 0 is %x, not the bundleId — the struct layout has shifted", st.BundleID)
	}
	if st.OperationID == ([32]byte{}) || st.MerkleRoot == ([32]byte{}) || !st.Valid {
		t.Fatalf("a real batch anchor decoded with operationID %x root %x valid %v — a position moved", st.OperationID, st.MerkleRoot, st.Valid)
	}
	if st.Version == contracts.BatchAnchorV8_2 && (st.AccumulateSetRoot == ([32]byte{}) || st.Incarnation == ([32]byte{})) {
		t.Fatal("a V8.2 anchor decoded without its Accumulate set root or incarnation, which createBatchAnchor requires")
	}
	t.Logf("%s layout confirmed against %s: operationID=0x%x", st.Version, anchor, st.OperationID)
}
