package execution

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// batchOperationIDViaV7 decodes operationID positionally out of the `anchors` struct getter,
// because getOperationID(bytes32) — which the code called for months — exists only on V6.1 and
// was never carried into V7/V8/V8_1. There the selector matched nothing, the call reverted with
// empty data, and it did so AFTER the flush had already mined a batch anchor: every cadence
// flush paid for an anchor and then died on the next read.
//
// Positional decoding trades one fragility for another: if a future anchor reorders the Anchor
// struct, index 7 silently becomes some other 32 bytes. So this asserts the layout against a
// DEPLOYED contract rather than a fixture.
//
// Live test. Set both to run it:
//
//	CERTEN_TEST_RPC_11155111  — a Sepolia RPC URL
//	CERTEN_TEST_ANCHOR_V8_1   — the deployed CertenAnchorV8_1 address
//	CERTEN_TEST_BATCH_BUNDLE  — (optional) a known batch anchor bundleId to decode
func TestAnchorsTupleLayoutMatchesDeployedContract(t *testing.T) {
	rpc := os.Getenv("CERTEN_TEST_RPC_11155111")
	anchor := os.Getenv("CERTEN_TEST_ANCHOR_V8_1")
	if rpc == "" || anchor == "" {
		t.Skip("set CERTEN_TEST_RPC_11155111 and CERTEN_TEST_ANCHOR_V8_1 to run this live check")
	}

	client, err := ethclient.Dial(rpc)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	bound := bind.NewBoundContract(common.HexToAddress(anchor), parsed, client, client, client)

	bundleHex := os.Getenv("CERTEN_TEST_BATCH_BUNDLE")
	if bundleHex == "" {
		t.Skip("set CERTEN_TEST_BATCH_BUNDLE to a known batch anchor to check field positions")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(bundleHex, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("CERTEN_TEST_BATCH_BUNDLE must be 32 bytes of hex, got %q", bundleHex)
	}
	var bundleID [32]byte
	copy(bundleID[:], raw)

	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: context.Background()}, &out, "anchors", bundleID); err != nil {
		t.Fatalf("anchors() call reverted — the struct getter is not present as declared: %v", err)
	}

	// The contract must expose every field this ABI names, or positional indexing is unsound.
	if len(out) != 15 {
		t.Fatalf("anchors() returned %d fields, expected 15 — the Anchor struct changed", len(out))
	}

	// Field 0 is bundleId and MUST echo the key. This is the anchor for the whole layout: if
	// the struct were reordered, this is the cheapest position to catch it.
	got0, ok := out[0].([32]byte)
	if !ok || got0 != bundleID {
		t.Fatalf("field 0 is not the bundleId (got %T %x) — struct layout has shifted", out[0], out[0])
	}

	// Field 7 is what the production path reads.
	opID, ok := out[7].([32]byte)
	if !ok {
		t.Fatalf("field 7 is %T, expected [32]byte for operationID", out[7])
	}
	if opID == ([32]byte{}) {
		t.Fatal("field 7 decoded as zero for a real batch anchor — either the anchor is not a " +
			"batch anchor or operationID is no longer at index 7")
	}

	// Field 11 (valid) must be a bool. A type mismatch here means the bytes32 run ended
	// somewhere other than where this ABI claims, which would also move index 7.
	if _, ok := out[11].(bool); !ok {
		t.Fatalf("field 11 is %T, expected bool (valid) — the bytes32 prefix length changed", out[11])
	}

	t.Logf("layout confirmed against %s: operationID=0x%x", anchor, opID)
}
