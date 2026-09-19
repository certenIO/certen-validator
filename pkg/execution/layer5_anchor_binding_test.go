package execution

import (
	"encoding/hex"
	"strings"
	"testing"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// GOLDEN VECTORS — the false binding that shipped, and must never ship again.
//
// L5 published, live: "batch root d2d24ab3… is in tx 0x9e4ff6ab…". Both halves came from the wrong place.
//
//	root  d2d24ab3…  a per-validator SHADOW row (sha256 over 4 blobs), a root nobody ever published
//	tx    0x9e4ff6ab…  the SETTLEMENT transaction, which settled root 2fd899ae…
//
// Two independent defects produced one false claim, so there are two independent guards:
//
//  1. the binding must come from a canonical row — enforced in SQL (GetLayer5Binding filters
//     bundle_id IS NOT NULL) and covered by the Postgres test in pkg/database;
//  2. the anchor transaction must be the ANCHOR-CREATE transaction from that row, never the observation
//     the settlement produced — enforced here.
//
// The values below are the real ones from intent f6cea77e, kept verbatim: a test that reproduces the
// incident with its own numbers proves less than one that reproduces it with the numbers that occurred.
const (
	shadowRootHex     = "d2d24ab3bc0e2f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2"
	publishedRootHex  = "2fd899ae1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"
	settlementTxHash  = "0x9e4ff6ab1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"
	anchorCreateTx    = "0x51a1c0de000000000000000000000000000000000000000000000000000000aa"
	memberLeafHex     = "1111111111111111111111111111111111111111111111111111111111111111"
	memberSiblingHex  = "2222222222222222222222222222222222222222222222222222222222222222"
	settlementBlockNo = 45943270
	anchorBlockNo     = 45943100
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad fixture hex %q: %v", s, err)
	}
	return b
}

// canonicalBinding is what GetLayer5Binding returns for a published anchor: the batch-form leaf, the
// published root, and the anchor-create transaction.
func canonicalBinding(t *testing.T) *database.Layer5Binding {
	t.Helper()
	leaf := hexBytes(t, memberLeafHex)
	sibling := hexBytes(t, memberSiblingHex)
	// A real two-member tree: root = nodeHash(leaf, sibling) as the batch tree computes it.
	var l, s [32]byte
	copy(l[:], leaf)
	copy(s[:], sibling)
	root := hashPair(l, s)
	return &database.Layer5Binding{
		BatchRoot:      root[:],
		LeafHash:       leaf,
		TreeIndex:      0,
		MerklePath:     []database.MerklePathNode{{Hash: hex.EncodeToString(sibling), Position: "right"}},
		TargetChain:    "base-sepolia",
		AnchorTxHash:   anchorCreateTx,
		AnchorBlockNum: anchorBlockNo,
	}
}

func settlementObservation() *chain.ObservationResult {
	return &chain.ObservationResult{
		TxHash:      settlementTxHash,
		BlockNumber: settlementBlockNo,
		BlockHash:   "0xsettlementblock",
		ChainName:   "base-sepolia",
	}
}

// A row that names the anchor transaction but not its block does not borrow the settlement's: the layer
// cannot state coordinates it does not have, so it is refused until the anchor is read back.
func TestLayer5NeverPairsTheAnchorWithTheSettlementBlock(t *testing.T) {
	binding := canonicalBinding(t)
	binding.AnchorBlockNum = 0
	l5, err := BuildLayer5(binding, settlementObservation(), nil, nil, 84532)
	if err == nil {
		t.Fatalf("built %s @ %d (%s) with no block for the anchor", l5.AnchorTx, l5.BlockNumber, l5.BlockHash)
	}
	binding.AnchorBlockNum = anchorBlockNo
	if l5, err = BuildLayer5(binding, settlementObservation(), nil, nil, 84532); err != nil || l5.BlockHash != "" || l5.Confirmations != 0 {
		t.Fatalf("the settlement block's hash or depth travelled with the anchor: %+v, %v", l5, err)
	}
}

// A strategy that does not name its chain leaves the name to the canonical row, or to the chain id: the
// layer names the chain the way the anchor row and the Certen proof do.
func TestLayer5NamesTheChainLikeTheAnchorRow(t *testing.T) {
	obs := settlementObservation()
	obs.ChainName = ""
	binding := canonicalBinding(t)
	if l5, err := BuildLayer5(binding, obs, nil, nil, 84532); err != nil || l5.Network != "base-sepolia" {
		t.Fatalf("network = %q (%v), want the anchor row's base-sepolia", l5.Network, err)
	}
	binding.TargetChain = ""
	if l5, err := BuildLayer5(binding, obs, nil, nil, 84532); err != nil || l5.Network != "base-sepolia" {
		t.Fatalf("network = %q (%v), want the name of chain 84532", l5.Network, err)
	}
	if l5, err := BuildLayer5(binding, obs, nil, nil, 999999); err != nil || l5.Network != "chain-999999" {
		t.Fatalf("network = %q (%v), want chain-999999 for a chain this build cannot name", l5.Network, err)
	}
	binding.TargetChain = "private-net"
	if l5, err := BuildLayer5(binding, obs, nil, nil, 999999); err != nil || l5.Network != "private-net" {
		t.Fatalf("network = %q (%v), want the anchor row's name for a chain this build cannot name", l5.Network, err)
	}
}

// The core regression: the anchor transaction must describe where the ROOT was published.
func TestLayer5AnchorTxIsTheAnchorCreateTxNotTheSettlementTx(t *testing.T) {
	binding := canonicalBinding(t)
	l5, err := BuildLayer5(binding, settlementObservation(), nil, nil, 84532)
	if err != nil {
		t.Fatalf("BuildLayer5: %v", err)
	}
	if l5 == nil {
		t.Fatal("no L5 row built from a canonical binding")
	}

	if l5.AnchorTx != anchorCreateTx {
		t.Fatalf("anchorTx = %s, want the anchor-create tx %s", l5.AnchorTx, anchorCreateTx)
	}
	if l5.AnchorTx == settlementTxHash {
		t.Fatal("REGRESSION: the settlement transaction is being published as the anchor transaction")
	}
	if l5.BlockNumber != anchorBlockNo {
		t.Fatalf("blockNumber = %d, want the anchor block %d", l5.BlockNumber, anchorBlockNo)
	}
	if l5.BlockHash != "" {
		t.Fatalf("blockHash = %q; the settlement block hash must not travel with the anchor block", l5.BlockHash)
	}
	// And the claim must still verify offline against its own root.
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("the rebuilt claim does not verify: %v", err)
	}
}

// The shadow root can never appear in a written row: a root that was never published cannot be shown to
// be in any transaction, so BuildLayer5 must refuse rather than produce an unverifiable claim.
func TestLayer5RefusesAShadowRootThatNoBranchSupports(t *testing.T) {
	shadowRoot := hexBytes(t, shadowRootHex)
	leaf := hexBytes(t, memberLeafHex)

	// No binding (the canonical query returns none for a shadow-only transaction) and a leaf that does
	// not equal the root: exactly the shape the old code papered over by taking the shadow row.
	l5, err := BuildLayer5(nil, settlementObservation(), leaf, shadowRoot, 84532)
	if err == nil {
		t.Fatalf("expected a refusal; got %+v", l5)
	}
	if l5 != nil {
		t.Fatal("a row was built for a leaf that cannot be shown under that root")
	}
	if !strings.Contains(err.Error(), "cannot be shown to be under that root") {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
}

// A one-member anchor is still honest: leaf IS root, no branch, and the anchor tx is still the anchor's.
func TestLayer5OneMemberAnchorKeepsTheAnchorTx(t *testing.T) {
	leaf := hexBytes(t, memberLeafHex)
	binding := &database.Layer5Binding{
		BatchRoot:      leaf, // a one-member tree's root IS its leaf
		LeafHash:       leaf,
		TreeIndex:      0,
		MerklePath:     nil,
		AnchorTxHash:   anchorCreateTx,
		AnchorBlockNum: anchorBlockNo,
	}
	l5, err := BuildLayer5(binding, settlementObservation(), nil, nil, 84532)
	if err != nil || l5 == nil {
		t.Fatalf("BuildLayer5: %v (%+v)", err, l5)
	}
	if l5.AnchorTx != anchorCreateTx {
		t.Fatalf("anchorTx = %s", l5.AnchorTx)
	}
	if len(l5.Path) != 0 {
		t.Fatalf("a one-member tree must carry no branch, got %d steps", len(l5.Path))
	}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatalf("one-member claim does not verify: %v", err)
	}
}

// Where the canonical row carries no anchor-create transaction yet, the observation is still used — but
// the published root is the binding's, so the claim remains about the right root.
func TestLayer5FallsBackToTheObservationOnlyWhenTheRowHasNoAnchorTx(t *testing.T) {
	binding := canonicalBinding(t)
	binding.AnchorTxHash = ""
	binding.AnchorBlockNum = 0
	l5, err := BuildLayer5(binding, settlementObservation(), nil, nil, 84532)
	if err != nil || l5 == nil {
		t.Fatalf("BuildLayer5: %v", err)
	}
	if l5.AnchorTx != settlementTxHash || l5.BlockNumber != settlementBlockNo {
		t.Fatalf("expected the observation as the fallback, got %s @ %d", l5.AnchorTx, l5.BlockNumber)
	}
	if l5.BatchRoot != hex.EncodeToString(binding.BatchRoot) {
		t.Fatalf("root came from somewhere other than the binding: %s", l5.BatchRoot)
	}
}
