// V6.1 A+++ golden-vector tests. Pin the EXACT byte layout that
// CertenAnchorV6_1.sol::_verifyBLSProof and the BFT signer compute, so any
// drift in either side fails here BEFORE Sepolia.
//
// Spec references:
//   - CertenAnchorV6_1.sol _verifyBLSProof (6-field abi.encode)
//   - CertenAnchorV6_1.sol _recomputeValidatorSetRoot (sorted abi.encode)
//   - pkg/consensus/v6_1_signing.go (BFT signing path)
//   - pkg/execution/ethereum_contracts.go (EVM submission path)
package contracts

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// govRoot — A+++ 10-field Accumulate Total State Binding
// =============================================================================

func TestComputeAccumulateGovRoot_PreimageLayout(t *testing.T) {
	in := AccumulateGovRootInputs{
		L1AccountHash:     bytes32From("0x01"),
		L2BPTRoot:         bytes32From("0x02"),
		L3BlockHash:       bytes32From("0x03"),
		L4ConsensusProofH: bytes32From("0x04"),
		G0CanonicalHash:   bytes32From("0x05"),
		G1CanonicalHash:   bytes32From("0x06"),
		G2CanonicalHash:   bytes32From("0x07"),
		KeypageURLHash:    bytes32From("0x08"),
		KeybookURLHash:    bytes32From("0x09"),
		OperationID:       bytes32From("0x0a"),
	}
	got := ComputeAccumulateGovRoot(in)

	// Hand-build the expected preimage: domain || 10 × 32 bytes.
	var domain [32]byte
	copy(domain[:], []byte("certen:govroot:v1.1"))
	expectedPreimage := append([]byte{}, domain[:]...)
	expectedPreimage = append(expectedPreimage, in.L1AccountHash[:]...)
	expectedPreimage = append(expectedPreimage, in.L2BPTRoot[:]...)
	expectedPreimage = append(expectedPreimage, in.L3BlockHash[:]...)
	expectedPreimage = append(expectedPreimage, in.L4ConsensusProofH[:]...)
	expectedPreimage = append(expectedPreimage, in.G0CanonicalHash[:]...)
	expectedPreimage = append(expectedPreimage, in.G1CanonicalHash[:]...)
	expectedPreimage = append(expectedPreimage, in.G2CanonicalHash[:]...)
	expectedPreimage = append(expectedPreimage, in.KeypageURLHash[:]...)
	expectedPreimage = append(expectedPreimage, in.KeybookURLHash[:]...)
	expectedPreimage = append(expectedPreimage, in.OperationID[:]...)
	if len(expectedPreimage) != 32+10*32 {
		t.Fatalf("expected %d-byte preimage, got %d", 32+10*32, len(expectedPreimage))
	}

	var want [32]byte
	copy(want[:], crypto.Keccak256(expectedPreimage))

	if got != want {
		t.Fatalf("A+++ govRoot mismatch\n  got:  %x\n  want: %x", got, want)
	}
}

func TestComputeAccumulateGovRoot_EveryFieldMatters(t *testing.T) {
	base := AccumulateGovRootInputs{
		L1AccountHash:     bytes32From("0x01"),
		L2BPTRoot:         bytes32From("0x02"),
		L3BlockHash:       bytes32From("0x03"),
		L4ConsensusProofH: bytes32From("0x04"),
		G0CanonicalHash:   bytes32From("0x05"),
		G1CanonicalHash:   bytes32From("0x06"),
		G2CanonicalHash:   bytes32From("0x07"),
		KeypageURLHash:    bytes32From("0x08"),
		KeybookURLHash:    bytes32From("0x09"),
		OperationID:       bytes32From("0x0a"),
	}
	original := ComputeAccumulateGovRoot(base)

	cases := []struct {
		name  string
		mut   func(*AccumulateGovRootInputs)
	}{
		{"L1", func(i *AccumulateGovRootInputs) { i.L1AccountHash = bytes32From("0xff") }},
		{"L2", func(i *AccumulateGovRootInputs) { i.L2BPTRoot = bytes32From("0xff") }},
		{"L3", func(i *AccumulateGovRootInputs) { i.L3BlockHash = bytes32From("0xff") }},
		{"L4", func(i *AccumulateGovRootInputs) { i.L4ConsensusProofH = bytes32From("0xff") }},
		{"G0", func(i *AccumulateGovRootInputs) { i.G0CanonicalHash = bytes32From("0xff") }},
		{"G1", func(i *AccumulateGovRootInputs) { i.G1CanonicalHash = bytes32From("0xff") }},
		{"G2", func(i *AccumulateGovRootInputs) { i.G2CanonicalHash = bytes32From("0xff") }},
		{"keypage", func(i *AccumulateGovRootInputs) { i.KeypageURLHash = bytes32From("0xff") }},
		{"keybook", func(i *AccumulateGovRootInputs) { i.KeybookURLHash = bytes32From("0xff") }},
		{"opID", func(i *AccumulateGovRootInputs) { i.OperationID = bytes32From("0xff") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perturbed := base
			tc.mut(&perturbed)
			got := ComputeAccumulateGovRoot(perturbed)
			if got == original {
				t.Fatalf("flipping %s did not change govRoot", tc.name)
			}
		})
	}
}

func TestComputeAccumulateGovRoot_AllZerosIsDeterministic(t *testing.T) {
	// All-zero inputs (G2 absent, no governance) must produce a non-trivial,
	// stable hash. Both signer and verifier produce the same value for
	// "nothing was provided," so they agree on the absence.
	got := ComputeAccumulateGovRoot(AccumulateGovRootInputs{})
	if got == ([32]byte{}) {
		t.Fatal("all-zero inputs should still hash to a non-zero value (domain tag)")
	}
	// Recompute — must be deterministic.
	again := ComputeAccumulateGovRoot(AccumulateGovRootInputs{})
	if got != again {
		t.Fatal("ComputeAccumulateGovRoot is not deterministic for empty inputs")
	}
}

// =============================================================================
// V6.1 pre-exec messageHash + bundleId
// =============================================================================

func TestComputeEvmMessageHashV6_1_Pre_PreimageLayout(t *testing.T) {
	chainID := int64(11155111) // Sepolia
	anchorId := bytes32From("0xaa")
	exec := bytes32From("0xbb")
	opID := bytes32From("0xcc")
	setRoot := bytes32From("0xdd")

	got := ComputeEvmMessageHashV6_1_Pre(chainID, anchorId, exec, opID, setRoot)

	var domain [32]byte
	copy(domain[:], []byte("certen:bls:v1:pre"))
	var chainBE [32]byte
	big.NewInt(chainID).FillBytes(chainBE[:])

	preimage := append([]byte{}, domain[:]...)
	preimage = append(preimage, chainBE[:]...)
	preimage = append(preimage, anchorId[:]...)
	preimage = append(preimage, exec[:]...)
	preimage = append(preimage, opID[:]...)
	preimage = append(preimage, setRoot[:]...)
	if len(preimage) != 6*32 {
		t.Fatalf("expected 192-byte preimage, got %d", len(preimage))
	}
	var want [32]byte
	copy(want[:], crypto.Keccak256(preimage))

	if got != want {
		t.Fatalf("V6.1 pre-exec messageHash mismatch\n  got:  %x\n  want: %x", got, want)
	}
}

func TestComputeEvmMessageHashV6_1_PreVsPostDomainsDiffer(t *testing.T) {
	chainID := int64(1)
	x := bytes32From("0xab")
	pre := ComputeEvmMessageHashV6_1_Pre(chainID, x, x, x, x)
	post := ComputeEvmMessageHashV6_1_Post(chainID, x, x, x, x)
	if pre == post {
		t.Fatal("pre and post messageHashes must differ — domain separation broken")
	}
}

func TestDeriveV6_1BundleID_IncludesOperationID(t *testing.T) {
	chainID := int64(11155111)
	adi := bytes32From("0x01")
	commits := V6_1Commitments{
		OperationCommitment:  bytes32From("0x02"),
		CrossChainCommitment: bytes32From("0x03"),
		GovernanceRoot:       bytes32From("0x04"),
		ExecutionCommitment:  bytes32From("0x05"),
	}
	h1 := DeriveV6_1BundleID(chainID, adi, commits, bytes32From("0x0a"), 100)
	h2 := DeriveV6_1BundleID(chainID, adi, commits, bytes32From("0x0b"), 100)
	if h1 == h2 {
		t.Fatal("different operationIDs must yield different bundleIds")
	}
}

// =============================================================================
// BuildV6_1PreExecBundle — full pipeline
// =============================================================================

func TestBuildV6_1PreExecBundle_DeterministicEndToEnd(t *testing.T) {
	in := V6_1PreExecBundleInputs{
		ChainID:               11155111,
		ValidatorSetRoot:      bytes32From("0xde"),
		AdiURLHash:            bytes32From("0x01"),
		OperationCommitment:   bytes32From("0x02"),
		CrossChainCommitment:  bytes32From("0x03"),
		ExecutionCommitment:   bytes32From("0x04"),
		OperationID:           bytes32From("0x05"),
		AccumulateBlockHeight: 12345,
		GovRootInputs: AccumulateGovRootInputs{
			L1AccountHash: bytes32From("0xa1"),
			L2BPTRoot:     bytes32From("0xa2"),
			OperationID:   bytes32From("0xa3"),
		},
	}
	anchorId1, govRoot1, msg1 := BuildV6_1PreExecBundle(in)
	anchorId2, govRoot2, msg2 := BuildV6_1PreExecBundle(in)
	if anchorId1 != anchorId2 || govRoot1 != govRoot2 || msg1 != msg2 {
		t.Fatal("BuildV6_1PreExecBundle is not deterministic")
	}
	// Sanity: outputs are non-zero (domain tags ensure this).
	if anchorId1 == ([32]byte{}) || govRoot1 == ([32]byte{}) || msg1 == ([32]byte{}) {
		t.Fatal("BuildV6_1PreExecBundle produced unexpected zero output")
	}
}

func TestBuildV6_1PreExecBundle_ValidatorSetRootBindingChangesMessageHash(t *testing.T) {
	base := V6_1PreExecBundleInputs{
		ChainID:               1,
		ValidatorSetRoot:      bytes32From("0xaa"),
		AdiURLHash:            bytes32From("0x01"),
		ExecutionCommitment:   bytes32From("0x02"),
		OperationID:           bytes32From("0x03"),
		AccumulateBlockHeight: 1,
	}
	_, _, m1 := BuildV6_1PreExecBundle(base)
	base.ValidatorSetRoot = bytes32From("0xbb")
	_, _, m2 := BuildV6_1PreExecBundle(base)
	if m1 == m2 {
		t.Fatal("changing validatorSetRoot must change messageHash")
	}
}

// =============================================================================
// AccumulateGovRootInputsBuilder — convenience flow used by both signing paths
// =============================================================================

func TestAccumulateGovRootInputsBuilder_NilSafeForAllSetters(t *testing.T) {
	// Each Set*FromJSON must accept nil and leave the corresponding slot
	// at zero — both signer and verifier produce identical govRoots for
	// "level not yet generated."
	b := NewAccumulateGovRootInputsBuilder().
		SetG0FromJSON(nil).
		SetG1FromJSON(nil).
		SetG2FromJSON(nil).
		SetL4ConsensusProofFromJSON(nil)
	got := b.Build()
	if got.G0CanonicalHash != ([32]byte{}) {
		t.Fatal("nil G0 should leave hash zero")
	}
	if got.G1CanonicalHash != ([32]byte{}) {
		t.Fatal("nil G1 should leave hash zero")
	}
	if got.G2CanonicalHash != ([32]byte{}) {
		t.Fatal("nil G2 should leave hash zero")
	}
	if got.L4ConsensusProofH != ([32]byte{}) {
		t.Fatal("nil L4 should leave hash zero")
	}
}

func TestAccumulateGovRootInputsBuilder_ShortHashSilentlyIgnored(t *testing.T) {
	// Hash inputs that aren't 32 bytes get skipped — both sides agree on
	// "input was bad, slot is zero."
	b := NewAccumulateGovRootInputsBuilder().
		SetL1AccountHash([]byte{1, 2, 3}).
		SetL2BPTRoot([]byte{}).
		SetL3BlockHash(nil)
	got := b.Build()
	if got.L1AccountHash != ([32]byte{}) {
		t.Fatal("3-byte L1 should be ignored")
	}
	if got.L2BPTRoot != ([32]byte{}) {
		t.Fatal("empty L2 should be ignored")
	}
	if got.L3BlockHash != ([32]byte{}) {
		t.Fatal("nil L3 should be ignored")
	}
}

// =============================================================================
// helpers
// =============================================================================

func bytes32From(s string) [32]byte {
	var out [32]byte
	hexStr := s
	if len(hexStr) >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		hexStr = hexStr[2:]
	}
	for i := 0; i < len(hexStr) && (i/2) < 32; i += 2 {
		hi := hexNibble(hexStr[i])
		var lo byte
		if i+1 < len(hexStr) {
			lo = hexNibble(hexStr[i+1])
		}
		out[i/2] = (hi << 4) | lo
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return 10 + c - 'a'
	case 'A' <= c && c <= 'F':
		return 10 + c - 'A'
	}
	return 0
}

// Sanity that bytes32From("0xff") and bytes.Equal agree for first-byte cases.
func TestBytes32From_LeftAligned(t *testing.T) {
	got := bytes32From("0xff")
	want := [32]byte{0xff}
	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("bytes32From left-alignment wrong: %x", got)
	}
}
