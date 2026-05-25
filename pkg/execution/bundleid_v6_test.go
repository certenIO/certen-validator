// Phase 3 tests for the V6 bundleId derivation and the supporting commitment
// helpers. These tests are deterministic and fast — they pin the byte-level
// formula that CertenAnchorV6.createAnchor's require() check enforces, so any
// off-by-one in field ordering, length encoding, or domain tag will trip them.
//
// Plan reference: audit-reports/EVM-NEW-001-EVM-003-EVM-004-completion-plan.md
// §2.7 (generateAnchorID formula) and §4.1 (Go unit tests).

package execution

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/ethereum/go-ethereum/crypto"
)

// minimalIntent returns the smallest CertenIntent that drives the V6
// commitment computation through its non-default branches.
func minimalIntent(id string) *intent.CertenIntent {
	return &intent.CertenIntent{
		IntentID:        id,
		OrganizationADI: "acc://test-org.acme",
	}
}

// minimalProof returns the smallest CertenProof needed for the V6 derivation.
func minimalProof(txHash string, blockHeight uint64) *proof.CertenProof {
	return &proof.CertenProof{
		TransactionHash: txHash,
		BlockHeight:     blockHeight,
		AccountURL:      "acc://test-org.acme/data",
	}
}

// newTestECM produces an EthereumContractManager with just enough config
// populated to call deriveV6BundleID. None of the network-related fields are
// exercised here.
func newTestECM(chainID int64) *EthereumContractManager {
	return &EthereumContractManager{
		config: &CertenContractConfig{ChainID: chainID},
	}
}

func TestDeriveV6BundleID_MatchesSolidityFormula(t *testing.T) {
	// Inputs are the same shape the validator passes to createAnchor:
	//   keccak256("certen:bundleid:v1" || chainId || adiURLHash ||
	//             op || cc || gov || exec || height)
	// where chainId and height are 32-byte big-endian uint256s.
	var chainID int64 = 11155111 // Sepolia
	var adiURLHash [32]byte
	for i := range adiURLHash {
		adiURLHash[i] = byte(i + 1)
	}
	var op, cc, gov, exec [32]byte
	for i := range op {
		op[i] = 0xA0 | byte(i)
		cc[i] = 0xB0 | byte(i)
		gov[i] = 0xC0 | byte(i)
		exec[i] = 0xD0 | byte(i)
	}
	height := uint64(12345)

	commitments := contracts.CommitmentData{
		OperationCommitment:  op,
		CrossChainCommitment: cc,
		GovernanceRoot:       gov,
		ExecutionCommitment:  exec,
	}

	ecm := newTestECM(chainID)
	got := ecm.deriveV6BundleID(adiURLHash, commitments, height)

	// Hand-compute the expected hash. This block IS the contract's
	// require() expression in Go form; if it ever diverges from the
	// Solidity side, the on-chain create-anchor revert will trip.
	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)
	heightBytes := make([]byte, 32)
	new(big.Int).SetUint64(height).FillBytes(heightBytes)

	expected := crypto.Keccak256(
		[]byte("certen:bundleid:v1"),
		chainIDBytes,
		adiURLHash[:],
		op[:],
		cc[:],
		gov[:],
		exec[:],
		heightBytes,
	)
	if !bytes.Equal(got[:], expected) {
		t.Fatalf("V6 bundleId mismatch:\n  got:      %x\n  expected: %x", got[:], expected)
	}
}

func TestDeriveV6BundleID_ChainIDInfluencesHash(t *testing.T) {
	// Same commitments + adiURLHash on chain 1 vs. chain 137 must yield
	// different bundleIds. This is the cross-chain replay guard from
	// EVM-NEW-001 step 6 / CRYPTO-005 (and the chainId binding in the
	// EVM-004 bundleId derivation).
	var adiURLHash [32]byte
	adiURLHash[0] = 0x42
	var op, cc, gov, exec [32]byte
	op[0] = 1
	cc[0] = 2
	gov[0] = 3
	exec[0] = 4
	commitments := contracts.CommitmentData{
		OperationCommitment:  op,
		CrossChainCommitment: cc,
		GovernanceRoot:       gov,
		ExecutionCommitment:  exec,
	}

	bidChain1 := newTestECM(1).deriveV6BundleID(adiURLHash, commitments, 100)
	bidChain137 := newTestECM(137).deriveV6BundleID(adiURLHash, commitments, 100)
	if bytes.Equal(bidChain1[:], bidChain137[:]) {
		t.Fatalf("chainId must influence bundleId; got identical hashes on chain 1 and 137")
	}
}

func TestDeriveV6BundleID_AnyCommitmentFlipChangesHash(t *testing.T) {
	// Each commitment field must contribute to the hash. If any of them
	// were accidentally omitted from keccak input, a one-byte flip there
	// would NOT change the hash — and that field could be tampered with
	// without invalidating the bundleId. This test asserts no such gap.
	mkBase := func() (contracts.CommitmentData, [32]byte, uint64) {
		var a [32]byte
		a[0] = 0xAA
		var op, cc, gov, exec [32]byte
		op[31] = 1
		cc[31] = 2
		gov[31] = 3
		exec[31] = 4
		return contracts.CommitmentData{
			OperationCommitment:  op,
			CrossChainCommitment: cc,
			GovernanceRoot:       gov,
			ExecutionCommitment:  exec,
		}, a, 7
	}

	ecm := newTestECM(1)
	base, adi, h := mkBase()
	baseHash := ecm.deriveV6BundleID(adi, base, h)

	mutators := []struct {
		name    string
		applyTo func(c *contracts.CommitmentData)
	}{
		{"OperationCommitment", func(c *contracts.CommitmentData) { c.OperationCommitment[0] ^= 0xff }},
		{"CrossChainCommitment", func(c *contracts.CommitmentData) { c.CrossChainCommitment[0] ^= 0xff }},
		{"GovernanceRoot", func(c *contracts.CommitmentData) { c.GovernanceRoot[0] ^= 0xff }},
		{"ExecutionCommitment", func(c *contracts.CommitmentData) { c.ExecutionCommitment[0] ^= 0xff }},
	}
	for _, m := range mutators {
		mutated, _, _ := mkBase()
		m.applyTo(&mutated)
		mutatedHash := ecm.deriveV6BundleID(adi, mutated, h)
		if bytes.Equal(baseHash[:], mutatedHash[:]) {
			t.Errorf("flipping %s did NOT change bundleId — that field is not bound", m.name)
		}
	}

	// Flip adiURLHash too — it must also be bound.
	adi2 := adi
	adi2[0] ^= 0xff
	flippedAdi := ecm.deriveV6BundleID(adi2, base, h)
	if bytes.Equal(baseHash[:], flippedAdi[:]) {
		t.Errorf("flipping adiURLHash did NOT change bundleId")
	}

	// Flip height too.
	flippedHeight := ecm.deriveV6BundleID(adi, base, h+1)
	if bytes.Equal(baseHash[:], flippedHeight[:]) {
		t.Errorf("changing height did NOT change bundleId")
	}
}

func TestComputeEvmMessageHashV6_MatchesContractFormula(t *testing.T) {
	// CertenAnchorV6._verifyBLSProof recomputes:
	//   keccak256(abi.encodePacked(
	//     "certen:bls:v1", DEPLOYMENT_CHAIN_ID, anchorId, executionCommitment
	//   ))
	// This test pins the validator-side computeEvmMessageHashV6 to that exact
	// byte sequence. Any drift would cause every V6 proof submission to fail
	// the contract's MessageHash equality check.
	chainID := int64(11155111) // Sepolia
	ecm := newTestECM(chainID)

	var anchorId, exec [32]byte
	anchorId[0] = 0xAA
	anchorId[31] = 0x55
	exec[0] = 0xBB
	exec[31] = 0x77

	got := ecm.computeEvmMessageHashV6(anchorId, exec)

	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)
	expected := crypto.Keccak256(
		[]byte("certen:bls:v1"),
		chainIDBytes,
		anchorId[:],
		exec[:],
	)

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("EVM messageHash mismatch:\n  got:      %x\n  expected: %x", got[:], expected)
	}
}

func TestComputeEvmMessageHashV6_AnyInputFlipChangesHash(t *testing.T) {
	// Each input field (chainId, anchorId, executionCommitment) must
	// contribute to the hash — if any were silently dropped, an attacker
	// could substitute that field without invalidating the proof.
	var anchorId, exec [32]byte
	anchorId[0] = 1
	exec[0] = 2

	base := newTestECM(1).computeEvmMessageHashV6(anchorId, exec)

	// Flip chainId
	if otherChain := newTestECM(2).computeEvmMessageHashV6(anchorId, exec); base == otherChain {
		t.Errorf("chainId must contribute to messageHash")
	}
	// Flip anchorId
	anchorId2 := anchorId
	anchorId2[0] ^= 0xff
	if other := newTestECM(1).computeEvmMessageHashV6(anchorId2, exec); base == other {
		t.Errorf("anchorId must contribute to messageHash")
	}
	// Flip executionCommitment
	exec2 := exec
	exec2[0] ^= 0xff
	if other := newTestECM(1).computeEvmMessageHashV6(anchorId, exec2); base == other {
		t.Errorf("executionCommitment must contribute to messageHash")
	}
}

func TestComputeV6MerkleProofForAdi_ShapeAndContent(t *testing.T) {
	// EVM-003: the validator must submit the real 3-element merkle proof
	// against the 5-leaf domain-tagged tree. This test asserts:
	//   - ProofHashes has length 3
	//   - LeafHash equals taggedAdi = keccak256("certen:adi:" || adiURLHash)
	//   - ProofHashes are [taggedOp, hash23, taggedExec] in that exact order
	//   - The walk from LeafHash through ProofHashes lands on MerkleRoot
	var adiURLHash [32]byte
	adiURLHash[0] = 0xAD
	var op, cc, gov, exec [32]byte
	op[0] = 1
	cc[0] = 2
	gov[0] = 3
	exec[0] = 4

	commitments := contracts.CommitmentData{
		OperationCommitment:  op,
		CrossChainCommitment: cc,
		GovernanceRoot:       gov,
		ExecutionCommitment:  exec,
	}
	mp := computeV6MerkleProofForAdi(adiURLHash, commitments)

	if len(mp.ProofHashes) != 3 {
		t.Fatalf("ProofHashes must have length 3 (taggedOp, hash23, taggedExec); got %d", len(mp.ProofHashes))
	}

	// LeafHash = taggedAdi
	expectedLeaf := crypto.Keccak256(append([]byte("certen:adi:"), adiURLHash[:]...))
	if !bytes.Equal(mp.LeafHash[:], expectedLeaf) {
		t.Errorf("LeafHash mismatch:\n  got:      %x\n  expected: %x (taggedAdi)", mp.LeafHash[:], expectedLeaf)
	}

	// ProofHashes[0] = taggedOp
	expectedTaggedOp := crypto.Keccak256(append([]byte("certen:op:"), op[:]...))
	if !bytes.Equal(mp.ProofHashes[0][:], expectedTaggedOp) {
		t.Errorf("ProofHashes[0] should be taggedOp")
	}
	// ProofHashes[2] = taggedExec
	expectedTaggedExec := crypto.Keccak256(append([]byte("certen:exec:"), exec[:]...))
	if !bytes.Equal(mp.ProofHashes[2][:], expectedTaggedExec) {
		t.Errorf("ProofHashes[2] should be taggedExec")
	}

	// Walk the proof: leaf + ProofHashes[0] -> level1; level1 + ProofHashes[1]
	// -> level2; level2 + ProofHashes[2] -> root. Each step uses sortedHash
	// (smaller first), matching CertenAnchorV6._verifyMerkleProof.
	cursor := append([]byte(nil), mp.LeafHash[:]...)
	for _, sibling := range mp.ProofHashes {
		cursor = sortedHash(cursor, sibling[:])
	}
	if !bytes.Equal(cursor, mp.MerkleRoot[:]) {
		t.Errorf("walking the proof did NOT land on the merkleRoot:\n  walked:  %x\n  root:    %x", cursor, mp.MerkleRoot[:])
	}
}

func TestComputeV6MerkleProofForAdi_TamperedProofRejectsWalk(t *testing.T) {
	// Walk the proof with a flipped ProofHash and verify the result no
	// longer matches MerkleRoot. (CertenAnchorV6._verifyMerkleProof uses the
	// same walk, so this proves a tampered proof would be rejected on-chain.)
	var adiURLHash [32]byte
	var op, cc, gov, exec [32]byte
	adiURLHash[0] = 0xAA
	op[0] = 1
	cc[0] = 2
	gov[0] = 3
	exec[0] = 4
	commitments := contracts.CommitmentData{
		OperationCommitment:  op,
		CrossChainCommitment: cc,
		GovernanceRoot:       gov,
		ExecutionCommitment:  exec,
	}
	mp := computeV6MerkleProofForAdi(adiURLHash, commitments)
	tampered := append([][32]byte{}, mp.ProofHashes...)
	tampered[0][0] ^= 0xff

	cursor := append([]byte(nil), mp.LeafHash[:]...)
	for _, sibling := range tampered {
		cursor = sortedHash(cursor, sibling[:])
	}
	if bytes.Equal(cursor, mp.MerkleRoot[:]) {
		t.Fatalf("tampered proof unexpectedly walked to the same root")
	}
}

func TestGenerateCommitmentHash_DeterministicFromIntentProof(t *testing.T) {
	// generateCommitmentHash must NOT depend on anchorResult.AnchorID (V5
	// bug — caused the bundleId derivation cycle). Same (intent, proof)
	// must always produce the same opCommitment.
	ecm := newTestECM(1)
	intent := minimalIntent("intent-abc")
	proof := minimalProof("0xdeadbeef", 42)
	first := ecm.generateCommitmentHash(intent, proof)
	second := ecm.generateCommitmentHash(intent, proof)
	if first != second {
		t.Fatalf("generateCommitmentHash not deterministic: %x vs %x", first, second)
	}

	// Same intent, different proof block height → different hash.
	differentProof := minimalProof("0xdeadbeef", 43)
	if first == ecm.generateCommitmentHash(intent, differentProof) {
		t.Errorf("block height must affect opCommitment")
	}

	// Same intent + proof block, different txHash → different hash.
	differentTx := minimalProof("0xabcdef00", 42)
	if first == ecm.generateCommitmentHash(intent, differentTx) {
		t.Errorf("txHash must affect opCommitment")
	}
}
