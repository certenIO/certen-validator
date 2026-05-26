// Copyright 2025 Certen Protocol
//
// BLS ZK Prover - Generates Groth16 proofs for BLS signature verification
//
// This package provides:
//   - Circuit compilation and setup (one-time)
//   - Proof generation for BLS signatures
//   - Verification key export for Solidity contract
//   - Proof serialization for on-chain submission

package bls_zkp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bn254_curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// TYPES
// =============================================================================

// BLSZKProver handles ZK proof generation for BLS signatures
type BLSZKProver struct {
	mu sync.RWMutex

	// Compiled circuit constraint system
	cs constraint.ConstraintSystem

	// Groth16 proving and verification keys
	pk groth16.ProvingKey
	vk groth16.VerifyingKey

	// Initialization state
	initialized bool
}

// BLSZKProof represents a generated proof ready for on-chain verification.
//
// V2 (BLSSignatureCircuitV2) adds two Pedersen artifacts that the V2 verifier
// reconstructs and consumes: Commitments (one G1 point, 2 coordinates) and
// CommitmentPok (proof-of-knowledge of the commitment, also one G1 point).
// These are required for groth16.Verify and for serialization to the V2
// BLSZKVerifierV2 ABI; they are zero/nil on legacy V1 proofs.
type BLSZKProof struct {
	// Groth16 proof components (A, B, C points)
	ProofA [2]*big.Int   `json:"proofA"`
	ProofB [2][2]*big.Int `json:"proofB"`
	ProofC [2]*big.Int   `json:"proofC"`

	// V2 BSB22 Pedersen artifacts — populated by extractProofComponents from
	// the underlying *groth16_bn254.Proof. Required by BLSZKVerifierV2Generated.
	Commitments   [2]*big.Int `json:"commitments,omitempty"`
	CommitmentPok [2]*big.Int `json:"commitmentPok,omitempty"`

	// Public inputs (4 total - must match BLSZKVerifierV2Generated)
	MessageHash       [32]byte `json:"messageHash"`
	PubkeyCommitment  [32]byte `json:"pubkeyCommitment"`
	SignedVotingPower uint64   `json:"signedVotingPower"`
	TotalVotingPower  uint64   `json:"totalVotingPower"`

	// V1 legacy: SignatureCommitment was a private circuit input on the old
	// SimpleBLSCircuit. Unused by V2 but kept for backward-compatible JSON.
	SignatureCommitment *big.Int `json:"signatureCommitment,omitempty"`

	// Threshold parameters — V2 ignores these (verifier reads its own stored
	// numerator/denominator), retained for V1-shape JSON callers.
	ThresholdNumerator   uint64 `json:"thresholdNumerator"`
	ThresholdDenominator uint64 `json:"thresholdDenominator"`
}

// setG1Coords assigns BLS12-381 G1 coordinates from big.Ints and verifies the
// point lies on the curve. Returns the populated point for convenient use.
func setG1Coords(p *bls12381.G1Affine, x, y *big.Int) (bls12381.G1Affine, error) {
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	if !p.IsOnCurve() {
		return bls12381.G1Affine{}, errors.New("G1 point not on BLS12-381 curve")
	}
	return *p, nil
}

// setG2Coords assigns BLS12-381 G2 coordinates (each in Fp2) and verifies the
// point lies on the curve.
func setG2Coords(p *bls12381.G2Affine, x0, x1, y0, y1 *big.Int) error {
	p.X.A0.SetBigInt(x0)
	p.X.A1.SetBigInt(x1)
	p.Y.A0.SetBigInt(y0)
	p.Y.A1.SetBigInt(y1)
	if !p.IsOnCurve() {
		return errors.New("G2 point not on BLS12-381 curve")
	}
	return nil
}

// VerificationKeyExport contains the verification key in Solidity-compatible format
type VerificationKeyExport struct {
	Alpha1 [2]*big.Int   `json:"alpha1"`
	Beta2  [2][2]*big.Int `json:"beta2"`
	Gamma2 [2][2]*big.Int `json:"gamma2"`
	Delta2 [2][2]*big.Int `json:"delta2"`
	IC     [][2]*big.Int  `json:"ic"`
}

// BLSSignatureWitness contains the private and public inputs for proof generation
type BLSSignatureWitness struct {
	// Public inputs
	MessageHash       [32]byte
	PubkeyCommitment  [32]byte
	SignedVotingPower uint64
	TotalVotingPower  uint64

	// Private inputs - signature point (G1)
	SignatureX *big.Int
	SignatureY *big.Int

	// Private inputs - aggregated public key point (G2)
	PubkeyX0 *big.Int
	PubkeyX1 *big.Int
	PubkeyY0 *big.Int
	PubkeyY1 *big.Int

	// Private inputs - H(message) point (G1)
	HashedMessageX *big.Int
	HashedMessageY *big.Int
}

// =============================================================================
// PROVER INITIALIZATION
// =============================================================================

// NewBLSZKProver creates a new BLS ZK prover instance
func NewBLSZKProver() *BLSZKProver {
	return &BLSZKProver{}
}

// Initialize compiles the circuit and generates proving/verification keys.
// This is a one-time setup operation that can take several minutes for V2
// (BLSSignatureCircuitV2 has ~775k constraints because of the emulated
// BLS12-381 pairing).
//
// EVM-NEW-001 (audit-reports/01-evm-VERIFIED.md:552) replaced the placeholder
// V1 SimpleBLSCircuit (which proved only linear commitments + a threshold
// inequality and DID NOT actually verify a BLS signature) with V2 which
// performs the real BLS12-381 pairing inside the BN254 SNARK.
//
// Operator note: V1-era on-disk keys (proving_key.bin / verification_key.bin
// / constraint_system.bin) are INCOMPATIBLE with V2 — the constraint system
// shape differs entirely. InitializeFromKeys will return a decode error on
// V1 key files. Run the V2 trusted setup (or use the V2 fixtures from
// pkg/crypto/bls_zkp/testdata/v2_fixtures.json) before starting the validator
// against a chain running V2 contracts.
func (p *BLSZKProver) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return nil
	}

	// Define the V2 circuit (real BLS pairing inside BN254).
	var circuit BLSSignatureCircuitV2

	// Compile the circuit to R1CS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile V2 circuit: %w", err)
	}
	p.cs = cs

	// Generate proving and verification keys (trusted setup)
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("groth16 setup: %w", err)
	}
	p.pk = pk
	p.vk = vk

	p.initialized = true
	return nil
}

// InitializeFromKeys loads pre-generated keys from files
func (p *BLSZKProver) InitializeFromKeys(pkPath, vkPath, csPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return nil
	}

	// Load constraint system
	csFile, err := os.Open(csPath)
	if err != nil {
		return fmt.Errorf("open constraint system: %w", err)
	}
	defer csFile.Close()

	p.cs = groth16.NewCS(ecc.BN254)
	_, err = p.cs.ReadFrom(csFile)
	if err != nil {
		return fmt.Errorf("read constraint system: %w", err)
	}

	// Load proving key
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return fmt.Errorf("open proving key: %w", err)
	}
	defer pkFile.Close()

	p.pk = groth16.NewProvingKey(ecc.BN254)
	_, err = p.pk.ReadFrom(pkFile)
	if err != nil {
		return fmt.Errorf("read proving key: %w", err)
	}

	// Load verification key
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return fmt.Errorf("open verification key: %w", err)
	}
	defer vkFile.Close()

	p.vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = p.vk.ReadFrom(vkFile)
	if err != nil {
		return fmt.Errorf("read verification key: %w", err)
	}

	p.initialized = true
	return nil
}

// SaveKeys saves the generated keys to files for later use
func (p *BLSZKProver) SaveKeys(pkPath, vkPath, csPath string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return errors.New("prover not initialized")
	}

	// Save constraint system
	csFile, err := os.Create(csPath)
	if err != nil {
		return fmt.Errorf("create constraint system file: %w", err)
	}
	defer csFile.Close()
	_, err = p.cs.WriteTo(csFile)
	if err != nil {
		return fmt.Errorf("write constraint system: %w", err)
	}

	// Save proving key
	pkFile, err := os.Create(pkPath)
	if err != nil {
		return fmt.Errorf("create proving key file: %w", err)
	}
	defer pkFile.Close()
	_, err = p.pk.WriteTo(pkFile)
	if err != nil {
		return fmt.Errorf("write proving key: %w", err)
	}

	// Save verification key
	vkFile, err := os.Create(vkPath)
	if err != nil {
		return fmt.Errorf("create verification key file: %w", err)
	}
	defer vkFile.Close()
	_, err = p.vk.WriteTo(vkFile)
	if err != nil {
		return fmt.Errorf("write verification key: %w", err)
	}

	return nil
}

// =============================================================================
// PROOF GENERATION
// =============================================================================

// GenerateProof generates a V2 Groth16 proof for a BLS signature.
//
// Witness translation: BLSSignatureWitness stores the BLS aggregate signature
// (G1) and the aggregate pubkey (G2) as separate big.Int coordinates that were
// extracted in BLS12-381 Fp form by CreateWitnessFromBLSData. We rebuild the
// native gnark-crypto bls12381.G1Affine / G2Affine values and hand them to
// BuildV2Witness, which (a) constructs the V2 circuit witness with Signature /
// Pubkey as sw_bls12381 emulated points and (b) computes the V2 pubkey
// commitment (MiMC over the G2 limbs) — the legacy V1 commitment
// PubkeyCommitment = PubkeyX + 7*PubkeyY in BLSSignatureWitness is discarded.
//
// Proving uses backend.WithProverHashToFieldFunction(NewKeccakToFieldHash())
// so the BSB22 Pedersen commitment is hashed with the same keccak-mod-R the
// on-chain BLSZKVerifierV2Generated.publicInputMSM uses; without this override
// the off-chain proof passes gnark.Verify but the on-chain pairing check fails.
func (p *BLSZKProver) GenerateProof(witness *BLSSignatureWitness) (*BLSZKProof, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, errors.New("prover not initialized")
	}

	// Rebuild the native gnark-crypto G1/G2 affine points from the witness's
	// big.Int coordinates (which are BLS12-381 Fp values, not BN254 Fr).
	var sigPoint bls12381.G1Affine
	if _, err := setG1Coords(&sigPoint, witness.SignatureX, witness.SignatureY); err != nil {
		return nil, fmt.Errorf("rebuild G1 signature point: %w", err)
	}

	var pkPoint bls12381.G2Affine
	if err := setG2Coords(&pkPoint, witness.PubkeyX0, witness.PubkeyX1, witness.PubkeyY0, witness.PubkeyY1); err != nil {
		return nil, fmt.Errorf("rebuild G2 pubkey point: %w", err)
	}

	// Construct the V2 circuit witness and compute the V2 pubkey commitment.
	assignment, pkCommitmentV2, err := BuildV2Witness(
		witness.MessageHash,
		sigPoint,
		pkPoint,
		witness.SignedVotingPower,
		witness.TotalVotingPower,
	)
	if err != nil {
		return nil, fmt.Errorf("BuildV2Witness: %w", err)
	}

	witnessData, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	// Generate proof with keccak-mod-R hash override (matches on-chain BSB22).
	proof, err := groth16.Prove(p.cs, p.pk, witnessData,
		backend.WithProverHashToFieldFunction(NewKeccakToFieldHash()),
	)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// Extract A, B, C, and the Pedersen commitments / PoK that the V2 verifier needs.
	zkProof, err := extractProofComponents(proof)
	if err != nil {
		return nil, fmt.Errorf("extract proof components: %w", err)
	}

	// Set public inputs — note PubkeyCommitment now comes from BuildV2Witness,
	// NOT from the V1-style witness.PubkeyCommitment field.
	zkProof.MessageHash = witness.MessageHash
	zkProof.PubkeyCommitment = pkCommitmentV2
	zkProof.SignedVotingPower = witness.SignedVotingPower
	zkProof.TotalVotingPower = witness.TotalVotingPower

	// === DIAGNOSTIC: Verify proof locally + manual pairing check ===
	localResult, localErr := p.VerifyProofLocally(zkProof)
	log.Printf("🔍 [BLS-ZK-DIAG] gnark local verify: result=%v err=%v", localResult, localErr)

	manualResult, manualErr := p.ManualPairingCheck(zkProof)
	log.Printf("🔍 [BLS-ZK-DIAG] Manual 4-pairing check: result=%v err=%v", manualResult, manualErr)

	vkHash, vkBuf := p.ComputeVKHash()
	log.Printf("🔍 [BLS-ZK-DIAG] VK hash (sha256): %s", hex.EncodeToString(vkHash[:]))
	// Also compute keccak256 for comparison with Solana on-chain VK hash
	keccakHash := crypto.Keccak256(vkBuf)
	log.Printf("🔍 [BLS-ZK-DIAG] VK keccak=%x (matches Rust G16-DIAG)", keccakHash[:8])

	// Log VK commitment info
	if vkBN254, ok := p.vk.(*groth16_bn254.VerifyingKey); ok {
		log.Printf("🔍 [BLS-ZK-DIAG] VK CommitmentKeys=%d PublicAndCommitmentCommitted=%d IC=%d",
			len(vkBN254.CommitmentKeys), len(vkBN254.PublicAndCommitmentCommitted), len(vkBN254.G1.K))
	}

	return zkProof, nil
}

// VerifyProofLocally verifies a proof locally (for testing)
func (p *BLSZKProver) VerifyProofLocally(proof *BLSZKProof) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return false, errors.New("prover not initialized")
	}

	// V2 public witness — same 4 public inputs as V1 (MessageHash,
	// PubkeyCommitment, SignedVotingPower, TotalVotingPower), but assigned via
	// BLSSignatureCircuitV2 so the circuit shape matches the compiled R1CS.
	// Signature/Pubkey are private fields; frontend.PublicOnly() strips them.
	assignment := &BLSSignatureCircuitV2{
		MessageHash:       new(big.Int).SetBytes(proof.MessageHash[:]),
		PubkeyCommitment:  new(big.Int).SetBytes(proof.PubkeyCommitment[:]),
		SignedVotingPower: proof.SignedVotingPower,
		TotalVotingPower:  proof.TotalVotingPower,
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("create public witness: %w", err)
	}

	// Reconstruct Groth16 proof from components.
	// reconstructProof must restore the V2 Pedersen commitments / PoK from
	// BLSZKProof.Commitments / CommitmentPok or Verify will fail with a
	// commitment-mismatch error.
	groth16Proof, err := reconstructProof(proof)
	if err != nil {
		return false, fmt.Errorf("reconstruct proof: %w", err)
	}

	// V2 verify uses keccak-mod-R for the BSB22 hash — matches the on-chain
	// publicInputMSM step in BLSZKVerifierV2Generated.
	err = groth16.Verify(groth16Proof, p.vk, publicWitness,
		backend.WithVerifierHashToFieldFunction(NewKeccakToFieldHash()),
	)
	if err != nil {
		return false, nil // Verification failed, but not an error
	}

	return true, nil
}

// =============================================================================
// VERIFICATION KEY EXPORT
// =============================================================================

// ExportVerificationKey exports the verification key in Solidity-compatible format
func (p *BLSZKProver) ExportVerificationKey() (*VerificationKeyExport, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, errors.New("prover not initialized")
	}

	// Cast to concrete BN254 verification key type
	vkBN254, ok := p.vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return nil, errors.New("verification key is not BN254 type")
	}

	// Extract Alpha1 (G1 point)
	alpha1X := new(big.Int)
	alpha1Y := new(big.Int)
	vkBN254.G1.Alpha.X.BigInt(alpha1X)
	vkBN254.G1.Alpha.Y.BigInt(alpha1Y)

	// Extract Beta2 (G2 point) - G2 points have X and Y as E2 (A0, A1)
	beta2X0 := new(big.Int)
	beta2X1 := new(big.Int)
	beta2Y0 := new(big.Int)
	beta2Y1 := new(big.Int)
	vkBN254.G2.Beta.X.A0.BigInt(beta2X0)
	vkBN254.G2.Beta.X.A1.BigInt(beta2X1)
	vkBN254.G2.Beta.Y.A0.BigInt(beta2Y0)
	vkBN254.G2.Beta.Y.A1.BigInt(beta2Y1)

	// Extract Gamma2 (G2 point)
	gamma2X0 := new(big.Int)
	gamma2X1 := new(big.Int)
	gamma2Y0 := new(big.Int)
	gamma2Y1 := new(big.Int)
	vkBN254.G2.Gamma.X.A0.BigInt(gamma2X0)
	vkBN254.G2.Gamma.X.A1.BigInt(gamma2X1)
	vkBN254.G2.Gamma.Y.A0.BigInt(gamma2Y0)
	vkBN254.G2.Gamma.Y.A1.BigInt(gamma2Y1)

	// Extract Delta2 (G2 point)
	delta2X0 := new(big.Int)
	delta2X1 := new(big.Int)
	delta2Y0 := new(big.Int)
	delta2Y1 := new(big.Int)
	vkBN254.G2.Delta.X.A0.BigInt(delta2X0)
	vkBN254.G2.Delta.X.A1.BigInt(delta2X1)
	vkBN254.G2.Delta.Y.A0.BigInt(delta2Y0)
	vkBN254.G2.Delta.Y.A1.BigInt(delta2Y1)

	// Extract IC points (G1 array)
	icPoints := make([][2]*big.Int, len(vkBN254.G1.K))
	for i, icPoint := range vkBN254.G1.K {
		icX := new(big.Int)
		icY := new(big.Int)
		icPoint.X.BigInt(icX)
		icPoint.Y.BigInt(icY)
		icPoints[i] = [2]*big.Int{icX, icY}
	}

	export := &VerificationKeyExport{
		Alpha1: [2]*big.Int{alpha1X, alpha1Y},
		Beta2:  [2][2]*big.Int{{beta2X0, beta2X1}, {beta2Y0, beta2Y1}},
		Gamma2: [2][2]*big.Int{{gamma2X0, gamma2X1}, {gamma2Y0, gamma2Y1}},
		Delta2: [2][2]*big.Int{{delta2X0, delta2X1}, {delta2Y0, delta2Y1}},
		IC:     icPoints,
	}

	return export, nil
}

// ExportVerificationKeyJSON exports verification key as JSON for contract deployment
func (p *BLSZKProver) ExportVerificationKeyJSON() ([]byte, error) {
	export, err := p.ExportVerificationKey()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(export, "", "  ")
}

// =============================================================================
// PROOF SERIALIZATION FOR ON-CHAIN SUBMISSION
// =============================================================================

// blsProofABI defines the ABI for the BLSSignatureProof struct used by
// BLSZKVerifierV2 in evm/src/core/BLSZKVerifierV2.sol:
//
//   struct Groth16Proof {
//       uint256[2] a;
//       uint256[2][2] b;
//       uint256[2] c;
//   }
//   struct BLSSignatureProof {
//       Groth16Proof proof;
//       uint256[2] commitments;
//       uint256[2] commitmentPok;
//       bytes32 messageHash;
//       bytes32 pubkeyCommitment;
//       uint256 signedVotingPower;
//       uint256 totalVotingPower;
//       uint256 thresholdNumerator;   // ignored by contract; kept for ABI stability
//       uint256 thresholdDenominator; // ignored by contract; kept for ABI stability
//   }
//
// V6's CertenAnchorV6 calls IBLSZKVerifier.verifyBLSSignature(bytes, bytes32);
// BLSZKVerifierV2 then runs abi.decode(bytes, (BLSSignatureProof)). All fields
// of BLSSignatureProof are statically sized, so abi.encode(struct) is byte-
// equivalent to abi.encode(field1, field2, ...). Each call site below packs
// the matching fields in order and strips the 4-byte selector — the remaining
// bytes are exactly what BLSZKVerifierV2 decodes.
var blsProofABI = mustParseABI(`[{
	"name": "encodeProof",
	"type": "function",
	"inputs": [
		{"name": "proof", "type": "tuple", "components": [
			{"name": "a", "type": "uint256[2]"},
			{"name": "b", "type": "uint256[2][2]"},
			{"name": "c", "type": "uint256[2]"}
		]},
		{"name": "commitments", "type": "uint256[2]"},
		{"name": "commitmentPok", "type": "uint256[2]"},
		{"name": "messageHash", "type": "bytes32"},
		{"name": "pubkeyCommitment", "type": "bytes32"},
		{"name": "signedVotingPower", "type": "uint256"},
		{"name": "totalVotingPower", "type": "uint256"},
		{"name": "thresholdNumerator", "type": "uint256"},
		{"name": "thresholdDenominator", "type": "uint256"}
	]
}]`)

// mustParseABI parses an ABI JSON string, panicking on error
func mustParseABI(abiJSON string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return parsed
}

// nonNilBI returns the input if non-nil, otherwise a fresh big.NewInt(0).
// Used to defend Pack from nil *big.Int dereferences when a V1-shaped
// BLSZKProof lacks V2 commitments.
func nonNilBI(b *big.Int) *big.Int {
	if b == nil {
		return big.NewInt(0)
	}
	return b
}

// solGroth16Proof is the Go shape of the Groth16Proof Solidity struct. Field
// names (A, B, C) are matched case-insensitively against the ABI components
// (a, b, c) by go-ethereum's abi.Pack reflection path.
type solGroth16Proof struct {
	A [2]*big.Int
	B [2][2]*big.Int
	C [2]*big.Int
}

// ToSolidityCalldata converts the proof to Solidity-compatible calldata in
// the V2 BLSSignatureProof wire format consumed by BLSZKVerifierV2:
//
//   abi.encode(BLSSignatureProof{
//     proof = Groth16Proof{a, b, c},
//     commitments, commitmentPok,
//     messageHash, pubkeyCommitment,
//     signedVotingPower, totalVotingPower,
//     thresholdNumerator, thresholdDenominator
//   })
//
// All fields are statically sized, so the encoding of the single struct is
// byte-equivalent to the concatenated encodings of its fields in order.
// Packing them as the 9 inputs of `encodeProof` and stripping the 4-byte
// method selector therefore yields the exact bytes BLSZKVerifierV2 decodes.
func (proof *BLSZKProof) ToSolidityCalldata() ([]byte, error) {
	// G2 element B must be encoded in EIP-197 imag-then-real ordering for
	// the on-chain BN254 pairing precompile (address 0x08). The proof
	// struct stores B in gnark-native real-then-imag (A0=real, A1=imag);
	// swap here at the serialization boundary so the bytes match what
	// gnark.MarshalSolidity (and BLSZKVerifierV2Generated.verifyProof)
	// expect. Without this swap, on-chain pairing fails with ProofInvalid
	// even though the proof verifies locally.
	proofTuple := solGroth16Proof{
		A: [2]*big.Int{nonNilBI(proof.ProofA[0]), nonNilBI(proof.ProofA[1])},
		B: [2][2]*big.Int{
			{nonNilBI(proof.ProofB[0][1]), nonNilBI(proof.ProofB[0][0])}, // X.A1, X.A0
			{nonNilBI(proof.ProofB[1][1]), nonNilBI(proof.ProofB[1][0])}, // Y.A1, Y.A0
		},
		C: [2]*big.Int{nonNilBI(proof.ProofC[0]), nonNilBI(proof.ProofC[1])},
	}

	commitments := [2]*big.Int{nonNilBI(proof.Commitments[0]), nonNilBI(proof.Commitments[1])}
	commitmentPok := [2]*big.Int{nonNilBI(proof.CommitmentPok[0]), nonNilBI(proof.CommitmentPok[1])}

	signedVP := new(big.Int).SetUint64(proof.SignedVotingPower)
	totalVP := new(big.Int).SetUint64(proof.TotalVotingPower)

	thresholdNum := new(big.Int).SetUint64(proof.ThresholdNumerator)
	thresholdDenom := new(big.Int).SetUint64(proof.ThresholdDenominator)
	if thresholdNum.Sign() == 0 {
		thresholdNum = big.NewInt(2)
	}
	if thresholdDenom.Sign() == 0 {
		thresholdDenom = big.NewInt(3)
	}

	encoded, err := blsProofABI.Pack("encodeProof",
		proofTuple,
		commitments,
		commitmentPok,
		proof.MessageHash,
		proof.PubkeyCommitment,
		signedVP,
		totalVP,
		thresholdNum,
		thresholdDenom,
	)
	if err != nil {
		return nil, fmt.Errorf("abi pack proof: %w", err)
	}

	if len(encoded) < 4 {
		return nil, errors.New("encoded data too short")
	}
	return encoded[4:], nil
}

// Deprecated: ToSolidityCalldataRaw produces V1-shape raw bytes (no Pedersen
// commitments, V1 field ordering). The V2 wire format consumed by
// BLSZKVerifierV2 is the ABI-encoded BLSSignatureProof produced by
// ToSolidityCalldata. There are no callers of this function in the validator
// codebase (grep `ToSolidityCalldataRaw` shows only this definition and stale
// validator-build snapshots), and it is retained only for compatibility with
// any out-of-tree consumer that might call it. Delete in a future cleanup.
//
// ToSolidityCalldataRaw converts the proof to raw byte format (without ABI struct encoding)
// This is useful for contracts that expect raw concatenated values
func (proof *BLSZKProof) ToSolidityCalldataRaw() []byte {
	encoded := make([]byte, 0, 448) // Pre-allocate for efficiency (added threshold fields)

	// Encode proof A (2 uint256)
	encoded = append(encoded, padBigInt(proof.ProofA[0])...)
	encoded = append(encoded, padBigInt(proof.ProofA[1])...)

	// Encode proof B (2x2 uint256)
	encoded = append(encoded, padBigInt(proof.ProofB[0][0])...)
	encoded = append(encoded, padBigInt(proof.ProofB[0][1])...)
	encoded = append(encoded, padBigInt(proof.ProofB[1][0])...)
	encoded = append(encoded, padBigInt(proof.ProofB[1][1])...)

	// Encode proof C (2 uint256)
	encoded = append(encoded, padBigInt(proof.ProofC[0])...)
	encoded = append(encoded, padBigInt(proof.ProofC[1])...)

	// Encode public inputs
	encoded = append(encoded, proof.MessageHash[:]...)
	encoded = append(encoded, proof.PubkeyCommitment[:]...)
	encoded = append(encoded, padUint64(proof.SignedVotingPower)...)
	encoded = append(encoded, padUint64(proof.TotalVotingPower)...)

	// Default threshold to 2/3 if not set
	thresholdNum := proof.ThresholdNumerator
	thresholdDenom := proof.ThresholdDenominator
	if thresholdNum == 0 {
		thresholdNum = 2
	}
	if thresholdDenom == 0 {
		thresholdDenom = 3
	}
	encoded = append(encoded, padUint64(thresholdNum)...)
	encoded = append(encoded, padUint64(thresholdDenom)...)

	return encoded
}

// ProofHash returns a unique hash of the proof for caching/deduplication
func (proof *BLSZKProof) ProofHash() [32]byte {
	h := sha256.New()
	h.Write(padBigInt(proof.ProofA[0]))
	h.Write(padBigInt(proof.ProofA[1]))
	h.Write(padBigInt(proof.ProofC[0]))
	h.Write(padBigInt(proof.ProofC[1]))
	h.Write(proof.MessageHash[:])
	h.Write(proof.PubkeyCommitment[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ToHex returns the proof as a hex string for debugging
func (proof *BLSZKProof) ToHex() string {
	calldata, _ := proof.ToSolidityCalldata()
	return hex.EncodeToString(calldata)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// computeCommitment computes a simple commitment from two field elements
func computeCommitment(x, y *big.Int) *big.Int {
	if x == nil || y == nil {
		return big.NewInt(0)
	}
	// commitment = x + y * 7
	seven := big.NewInt(7)
	result := new(big.Int).Mul(y, seven)
	result.Add(result, x)
	return result
}

// extractProofComponents extracts A, B, C points from a gnark proof
func extractProofComponents(proof groth16.Proof) (*BLSZKProof, error) {
	// Cast to concrete BN254 proof type
	proofBN254, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		return nil, errors.New("proof is not BN254 type")
	}

	// === DIAGNOSTIC: Check for Pedersen commitments ===
	log.Printf("🔍 [BLS-ZK-DIAG] gnark proof Commitments count: %d", len(proofBN254.Commitments))
	if len(proofBN254.Commitments) > 0 {
		log.Printf("⚠️ [BLS-ZK-DIAG] PROOF HAS %d PEDERSEN COMMITMENTS - standard 4-pairing check may be INCOMPLETE!", len(proofBN254.Commitments))
		for i, c := range proofBN254.Commitments {
			cx := new(big.Int)
			cy := new(big.Int)
			c.X.BigInt(cx)
			c.Y.BigInt(cy)
			log.Printf("⚠️ [BLS-ZK-DIAG] Commitment[%d]: x=%s y=%s", i, cx.Text(16)[:16], cy.Text(16)[:16])
		}
	}
	pokX := new(big.Int)
	pokY := new(big.Int)
	proofBN254.CommitmentPok.X.BigInt(pokX)
	proofBN254.CommitmentPok.Y.BigInt(pokY)
	log.Printf("🔍 [BLS-ZK-DIAG] CommitmentPok: isZero=%v", pokX.Sign() == 0 && pokY.Sign() == 0)

	// Extract ProofA (Ar - G1 point)
	proofAX := new(big.Int)
	proofAY := new(big.Int)
	proofBN254.Ar.X.BigInt(proofAX)
	proofBN254.Ar.Y.BigInt(proofAY)

	// Extract ProofB (Bs - G2 point)
	proofBX0 := new(big.Int)
	proofBX1 := new(big.Int)
	proofBY0 := new(big.Int)
	proofBY1 := new(big.Int)
	proofBN254.Bs.X.A0.BigInt(proofBX0)
	proofBN254.Bs.X.A1.BigInt(proofBX1)
	proofBN254.Bs.Y.A0.BigInt(proofBY0)
	proofBN254.Bs.Y.A1.BigInt(proofBY1)

	// Extract ProofC (Krs - G1 point)
	proofCX := new(big.Int)
	proofCY := new(big.Int)
	proofBN254.Krs.X.BigInt(proofCX)
	proofBN254.Krs.Y.BigInt(proofCY)

	// Keep gnark-native real-then-imag (A0=real, A1=imag) here so the
	// in-process gnark.Verify (VerifyProofLocally) round-trips the proof
	// consistently. The EIP-197 imag-then-real swap required by the BN254
	// pairing precompile is applied ONLY at the Solidity-serialization
	// boundary (ToSolidityCalldata).
	zkProof := &BLSZKProof{
		ProofA: [2]*big.Int{proofAX, proofAY},
		ProofB: [2][2]*big.Int{
			{proofBX0, proofBX1},
			{proofBY0, proofBY1},
		},
		ProofC: [2]*big.Int{proofCX, proofCY},
	}

	// Phase 2.1: extract the V2 BSB22 Pedersen commitment + PoK from the
	// gnark proof. BLSSignatureCircuitV2 uses gnark's emulated BLS12-381
	// pairing gadget, which injects exactly one Pedersen commitment per
	// proof; the on-chain BLSZKVerifierV2Generated.verifyProof consumes
	// (commitments[2], commitmentPok[2]) alongside (A, B, C). Without these,
	// V6 rejects every proof with ProofInvalid / CommitmentInvalid.
	//
	// Defensive: V1-era code paths and unit-test fixtures may yield proofs
	// with no commitments (e.g. plain Groth16 with no BSB22). In that case
	// we leave Commitments / CommitmentPok zero-valued so the V1 callers
	// (which ignore them) are unaffected.
	commitments := [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	commitmentPok := [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	if len(proofBN254.Commitments) >= 1 {
		cx := new(big.Int)
		cy := new(big.Int)
		proofBN254.Commitments[0].X.BigInt(cx)
		proofBN254.Commitments[0].Y.BigInt(cy)
		commitments = [2]*big.Int{cx, cy}

		px := new(big.Int)
		py := new(big.Int)
		proofBN254.CommitmentPok.X.BigInt(px)
		proofBN254.CommitmentPok.Y.BigInt(py)
		commitmentPok = [2]*big.Int{px, py}
	}
	zkProof.Commitments = commitments
	zkProof.CommitmentPok = commitmentPok

	return zkProof, nil
}

// reconstructProof reconstructs a gnark proof from components
func reconstructProof(zkProof *BLSZKProof) (groth16.Proof, error) {
	// Create a new BN254 proof
	proof := &groth16_bn254.Proof{}

	// Set ProofA (Ar - G1 point)
	proof.Ar.X.SetBigInt(zkProof.ProofA[0])
	proof.Ar.Y.SetBigInt(zkProof.ProofA[1])

	// Set ProofB (Bs - G2 point)
	proof.Bs.X.A0.SetBigInt(zkProof.ProofB[0][0])
	proof.Bs.X.A1.SetBigInt(zkProof.ProofB[0][1])
	proof.Bs.Y.A0.SetBigInt(zkProof.ProofB[1][0])
	proof.Bs.Y.A1.SetBigInt(zkProof.ProofB[1][1])

	// Set ProofC (Krs - G1 point)
	proof.Krs.X.SetBigInt(zkProof.ProofC[0])
	proof.Krs.Y.SetBigInt(zkProof.ProofC[1])

	// Phase 2.2: restore V2 BSB22 Pedersen commitment + PoK if present.
	// Without these, groth16.Verify rejects every V2 proof (the verifier
	// checks the commitment contribution to vk_x). A V1-era zkProof has
	// nil/zero commitments — leave the gnark proof object with empty
	// Commitments slice in that case, matching the gnark-native V1 shape.
	if hasV2Commitments(zkProof) {
		var c bn254_curve.G1Affine
		c.X.SetBigInt(zkProof.Commitments[0])
		c.Y.SetBigInt(zkProof.Commitments[1])
		proof.Commitments = []bn254_curve.G1Affine{c}

		proof.CommitmentPok.X.SetBigInt(zkProof.CommitmentPok[0])
		proof.CommitmentPok.Y.SetBigInt(zkProof.CommitmentPok[1])
	}

	return proof, nil
}

// hasV2Commitments reports whether the proof carries non-zero V2 Pedersen
// commitment data. Zero values indicate a V1-era proof; non-zero indicates
// gnark's BSB22 commitment injection happened (i.e. V2 circuit).
func hasV2Commitments(zkProof *BLSZKProof) bool {
	if zkProof.Commitments[0] == nil || zkProof.Commitments[1] == nil {
		return false
	}
	return zkProof.Commitments[0].Sign() != 0 || zkProof.Commitments[1].Sign() != 0
}

// padBigInt pads a big.Int to 32 bytes
func padBigInt(n *big.Int) []byte {
	if n == nil {
		return make([]byte, 32)
	}
	b := n.Bytes()
	if len(b) >= 32 {
		return b[:32]
	}
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

// padUint64 pads a uint64 to 32 bytes
func padUint64(n uint64) []byte {
	result := make([]byte, 32)
	for i := 0; i < 8; i++ {
		result[31-i] = byte(n >> (8 * i))
	}
	return result
}

// =============================================================================
// CONVENIENCE FUNCTIONS
// =============================================================================

// ComputePubkeyCommitmentFromBytes computes commitment from serialized public keys
func ComputePubkeyCommitmentFromBytes(pubkeys [][]byte) ([32]byte, error) {
	h := sha256.New()
	for _, pk := range pubkeys {
		h.Write(pk)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// CreateWitnessFromBLSData creates a witness from raw BLS signature data
//
// CRITICAL: NO SIMPLIFICATIONS OR BYPASSES
// Uses gnark-crypto's native BLS12-381 point deserialization for correctness.
//
// BLS12-381 Point Formats (per gnark-crypto):
// - G1 point (signature): 48 bytes compressed (serialized with SetBytes/Bytes)
// - G2 point (pubkey): 96 bytes compressed (serialized with SetBytes/Bytes)
//   gnark-crypto handles decompression internally using proper curve arithmetic.
//
// The pubkey commitment MUST match the circuit's computation exactly.
func CreateWitnessFromBLSData(
	messageHash [32]byte,
	aggregateSignature []byte,
	aggregatedPubkey []byte,
	signedVotingPower uint64,
	totalVotingPower uint64,
) (*BLSSignatureWitness, error) {
	// Validate minimum sizes for BLS12-381
	if len(aggregateSignature) < 48 {
		return nil, fmt.Errorf("aggregate signature too short: %d bytes (need 48 for compressed G1)", len(aggregateSignature))
	}
	if len(aggregatedPubkey) < 96 {
		return nil, fmt.Errorf("aggregated pubkey too short: %d bytes (need 96 for compressed G2)", len(aggregatedPubkey))
	}

	// Parse signature using gnark-crypto's G1 point deserialization
	// This properly handles compressed format and decompression
	var sigPoint bls12381.G1Affine
	_, err := sigPoint.SetBytes(aggregateSignature[:48])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 signature: %w", err)
	}

	// Extract X and Y coordinates from the deserialized G1 point
	sigX := new(big.Int)
	sigY := new(big.Int)
	sigPoint.X.BigInt(sigX)
	sigPoint.Y.BigInt(sigY)

	// Parse pubkey using gnark-crypto's G2 point deserialization
	// This properly handles compressed format and decompression with Fp2 arithmetic
	var pkPoint bls12381.G2Affine
	_, err = pkPoint.SetBytes(aggregatedPubkey[:96])
	if err != nil {
		return nil, fmt.Errorf("deserialize G2 pubkey: %w", err)
	}

	// Extract coordinates from the deserialized G2 point
	// G2 uses extension field Fp2, so X and Y each have A0 and A1 components
	pkX0 := new(big.Int)
	pkX1 := new(big.Int)
	pkY0 := new(big.Int)
	pkY1 := new(big.Int)
	pkPoint.X.A0.BigInt(pkX0)
	pkPoint.X.A1.BigInt(pkX1)
	pkPoint.Y.A0.BigInt(pkY0)
	pkPoint.Y.A1.BigInt(pkY1)

	// CRITICAL: Compute pubkey commitment EXACTLY as the circuit does
	// SimpleBLSCircuit uses: PubkeyCommitment = PubkeyX + PubkeyY * 7
	// where PubkeyX = pkX0 and PubkeyY = pkY0
	seven := big.NewInt(7)
	pubkeyCommitmentInt := new(big.Int).Mul(pkY0, seven)
	pubkeyCommitmentInt.Add(pubkeyCommitmentInt, pkX0)

	// The commitment value may exceed 32 bytes in the BLS12-381 field
	// Reduce modulo the BN254 scalar field to fit in circuit
	bn254ScalarField := new(big.Int)
	bn254ScalarField.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	pubkeyCommitmentInt.Mod(pubkeyCommitmentInt, bn254ScalarField)

	// Convert to [32]byte for witness
	var pubkeyCommitment [32]byte
	commitmentBytes := pubkeyCommitmentInt.Bytes()
	if len(commitmentBytes) <= 32 {
		copy(pubkeyCommitment[32-len(commitmentBytes):], commitmentBytes)
	} else {
		// This should not happen after modulo reduction
		return nil, errors.New("pubkey commitment exceeds 32 bytes after modulo reduction")
	}

	return &BLSSignatureWitness{
		MessageHash:       messageHash,
		PubkeyCommitment:  pubkeyCommitment,
		SignedVotingPower: signedVotingPower,
		TotalVotingPower:  totalVotingPower,
		SignatureX:        sigX,
		SignatureY:        sigY,
		PubkeyX0:          pkX0,
		PubkeyX1:          pkX1,
		PubkeyY0:          pkY0,
		PubkeyY1:          pkY1,
	}, nil
}

// =============================================================================
// GROTH16 PAIRING DIAGNOSTIC
// =============================================================================

// ManualPairingCheck performs the exact same 4-pairing Groth16 verification
// that our Solana Rust code does, using gnark-crypto's native BN254 pairing.
// This is the DEFINITIVE test: if this passes in Go but fails on-chain,
// the issue is in the data pipeline. If this also fails, the equation is wrong.
func (p *BLSZKProver) ManualPairingCheck(zkProof *BLSZKProof) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return false, errors.New("prover not initialized")
	}

	vkBN254, ok := p.vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return false, errors.New("VK is not BN254 type")
	}

	if len(vkBN254.G1.K) != 5 {
		return false, fmt.Errorf("expected 5 IC points, got %d", len(vkBN254.G1.K))
	}

	// Reconstruct proof point A (G1)
	var A bn254_curve.G1Affine
	A.X.SetBigInt(zkProof.ProofA[0])
	A.Y.SetBigInt(zkProof.ProofA[1])

	// Reconstruct proof point B (G2)
	var B bn254_curve.G2Affine
	B.X.A0.SetBigInt(zkProof.ProofB[0][0])
	B.X.A1.SetBigInt(zkProof.ProofB[0][1])
	B.Y.A0.SetBigInt(zkProof.ProofB[1][0])
	B.Y.A1.SetBigInt(zkProof.ProofB[1][1])

	// Reconstruct proof point C (G1)
	var C bn254_curve.G1Affine
	C.X.SetBigInt(zkProof.ProofC[0])
	C.Y.SetBigInt(zkProof.ProofC[1])

	// Construct public inputs as Fr elements (same reduction as gnark does)
	var inputs [4]fr.Element
	inputs[0].SetBytes(zkProof.MessageHash[:])
	inputs[1].SetBytes(zkProof.PubkeyCommitment[:])
	inputs[2].SetUint64(zkProof.SignedVotingPower)
	inputs[3].SetUint64(zkProof.TotalVotingPower)

	// Log inputs for debugging
	for i, inp := range inputs {
		var v big.Int
		inp.BigInt(&v)
		b := padBigInt(&v)
		log.Printf("🔍 [BLS-DIAG-PAIRING] input[%d] first8=%x", i, b[:8])
	}

	// Compute vk_x = IC[0] + sum(inputs[i] * IC[i+1])
	var vk_x bn254_curve.G1Jac
	vk_x.FromAffine(&vkBN254.G1.K[0])
	for i := 0; i < 4; i++ {
		var scalar big.Int
		inputs[i].BigInt(&scalar)
		var term bn254_curve.G1Jac
		term.FromAffine(&vkBN254.G1.K[i+1])
		term.ScalarMultiplication(&term, &scalar)
		vk_x.AddAssign(&term)
	}
	var vk_x_aff bn254_curve.G1Affine
	vk_x_aff.FromJacobian(&vk_x)

	vkxX := new(big.Int)
	vk_x_aff.X.BigInt(vkxX)
	log.Printf("🔍 [BLS-DIAG-PAIRING] vk_x.x=%s", vkxX.Text(16)[:16])

	// Negate G1 points: alpha, vk_x, C
	var negAlpha, negVkX, negC bn254_curve.G1Affine
	negAlpha.Neg(&vkBN254.G1.Alpha)
	negVkX.Neg(&vk_x_aff)
	negC.Neg(&C)

	// 4-pairing check: e(A,B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
	ok2, err := bn254_curve.PairingCheck(
		[]bn254_curve.G1Affine{A, negAlpha, negVkX, negC},
		[]bn254_curve.G2Affine{B, vkBN254.G2.Beta, vkBN254.G2.Gamma, vkBN254.G2.Delta},
	)
	if err != nil {
		log.Printf("❌ [BLS-DIAG-PAIRING] PairingCheck error: %v", err)
		return false, err
	}

	log.Printf("🔍 [BLS-DIAG-PAIRING] 4-pairing check result: %v", ok2)
	return ok2, nil
}

// V2 ABI byte size: 8 (A,B,C) + 2 (commitments) + 2 (commitmentPok)
// + 4 (public inputs) + 2 (thresholds) = 18 × 32-byte slots = 576 bytes.
// All BLSSignatureProof fields are statically sized, so abi.encode produces
// a flat 576-byte blob with no length prefix.
const v2ABIByteSize = 576

// V2 ABI byte offsets — see ToSolidityCalldata for the encoding contract.
const (
	v2OffProofAX        = 0
	v2OffProofAY        = 32
	v2OffProofBX0       = 64
	v2OffProofBX1       = 96
	v2OffProofBY0       = 128
	v2OffProofBY1       = 160
	v2OffProofCX        = 192
	v2OffProofCY        = 224
	v2OffCommitmentX    = 256
	v2OffCommitmentY    = 288
	v2OffCommitmentPokX = 320
	v2OffCommitmentPokY = 352
	v2OffMessageHash    = 384
	v2OffPubkeyCommit   = 416
	v2OffSignedVP       = 448
	v2OffTotalVP        = 480
	v2OffThresholdNum   = 512
	v2OffThresholdDenom = 544
)

// VerifyFromABIBytes deserializes the V2 BLSSignatureProof bytes and runs
// gnark's commitment-augmented Groth16 verifier. This is the round-trip
// diagnostic for the ToSolidityCalldata encoder — if Go-side Verify rejects
// the bytes Go-side Pack just produced, there is a serialization bug.
//
// The V1 version of this function did a manual 4-pairing check matching the
// "standard Groth16" equation used by the NEAR contract. That equation does
// NOT apply to V2 proofs: BLSSignatureCircuitV2 uses gnark's emulated BLS12-381
// pairing gadget, which injects a BSB22 Pedersen commitment that augments the
// pairing equation with additional terms. Reimplementing that manually is the
// "hand-rolled commitment-augmented verifier" the V2 contract architecture
// explicitly avoids (see evm/src/core/BLSZKVerifierV2.sol header). We instead
// reconstruct the gnark proof + V2 public witness and call groth16.Verify
// with the keccak-mod-R hash override that matches the on-chain BSB22
// challenge derivation.
func (p *BLSZKProver) VerifyFromABIBytes(abiBytes []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return false, errors.New("prover not initialized")
	}
	if len(abiBytes) < v2ABIByteSize {
		return false, fmt.Errorf("V2 ABI bytes too short: %d (expected %d)", len(abiBytes), v2ABIByteSize)
	}

	readBI := func(offset int) *big.Int {
		return new(big.Int).SetBytes(abiBytes[offset : offset+32])
	}
	readBytes32 := func(offset int) [32]byte {
		var out [32]byte
		copy(out[:], abiBytes[offset:offset+32])
		return out
	}

	// Wire format encodes B in EIP-197 imag-then-real (set by
	// ToSolidityCalldata). Swap back to gnark-native real-then-imag so
	// reconstructProof can rebuild a gnark Proof that VerifyProofLocally
	// accepts. Without this back-swap the in-process round-trip Verify
	// rejects valid proofs and the validator submits empty proof bytes.
	zkProof := &BLSZKProof{
		ProofA: [2]*big.Int{readBI(v2OffProofAX), readBI(v2OffProofAY)},
		ProofB: [2][2]*big.Int{
			{readBI(v2OffProofBX1), readBI(v2OffProofBX0)}, // wire[imag, real] -> struct[real, imag]
			{readBI(v2OffProofBY1), readBI(v2OffProofBY0)}, // wire[imag, real] -> struct[real, imag]
		},
		ProofC:               [2]*big.Int{readBI(v2OffProofCX), readBI(v2OffProofCY)},
		Commitments:          [2]*big.Int{readBI(v2OffCommitmentX), readBI(v2OffCommitmentY)},
		CommitmentPok:        [2]*big.Int{readBI(v2OffCommitmentPokX), readBI(v2OffCommitmentPokY)},
		MessageHash:          readBytes32(v2OffMessageHash),
		PubkeyCommitment:     readBytes32(v2OffPubkeyCommit),
		SignedVotingPower:    readBI(v2OffSignedVP).Uint64(),
		TotalVotingPower:     readBI(v2OffTotalVP).Uint64(),
		ThresholdNumerator:   readBI(v2OffThresholdNum).Uint64(),
		ThresholdDenominator: readBI(v2OffThresholdDenom).Uint64(),
	}

	groth16Proof, err := reconstructProof(zkProof)
	if err != nil {
		return false, fmt.Errorf("reconstruct proof: %w", err)
	}

	assignment := &BLSSignatureCircuitV2{
		MessageHash:       new(big.Int).SetBytes(zkProof.MessageHash[:]),
		PubkeyCommitment:  new(big.Int).SetBytes(zkProof.PubkeyCommitment[:]),
		SignedVotingPower: zkProof.SignedVotingPower,
		TotalVotingPower:  zkProof.TotalVotingPower,
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("create public witness: %w", err)
	}

	err = groth16.Verify(groth16Proof, p.vk, publicWitness,
		backend.WithVerifierHashToFieldFunction(NewKeccakToFieldHash()),
	)
	if err != nil {
		log.Printf("🔍 [V2-ABI-ROUNDTRIP] groth16.Verify rejected: %v", err)
		return false, nil
	}
	log.Printf("✅ [V2-ABI-ROUNDTRIP] groth16.Verify accepted")
	return true, nil
}

// ComputeVKHash computes a SHA256 hash of all VK component bytes for comparison
// with the on-chain VK. Also returns the raw buffer for keccak computation.
// The byte representation matches the Rust Solana verifier's VK ordering.
func (p *BLSZKProver) ComputeVKHash() ([32]byte, []byte) {
	var empty [32]byte

	vkBN254, ok := p.vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		log.Printf("❌ [BLS-ZK-DIAG] VK is not BN254 type")
		return empty, nil
	}

	// Build the same byte buffer as the Rust side: alpha1, beta2, gamma2, delta2, IC[]
	var buf []byte

	// alpha1 (G1)
	buf = appendG1Point(buf, &vkBN254.G1.Alpha)

	// beta2 (G2): x[0]=A0=c0, x[1]=A1=c1, y[0]=A0=c0, y[1]=A1=c1
	buf = appendG2Point(buf, &vkBN254.G2.Beta)

	// gamma2 (G2)
	buf = appendG2Point(buf, &vkBN254.G2.Gamma)

	// delta2 (G2)
	buf = appendG2Point(buf, &vkBN254.G2.Delta)

	// IC points
	for _, ic := range vkBN254.G1.K {
		buf = appendG1Point(buf, &ic)
	}

	h := sha256.New()
	h.Write(buf)
	var result [32]byte
	copy(result[:], h.Sum(nil))

	// Log the raw first 16 bytes of the VK buffer for direct comparison
	if len(buf) >= 16 {
		log.Printf("🔍 [BLS-ZK-DIAG] VK raw bytes first16=%x (total %d bytes)", buf[:16], len(buf))
	}

	return result, buf
}

func appendG1Point(buf []byte, p *bn254_curve.G1Affine) []byte {
	x := new(big.Int)
	y := new(big.Int)
	p.X.BigInt(x)
	p.Y.BigInt(y)
	buf = append(buf, padBigInt(x)...)
	buf = append(buf, padBigInt(y)...)
	return buf
}

func appendG2Point(buf []byte, p *bn254_curve.G2Affine) []byte {
	x0 := new(big.Int)
	x1 := new(big.Int)
	y0 := new(big.Int)
	y1 := new(big.Int)
	p.X.A0.BigInt(x0)
	p.X.A1.BigInt(x1)
	p.Y.A0.BigInt(y0)
	p.Y.A1.BigInt(y1)
	buf = append(buf, padBigInt(x0)...)
	buf = append(buf, padBigInt(x1)...)
	buf = append(buf, padBigInt(y0)...)
	buf = append(buf, padBigInt(y1)...)
	return buf
}
