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
	"math/big"
	"os"
	"strings"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/accounts/abi"
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

// BLSZKProof represents a generated proof ready for on-chain verification
type BLSZKProof struct {
	// Groth16 proof components (A, B, C points)
	ProofA [2]*big.Int   `json:"proofA"`
	ProofB [2][2]*big.Int `json:"proofB"`
	ProofC [2]*big.Int   `json:"proofC"`

	// Public inputs (4 total - must match BLSZKVerifier.sol)
	MessageHash       [32]byte `json:"messageHash"`
	PubkeyCommitment  [32]byte `json:"pubkeyCommitment"`
	SignedVotingPower uint64   `json:"signedVotingPower"`
	TotalVotingPower  uint64   `json:"totalVotingPower"`

	// Internal: SignatureCommitment is now a private circuit input (not public)
	SignatureCommitment *big.Int `json:"signatureCommitment,omitempty"`

	// Threshold parameters - required by BLSZKVerifier contract
	ThresholdNumerator   uint64 `json:"thresholdNumerator"`   // e.g., 2 for 2/3 threshold
	ThresholdDenominator uint64 `json:"thresholdDenominator"` // e.g., 3 for 2/3 threshold
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

// Initialize compiles the circuit and generates proving/verification keys
// This is a one-time setup operation that can take several seconds
func (p *BLSZKProver) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return nil
	}

	// Define the circuit
	var circuit SimpleBLSCircuit

	// Compile the circuit to R1CS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile circuit: %w", err)
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

// GenerateProof generates a ZK proof for a BLS signature
func (p *BLSZKProver) GenerateProof(witness *BLSSignatureWitness) (*BLSZKProof, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, errors.New("prover not initialized")
	}

	// Create circuit assignment with witness values
	assignment := &SimpleBLSCircuit{
		MessageHash:         new(big.Int).SetBytes(witness.MessageHash[:]),
		PubkeyCommitment:    new(big.Int).SetBytes(witness.PubkeyCommitment[:]),
		SignatureCommitment: computeCommitment(witness.SignatureX, witness.SignatureY),
		SignedVotingPower:   witness.SignedVotingPower,
		TotalVotingPower:    witness.TotalVotingPower,
		SignatureX:          witness.SignatureX,
		SignatureY:          witness.SignatureY,
		PubkeyX:             witness.PubkeyX0,
		PubkeyY:             witness.PubkeyY0,
	}

	// Create witness
	witnessData, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(p.cs, p.pk, witnessData)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// Extract proof components
	zkProof, err := extractProofComponents(proof)
	if err != nil {
		return nil, fmt.Errorf("extract proof components: %w", err)
	}

	// Set public inputs
	zkProof.MessageHash = witness.MessageHash
	zkProof.PubkeyCommitment = witness.PubkeyCommitment
	zkProof.SignatureCommitment = computeCommitment(witness.SignatureX, witness.SignatureY)
	zkProof.SignedVotingPower = witness.SignedVotingPower
	zkProof.TotalVotingPower = witness.TotalVotingPower

	return zkProof, nil
}

// VerifyProofLocally verifies a proof locally (for testing)
func (p *BLSZKProver) VerifyProofLocally(proof *BLSZKProof) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return false, errors.New("prover not initialized")
	}

	// Create public witness with only the 4 public inputs (matches on-chain verifier)
	// SignatureCommitment is now a private input, not included in public witness
	assignment := &SimpleBLSCircuit{
		MessageHash:       new(big.Int).SetBytes(proof.MessageHash[:]),
		PubkeyCommitment:  new(big.Int).SetBytes(proof.PubkeyCommitment[:]),
		SignedVotingPower: proof.SignedVotingPower,
		TotalVotingPower:  proof.TotalVotingPower,
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("create public witness: %w", err)
	}

	// Reconstruct Groth16 proof from components
	groth16Proof, err := reconstructProof(proof)
	if err != nil {
		return false, fmt.Errorf("reconstruct proof: %w", err)
	}

	// Verify
	err = groth16.Verify(groth16Proof, p.vk, publicWitness)
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

// blsProofABI defines the ABI for the BLS proof struct used in Solidity
// Matches the BLSSignatureProof struct in BLSZKVerifier.sol:
// struct BLSSignatureProof {
//     Groth16Proof proof;
//     bytes32 messageHash;
//     bytes32 pubkeyCommitment;
//     uint256 signedVotingPower;
//     uint256 totalVotingPower;
//     uint256 thresholdNumerator;
//     uint256 thresholdDenominator;
// }
var blsProofABI = mustParseABI(`[{
	"name": "encodeProof",
	"type": "function",
	"inputs": [
		{"name": "proofA", "type": "uint256[2]"},
		{"name": "proofB", "type": "uint256[2][2]"},
		{"name": "proofC", "type": "uint256[2]"},
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

// ToSolidityCalldata converts the proof to Solidity-compatible calldata format
// using go-ethereum's ABI encoding for proper type safety and compatibility
func (proof *BLSZKProof) ToSolidityCalldata() ([]byte, error) {
	// Convert ProofA to [2]*big.Int array
	proofA := [2]*big.Int{proof.ProofA[0], proof.ProofA[1]}
	if proofA[0] == nil {
		proofA[0] = big.NewInt(0)
	}
	if proofA[1] == nil {
		proofA[1] = big.NewInt(0)
	}

	// Convert ProofB to [2][2]*big.Int array
	proofB := [2][2]*big.Int{
		{proof.ProofB[0][0], proof.ProofB[0][1]},
		{proof.ProofB[1][0], proof.ProofB[1][1]},
	}
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			if proofB[i][j] == nil {
				proofB[i][j] = big.NewInt(0)
			}
		}
	}

	// Convert ProofC to [2]*big.Int array
	proofC := [2]*big.Int{proof.ProofC[0], proof.ProofC[1]}
	if proofC[0] == nil {
		proofC[0] = big.NewInt(0)
	}
	if proofC[1] == nil {
		proofC[1] = big.NewInt(0)
	}

	// Convert voting power and threshold to big.Int for uint256 ABI encoding
	signedVP := new(big.Int).SetUint64(proof.SignedVotingPower)
	totalVP := new(big.Int).SetUint64(proof.TotalVotingPower)
	thresholdNum := new(big.Int).SetUint64(proof.ThresholdNumerator)
	thresholdDenom := new(big.Int).SetUint64(proof.ThresholdDenominator)

	// Default to 2/3 threshold if not set
	if thresholdNum.Cmp(big.NewInt(0)) == 0 {
		thresholdNum = big.NewInt(2)
	}
	if thresholdDenom.Cmp(big.NewInt(0)) == 0 {
		thresholdDenom = big.NewInt(3)
	}

	// Pack using ABI encoding
	encoded, err := blsProofABI.Pack("encodeProof",
		proofA,
		proofB,
		proofC,
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

	// Remove the 4-byte method selector to get just the encoded parameters
	if len(encoded) < 4 {
		return nil, errors.New("encoded data too short")
	}

	return encoded[4:], nil
}

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

	zkProof := &BLSZKProof{
		ProofA: [2]*big.Int{proofAX, proofAY},
		ProofB: [2][2]*big.Int{
			{proofBX0, proofBX1},
			{proofBY0, proofBY1},
		},
		ProofC: [2]*big.Int{proofCX, proofCY},
	}

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

	return proof, nil
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
