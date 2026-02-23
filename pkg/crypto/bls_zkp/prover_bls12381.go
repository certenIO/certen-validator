package bls_zkp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// BLS12-381 scalar field modulus (Fr)
var bls12381FrModulus, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)

// BLS12381Prover handles Groth16 proof generation using BLS12-381 curve.
// Used specifically for TON chain which has native TVM BLS12-381 opcodes.
type BLS12381Prover struct {
	mu          sync.RWMutex
	cs          constraint.ConstraintSystem
	pk          groth16.ProvingKey
	vk          groth16.VerifyingKey
	initialized bool
}

// BLS12381Proof represents a Groth16 proof on the BLS12-381 curve
type BLS12381Proof struct {
	PiA []byte // 48 bytes compressed G1
	PiB []byte // 96 bytes compressed G2
	PiC []byte // 48 bytes compressed G1

	MessageHash       [32]byte
	PubkeyCommitment  [32]byte
	SignedVotingPower uint64
	TotalVotingPower  uint64
}

// BLS12381VKExport contains VK points as hex strings for Tact contract constants
type BLS12381VKExport struct {
	AlphaG1Hex string   // 48 bytes = 96 hex chars
	BetaG2Hex  string   // 96 bytes = 192 hex chars
	GammaG2Hex string   // 96 bytes = 192 hex chars
	DeltaG2Hex string   // 96 bytes = 192 hex chars
	ICG1Hex    []string // Each 48 bytes = 96 hex chars
}

func NewBLS12381Prover() *BLS12381Prover {
	return &BLS12381Prover{}
}

// Initialize compiles SimpleBLSCircuit for BLS12-381 and runs trusted setup
func (p *BLS12381Prover) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return nil
	}

	var circuit SimpleBLSCircuit
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile circuit for BLS12-381: %w", err)
	}
	p.cs = cs

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("groth16 setup for BLS12-381: %w", err)
	}
	p.pk = pk
	p.vk = vk

	p.initialized = true
	log.Printf("✅ [BLS12-381] Prover initialized (circuit compiled + trusted setup complete)")
	return nil
}

// InitializeFromKeys loads pre-generated BLS12-381 keys from files
func (p *BLS12381Prover) InitializeFromKeys(pkPath, vkPath, csPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return nil
	}

	csFile, err := os.Open(csPath)
	if err != nil {
		return fmt.Errorf("open constraint system: %w", err)
	}
	defer csFile.Close()
	p.cs = groth16.NewCS(ecc.BLS12_381)
	if _, err = p.cs.ReadFrom(csFile); err != nil {
		return fmt.Errorf("read constraint system: %w", err)
	}

	pkFile, err := os.Open(pkPath)
	if err != nil {
		return fmt.Errorf("open proving key: %w", err)
	}
	defer pkFile.Close()
	p.pk = groth16.NewProvingKey(ecc.BLS12_381)
	if _, err = p.pk.ReadFrom(pkFile); err != nil {
		return fmt.Errorf("read proving key: %w", err)
	}

	vkFile, err := os.Open(vkPath)
	if err != nil {
		return fmt.Errorf("open verification key: %w", err)
	}
	defer vkFile.Close()
	p.vk = groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err = p.vk.ReadFrom(vkFile); err != nil {
		return fmt.Errorf("read verification key: %w", err)
	}

	p.initialized = true
	log.Printf("✅ [BLS12-381] Prover initialized from pre-generated keys")
	return nil
}

// SaveKeys saves the BLS12-381 keys to files
func (p *BLS12381Prover) SaveKeys(pkPath, vkPath, csPath string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return errors.New("prover not initialized")
	}

	csFile, err := os.Create(csPath)
	if err != nil {
		return fmt.Errorf("create cs file: %w", err)
	}
	defer csFile.Close()
	if _, err = p.cs.WriteTo(csFile); err != nil {
		return fmt.Errorf("write cs: %w", err)
	}

	pkFile, err := os.Create(pkPath)
	if err != nil {
		return fmt.Errorf("create pk file: %w", err)
	}
	defer pkFile.Close()
	if _, err = p.pk.WriteTo(pkFile); err != nil {
		return fmt.Errorf("write pk: %w", err)
	}

	vkFile, err := os.Create(vkPath)
	if err != nil {
		return fmt.Errorf("create vk file: %w", err)
	}
	defer vkFile.Close()
	if _, err = p.vk.WriteTo(vkFile); err != nil {
		return fmt.Errorf("write vk: %w", err)
	}

	return nil
}

// GenerateProof generates a BLS12-381 Groth16 proof
func (p *BLS12381Prover) GenerateProof(witness *BLSSignatureWitness) (*BLS12381Proof, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, errors.New("BLS12-381 prover not initialized")
	}

	// Compute commitments using BLS12-381 scalar field
	pkCommitment := computeCommitmentBLS12381(witness.PubkeyX0, witness.PubkeyY0)
	sigCommitment := computeCommitmentBLS12381(witness.SignatureX, witness.SignatureY)

	assignment := &SimpleBLSCircuit{
		MessageHash:         new(big.Int).SetBytes(witness.MessageHash[:]),
		PubkeyCommitment:    pkCommitment,
		SignatureCommitment: sigCommitment,
		SignedVotingPower:   witness.SignedVotingPower,
		TotalVotingPower:    witness.TotalVotingPower,
		SignatureX:          witness.SignatureX,
		SignatureY:          witness.SignatureY,
		PubkeyX:            witness.PubkeyX0,
		PubkeyY:            witness.PubkeyY0,
	}

	witnessData, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	proof, err := groth16.Prove(p.cs, p.pk, witnessData)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// Cast to BLS12-381 proof type and extract compressed points
	proofBLS, ok := proof.(*groth16_bls12381.Proof)
	if !ok {
		return nil, errors.New("proof is not BLS12-381 type")
	}

	piABytes := proofBLS.Ar.Bytes()  // [48]byte compressed G1
	piBBytes := proofBLS.Bs.Bytes()  // [96]byte compressed G2
	piCBytes := proofBLS.Krs.Bytes() // [48]byte compressed G1

	// Pubkey commitment as bytes
	var pkCommitBytes [32]byte
	cBytes := pkCommitment.Bytes()
	copy(pkCommitBytes[32-len(cBytes):], cBytes)

	result := &BLS12381Proof{
		PiA:               piABytes[:],
		PiB:               piBBytes[:],
		PiC:               piCBytes[:],
		MessageHash:       witness.MessageHash,
		PubkeyCommitment:  pkCommitBytes,
		SignedVotingPower: witness.SignedVotingPower,
		TotalVotingPower:  witness.TotalVotingPower,
	}

	// Verify locally using loaded VK
	valid, verifyErr := p.VerifyProofLocally(result)
	log.Printf("🔍 [BLS12-381] Local verify: result=%v err=%v", valid, verifyErr)
	if !valid {
		log.Printf("⚠️ [BLS12-381] Local verification failed!")
	}

	// Also verify using hardcoded contract VK constants (manual pairing)
	manualValid := VerifyWithContractVK(result)
	log.Printf("🔍 [BLS12-381] Manual contract VK verify: result=%v", manualValid)
	if valid && !manualValid {
		log.Printf("🚨 [BLS12-381] CRITICAL: Local VK passes but contract VK fails! VK MISMATCH!")
	}

	return result, nil
}

// VerifyProofLocally verifies a BLS12-381 proof locally
func (p *BLS12381Prover) VerifyProofLocally(proof *BLS12381Proof) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return false, errors.New("prover not initialized")
	}

	pkCommitInt := new(big.Int).SetBytes(proof.PubkeyCommitment[:])

	assignment := &SimpleBLSCircuit{
		MessageHash:       new(big.Int).SetBytes(proof.MessageHash[:]),
		PubkeyCommitment:  pkCommitInt,
		SignedVotingPower: proof.SignedVotingPower,
		TotalVotingPower:  proof.TotalVotingPower,
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("create public witness: %w", err)
	}

	// Reconstruct proof from compressed bytes
	groth16Proof := &groth16_bls12381.Proof{}

	var piA bls12381.G1Affine
	var piB bls12381.G2Affine
	var piC bls12381.G1Affine

	if _, err := piA.SetBytes(proof.PiA); err != nil {
		return false, fmt.Errorf("decode pi_a: %w", err)
	}
	if _, err := piB.SetBytes(proof.PiB); err != nil {
		return false, fmt.Errorf("decode pi_b: %w", err)
	}
	if _, err := piC.SetBytes(proof.PiC); err != nil {
		return false, fmt.Errorf("decode pi_c: %w", err)
	}

	groth16Proof.Ar = piA
	groth16Proof.Bs = piB
	groth16Proof.Krs = piC

	err = groth16.Verify(groth16Proof, p.vk, publicWitness)
	if err != nil {
		return false, nil // Verification failed but not a system error
	}

	return true, nil
}

// ExportVerificationKeyHex exports VK as hex strings for Tact contract constants.
// Returns compressed BLS12-381 points as hex-encoded bytes ready for rawSlice().
func (p *BLS12381Prover) ExportVerificationKeyHex() (*BLS12381VKExport, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.initialized {
		return nil, errors.New("prover not initialized")
	}

	vkBLS, ok := p.vk.(*groth16_bls12381.VerifyingKey)
	if !ok {
		return nil, errors.New("VK is not BLS12-381 type")
	}

	alphaBytes := vkBLS.G1.Alpha.Bytes()
	betaBytes := vkBLS.G2.Beta.Bytes()
	gammaBytes := vkBLS.G2.Gamma.Bytes()
	deltaBytes := vkBLS.G2.Delta.Bytes()

	icHex := make([]string, len(vkBLS.G1.K))
	for i, ic := range vkBLS.G1.K {
		icBytes := ic.Bytes()
		icHex[i] = hex.EncodeToString(icBytes[:])
	}

	export := &BLS12381VKExport{
		AlphaG1Hex: hex.EncodeToString(alphaBytes[:]),
		BetaG2Hex:  hex.EncodeToString(betaBytes[:]),
		GammaG2Hex: hex.EncodeToString(gammaBytes[:]),
		DeltaG2Hex: hex.EncodeToString(deltaBytes[:]),
		ICG1Hex:    icHex,
	}

	log.Printf("📋 [BLS12-381] VK exported: alpha=%dB beta=%dB gamma=%dB delta=%dB IC=%d points",
		len(alphaBytes), len(betaBytes), len(gammaBytes), len(deltaBytes), len(icHex))

	return export, nil
}

// computeCommitmentBLS12381 computes commitment = (x + y * 7) mod BLS12-381 Fr.
// This matches the SimpleBLSCircuit constraint: PubkeyCommitment = PubkeyX + PubkeyY * 7
func computeCommitmentBLS12381(x, y *big.Int) *big.Int {
	if x == nil || y == nil {
		return big.NewInt(0)
	}
	seven := big.NewInt(7)
	result := new(big.Int).Mul(y, seven)
	result.Add(result, x)
	result.Mod(result, bls12381FrModulus)
	return result
}

// CreateWitnessFromBLSDataBLS12381 creates a witness for BLS12-381 Groth16 circuit.
// Uses BLS12-381 scalar field for pubkey commitment computation.
func CreateWitnessFromBLSDataBLS12381(
	messageHash [32]byte,
	aggregateSignature []byte,
	aggregatedPubkey []byte,
	signedVotingPower uint64,
	totalVotingPower uint64,
) (*BLSSignatureWitness, error) {
	if len(aggregateSignature) < 48 {
		return nil, fmt.Errorf("aggregate signature too short: %d bytes (need 48 for compressed G1)", len(aggregateSignature))
	}
	if len(aggregatedPubkey) < 96 {
		return nil, fmt.Errorf("aggregated pubkey too short: %d bytes (need 96 for compressed G2)", len(aggregatedPubkey))
	}

	// Parse BLS12-381 signature (G1 point)
	var sigPoint bls12381.G1Affine
	_, err := sigPoint.SetBytes(aggregateSignature[:48])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 signature: %w", err)
	}
	sigX := new(big.Int)
	sigY := new(big.Int)
	sigPoint.X.BigInt(sigX)
	sigPoint.Y.BigInt(sigY)

	// Parse BLS12-381 pubkey (G2 point)
	var pkPoint bls12381.G2Affine
	_, err = pkPoint.SetBytes(aggregatedPubkey[:96])
	if err != nil {
		return nil, fmt.Errorf("deserialize G2 pubkey: %w", err)
	}
	pkX0 := new(big.Int)
	pkX1 := new(big.Int)
	pkY0 := new(big.Int)
	pkY1 := new(big.Int)
	pkPoint.X.A0.BigInt(pkX0)
	pkPoint.X.A1.BigInt(pkX1)
	pkPoint.Y.A0.BigInt(pkY0)
	pkPoint.Y.A1.BigInt(pkY1)

	// Compute pubkey commitment mod BLS12-381 scalar field
	pubkeyCommitmentInt := computeCommitmentBLS12381(pkX0, pkY0)

	var pubkeyCommitment [32]byte
	commitBytes := pubkeyCommitmentInt.Bytes()
	if len(commitBytes) <= 32 {
		copy(pubkeyCommitment[32-len(commitBytes):], commitBytes)
	} else {
		return nil, errors.New("pubkey commitment exceeds 32 bytes after BLS12-381 Fr reduction")
	}

	return &BLSSignatureWitness{
		MessageHash:       messageHash,
		PubkeyCommitment:  pubkeyCommitment,
		SignedVotingPower: signedVotingPower,
		TotalVotingPower:  totalVotingPower,
		SignatureX:        sigX,
		SignatureY:        sigY,
		PubkeyX0:         pkX0,
		PubkeyX1:         pkX1,
		PubkeyY0:         pkY0,
		PubkeyY1:         pkY1,
	}, nil
}

// VerifyWithContractVK verifies a BLS12-381 proof using the HARDCODED contract VK constants.
// This tests whether the proof verifies with the on-chain VK (not the loaded VK).
func VerifyWithContractVK(proof *BLS12381Proof) bool {
	// Hardcoded VK constants from groth16_verifier.tact
	alphaHex := "975d7a60c8d4cc80d0e11fe03ac847aca8566a2489b13a24d3ee6d2196d7d7e02833a5ea180db253e53c968063c622a6"
	betaHex := "805025fe46217a2bb9353df881e249f81bfc1ba35dbbae028da316d910106a64a9622235b6f62e22f965894ff753268a02a6bbbba2c9d0288e1da4f9f55fd7421304c5a930899ade7bf6b10383553983633310a9f604b3457944d77d6898c34f"
	gammaHex := "8f3b0f5f0294ce236480f0bc2b4c91e37a9bca7f109c72e86935c307ea31a96c2adac1e5f173c13db243eaae7eef94b106e02c98bd5f337345d495fa4af6682438547dcf6d871843d4d28b61139c31cb1a8ad8f5fecae9e1fe9a3456a9bf0cf0"
	deltaHex := "82c2d452b5565a58496b691bb74eacc338ab8dc2c79abb2234a8c97aa3ee13b7b26924ebd004fff475b25f67a7fa0662014c4ef0eefb6125902e7687c9de57a73b011bcf7b46d26e1aa91e8f526a41bf75f747e62cda6b4b0516a5ac15a70f5e"
	icHex := []string{
		"81e4e2b29ffd0c6a067f06733c8c471cfdf94c665802866a8f95d49b9694461ea006efd0cbdcf90d308aa0acdd72e3a8",
		"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"a5da549892da7d7186a042f2ff9ec2f3220714d4cfd9ab88e47c524d5b0fdddc49e91d2f5b1c44200cb5f819c5998d48",
		"a3e4bb8e12a48b821a8367d38ad86462c4301165157ca33b4eaec058f25631f5f98a50ffa3be0bf2268b40a54542ef41",
		"80a93dd1605a8c93d3637f7b1c7446c24b8c8f849ef2d3e7e64cf6cc90766256de553bb37dae830cb060f2382c78e2b7",
	}

	// Decode VK points
	decodeG1 := func(h string) (bls12381.G1Affine, error) {
		b, _ := hex.DecodeString(h)
		var p bls12381.G1Affine
		_, err := p.SetBytes(b)
		return p, err
	}
	decodeG2 := func(h string) (bls12381.G2Affine, error) {
		b, _ := hex.DecodeString(h)
		var p bls12381.G2Affine
		_, err := p.SetBytes(b)
		return p, err
	}

	alpha, err := decodeG1(alphaHex)
	if err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode alpha: %v", err)
		return false
	}
	beta, err := decodeG2(betaHex)
	if err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode beta: %v", err)
		return false
	}
	gamma, err := decodeG2(gammaHex)
	if err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode gamma: %v", err)
		return false
	}
	delta, err := decodeG2(deltaHex)
	if err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode delta: %v", err)
		return false
	}

	ic := make([]bls12381.G1Affine, len(icHex))
	for i, h := range icHex {
		ic[i], err = decodeG1(h)
		if err != nil {
			log.Printf("⚠️ [MANUAL-VK] Failed to decode IC[%d]: %v", i, err)
			return false
		}
	}

	// Decode proof points
	var piA bls12381.G1Affine
	if _, err := piA.SetBytes(proof.PiA); err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode piA: %v", err)
		return false
	}
	var piB bls12381.G2Affine
	if _, err := piB.SetBytes(proof.PiB); err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode piB: %v", err)
		return false
	}
	var piC bls12381.G1Affine
	if _, err := piC.SetBytes(proof.PiC); err != nil {
		log.Printf("⚠️ [MANUAL-VK] Failed to decode piC: %v", err)
		return false
	}

	// Compute public inputs as Fr scalars
	msgHashInt := new(big.Int).SetBytes(proof.MessageHash[:])
	pkCommitInt := new(big.Int).SetBytes(proof.PubkeyCommitment[:])
	signedVPInt := new(big.Int).SetUint64(proof.SignedVotingPower)
	totalVPInt := new(big.Int).SetUint64(proof.TotalVotingPower)

	// Compute vk_x = IC[0] + msgHash*IC[1] + pkCommit*IC[2] + signedVP*IC[3] + totalVP*IC[4]
	scalars := []*big.Int{msgHashInt, pkCommitInt, signedVPInt, totalVPInt}
	var vkX bls12381.G1Jac
	vkX.FromAffine(&ic[0])
	for i := 0; i < 4; i++ {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&ic[i+1], scalars[i])
		var termJac bls12381.G1Jac
		termJac.FromAffine(&term)
		vkX.AddAssign(&termJac)
	}
	var vkXAff bls12381.G1Affine
	vkXAff.FromJacobian(&vkX)

	// Negate piA
	var negA bls12381.G1Affine
	negA.Neg(&piA)

	// Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
	ml, err := bls12381.MillerLoop(
		[]bls12381.G1Affine{negA, alpha, vkXAff, piC},
		[]bls12381.G2Affine{piB, beta, gamma, delta},
	)
	if err != nil {
		log.Printf("⚠️ [MANUAL-VK] MillerLoop failed: %v", err)
		return false
	}
	result := bls12381.FinalExponentiation(&ml)

	var one bls12381.GT
	one.SetOne()
	isValid := result.Equal(&one)
	log.Printf("🔍 [MANUAL-VK] Pairing check result=%v", isValid)

	return isValid
}
