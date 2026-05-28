// BLS12-381 V2 prover — generates Groth16 proofs of the messageHash-bound
// BLSSignatureCircuitV2BLS381 circuit, verifiable by Cardano's Plutus V3
// bls12_381_* builtins. This is the Cardano-parity prover: unlike the V1
// SimpleBLSCircuit (which only constrained a pubkey commitment + threshold
// and left messageHash unbound), the V2 circuit verifies the real BLS
// pairing and binds messageHash via in-circuit MapToG1 — so the resulting
// proof's VK has a real IC[1] (not infinity), giving the same cryptographic
// guarantee as the EVM/NEAR BN254 V2 verifier.

package bls_zkp

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// BLS12381V2Proof carries the Cardano-ready compressed proof points + public
// inputs. All point fields are compressed hex (G1 = 48 bytes, G2 = 96 bytes).
type BLS12381V2Proof struct {
	ProofA           []byte // 48-byte compressed G1
	ProofB           []byte // 96-byte compressed G2
	ProofC           []byte // 48-byte compressed G1
	Commitments      []byte // 48-byte compressed G1 (BSB22 Pedersen commitment)
	CommitmentPok    []byte // 48-byte compressed G1 (BSB22 proof of knowledge)
	MessageHash      [32]byte
	PubkeyCommitment [32]byte
	SignedVP         uint64
	TotalVP          uint64
}

// BLS12381V2Prover wraps the compiled circuit + V2 keys.
type BLS12381V2Prover struct {
	mu          sync.RWMutex
	cs          constraint.ConstraintSystem
	pk          groth16.ProvingKey
	vk          groth16.VerifyingKey
	initialized bool
}

var (
	globalBLS12381V2Prover     *BLS12381V2Prover
	globalBLS12381V2ProverOnce sync.Once
)

// GetBLS12381V2Prover returns the singleton, loading keys lazily from
// CARDANO_BLS12381_V2_KEYS_DIR (default ./bls_zk_keys_bls12381_v2) on first
// use. Returns (nil, err) if keys are missing.
func GetBLS12381V2Prover() (*BLS12381V2Prover, error) {
	var initErr error
	globalBLS12381V2ProverOnce.Do(func() {
		dir := os.Getenv("CARDANO_BLS12381_V2_KEYS_DIR")
		if dir == "" {
			dir = "./bls_zk_keys_bls12381_v2"
		}
		p := &BLS12381V2Prover{}
		if err := p.InitializeFromKeys(dir); err != nil {
			initErr = err
			return
		}
		globalBLS12381V2Prover = p
	})
	if globalBLS12381V2Prover == nil {
		if initErr != nil {
			return nil, initErr
		}
		return nil, errors.New("BLS12-381 V2 prover not initialized")
	}
	return globalBLS12381V2Prover, nil
}

// InitializeFromKeys loads proving_key.bin / verification_key.bin /
// constraint_system.bin from dir.
func (p *BLS12381V2Prover) InitializeFromKeys(dir string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.initialized {
		return nil
	}

	csF, err := os.Open(filepath.Join(dir, "constraint_system.bin"))
	if err != nil {
		return fmt.Errorf("open cs: %w", err)
	}
	defer csF.Close()
	p.cs = groth16.NewCS(ecc.BLS12_381)
	if _, err := p.cs.ReadFrom(csF); err != nil {
		return fmt.Errorf("read cs: %w", err)
	}

	pkF, err := os.Open(filepath.Join(dir, "proving_key.bin"))
	if err != nil {
		return fmt.Errorf("open pk: %w", err)
	}
	defer pkF.Close()
	p.pk = groth16.NewProvingKey(ecc.BLS12_381)
	if _, err := p.pk.ReadFrom(pkF); err != nil {
		return fmt.Errorf("read pk: %w", err)
	}

	vkF, err := os.Open(filepath.Join(dir, "verification_key.bin"))
	if err != nil {
		return fmt.Errorf("open vk: %w", err)
	}
	defer vkF.Close()
	p.vk = groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := p.vk.ReadFrom(vkF); err != nil {
		return fmt.Errorf("read vk: %w", err)
	}

	p.initialized = true
	return nil
}

// GenerateProof builds + proves the V2 circuit for the given BLS aggregate
// signature (48-byte compressed G1), aggregate pubkey (96-byte compressed
// G2), messageHash and voting powers. Returns the Cardano-ready proof.
func (p *BLS12381V2Prover) GenerateProof(
	messageHash [32]byte,
	aggregateSignature []byte,
	aggregatedPubkey []byte,
	signedVotingPower uint64,
	totalVotingPower uint64,
) (*BLS12381V2Proof, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.initialized {
		return nil, errors.New("prover not initialized")
	}
	if len(aggregateSignature) < 48 {
		return nil, fmt.Errorf("signature too short: %d (need 48)", len(aggregateSignature))
	}
	if len(aggregatedPubkey) < 96 {
		return nil, fmt.Errorf("pubkey too short: %d (need 96)", len(aggregatedPubkey))
	}

	var sigPoint bls12381.G1Affine
	if _, err := sigPoint.SetBytes(aggregateSignature[:48]); err != nil {
		return nil, fmt.Errorf("deserialize G1 signature: %w", err)
	}
	var pkPoint bls12381.G2Affine
	if _, err := pkPoint.SetBytes(aggregatedPubkey[:96]); err != nil {
		return nil, fmt.Errorf("deserialize G2 pubkey: %w", err)
	}

	assignment, pkCommitment, err := BuildV2WitnessBLS381(
		messageHash, sigPoint, pkPoint, signedVotingPower, totalVotingPower,
	)
	if err != nil {
		return nil, fmt.Errorf("BuildV2WitnessBLS381: %w", err)
	}

	witnessData, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("new witness: %w", err)
	}

	// Cardano-compatible BSB22 commitment hash: publicCommitment =
	// keccak256(compressed(commitment)) mod BLS12-381 Fr — derivable on-chain
	// via bls12_381_g1_compress (CIP-381 can't read raw coordinates).
	proof, err := groth16.Prove(p.cs, p.pk, witnessData,
		backend.WithProverHashToFieldFunction(NewKeccakToFieldHashBLS12381Compressed()),
	)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	proofBLS, ok := proof.(*groth16_bls12381.Proof)
	if !ok {
		return nil, fmt.Errorf("unexpected proof type %T", proof)
	}

	out := &BLS12381V2Proof{
		MessageHash:      messageHash,
		PubkeyCommitment: pkCommitment,
		SignedVP:         signedVotingPower,
		TotalVP:          totalVotingPower,
	}
	arBytes := proofBLS.Ar.Bytes()
	bsBytes := proofBLS.Bs.Bytes()
	krsBytes := proofBLS.Krs.Bytes()
	out.ProofA = arBytes[:]
	out.ProofB = bsBytes[:]
	out.ProofC = krsBytes[:]

	if len(proofBLS.Commitments) > 0 {
		cBytes := proofBLS.Commitments[0].Bytes()
		out.Commitments = cBytes[:]
	}
	pokBytes := proofBLS.CommitmentPok.Bytes()
	out.CommitmentPok = pokBytes[:]

	return out, nil
}

// VerifyLocally re-verifies the proof in-process (sanity check before
// submission). Reconstructs the public witness from the proof's public
// inputs.
func (p *BLS12381V2Prover) VerifyLocally(proof *BLS12381V2Proof) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.initialized {
		return false, errors.New("prover not initialized")
	}

	// Rebuild a groth16_bls12381.Proof from the compressed bytes.
	gp := &groth16_bls12381.Proof{}
	if _, err := gp.Ar.SetBytes(proof.ProofA); err != nil {
		return false, fmt.Errorf("set Ar: %w", err)
	}
	if _, err := gp.Bs.SetBytes(proof.ProofB); err != nil {
		return false, fmt.Errorf("set Bs: %w", err)
	}
	if _, err := gp.Krs.SetBytes(proof.ProofC); err != nil {
		return false, fmt.Errorf("set Krs: %w", err)
	}
	if len(proof.Commitments) > 0 {
		var c bls12381.G1Affine
		if _, err := c.SetBytes(proof.Commitments); err != nil {
			return false, fmt.Errorf("set commitment: %w", err)
		}
		gp.Commitments = []bls12381.G1Affine{c}
	}
	if len(proof.CommitmentPok) > 0 {
		if _, err := gp.CommitmentPok.SetBytes(proof.CommitmentPok); err != nil {
			return false, fmt.Errorf("set pok: %w", err)
		}
	}

	assignment := &BLSSignatureCircuitV2BLS381{
		MessageHash:       new(big.Int).SetBytes(proof.MessageHash[:]),
		PubkeyCommitment:  new(big.Int).SetBytes(proof.PubkeyCommitment[:]),
		SignedVotingPower: proof.SignedVP,
		TotalVotingPower:  proof.TotalVP,
	}
	pubWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return false, fmt.Errorf("public witness: %w", err)
	}
	if err := groth16.Verify(gp, p.vk, pubWitness,
		backend.WithVerifierHashToFieldFunction(NewKeccakToFieldHashBLS12381Compressed()),
	); err != nil {
		return false, nil
	}
	return true, nil
}
