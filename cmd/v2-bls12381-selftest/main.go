// Self-test: generate a BLS12-381 V2 proof from a real keypair + signature
// and verify it locally. Confirms the circuit + trusted setup + prover are
// cryptographically sound (messageHash bound, pairing satisfied).
package main

import (
	"fmt"
	"log"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	bls_zkp "github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

func main() {
	// 1. Random BLS keypair.
	sk, _, err := bls.GenerateKeyPair()
	if err != nil {
		log.Fatalf("genkey: %v", err)
	}
	pkBytes := sk.PublicKey().Bytes() // 96-byte compressed G2

	// 2. A messageHash + sign via the BLS12-381 V2 hash-to-G1.
	var msgHash [32]byte
	copy(msgHash[:], []byte("certen-cardano-v2-selftest-msg!!"))
	h := bls_zkp.HashMessageToG1V2BLS381(msgHash)
	sig := sk.SignG1(h)
	sigBytes := sig.Bytes() // 48-byte compressed G1

	fmt.Printf("pk=%d bytes, sig=%d bytes\n", len(pkBytes), len(sigBytes))

	// 3. Load V2 prover + generate proof.
	prover, err := bls_zkp.GetBLS12381V2Prover()
	if err != nil {
		log.Fatalf("load prover: %v", err)
	}
	proof, err := prover.GenerateProof(msgHash, sigBytes, pkBytes, 200, 300)
	if err != nil {
		log.Fatalf("generate proof: %v", err)
	}
	fmt.Printf("proof: A=%d B=%d C=%d commitments=%d pok=%d pkCommit=%x\n",
		len(proof.ProofA), len(proof.ProofB), len(proof.ProofC),
		len(proof.Commitments), len(proof.CommitmentPok), proof.PubkeyCommitment[:8])

	// 4. Verify locally.
	ok, err := prover.VerifyLocally(proof)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("✅ V2 BLS12-381 proof verifies locally: %v\n", ok)
	if !ok {
		log.Fatal("proof did NOT verify")
	}

	// 5. Dump proof fields as hex for the Aiken on-chain verify test.
	hx := func(b []byte) string {
		const d = "0123456789abcdef"
		o := make([]byte, len(b)*2)
		for i, c := range b {
			o[i*2] = d[c>>4]
			o[i*2+1] = d[c&0xf]
		}
		return string(o)
	}
	fmt.Println("=== AIKEN-PROOF ===")
	fmt.Printf("proof_a=%s\n", hx(proof.ProofA))
	fmt.Printf("proof_b=%s\n", hx(proof.ProofB))
	fmt.Printf("proof_c=%s\n", hx(proof.ProofC))
	fmt.Printf("commitments=%s\n", hx(proof.Commitments))
	fmt.Printf("commitment_pok=%s\n", hx(proof.CommitmentPok))
	fmt.Printf("message_hash=%s\n", hx(proof.MessageHash[:]))
	fmt.Printf("pubkey_commitment=%s\n", hx(proof.PubkeyCommitment[:]))
	fmt.Printf("signed_vp=%d total_vp=%d\n", proof.SignedVP, proof.TotalVP)
}
