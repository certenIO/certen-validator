// BLS12-381 V2 trusted-setup ceremony for BLSSignatureCircuitV2BLS381.
//
// Produces the Cardano-parity proving/verifying keys: the same real-pairing +
// messageHash-binding V2 circuit as the EVM/NEAR BN254 setup, but compiled
// over the BLS12-381 SNARK curve so the resulting Groth16 proof is verifiable
// by Cardano's Plutus V3 bls12_381_* builtins.
//
// Outputs (to --keys-out, default ./bls_zk_keys_bls12381_v2):
//   proving_key.bin          — validator loads this to generate V2 proofs
//   verification_key.bin     — gnark VK (binary)
//   constraint_system.bin    — compiled R1CS
//   vk-cardano-v2.json       — VK in the Cardano/Aiken JSON shape
//                              (alpha/beta/gamma/delta/pedersen + IC)
//
// Runtime: the circuit has ~775k constraints (emulated BLS12-381 pairing).
// Compile ~10-20s; setup is slow (~15-40 min) and memory-hungry (~4-6GB).
//
// Usage:
//   go run ./cmd/v2-trusted-setup-bls12381 --keys-out ./bls_zk_keys_bls12381_v2

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	bls_zkp "github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

func main() {
	keysOut := flag.String("keys-out", "./bls_zk_keys_bls12381_v2",
		"directory to write proving_key.bin / verification_key.bin / constraint_system.bin / vk-cardano-v2.json")
	flag.Parse()

	if err := os.MkdirAll(*keysOut, 0o755); err != nil {
		log.Fatalf("mkdir keys-out: %v", err)
	}

	log.Println("🔧 Compiling BLSSignatureCircuitV2BLS381 over BLS12-381...")
	t0 := time.Now()
	var circuit bls_zkp.BLSSignatureCircuitV2BLS381
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("compile: %v", err)
	}
	log.Printf("✅ Compiled in %s — %d constraints", time.Since(t0), cs.GetNbConstraints())

	log.Println("🔧 Running groth16.Setup (this is the slow part — minutes)...")
	t1 := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("setup: %v", err)
	}
	log.Printf("✅ Setup done in %s", time.Since(t1))

	// Save binary artifacts (gnark types implement io.WriterTo).
	writeBin(filepath.Join(*keysOut, "constraint_system.bin"), cs)
	writeBin(filepath.Join(*keysOut, "proving_key.bin"), pk)
	writeBin(filepath.Join(*keysOut, "verification_key.bin"), vk)

	// Export VK as Cardano/Aiken JSON.
	vkBLS, ok := vk.(*groth16_bls12381.VerifyingKey)
	if !ok {
		log.Fatalf("unexpected VK type %T", vk)
	}
	exportVKJSON(filepath.Join(*keysOut, "vk-cardano-v2.json"), vkBLS)

	log.Printf("🎉 BLS12-381 V2 keys written to %s", *keysOut)
}

func writeBin(path string, w io.WriterTo) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

// exportVKJSON serializes the VK into the Cardano/Aiken shape: compressed-hex
// G1/G2 points + split G2 halves are produced later by extract-vk; here we
// emit the canonical compressed-hex form (alpha G1, beta/gamma/delta G2,
// pedersen G2s for BSB22, and the IC G1 list). The Cardano extract script
// reads this and splits the 96-byte G2 points into 48-byte halves.
func exportVKJSON(path string, vk *groth16_bls12381.VerifyingKey) {
	g1hex := func(p bls12381.G1Affine) string {
		c := p.Bytes() // 48-byte compressed
		return hexEnc(c[:])
	}
	g2hex := func(p bls12381.G2Affine) string {
		c := p.Bytes() // 96-byte compressed
		return hexEnc(c[:])
	}

	out := map[string]interface{}{}
	out["AlphaG1Hex"] = g1hex(vk.G1.Alpha)
	// gnark stores beta/gamma/delta in G2 as the (negated) forms used by its
	// pairing equation. We emit them as-is; the Cardano extract script
	// applies the un-negation to match the Aiken verifier's e(-A,B) form.
	out["BetaG2Hex"] = g2hex(vk.G2.Beta)
	out["GammaG2Hex"] = g2hex(vk.G2.Gamma)
	out["DeltaG2Hex"] = g2hex(vk.G2.Delta)

	icHex := make([]string, len(vk.G1.K))
	for i, k := range vk.G1.K {
		icHex[i] = g1hex(k)
	}
	out["ICG1Hex"] = icHex

	// BSB22 commitment key (Pedersen) — present when the circuit emits a
	// commitment. gnark exposes it via vk.CommitmentKey; serialize the G2
	// points the on-chain Pedersen check needs.
	if len(vk.CommitmentKeys) > 0 {
		ck := vk.CommitmentKeys[0]
		out["PedersenGHex"] = g2hex(ck.G)
		out["PedersenGSigmaNegHex"] = g2hex(ck.GSigmaNeg)
	}

	// Diagnostic: flag whether IC[1] is the infinity point (the V1 bug). For
	// V2 it MUST be a real point — that's what binds the messageHash.
	if len(vk.G1.K) > 1 {
		var inf bls12381.G1Affine // zero value = infinity
		out["IC1IsInfinity"] = vk.G1.K[1].Equal(&inf)
	}

	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write vk json: %v", err)
	}
	fmt.Printf("VK JSON written: IC length=%d\n", len(vk.G1.K))
}

func hexEnc(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
