// V2 trusted-setup ceremony for BLSSignatureCircuitV2.
//
// What this does:
//   1. Compiles BLSSignatureCircuitV2 to R1CS over BN254.
//   2. Runs groth16.Setup → produces (ProvingKey, VerifyingKey) for V2.
//   3. Writes the proving key, verifying key, and constraint system as .bin
//      files to ./bls_zk_keys/ — these are what the validator binary loads
//      at startup to generate V2 proofs.
//   4. Calls gnark's VerifyingKey.ExportSolidity to emit the matching
//      on-chain verifier contract; renames the gnark-default "contract Verifier"
//      to "contract BLSZKVerifierV2Generated" so the file slots directly into
//      evm/src/core/BLSZKVerifierV2Generated.sol.
//
// Why this exists separately from cmd/bls-zk-setup:
//   The legacy cmd/bls-zk-setup tool's ExportForSolidity emits a V1-shape
//   "SetVerificationKey.sol" that loads VK at runtime via setVerificationKey.
//   The V2 contract instead bakes the VK into bytecode (audit-reports/
//   01-evm-VERIFIED.md EVM-NEW-001 step 4 hardening). The two formats are
//   incompatible. This cmd does the V2-shape export.
//
// Runtime expectations:
//   The V2 circuit has ~775k constraints (emulated BLS12-381 pairing inside
//   BN254). Compile is fast (~10s). Setup is slow (~10-30 minutes depending
//   on hardware) and memory-hungry (~3-5GB peak). Keep the machine warm.
//
// Usage:
//   go run ./cmd/v2-trusted-setup \
//     --keys-out ./bls_zk_keys \
//     --solidity-out ../certen-contracts/evm/src/core/BLSZKVerifierV2Generated.sol
//
// Both flags optional; defaults shown above.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	bls_zkp "github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

func main() {
	keysOut := flag.String("keys-out", "./bls_zk_keys",
		"directory to write proving_key.bin / verification_key.bin / constraint_system.bin")
	solidityOut := flag.String("solidity-out",
		"../certen-contracts/evm/src/core/BLSZKVerifierV2Generated.sol",
		"path to write the generated Solidity verifier contract")
	skipSolidity := flag.Bool("skip-solidity", false,
		"skip writing the Solidity contract (useful if regenerating keys only)")
	flag.Parse()

	log.Println("V2 trusted-setup ceremony starting")
	log.Printf("Keys output directory: %s", *keysOut)
	if !*skipSolidity {
		log.Printf("Solidity output path:  %s", *solidityOut)
	}

	if err := os.MkdirAll(*keysOut, 0o755); err != nil {
		log.Fatalf("create keys dir: %v", err)
	}

	// Step 1: Compile the V2 circuit.
	log.Println("[1/4] Compiling BLSSignatureCircuitV2 → R1CS (BN254)...")
	t0 := time.Now()
	var circuit bls_zkp.BLSSignatureCircuitV2
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("compile circuit: %v", err)
	}
	log.Printf("[1/4] Compile done in %v: nbConstraints=%d nbInternalVars=%d",
		time.Since(t0).Round(time.Second), cs.GetNbConstraints(), cs.GetNbInternalVariables())

	// Sanity: V2 must be substantially larger than V1's ~5 constraints.
	// If we somehow compiled V1 by accident, fail loudly rather than ship
	// keys that match the wrong circuit.
	if cs.GetNbConstraints() < 100_000 {
		log.Fatalf("constraint count %d is suspiciously low — expected ~775k for V2; refusing to proceed",
			cs.GetNbConstraints())
	}

	// Step 2: Trusted setup (slow).
	log.Println("[2/4] Running groth16.Setup — this takes 10-30 min and several GB of RAM...")
	t1 := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("groth16 setup: %v", err)
	}
	log.Printf("[2/4] Setup done in %v", time.Since(t1).Round(time.Second))

	// Step 3: Write keys to disk.
	log.Println("[3/4] Writing keys to disk...")
	if err := writeArtifact(filepath.Join(*keysOut, "proving_key.bin"), pk); err != nil {
		log.Fatalf("write proving key: %v", err)
	}
	if err := writeArtifact(filepath.Join(*keysOut, "verification_key.bin"), vk); err != nil {
		log.Fatalf("write verification key: %v", err)
	}
	if err := writeArtifact(filepath.Join(*keysOut, "constraint_system.bin"), cs); err != nil {
		log.Fatalf("write constraint system: %v", err)
	}
	log.Printf("[3/4] Keys written to %s", *keysOut)

	// Step 4: Export Solidity verifier matching this VK.
	if *skipSolidity {
		log.Println("[4/4] Skipping Solidity export (--skip-solidity)")
	} else {
		log.Println("[4/4] Exporting V2 Solidity verifier...")
		if err := exportSolidityV2(vk, *solidityOut); err != nil {
			log.Fatalf("export Solidity: %v", err)
		}
		log.Printf("[4/4] Solidity verifier written to %s", *solidityOut)
	}

	log.Println("")
	log.Println("=========================================================")
	log.Println("V2 TRUSTED SETUP COMPLETE")
	log.Println("=========================================================")
	log.Println("Next steps:")
	log.Println("  1. Redeploy V2 verifier on each EVM chain (the contract bytes")
	log.Println("     have changed; the OLD on-chain BLSZKVerifierV2Generated")
	log.Println("     contains a stale VK that this setup will not match).")
	log.Println("  2. Update CertenAnchorV6.setBLSZKVerifier(NEW adapter address).")
	log.Println("  3. Distribute proving_key.bin / verification_key.bin /")
	log.Println("     constraint_system.bin to each validator node's")
	log.Println("     BLS_ZK_KEYS_DIR (default ./bls_zk_keys).")
	log.Println("  4. Restart validator binaries.")
	log.Println("=========================================================")
}

// writeArtifact writes a gnark binary artifact (ProvingKey / VerifyingKey /
// ConstraintSystem) to disk. All three expose `WriteTo(io.Writer)`; the
// type switch is just for clarity in logs.
func writeArtifact(path string, obj any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	switch v := obj.(type) {
	case groth16.ProvingKey:
		_, err = v.WriteTo(f)
	case groth16.VerifyingKey:
		_, err = v.WriteTo(f)
	case constraint.ConstraintSystem:
		_, err = v.WriteTo(f)
	default:
		err = fmt.Errorf("unknown artifact type %T (no WriteTo)", obj)
	}
	if err != nil {
		return err
	}
	stat, _ := f.Stat()
	log.Printf("  wrote %s (%d bytes)", path, stat.Size())
	return nil
}

// exportSolidityV2 writes a Solidity verifier matching the given V2 VK,
// renaming the gnark-default "contract Verifier" to
// "contract BLSZKVerifierV2Generated" so the file slots directly into the
// V6 contracts layout.
func exportSolidityV2(vk groth16.VerifyingKey, outPath string) error {
	vkBN254, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("VK is not BN254 type (got %T)", vk)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create solidity dir: %w", err)
	}

	// Write to a temp buffer first so we can rename the contract.
	tmp, err := os.CreateTemp("", "v2-verifier-*.sol")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := vkBN254.ExportSolidity(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("gnark ExportSolidity: %w", err)
	}
	tmp.Close()

	raw, err := os.ReadFile(tmpName)
	if err != nil {
		return fmt.Errorf("read temp solidity: %w", err)
	}
	out := strings.Replace(string(raw), "contract Verifier ", "contract BLSZKVerifierV2Generated ", 1)
	if !strings.Contains(out, "contract BLSZKVerifierV2Generated ") {
		return fmt.Errorf("rename failed: gnark-emitted contract name did not match \"contract Verifier \"; raw header:\n%s",
			truncate(string(raw), 200))
	}

	// Prepend a header noting the regeneration provenance so the file isn't
	// mistaken for hand-edited code.
	header := fmt.Sprintf(
		"// SPDX-License-Identifier: MIT\n"+
			"//\n"+
			"// AUTO-GENERATED by cmd/v2-trusted-setup at %s.\n"+
			"// Regenerated together with bls_zk_keys/proving_key.bin —\n"+
			"// the on-chain VK and the validator's PK MUST be from the same setup\n"+
			"// run, or every proof submission will revert with ProofInvalid().\n"+
			"//\n"+
			"// gnark's ExportSolidity defaults to `contract Verifier`; we rename to\n"+
			"// `contract BLSZKVerifierV2Generated` so the file slots into\n"+
			"// evm/src/core/ directly. Do not hand-edit; rerun cmd/v2-trusted-setup\n"+
			"// to regenerate.\n//\n",
		time.Now().UTC().Format(time.RFC3339))

	// gnark's output already starts with `// SPDX-License-Identifier` and a
	// pragma. Strip its SPDX line so we don't have two SPDX headers stacked.
	out = stripFirstSPDX(out)

	if err := os.WriteFile(outPath, []byte(header+out), 0o644); err != nil {
		return fmt.Errorf("write solidity: %w", err)
	}
	return nil
}

func stripFirstSPDX(s string) string {
	const marker = "// SPDX-License-Identifier"
	idx := strings.Index(s, marker)
	if idx < 0 {
		return s
	}
	end := strings.Index(s[idx:], "\n")
	if end < 0 {
		return s
	}
	return s[idx+end+1:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
