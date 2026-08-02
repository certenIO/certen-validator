// vkcheck proves that the ZK verification key on this machine is the one the DEPLOYED
// verifier contract will check proofs against.
//
// # WHY THIS EXISTS
//
// The Dockerfile used to regenerate the ZK keys whenever `bls_zk_keys/proving_key.bin` was
// absent from the build context:
//
//	if [ ! -f /build/bls_zk_keys/proving_key.bin ]; then go run ./cmd/bls-zk-setup; fi
//
// gnark's groth16.Setup samples fresh toxic waste from crypto/rand on every invocation. It is
// NOT deterministic and cannot be made so by re-running it. A regenerated key therefore has a
// verification key that CANNOT match the constants compiled into BLSZKVerifierV2Generated.sol.
//
// An image built that way looks perfectly healthy: it compiles, starts, signs, and produces
// structurally valid Groth16 proofs. Every one of them fails on chain — not only batch
// attestations but the working per-intent on_demand path too, because both submit through
// generateBLSZKProof. That is a total settlement outage presenting as a cryptographic bug.
//
// So the key is treated as a deployment artifact that must be VERIFIED, never derived:
//
//	vkcheck -keys ./bls_zk_keys -verifier <path to BLSZKVerifierV2Generated.sol>
//
// Exit code is non-zero on any mismatch, so it can gate a build or a deploy.
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

// vkConstants are the Groth16 verification-key elements the generated Solidity verifier
// compiles in. Names match the contract's `uint256 constant` identifiers exactly.
//
// The contract stores BETA, GAMMA and DELTA NEGATED — the pairing check folds the negation in
// so the EVM does not have to. Comparing a freshly exported key against them therefore means
// negating the exported G2 Y coordinates over the BN254 base field first; see negFp.
type vkConstants map[string]*big.Int

// bn254P is the BN254 base field modulus, from the contract's `uint256 constant P`.
var bn254P, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

func negFp(v *big.Int) *big.Int {
	if v.Sign() == 0 {
		return new(big.Int)
	}
	return new(big.Int).Sub(bn254P, new(big.Int).Mod(v, bn254P))
}

var constRe = regexp.MustCompile(`uint256\s+constant\s+([A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)\s*;`)

func parseVerifier(path string) (vkConstants, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := vkConstants{}
	for _, m := range constRe.FindAllStringSubmatch(string(b), -1) {
		name, lit := m[1], m[2]
		v := new(big.Int)
		if strings.HasPrefix(lit, "0x") || strings.HasPrefix(lit, "0X") {
			if _, ok := v.SetString(lit[2:], 16); !ok {
				continue
			}
		} else if _, ok := v.SetString(lit, 10); !ok {
			continue
		}
		out[name] = v
	}
	return out, nil
}

type check struct {
	label    string
	got      *big.Int
	wantName string
}

func main() {
	keysDir := flag.String("keys", "./bls_zk_keys", "directory holding proving_key.bin / verification_key.bin / constraint_system.bin")
	verifier := flag.String("verifier", "", "path to BLSZKVerifierV2Generated.sol (required)")
	flag.Parse()

	if *verifier == "" {
		fmt.Println("❌ -verifier is required: the whole point is to compare against the DEPLOYED verifier")
		os.Exit(2)
	}

	fmt.Printf("\n=== ZK verification-key binding ===\nkeys     %s\nverifier %s\n\n", *keysDir, *verifier)

	// ---- The keys must be PRESENT. Never generate here. ---------------------
	for _, f := range []string{"proving_key.bin", "verification_key.bin", "constraint_system.bin"} {
		p := filepath.Join(*keysDir, f)
		st, err := os.Stat(p)
		if err != nil {
			fmt.Printf("❌ %s is missing.\n\n"+
				"   Do NOT regenerate it. groth16.Setup samples fresh toxic waste every run, so a\n"+
				"   regenerated key can never match the deployed verifier, and every BLS ZK proof\n"+
				"   would fail on chain — including the per-intent on_demand path.\n"+
				"   Restore it from the operator's key custody instead.\n", p)
			os.Exit(1)
		}
		fmt.Printf("  present %-24s %10d bytes\n", f, st.Size())
	}

	// ---- Load the key and export its VK -------------------------------------
	prover := bls_zkp.NewBLSZKProver()
	if err := prover.InitializeFromKeys(
		filepath.Join(*keysDir, "proving_key.bin"),
		filepath.Join(*keysDir, "verification_key.bin"),
		filepath.Join(*keysDir, "constraint_system.bin"),
	); err != nil {
		fmt.Printf("\n❌ loading keys failed: %v\n", err)
		os.Exit(1)
	}
	vk, err := prover.ExportVerificationKey()
	if err != nil {
		fmt.Printf("\n❌ exporting verification key: %v\n", err)
		os.Exit(1)
	}

	consts, err := parseVerifier(*verifier)
	if err != nil {
		fmt.Printf("\n❌ reading verifier contract: %v\n", err)
		os.Exit(1)
	}
	if len(consts) == 0 {
		fmt.Println("\n❌ no uint256 constants parsed from the verifier — wrong file?")
		os.Exit(1)
	}

	// ---- Compare ------------------------------------------------------------
	//
	// gnark's G2 element ordering is [A0, A1] where the contract writes _0 / _1 in the same
	// order. ALPHA is stored plain; BETA/GAMMA/DELTA are stored negated.
	checks := []check{
		{"alpha.X", vk.Alpha1[0], "ALPHA_X"},
		{"alpha.Y", vk.Alpha1[1], "ALPHA_Y"},

		{"-beta.X0", vk.Beta2[0][0], "BETA_NEG_X_0"},
		{"-beta.X1", vk.Beta2[0][1], "BETA_NEG_X_1"},
		{"-beta.Y0", negFp(vk.Beta2[1][0]), "BETA_NEG_Y_0"},
		{"-beta.Y1", negFp(vk.Beta2[1][1]), "BETA_NEG_Y_1"},

		{"-gamma.X0", vk.Gamma2[0][0], "GAMMA_NEG_X_0"},
		{"-gamma.X1", vk.Gamma2[0][1], "GAMMA_NEG_X_1"},
		{"-gamma.Y0", negFp(vk.Gamma2[1][0]), "GAMMA_NEG_Y_0"},
		{"-gamma.Y1", negFp(vk.Gamma2[1][1]), "GAMMA_NEG_Y_1"},

		{"-delta.X0", vk.Delta2[0][0], "DELTA_NEG_X_0"},
		{"-delta.X1", vk.Delta2[0][1], "DELTA_NEG_X_1"},
		{"-delta.Y0", negFp(vk.Delta2[1][0]), "DELTA_NEG_Y_0"},
		{"-delta.Y1", negFp(vk.Delta2[1][1]), "DELTA_NEG_Y_1"},
	}

	// IC (one per public input, plus the constant term) is where a circuit-shape change shows
	// up. Names in the generated verifier are CONSTANT_X/Y then PUB_<i>_X/Y.
	icNames := [][2]string{{"CONSTANT_X", "CONSTANT_Y"}}
	for i := 0; i+1 < len(vk.IC); i++ {
		icNames = append(icNames, [2]string{
			fmt.Sprintf("PUB_%d_X", i), fmt.Sprintf("PUB_%d_Y", i),
		})
	}
	for i, n := range icNames {
		if i >= len(vk.IC) {
			break
		}
		if _, ok := consts[n[0]]; !ok {
			continue // verifier names IC differently; the G1/G2 checks above are decisive
		}
		checks = append(checks,
			check{fmt.Sprintf("ic[%d].X", i), vk.IC[i][0], n[0]},
			check{fmt.Sprintf("ic[%d].Y", i), vk.IC[i][1], n[1]},
		)
	}

	var mismatched, missing int
	fmt.Println()
	for _, c := range checks {
		want, ok := consts[c.wantName]
		if !ok {
			fmt.Printf("  ?  %-12s %-16s not found in verifier\n", c.label, c.wantName)
			missing++
			continue
		}
		if c.got.Cmp(want) != 0 {
			fmt.Printf("  ❌ %-12s %s\n       local  %s\n       chain  %s\n",
				c.label, c.wantName, c.got, want)
			mismatched++
			continue
		}
		fmt.Printf("  ✅ %-12s %s\n", c.label, c.wantName)
	}

	fmt.Println()
	if mismatched > 0 {
		fmt.Printf("❌ VERIFICATION KEY DOES NOT MATCH THE DEPLOYED VERIFIER (%d element(s) differ).\n\n"+
			"   These keys must NOT ship. Every Groth16 proof they produce will be structurally\n"+
			"   valid and rejected on chain, taking down batch attestation AND the per-intent\n"+
			"   on_demand path with it.\n\n"+
			"   Either restore the keys that match the deployed verifier, or deploy a verifier\n"+
			"   generated from THESE keys — never ship a mismatch.\n", mismatched)
		os.Exit(1)
	}
	if missing == len(checks) {
		fmt.Println("❌ nothing could be compared — the verifier's constant names did not match any expected name.")
		os.Exit(1)
	}
	fmt.Printf("✅ VERIFICATION KEY MATCHES THE DEPLOYED VERIFIER (%d element(s) compared, %d not present in the contract)\n\n",
		len(checks)-missing, missing)
}
