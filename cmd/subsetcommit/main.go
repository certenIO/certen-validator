// Command subsetcommit enumerates every permitted signer subset of the registered validator
// set and emits the aggregate-pubkey commitment for each, for registration via
// CertenAnchorV8.setAuthorizedPubkeyCommitments (CRYPTO-007).
//
// # WHY EVERY SUBSET
//
// A 5-of-7 aggregate pubkey is a different G2 point than 6-of-7 or 7-of-7, so it folds to a
// different commitment. Authorizing only the full set would silently convert the 2/3 BFT
// threshold into a 7-of-7 requirement — trading away liveness. Every subset meeting the
// threshold is enumerated instead: C(7,5)+C(7,6)+C(7,7) = 21+7+1 = 29.
//
// # WHICH FOLD
//
// ComputePubkeyCommitmentV2 — the BN254 variant. This is NOT arbitrary: the production
// prover reaches it via BLSZKProver.GenerateProof -> BuildV2Witness -> ComputePubkeyCommitmentV2,
// and the EVM verifier is BN254 (BLSZKVerifierV2.R is the BN254 scalar modulus).
// ComputePubkeyCommitmentV2BLS381 exists for the BLS12-381 target (Cardano) and would
// produce values no EVM proof can ever match — authorizing those would lock the honest
// quorum out with no way to attest the transaction that fixes it, permanently.
//
// The matching proving keys are BLS_ZK_KEYS_DIR=/app/bls_zk_keys (BN254, ~215MB).
// bls_zk_keys_bls12381* is the Cardano set; loading it here fails with
//
//	"read proving key: read domain: invalid fr.Element encoding"
//
// which is the second, independent signal that the BN254 path is the correct one.
//
// VERIFIED 2026-08-01 on Sepolia: the real prover emitted pubkeyCommitment
// 0x00790bb79d07a0ebaa826c749d9940f8534f56213c106ca0f4b214f195171354 for 7-of-7,
// byte-identical to this tool's output.
//
// -selfcheck (default on) proves that equivalence rather than asserting it: it signs a
// message with all seven keys, aggregates, runs the REAL prover witness path, and requires
// the resulting commitment to equal the one this tool computed for the full set.
//
// Usage:
//
//	go run ./cmd/subsetcommit -keys bls_keys_backup_MASTER.json [-threshold-num 2 -threshold-den 3]
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

type keyFile struct {
	Validators []struct {
		ValidatorID   string `json:"validator_id"`
		BLSPublicKey  string `json:"bls_public_key"`
		BLSPrivateKey string `json:"bls_private_key"`
	} `json:"validators"`
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	var (
		keysPath  = flag.String("keys", "bls_keys_backup_MASTER.json", "validator BLS key file")
		thrNum    = flag.Int("threshold-num", 2, "threshold numerator")
		thrDen    = flag.Int("threshold-den", 3, "threshold denominator")
		power     = flag.Int("power", 100, "voting power per validator (uniform)")
		selfcheck = flag.Bool("selfcheck", true, "prove the fold matches the production prover")
		asJSON    = flag.Bool("json", false, "emit JSON instead of a report")
	)
	flag.Parse()

	raw, err := os.ReadFile(*keysPath)
	if err != nil {
		fatal("reading %s: %v", *keysPath, err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		fatal("parsing key file: %v", err)
	}
	n := len(kf.Validators)
	if n == 0 {
		fatal("key file contains no validators")
	}

	// Load every keypair. Private keys are needed only for -selfcheck.
	pubs := make([]*bls.PublicKey, n)
	privs := make([]*bls.PrivateKey, n)
	for i, v := range kf.Validators {
		skBytes, err := hex.DecodeString(strings.TrimPrefix(v.BLSPrivateKey, "0x"))
		if err != nil {
			fatal("%s: bad private key: %v", v.ValidatorID, err)
		}
		sk, err := bls.PrivateKeyFromBytes(skBytes)
		if err != nil {
			fatal("%s: loading private key: %v", v.ValidatorID, err)
		}
		privs[i] = sk
		pubs[i] = sk.PublicKey()

		// The derived public key must match what the backup records, or the file and the
		// derivation have diverged and every commitment below would be wrong.
		want := strings.TrimPrefix(strings.ToLower(v.BLSPublicKey), "0x")
		got := strings.TrimPrefix(strings.ToLower(pubs[i].Hex()), "0x")
		if want != "" && want != got {
			fatal("%s: derived pubkey does not match the backup file\n  file: %s\n  derived: %s",
				v.ValidatorID, want, got)
		}
	}
	fmt.Printf("loaded %d validators; derived pubkeys match the backup file\n", n)

	total := n * *power
	required := (total * *thrNum) / *thrDen
	minSigners := 0
	for k := 1; k <= n; k++ {
		if k**power >= required {
			minSigners = k
			break
		}
	}
	if minSigners == 0 {
		fatal("no subset size can meet the threshold")
	}
	fmt.Printf("total power %d, threshold %d/%d -> need >= %d -> minimum %d signers\n\n",
		total, *thrNum, *thrDen, required, minSigners)

	// ---- selfcheck: prove this fold is the one the production prover uses ----
	if *selfcheck {
		if err := proveFoldMatchesProver(privs, pubs); err != nil {
			fatal("SELFCHECK FAILED — do NOT authorize these commitments: %v", err)
		}
		fmt.Println("selfcheck: fold matches the production prover witness path")
		fmt.Println()
	}

	// ---- enumerate every subset of size >= minSigners ------------------------
	type entry struct {
		Signers    []string `json:"signers"`
		Size       int      `json:"size"`
		Commitment string   `json:"commitment"`
	}
	var out []entry
	seen := map[string]string{}

	for mask := 1; mask < (1 << n); mask++ {
		var idxs []int
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				idxs = append(idxs, i)
			}
		}
		if len(idxs) < minSigners {
			continue
		}

		subset := make([]*bls.PublicKey, 0, len(idxs))
		names := make([]string, 0, len(idxs))
		for _, i := range idxs {
			subset = append(subset, pubs[i])
			names = append(names, kf.Validators[i].ValidatorID)
		}

		agg, err := bls.AggregatePublicKeys(subset)
		if err != nil {
			fatal("aggregating subset %v: %v", names, err)
		}
		c, err := commitmentFor(agg)
		if err != nil {
			fatal("folding subset %v: %v", names, err)
		}
		hexc := "0x" + hex.EncodeToString(c[:])

		// Two distinct subsets sharing a commitment would mean one could impersonate the
		// other. Astronomically unlikely, but it is cheap to prove it did not happen.
		if prev, dup := seen[hexc]; dup {
			fatal("COLLISION: subsets %s and %s fold to the same commitment %s",
				prev, strings.Join(names, "+"), hexc)
		}
		seen[hexc] = strings.Join(names, "+")

		out = append(out, entry{Signers: names, Size: len(idxs), Commitment: hexc})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size < out[j].Size
		}
		return out[i].Commitment < out[j].Commitment
	})

	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("%d authorized subsets (no commitment collisions)\n\n", len(out))
	bySize := map[int]int{}
	for _, e := range out {
		bySize[e.Size]++
	}
	for k := minSigners; k <= n; k++ {
		fmt.Printf("  %d-of-%d : %d subsets\n", k, n, bySize[k])
	}
	fmt.Println()
	for _, e := range out {
		fmt.Printf("%s  %d-of-%d  %s\n", e.Commitment, e.Size, n, strings.Join(e.Signers, ","))
	}

	fmt.Println("\n--- solidity calldata (setAuthorizedPubkeyCommitments) ---")
	parts := make([]string, 0, len(out))
	for _, e := range out {
		parts = append(parts, e.Commitment)
	}
	fmt.Printf("[%s]\n", strings.Join(parts, ","))
}

// commitmentFor folds an aggregate pubkey exactly as the circuit does.
func commitmentFor(agg *bls.PublicKey) ([32]byte, error) {
	pt, err := toG2(agg.Bytes())
	if err != nil {
		return [32]byte{}, err
	}
	return bls_zkp.ComputePubkeyCommitmentV2(pt)
}

// toG2 deserializes a compressed G2 pubkey. Uses gnark-crypto's SetBytes so the point is
// decompressed exactly as CreateWitnessFromBLSData does.
func toG2(b []byte) (bls12381.G2Affine, error) {
	var p bls12381.G2Affine
	if len(b) < 96 {
		return p, fmt.Errorf("pubkey too short: %d bytes (need 96 compressed G2)", len(b))
	}
	if _, err := p.SetBytes(b[:96]); err != nil {
		return p, fmt.Errorf("deserialize G2 pubkey: %w", err)
	}
	return p, nil
}

// toG1 deserializes a compressed G1 signature.
func toG1(b []byte) (bls12381.G1Affine, error) {
	var p bls12381.G1Affine
	if len(b) < 48 {
		return p, fmt.Errorf("signature too short: %d bytes (need 48 compressed G1)", len(b))
	}
	if _, err := p.SetBytes(b[:48]); err != nil {
		return p, fmt.Errorf("deserialize G1 signature: %w", err)
	}
	return p, nil
}

// proveFoldMatchesProver signs with every key, aggregates, and drives the REAL prover
// witness path — the one GenerateProof uses — then requires the commitment it produces to
// equal this tool's. Anything less would be asserting the equivalence rather than proving it.
func proveFoldMatchesProver(privs []*bls.PrivateKey, pubs []*bls.PublicKey) error {
	var msg [32]byte
	copy(msg[:], []byte("certen:subsetcommit:selfcheck:v1"))

	sigs := make([]*bls.Signature, 0, len(privs))
	for _, sk := range privs {
		s := bls_zkp.SignV6_1PreExec(sk, msg)
		if s == nil {
			return fmt.Errorf("signing returned nil")
		}
		sigs = append(sigs, s)
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return fmt.Errorf("aggregate signatures: %w", err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		return fmt.Errorf("aggregate pubkeys: %w", err)
	}

	vp := uint64(100 * len(privs))

	// BuildV2Witness is exactly what BLSZKProver.GenerateProof calls, so driving it here
	// proves the equivalence rather than assuming it.
	sigPt, err := toG1(aggSig.Bytes())
	if err != nil {
		return err
	}
	pkPt, err := toG2(aggPub.Bytes())
	if err != nil {
		return err
	}
	_, proverCommitment, err := bls_zkp.BuildV2Witness(msg, sigPt, pkPt, vp, vp)
	if err != nil {
		return fmt.Errorf("build v2 witness: %w", err)
	}

	mine, err := commitmentFor(aggPub)
	if err != nil {
		return err
	}
	if mine != proverCommitment {
		return fmt.Errorf("fold mismatch\n  subsetcommit: %x\n  prover      : %x", mine, proverCommitment)
	}
	return nil
}
