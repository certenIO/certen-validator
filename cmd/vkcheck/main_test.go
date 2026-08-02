package main

import (
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// The build must never mint ZK keys
// =============================================================================
//
// groth16.Setup samples fresh toxic waste from crypto/rand on every invocation, so a
// regenerated key can never match the deployed verifier. An image built that way compiles,
// starts, and emits structurally valid proofs that the chain rejects — taking down batch
// attestation AND the per-intent on_demand path, and presenting as a cryptographic bug.
//
// The Dockerfile once regenerated the keys whenever they were absent, under a comment claiming
// they were deterministic. This is the tripwire against that returning.

func dockerfile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("reading Dockerfile: %v", err)
	}
	return string(b)
}

func TestDockerfileNeverRunsTheTrustedSetup(t *testing.T) {
	src := dockerfile(t)

	// Strip comments: the file explains the hazard by name, and that prose must not trip this.
	var code []string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		code = append(code, line)
	}
	joined := strings.Join(code, "\n")

	for _, banned := range []string{"bls-zk-setup", "RunSetupCLI", "groth16.Setup"} {
		if strings.Contains(joined, banned) {
			t.Fatalf("Dockerfile invokes %q. A trusted setup during the build mints keys that "+
				"CANNOT match the deployed verifier — every proof would be rejected on chain, "+
				"including the per-intent on_demand path. It also drove the production host past "+
				"load average 5800. Keys must be staged and verified, never generated.", banned)
		}
	}
}

// The build must actively verify the keys, not merely refrain from generating them. A build
// that silently accepts whatever bytes happen to be present is the same outage with an extra
// step.
func TestDockerfileVerifiesKeyDigests(t *testing.T) {
	src := dockerfile(t)
	if !strings.Contains(src, "sha256sum -c") {
		t.Fatal("Dockerfile does not verify the ZK key digests; substituted keys would ship")
	}
	if !strings.Contains(src, "bls_zk_keys.SHA256SUMS") {
		t.Fatal("Dockerfile does not reference the pinned digest file")
	}
}

// The pinned digests must be tracked in git. bls_zk_keys/ itself is gitignored — a 215 MB
// proving key does not belong in the repo — so if the pins lived beside the keys they would be
// ignored too and no checkout would carry them.
func TestPinnedDigestsExistAndAreWellFormed(t *testing.T) {
	p := filepath.Join("..", "..", "deploy", "bls_zk_keys.SHA256SUMS")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("pinned digests missing at %s: %v", p, err)
	}
	want := map[string]bool{
		"proving_key.bin": false, "verification_key.bin": false, "constraint_system.bin": false,
	}
	line := regexp.MustCompile(`^([0-9a-f]{64})\s+\*?(\S+)$`)
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		m := line.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			t.Fatalf("malformed digest line: %q", l)
		}
		if _, ok := want[m[2]]; ok {
			want[m[2]] = true
		}
	}
	for f, seen := range want {
		if !seen {
			t.Fatalf("no pinned digest for %s", f)
		}
	}
}

// =============================================================================
// Field negation
// =============================================================================
//
// The generated verifier stores beta, gamma and delta NEGATED so the pairing check does not
// have to negate on chain. Comparing an exported key against those constants therefore means
// negating the exported G2 Y coordinates over the BN254 base field first. Getting this backwards
// would make a CORRECT key look mismatched — and, worse, could make a mismatched one look
// correct if someone "fixed" the comparison by dropping the negation.

func TestNegFpIsAnInvolutionOverBn254(t *testing.T) {
	for _, s := range []string{
		"1",
		"12345678901234567890",
		"21888242871839275222246405745257275088696311157297823662689037894645226208582", // P-1
	} {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("bad fixture %q", s)
		}
		if got := negFp(negFp(v)); got.Cmp(v) != 0 {
			t.Fatalf("neg(neg(%s)) = %s, want %s", v, got, v)
		}
		// x + (-x) must be exactly the modulus for any non-zero x.
		sum := new(big.Int).Add(v, negFp(v))
		if sum.Cmp(bn254P) != 0 {
			t.Fatalf("%s + neg = %s, want the modulus %s", v, sum, bn254P)
		}
	}
}

// Zero is its own negation. Returning P for zero would put the value outside the field and make
// a legitimate zero coordinate compare unequal.
func TestNegFpZeroStaysZero(t *testing.T) {
	if got := negFp(big.NewInt(0)); got.Sign() != 0 {
		t.Fatalf("neg(0) = %s, want 0", got)
	}
}

// The modulus itself must be BN254's, not BLS12-381's. The circuit proves a BLS12-381 pairing
// INSIDE BN254, so both moduli are in scope and swapping them is an easy, silent error.
func TestModulusIsBn254(t *testing.T) {
	const bn254 = "21888242871839275222246405745257275088696311157297823662689037894645226208583"
	if bn254P.String() != bn254 {
		t.Fatalf("modulus is %s, want the BN254 base field %s", bn254P, bn254)
	}
}

// The verifier parser must actually find constants — a silent zero-match would report success
// while comparing nothing.
func TestParseVerifierExtractsConstants(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "V.sol")
	body := `contract V {
    uint256 constant ALPHA_X = 20205644587983953978451790240681842921278346330089820527610668355527449406531;
    uint256 constant P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d constants, want 2", len(got))
	}
	if got["ALPHA_X"].String() != "20205644587983953978451790240681842921278346330089820527610668355527449406531" {
		t.Fatalf("decimal constant wrong: %s", got["ALPHA_X"])
	}
	if got["P"].Cmp(bn254P) != 0 {
		t.Fatalf("hex constant wrong: %s", got["P"])
	}
}
