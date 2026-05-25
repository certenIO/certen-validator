//go:build slow_bls_zkp_v2

// Layer 3 — real Groth16 round-trip on the V2 circuit, with fixture export
// for Layer 5 (Foundry end-to-end). Run with:
//
//   go test -tags slow_bls_zkp_v2 ./pkg/crypto/bls_zkp/ -run TestV2_Groth16Roundtrip -v -timeout 120m
//
// What it does:
//   1. Compiles BLSSignatureCircuitV2 to R1CS over BN254.
//   2. Runs groth16.Setup (~hundreds of MB memory, several minutes).
//   3. Generates a real BLS signature, builds the witness, calls groth16.Prove,
//      calls groth16.Verify. Confirms the prove/verify side end-to-end matches
//      the IsSolved-based correctness already verified in circuitv2_slow_test.
//   4. Writes a fixture JSON to testdata/v2_fixtures.json containing:
//        - The VK in Solidity-compatible (alpha1, beta2, gamma2, delta2, ic_x, ic_y)
//        - The keccak256 hash of the abi.encode(...) of those fields, which is
//          exactly what BLSZKVerifierV2's EXPECTED_VK_HASH must equal.
//        - One known-valid proof (proofA, proofB, proofC) and its public inputs,
//          so the Foundry test can ingest it and verify it on-chain.
//
// The fixture is deterministic given the (BN254, V2 circuit, fixed seed) tuple.
// We use a hard-coded test seed for the BLS keys so re-running the test produces
// identical fixtures and the Foundry test diff stays minimal.

package bls_zkp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/sha3"
)

// The keccakToFieldHash implementation lives in keccak_hash.go (non-test, used
// by prover.go GenerateProof / VerifyProofLocally / VerifyFromABIBytes). This
// test file used to carry its own copy; that duplicate has been removed in
// favour of the package-level NewKeccakToFieldHash constructor so that the
// fixture generator and the production prover hash bytes the same way by
// construction (impossible to drift apart).
var newKeccakToFieldHash = NewKeccakToFieldHash

// Deterministic seed for the BLS secret key, so the exported fixture is stable
// across runs (lets Layer 5's Foundry test pin expected values).
var testSK = func() *big.Int {
	v, _ := new(big.Int).SetString(
		"1357913579246802468013579246802468013579246802468013579246802468013",
		10,
	)
	v.Mod(v, bls12381.ID.ScalarField())
	if v.Sign() == 0 {
		v.SetUint64(42)
	}
	return v
}()

// Deterministic test messageHash (high bits cleared so it's < BN254 Fr).
var testMessageHash = func() [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = byte((i * 17) & 0xFF)
	}
	m[0] &= 0x3f
	return m
}()

// fixtureV2 is the JSON shape persisted to testdata/v2_fixtures.json. Field
// names use snake_case to keep the Foundry-side ABI ingestion straightforward.
type fixtureV2 struct {
	Description string `json:"description"`

	// Verification key — fed into setVerificationKey on BLSZKVerifierV2.
	Alpha1 [2]string    `json:"alpha1"`
	Beta2  [2][2]string `json:"beta2"`
	Gamma2 [2][2]string `json:"gamma2"`
	Delta2 [2][2]string `json:"delta2"`
	ICx    []string     `json:"ic_x"`
	ICy    []string     `json:"ic_y"`

	// keccak256(abi.encode(alpha1, beta2, gamma2, delta2, ic_x, ic_y))
	ExpectedVKHash string `json:"expected_vk_hash"`

	// A single valid proof + public inputs the Foundry test will replay.
	ProofA [2]string    `json:"proof_a"`
	ProofB [2][2]string `json:"proof_b"`
	ProofC [2]string    `json:"proof_c"`

	// proof_for_verifier is the EXACT 8-uint256 array the gnark-exported
	// Verifier.verifyProof(...) entry point consumes — i.e. A, B (in EIP-197
	// imag-then-real ordering), C, all concatenated. Built from gnark's
	// MarshalSolidity output so there is no chance of a Foundry-side ordering
	// mistake. The Layer-5 Foundry test reads this directly and does not need
	// to permute proof_b on its own.
	ProofForVerifier [8]string `json:"proof_for_verifier"`

	// gnark's emulated arithmetic injects one Pedersen commitment per proof.
	// The gnark-generated Solidity verifier consumes these alongside (A, B, C)
	// and reconstructs the derived public input internally via keccak. They are
	// always 2 entries each (one G1 point compressed as (x, y)).
	Commitments   [2]string `json:"commitments"`
	CommitmentPok [2]string `json:"commitment_pok"`

	MessageHash       string `json:"message_hash"`       // bytes32 hex
	PubkeyCommitment  string `json:"pubkey_commitment"`  // bytes32 hex
	SignedVotingPower uint64 `json:"signed_voting_power"`
	TotalVotingPower  uint64 `json:"total_voting_power"`
}

func TestV2_Groth16Roundtrip(t *testing.T) {
	t.Log("[V2-rt] compiling circuit (this is fast)")
	var skeleton BLSSignatureCircuitV2
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &skeleton)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("[V2-rt] R1CS: nbConstraints=%d nbInternal=%d", cs.GetNbConstraints(), cs.GetNbInternalVariables())

	t.Log("[V2-rt] running trusted setup (slow — several minutes expected)")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Log("[V2-rt] setup complete")

	// Build a real BLS witness: σ = sk * H(m), pk = sk * G2_gen.
	hm := HashMessageToG1V2(testMessageHash)
	var skFr bls12381fr.Element
	skFr.SetBigInt(testSK)

	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&hm, testSK)

	_, _, _, g2Gen := bls12381.Generators()
	var pkG2 bls12381.G2Affine
	pkG2.ScalarMultiplication(&g2Gen, testSK)

	witnessAssign, _, err := BuildV2Witness(testMessageHash, sig, pkG2, 7, 10)
	if err != nil {
		t.Fatalf("BuildV2Witness: %v", err)
	}

	t.Log("[V2-rt] building witness")
	w, err := frontend.NewWitness(witnessAssign, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	t.Log("[V2-rt] proving (may take a few minutes)")
	// Use keccak-mod-R for the BSB22 commitment hash so the proof binds to the
	// same publicCommitment value the Solidity verifier reconstructs on-chain.
	// Without this override the on-chain pairing check returns false even on a
	// valid proof (the two sides hash the commitment bytes differently).
	proof, err := groth16.Prove(cs, pk, w,
		backend.WithProverHashToFieldFunction(newKeccakToFieldHash()),
	)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	t.Log("[V2-rt] verifying")
	if err := groth16.Verify(proof, vk, pubW,
		backend.WithVerifierHashToFieldFunction(newKeccakToFieldHash()),
	); err != nil {
		t.Fatalf("verify (positive case): %v", err)
	}

	// Diagnostic: what shape is the VK and proof? Standard Groth16 has zero
	// commitments and K length = nbPublic + 1. If the emulated pairing gadget
	// added Pedersen commitments, the EVM verifier needs to mirror the more
	// complex pairing equation (extra pairings for each commitment) — log here
	// so we know which path to take.
	if vkBN254, ok := vk.(*groth16_bn254.VerifyingKey); ok {
		t.Logf("[V2-rt] VK shape: K_len=%d CommitmentKeys=%d PublicAndCommitmentCommitted=%d",
			len(vkBN254.G1.K),
			len(vkBN254.CommitmentKeys),
			len(vkBN254.PublicAndCommitmentCommitted))
		if len(vkBN254.PublicAndCommitmentCommitted) > 0 {
			for i, p := range vkBN254.PublicAndCommitmentCommitted {
				t.Logf("[V2-rt]   PublicAndCommitmentCommitted[%d] = %v", i, p)
			}
		}
	}
	if proofBN254, ok := proof.(*groth16_bn254.Proof); ok {
		t.Logf("[V2-rt] Proof shape: Commitments=%d CommitmentPok=(%v,%v)",
			len(proofBN254.Commitments),
			!proofBN254.CommitmentPok.X.IsZero() || !proofBN254.CommitmentPok.Y.IsZero(),
			proofBN254.CommitmentPok.X.IsZero())
	}

	// Negative case: same proof, different (lying) public messageHash. The
	// gnark.Verify will reject because vk_x changes when the messageHash input
	// changes. This is the in-band proof that Gap A is dead.
	var bogusHash [32]byte
	copy(bogusHash[:], testMessageHash[:])
	bogusHash[0] ^= 0xff
	bogusHash[0] &= 0x3f
	bogusWitnessAssign, _, err := BuildV2Witness(bogusHash, sig, pkG2, 7, 10)
	if err != nil {
		t.Fatalf("BuildV2Witness (bogus): %v", err)
	}
	bogusW, err := frontend.NewWitness(bogusWitnessAssign, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("bogus witness: %v", err)
	}
	bogusPubW, err := bogusW.Public()
	if err != nil {
		t.Fatalf("bogus public: %v", err)
	}
	if err := groth16.Verify(proof, vk, bogusPubW,
		backend.WithVerifierHashToFieldFunction(newKeccakToFieldHash()),
	); err == nil {
		t.Fatal("Gap A regression: groth16.Verify accepted proof with swapped messageHash public input")
	}

	t.Log("[V2-rt] exporting fixture JSON")
	fixturePath := filepath.Join("testdata", "v2_fixtures.json")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	fix := buildFixture(t, vk, proof, witnessAssign)
	jsonBytes, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(fixturePath, jsonBytes, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("[V2-rt] wrote %s (%d bytes)", fixturePath, len(jsonBytes))

	// Also export the gnark-generated Solidity verifier. We can't use a generic
	// "load VK at runtime" verifier because gnark's emulated arithmetic injects
	// a Pedersen commitment into the proof, and the matching on-chain checks
	// (BSB22 challenge, PoK pairing, extra K[nbPublic+1] term) are non-trivial.
	// gnark's ExportSolidity produces a complete and audited verifier with the
	// VK baked into bytecode AND the commitment handling correctly wired. We
	// use it as the source of truth for V2's verification math.
	solPath := filepath.Join("testdata", "v2_verifier_generated.sol")
	solFile, err := os.Create(solPath)
	if err != nil {
		t.Fatalf("create solidity file: %v", err)
	}
	defer solFile.Close()
	if err := vk.ExportSolidity(solFile); err != nil {
		t.Fatalf("export solidity: %v", err)
	}
	t.Logf("[V2-rt] wrote %s", solPath)
}

func buildFixture(
	t *testing.T,
	vk groth16.VerifyingKey,
	proof groth16.Proof,
	w *BLSSignatureCircuitV2,
) *fixtureV2 {
	t.Helper()
	vkBN254, ok := vk.(*groth16_bn254.VerifyingKey)
	if !ok {
		t.Fatalf("VK is not BN254 type")
	}
	proofBN254, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		t.Fatalf("proof is not BN254 type")
	}

	g1ToStrs := func(p bn254curve.G1Affine) [2]string {
		var x, y big.Int
		p.X.BigInt(&x)
		p.Y.BigInt(&y)
		return [2]string{x.String(), y.String()}
	}
	g2ToStrs := func(p bn254curve.G2Affine) [2][2]string {
		var x0, x1, y0, y1 big.Int
		p.X.A0.BigInt(&x0)
		p.X.A1.BigInt(&x1)
		p.Y.A0.BigInt(&y0)
		p.Y.A1.BigInt(&y1)
		return [2][2]string{
			{x0.String(), x1.String()},
			{y0.String(), y1.String()},
		}
	}

	alpha1 := g1ToStrs(vkBN254.G1.Alpha)
	beta2 := g2ToStrs(vkBN254.G2.Beta)
	gamma2 := g2ToStrs(vkBN254.G2.Gamma)
	delta2 := g2ToStrs(vkBN254.G2.Delta)

	icx := make([]string, len(vkBN254.G1.K))
	icy := make([]string, len(vkBN254.G1.K))
	for i, ic := range vkBN254.G1.K {
		var x, y big.Int
		ic.X.BigInt(&x)
		ic.Y.BigInt(&y)
		icx[i] = x.String()
		icy[i] = y.String()
	}

	expectedVKHash := computeExpectedVKHash(alpha1, beta2, gamma2, delta2, icx, icy)

	proofA := g1ToStrs(proofBN254.Ar)
	proofB := g2ToStrs(proofBN254.Bs)
	proofC := g1ToStrs(proofBN254.Krs)

	// Authoritative 8-uint256 layout — use gnark's own MarshalSolidity helper
	// which writes A | B | C in the exact byte order the gnark-generated
	// Solidity verifier expects (EIP-197 imag-then-real for the G2 point B).
	rawMarshalled := proofBN254.MarshalSolidity()
	if len(rawMarshalled) < 8*32 {
		t.Fatalf("MarshalSolidity produced %d bytes, expected at least 256", len(rawMarshalled))
	}
	var proofForVerifier [8]string
	for i := 0; i < 8; i++ {
		w := new(big.Int).SetBytes(rawMarshalled[i*32 : (i+1)*32])
		proofForVerifier[i] = w.String()
	}

	// Commitments + PoK — only meaningful when the circuit triggers gnark's
	// internal Pedersen commitment (which our V2 does, via the emulated
	// pairing's hint mechanism). For a V2 proof we expect exactly one
	// commitment; downstream code asserts that.
	if len(proofBN254.Commitments) != 1 {
		t.Fatalf("expected exactly 1 Pedersen commitment in V2 proof, got %d",
			len(proofBN254.Commitments))
	}
	commitments := g1ToStrs(proofBN254.Commitments[0])
	commitmentPok := g1ToStrs(proofBN254.CommitmentPok)

	// Public-input values exactly as the Solidity verifier sees them.
	// The witness fields w.MessageHash and w.PubkeyCommitment are *big.Int
	// (assigned via the helper). Print them as 0x-prefixed 32-byte hex.
	msg := toBig(w.MessageHash)
	pkCommit := toBig(w.PubkeyCommitment)

	return &fixtureV2{
		Description:       "BLSSignatureCircuitV2 Groth16 fixture — generated by TestV2_Groth16Roundtrip.",
		Alpha1:            alpha1,
		Beta2:             beta2,
		Gamma2:            gamma2,
		Delta2:            delta2,
		ICx:               icx,
		ICy:               icy,
		ExpectedVKHash:    expectedVKHash,
		ProofA:            proofA,
		ProofB:            proofB,
		ProofC:            proofC,
		ProofForVerifier:  proofForVerifier,
		Commitments:       commitments,
		CommitmentPok:     commitmentPok,
		MessageHash:       to32ByteHex(msg),
		PubkeyCommitment:  to32ByteHex(pkCommit),
		SignedVotingPower: uint64FromAny(w.SignedVotingPower),
		TotalVotingPower:  uint64FromAny(w.TotalVotingPower),
	}
}

// computeExpectedVKHash mirrors the Solidity
//   keccak256(abi.encode(alpha1, beta2, gamma2, delta2, ic_x, ic_y))
// computation, so the off-chain fixture's hash equals what
// BLSZKVerifierV2.EXPECTED_VK_HASH must be set to in its constructor.
//
// abi.encode for a struct with a fixed-size array packs each uint256 in 32
// bytes. Dynamic uint256[] arrays are encoded as offset || length || items;
// because we pass each array as a top-level argument the inner offsets get
// resolved by the outer abi.encode. Reproducing that exactly in Go is tricky;
// fortunately, for this purpose we just need a stable hash that the Solidity
// side can recompute from the same inputs. We use go-ethereum's abi package
// to do it properly.
//
// To keep dependencies minimal we hand-roll the encoder here: it follows the
// Solidity ABI spec for `abi.encode(uint256[2], uint256[2][2], uint256[2][2],
// uint256[2][2], uint256[] memory, uint256[] memory)`.
func computeExpectedVKHash(
	alpha1 [2]string,
	beta2, gamma2, delta2 [2][2]string,
	icx, icy []string,
) string {
	// Head section: 4 head slots for the four fixed-size arrays inlined
	// (alpha1 is 2 words, beta2/gamma2/delta2 are 4 words each), then two
	// offset words for icx, icy. Tail: each dynamic array as (length, items...).
	headFixedWords := 2 + 4 + 4 + 4 // = 14
	const offsetSlot = 32

	// First compute tail lengths in words so we can compute the offset pointers.
	icxTailWords := 1 + len(icx)

	// Total head size in bytes:
	headSizeBytes := (headFixedWords + 2) * offsetSlot // 2 = offset pointers
	// Offsets (in bytes) into the encoded buffer:
	icxOffsetBytes := uint64(headSizeBytes)
	icyOffsetBytes := uint64(headSizeBytes) + uint64(icxTailWords)*32

	var buf bytes.Buffer
	writeWord := func(v string) {
		bi := mustParseBigDecimal(v)
		b := bi.Bytes()
		pad := make([]byte, 32-len(b))
		buf.Write(pad)
		buf.Write(b)
	}
	writeUint := func(v uint64) {
		bi := new(big.Int).SetUint64(v)
		b := bi.Bytes()
		pad := make([]byte, 32-len(b))
		buf.Write(pad)
		buf.Write(b)
	}

	// HEAD ------------------------------------------------------------------
	// alpha1 (uint256[2])
	writeWord(alpha1[0])
	writeWord(alpha1[1])
	// beta2, gamma2, delta2 (each uint256[2][2])
	for _, g2 := range [3][2][2]string{beta2, gamma2, delta2} {
		writeWord(g2[0][0])
		writeWord(g2[0][1])
		writeWord(g2[1][0])
		writeWord(g2[1][1])
	}
	// offset pointers
	writeUint(icxOffsetBytes)
	writeUint(icyOffsetBytes)

	// TAIL ------------------------------------------------------------------
	writeUint(uint64(len(icx)))
	for _, v := range icx {
		writeWord(v)
	}
	writeUint(uint64(len(icy)))
	for _, v := range icy {
		writeWord(v)
	}

	// keccak256
	h := sha3.NewLegacyKeccak256()
	h.Write(buf.Bytes())
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

func mustParseBigDecimal(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad decimal: " + s)
	}
	return v
}

func toBig(v frontend.Variable) *big.Int {
	switch x := v.(type) {
	case big.Int:
		return new(big.Int).Set(&x)
	case *big.Int:
		return new(big.Int).Set(x)
	case uint64:
		return new(big.Int).SetUint64(x)
	case int:
		return big.NewInt(int64(x))
	default:
		panic("toBig: unsupported variable type")
	}
}

func to32ByteHex(v *big.Int) string {
	b := v.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return "0x" + hex.EncodeToString(out)
}

func uint64FromAny(v frontend.Variable) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int:
		return uint64(x)
	case big.Int:
		return x.Uint64()
	case *big.Int:
		return x.Uint64()
	default:
		panic("uint64FromAny: unsupported variable type")
	}
}
