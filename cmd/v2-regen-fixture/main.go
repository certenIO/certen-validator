// V2 fixture regenerator.
//
// After a fresh V2 trusted-setup ceremony, the on-chain VK and the validator's
// PK change but evm/test/fixtures/v2_fixtures.json still holds the OLD VK +
// proof. The Foundry E2E tests (BLSZKVerifierV2_E2E.t.sol, _Direct.t.sol)
// then fail with CommitmentInvalid / "Go/Solidity drift" until the fixture
// is regenerated.
//
// This tool loads the keys saved by cmd/v2-trusted-setup, builds a real
// BLS12-381 witness deterministically, runs groth16.Prove with the keccak-mod-R
// hash override the on-chain verifier expects, and writes a fresh fixture
// JSON. It does NOT re-run Setup, so the resulting proof verifies against the
// on-chain VK that cmd/v2-trusted-setup deployed.
//
// Usage:
//   go run ./cmd/v2-regen-fixture \
//     --keys-in  ./bls_zk_keys \
//     --fixture-out ../certen-contracts/evm/test/fixtures/v2_fixtures.json

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bn254curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	bls_zkp "github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

// fixtureV2 mirrors the schema in
// independant_validator/pkg/crypto/bls_zkp/circuitv2_roundtrip_test.go.
// Field order/names MUST match what the Foundry tests
// (BLSZKVerifierV2_E2E.t.sol, _Direct.t.sol) decode.
type fixtureV2 struct {
	Description string `json:"description"`

	Alpha1 [2]string    `json:"alpha1"`
	Beta2  [2][2]string `json:"beta2"`
	Gamma2 [2][2]string `json:"gamma2"`
	Delta2 [2][2]string `json:"delta2"`
	ICx    []string     `json:"ic_x"`
	ICy    []string     `json:"ic_y"`

	ExpectedVKHash string `json:"expected_vk_hash"`

	ProofA [2]string    `json:"proof_a"`
	ProofB [2][2]string `json:"proof_b"`
	ProofC [2]string    `json:"proof_c"`

	ProofForVerifier [8]string `json:"proof_for_verifier"`

	Commitments   [2]string `json:"commitments"`
	CommitmentPok [2]string `json:"commitment_pok"`

	MessageHash       string `json:"message_hash"`
	PubkeyCommitment  string `json:"pubkey_commitment"`
	SignedVotingPower uint64 `json:"signed_voting_power"`
	TotalVotingPower  uint64 `json:"total_voting_power"`
}

// Deterministic test BLS secret key — same as the round-trip test so the
// fixture is reproducible across regenerations (as long as the keys haven't
// changed). Cryptographically meaningless; do not reuse anywhere real.
func makeTestSK() *big.Int {
	v, _ := new(big.Int).SetString(
		"1357913579246802468013579246802468013579246802468013579246802468013",
		10,
	)
	v.Mod(v, bls12381.ID.ScalarField())
	if v.Sign() == 0 {
		v.SetUint64(42)
	}
	return v
}

// Deterministic test messageHash — high bits cleared so it's < BN254 Fr.
func makeTestMessageHash() [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = byte((i * 17) & 0xFF)
	}
	m[0] &= 0x3f
	return m
}

func main() {
	keysIn := flag.String("keys-in", "./bls_zk_keys",
		"directory containing proving_key.bin, verification_key.bin, constraint_system.bin")
	fixtureOut := flag.String("fixture-out",
		"../certen-contracts/evm/test/fixtures/v2_fixtures.json",
		"path to write the V2 fixture JSON")
	flag.Parse()

	log.Println("V2 fixture regenerator")
	log.Printf("Keys input directory:  %s", *keysIn)
	log.Printf("Fixture output path:   %s", *fixtureOut)

	// Load PK / VK / R1CS — saved by cmd/v2-trusted-setup.
	pk, vk, cs, err := loadArtifacts(*keysIn)
	if err != nil {
		log.Fatalf("load keys: %v", err)
	}
	log.Printf("[1/4] Loaded artifacts: pk + vk + cs (%d constraints)", cs.GetNbConstraints())
	if cs.GetNbConstraints() < 100_000 {
		log.Fatalf("constraint count %d looks like V1 SimpleBLSCircuit, not V2; refusing",
			cs.GetNbConstraints())
	}

	// Build a real BLS signature so Prove succeeds against the V2 pairing constraints.
	testSK := makeTestSK()
	testMessageHash := makeTestMessageHash()

	hm := bls_zkp.HashMessageToG1V2(testMessageHash)
	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&hm, testSK)

	_, _, _, g2Gen := bls12381.Generators()
	var pkG2 bls12381.G2Affine
	pkG2.ScalarMultiplication(&g2Gen, testSK)

	signedPower := uint64(7)
	totalPower := uint64(10)

	w, _, err := bls_zkp.BuildV2Witness(testMessageHash, sig, pkG2, signedPower, totalPower)
	if err != nil {
		log.Fatalf("BuildV2Witness: %v", err)
	}
	log.Println("[2/4] Built V2 witness (signed=7, total=10, msg=deterministic)")

	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("frontend.NewWitness: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Public(): %v", err)
	}

	log.Println("[3/4] Running groth16.Prove (keccak-mod-R hash override)...")
	proof, err := groth16.Prove(cs, pk, witness,
		backend.WithProverHashToFieldFunction(bls_zkp.NewKeccakToFieldHash()),
	)
	if err != nil {
		log.Fatalf("groth16.Prove: %v", err)
	}

	// Verify locally as a sanity check before writing.
	if err := groth16.Verify(proof, vk, publicWitness,
		backend.WithVerifierHashToFieldFunction(bls_zkp.NewKeccakToFieldHash()),
	); err != nil {
		log.Fatalf("groth16.Verify on freshly generated proof: %v (this means PK/VK don't match; rerun cmd/v2-trusted-setup)", err)
	}
	log.Println("       Prove + Verify round-trip succeeded")

	// Build the fixture and write it.
	fix := buildFixture(vk, proof, w)
	if err := os.MkdirAll(filepath.Dir(*fixtureOut), 0o755); err != nil {
		log.Fatalf("create fixture dir: %v", err)
	}
	body, err := json.MarshalIndent(fix, "", "  ")
	if err != nil {
		log.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(*fixtureOut, body, 0o644); err != nil {
		log.Fatalf("write fixture: %v", err)
	}
	log.Printf("[4/4] Fixture written to %s (%d bytes)", *fixtureOut, len(body))
	log.Println("Done. Foundry E2E tests should now pass against the redeployed V2 verifier.")
}

func loadArtifacts(dir string) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem, error) {
	// PK
	pkF, err := os.Open(filepath.Join(dir, "proving_key.bin"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open pk: %w", err)
	}
	defer pkF.Close()
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkF); err != nil {
		return nil, nil, nil, fmt.Errorf("read pk: %w", err)
	}

	// VK
	vkF, err := os.Open(filepath.Join(dir, "verification_key.bin"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open vk: %w", err)
	}
	defer vkF.Close()
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkF); err != nil {
		return nil, nil, nil, fmt.Errorf("read vk: %w", err)
	}

	// R1CS
	csF, err := os.Open(filepath.Join(dir, "constraint_system.bin"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open cs: %w", err)
	}
	defer csF.Close()
	cs := groth16.NewCS(ecc.BN254)
	if _, err := cs.ReadFrom(csF); err != nil {
		return nil, nil, nil, fmt.Errorf("read cs: %w", err)
	}
	return pk, vk, cs, nil
}

func buildFixture(
	vk groth16.VerifyingKey,
	proof groth16.Proof,
	w *bls_zkp.BLSSignatureCircuitV2,
) *fixtureV2 {
	vkBN254 := vk.(*groth16_bn254.VerifyingKey)
	proofBN254 := proof.(*groth16_bn254.Proof)

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
		return [2][2]string{{x0.String(), x1.String()}, {y0.String(), y1.String()}}
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

	proofA := g1ToStrs(proofBN254.Ar)
	proofB := g2ToStrs(proofBN254.Bs)
	proofC := g1ToStrs(proofBN254.Krs)

	rawMarshalled := proofBN254.MarshalSolidity()
	var proofForVerifier [8]string
	for i := 0; i < 8; i++ {
		proofForVerifier[i] = new(big.Int).SetBytes(rawMarshalled[i*32 : (i+1)*32]).String()
	}

	if len(proofBN254.Commitments) != 1 {
		log.Fatalf("expected exactly 1 Pedersen commitment in V2 proof, got %d",
			len(proofBN254.Commitments))
	}
	commitments := g1ToStrs(proofBN254.Commitments[0])
	commitmentPok := g1ToStrs(proofBN254.CommitmentPok)

	msgBI := varToBig(w.MessageHash)
	pkBI := varToBig(w.PubkeyCommitment)

	return &fixtureV2{
		Description: "BLSSignatureCircuitV2 Groth16 fixture — generated by cmd/v2-regen-fixture against the keys at the time of regeneration. The expected_vk_hash field is computed by Solidity at test time via keccak256(abi.encode(...)); we leave it blank here because the on-chain BLSZKVerifierV2Generated bakes the VK into bytecode (no setter to validate against a hash).",
		Alpha1:           alpha1,
		Beta2:            beta2,
		Gamma2:           gamma2,
		Delta2:           delta2,
		ICx:              icx,
		ICy:              icy,
		ExpectedVKHash:   "", // bytecode-baked, not used by V2 tests
		ProofA:           proofA,
		ProofB:           proofB,
		ProofC:           proofC,
		ProofForVerifier: proofForVerifier,
		Commitments:      commitments,
		CommitmentPok:    commitmentPok,
		MessageHash:      to32ByteHex(msgBI),
		PubkeyCommitment: to32ByteHex(pkBI),
		SignedVotingPower: 7,
		TotalVotingPower:  10,
	}
}

func varToBig(v frontend.Variable) *big.Int {
	switch x := v.(type) {
	case *big.Int:
		return x
	case big.Int:
		return &x
	case int:
		return big.NewInt(int64(x))
	case int64:
		return big.NewInt(x)
	case uint64:
		return new(big.Int).SetUint64(x)
	case string:
		bi, _ := new(big.Int).SetString(x, 10)
		return bi
	}
	log.Fatalf("varToBig: unsupported %T", v)
	return nil
}

func to32ByteHex(bi *big.Int) string {
	buf := make([]byte, 32)
	bi.FillBytes(buf)
	return "0x" + hex.EncodeToString(buf)
}
