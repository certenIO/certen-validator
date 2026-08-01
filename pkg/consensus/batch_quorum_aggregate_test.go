package consensus

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

// The seven production validator EVM addresses, in the registry's canonical (lowercased) form.
// These are the real Sepolia set — the same seven registered on CertenAnchorV8_1.
var testAddrs = []string{
	"0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d",
	"0x5555afa8ff8048bddaac1554afd790c9bf7ec6e0",
	"0x6acaa68417f5ad5d4a02d9d3d72e291effcdf30a",
	"0x16ab06f3634218a8f1f3b01dcdd32ddfbdc8a69d",
	"0xf150ff923e29f797b4598b89bd7d02002d00db3a",
	"0x70a6a81bb5e3b63b1929301239de1f5c63ec4f3a",
	"0xee2efa29989fe6e53572087680c661ec29e045fe",
}

type testValidator struct {
	addr string
	sk   *bls.PrivateKey
	pk   *bls.PublicKey
}

// makeSet builds n validators with deterministic keys, plus the registry describing them.
func makeSet(t *testing.T, n int, power int64) ([]testValidator, map[string]ValidatorRegistryEntry) {
	t.Helper()
	vs := make([]testValidator, 0, n)
	reg := make(map[string]ValidatorRegistryEntry, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, 32)
		seed[31] = byte(i + 1)
		sk, err := bls.PrivateKeyFromBytes(seed)
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		pk := sk.PublicKey()
		addr := testAddrs[i%len(testAddrs)]
		vs = append(vs, testValidator{addr: addr, sk: sk, pk: pk})
		reg[addr] = ValidatorRegistryEntry{
			EVMAddress:   addr,
			PublicKeyHex: pk.Hex(),
			VotingPower:  big.NewInt(power),
		}
	}
	return vs, reg
}

func msgFor(b byte) [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = b
	}
	return m
}

func attest(t *testing.T, v testValidator, msg [32]byte) BatchAttestationEntry {
	t.Helper()
	sigHex, err := SignBatchAttestation(v.sk, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return BatchAttestationEntry{
		ValidatorID:  v.addr,
		EVMAddress:   v.addr,
		SignatureHex: sigHex,
		PublicKeyHex: v.pk.Hex(),
	}
}

// =============================================================================
// The property that matters most
// =============================================================================

// A single validator must NEVER be able to produce an aggregate. This is the exact forgery the
// batch path previously set up: one signature, 700/700 declared. If this test ever passes with
// an aggregate returned, the CRYPTO-007 protection is gone.
func TestAggregate_SingleSignerIsRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x11)

	got, err := AggregateBatchAttestations(
		[]BatchAttestationEntry{attest(t, vs[0], msg)}, reg, msg, 2, 3)
	if err == nil {
		t.Fatalf("one signer produced an aggregate claiming %s power — this is the quorum forgery",
			got.SignedVotingPower)
	}
	if !strings.Contains(err.Error(), "quorum not met") {
		t.Fatalf("expected a quorum failure, got: %v", err)
	}
}

// Four of seven is 400/700 — under 2/3 (467). Must be refused.
func TestAggregate_BelowThresholdIsRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x22)

	var atts []BatchAttestationEntry
	for i := 0; i < 4; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("4-of-7 (400/700) is below the 2/3 threshold and must be refused")
	}
}

// SignedVotingPower must be the SUM OF ACTUAL SIGNERS, never the total and never a constant.
func TestAggregate_SignedPowerReflectsRealSigners(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)

	for _, k := range []int{5, 6, 7} {
		msg := msgFor(byte(0x30 + k))
		var atts []BatchAttestationEntry
		for i := 0; i < k; i++ {
			atts = append(atts, attest(t, vs[i], msg))
		}
		agg, err := AggregateBatchAttestations(atts, reg, msg, 2, 3)
		if err != nil {
			t.Fatalf("%d-of-7 should reach quorum: %v", k, err)
		}
		if want := big.NewInt(int64(k) * 100); agg.SignedVotingPower.Cmp(want) != 0 {
			t.Fatalf("%d signers: signedPower=%s want %s", k, agg.SignedVotingPower, want)
		}
		if agg.TotalVotingPower.Cmp(big.NewInt(700)) != 0 {
			t.Fatalf("total power must come from the registry, got %s", agg.TotalVotingPower)
		}
		if len(agg.Signers) != k {
			t.Fatalf("expected %d signers, got %d", k, len(agg.Signers))
		}
		// Signers must be deterministic (ascending) so every validator folds identically.
		for i := 1; i < len(agg.Signers); i++ {
			if agg.Signers[i-1] >= agg.Signers[i] {
				t.Fatal("signers must be in ascending order for cross-validator determinism")
			}
		}
	}
}

// The aggregate must actually verify — this is what the chain will check.
func TestAggregate_VerifiesUnderAggregateKey(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x44)

	var atts []BatchAttestationEntry
	for i := 0; i < 5; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	agg, err := AggregateBatchAttestations(atts, reg, msg, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := publicKeyFromHex(agg.AggregatePublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signatureFromHex(agg.AggregateSignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	if !pk.VerifyG1(sig, bls_zkp.HashMessageToG1V2(msg)) {
		t.Fatal("aggregate does not verify — the chain would reject this")
	}

	// And it must NOT verify against a different message: this is the binding that stops an
	// aggregate for batch A being replayed onto batch B.
	if pk.VerifyG1(sig, bls_zkp.HashMessageToG1V2(msgFor(0x45))) {
		t.Fatal("aggregate verified against the WRONG message — no batch binding")
	}
}

// =============================================================================
// Rejection paths
// =============================================================================

func TestAggregate_DuplicateSignerRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x55)

	// Five distinct plus one repeat: a naive count would see 6 and pass at inflated power.
	atts := []BatchAttestationEntry{
		attest(t, vs[0], msg), attest(t, vs[1], msg), attest(t, vs[2], msg),
		attest(t, vs[3], msg), attest(t, vs[4], msg), attest(t, vs[0], msg),
	}
	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("a duplicate signer must be refused, not counted twice")
	}
}

func TestAggregate_UnregisteredSignerRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x66)

	var atts []BatchAttestationEntry
	for i := 0; i < 5; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	// A validly-signed attestation from an identity that is simply not in the registry.
	seed := make([]byte, 32)
	seed[31] = 99
	sk, _ := bls.PrivateKeyFromBytes(seed)
	rogue := testValidator{addr: "0x00000000000000000000000000000000000dead0", sk: sk, pk: sk.PublicKey()}
	atts = append(atts, attest(t, rogue, msg))

	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("an unregistered validator must not contribute to the aggregate")
	}
}

// A signature over a DIFFERENT message must be caught, not folded in. Otherwise a validator
// could attest batch A and have it counted toward batch B.
func TestAggregate_WrongMessageRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x77)
	other := msgFor(0x78)

	var atts []BatchAttestationEntry
	for i := 0; i < 4; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	atts = append(atts, attest(t, vs[4], other)) // signed the wrong batch

	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("a signature over a different message must be refused")
	}
}

// Substituting a key you control for the registered one must fail, or an attacker could
// contribute another validator's voting power using their own key.
func TestAggregate_KeySubstitutionRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x88)

	var atts []BatchAttestationEntry
	for i := 0; i < 4; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	seed := make([]byte, 32)
	seed[31] = 123
	attackerSK, _ := bls.PrivateKeyFromBytes(seed)
	sigHex, _ := SignBatchAttestation(attackerSK, msg)
	atts = append(atts, BatchAttestationEntry{
		ValidatorID:  vs[4].addr,
		EVMAddress:   vs[4].addr, // claims validator 5's slot...
		SignatureHex: sigHex,     // ...but signed with a key it controls
		PublicKeyHex: attackerSK.PublicKey().Hex(),
	})

	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("a signature under a non-registered key must be refused for that slot")
	}
}

// Even with the public key omitted (so no mismatch is detectable up front), verification
// against the REGISTRY key must still reject an attacker's signature.
func TestAggregate_KeySubstitutionRefusedWhenKeyOmitted(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x89)

	var atts []BatchAttestationEntry
	for i := 0; i < 4; i++ {
		atts = append(atts, attest(t, vs[i], msg))
	}
	seed := make([]byte, 32)
	seed[31] = 124
	attackerSK, _ := bls.PrivateKeyFromBytes(seed)
	sigHex, _ := SignBatchAttestation(attackerSK, msg)
	atts = append(atts, BatchAttestationEntry{
		EVMAddress:   vs[4].addr,
		SignatureHex: sigHex,
		PublicKeyHex: "", // omitted on purpose
	})

	if _, err := AggregateBatchAttestations(atts, reg, msg, 2, 3); err == nil {
		t.Fatal("verification against the registry key must reject a substituted signature")
	}
}

func TestAggregate_MalformedInputsRefused(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0x99)

	base := func() []BatchAttestationEntry {
		var a []BatchAttestationEntry
		for i := 0; i < 5; i++ {
			a = append(a, attest(t, vs[i], msg))
		}
		return a
	}

	cases := []struct {
		name   string
		mutate func([]BatchAttestationEntry) []BatchAttestationEntry
	}{
		{"empty address", func(a []BatchAttestationEntry) []BatchAttestationEntry {
			a[2].EVMAddress = ""
			return a
		}},
		{"empty signature", func(a []BatchAttestationEntry) []BatchAttestationEntry {
			a[2].SignatureHex = ""
			return a
		}},
		{"garbage signature hex", func(a []BatchAttestationEntry) []BatchAttestationEntry {
			a[2].SignatureHex = "not-hex"
			return a
		}},
		{"truncated signature", func(a []BatchAttestationEntry) []BatchAttestationEntry {
			a[2].SignatureHex = a[2].SignatureHex[:20]
			return a
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AggregateBatchAttestations(c.mutate(base()), reg, msg, 2, 3); err == nil {
				t.Fatal("must be refused")
			}
		})
	}

	if _, err := AggregateBatchAttestations(nil, reg, msg, 2, 3); err == nil {
		t.Fatal("no attestations must be refused")
	}
	if _, err := AggregateBatchAttestations(base(), nil, msg, 2, 3); err == nil {
		t.Fatal("empty registry must be refused — voting power would be unestablished")
	}
	if _, err := AggregateBatchAttestations(base(), reg, msg, 3, 2); err == nil {
		t.Fatal("nonsensical threshold must be refused")
	}
}

// Aggregation must not depend on the order attestations arrive in, or validators would fold
// differently and produce different aggregates for the same batch.
func TestAggregate_OrderIndependent(t *testing.T) {
	vs, reg := makeSet(t, 7, 100)
	msg := msgFor(0xAA)

	fwd := []BatchAttestationEntry{
		attest(t, vs[0], msg), attest(t, vs[1], msg), attest(t, vs[2], msg),
		attest(t, vs[3], msg), attest(t, vs[4], msg),
	}
	rev := make([]BatchAttestationEntry, len(fwd))
	for i := range fwd {
		rev[len(fwd)-1-i] = fwd[i]
	}

	a1, err := AggregateBatchAttestations(fwd, reg, msg, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := AggregateBatchAttestations(rev, reg, msg, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if a1.AggregateSignatureHex != a2.AggregateSignatureHex ||
		a1.AggregatePublicKeyHex != a2.AggregatePublicKeyHex {
		t.Fatal("aggregation must be order-independent")
	}
}

// =============================================================================
// Live cross-check against the real production keys
// =============================================================================

// The aggregate public key produced here must fold to one of the 29 commitments authorized on
// CertenAnchorV8_1. If it does not, the chain rejects the attestation no matter how correct the
// aggregation logic is. Uses the real key file so this is not a self-consistent fiction.
//
//	CERTEN_TEST_BLS_KEYS=/path/to/bls_keys_backup_MASTER.json
func TestAggregate_RealKeysFoldToAuthorizedCommitment(t *testing.T) {
	path := os.Getenv("CERTEN_TEST_BLS_KEYS")
	if path == "" {
		t.Skip("set CERTEN_TEST_BLS_KEYS to the validator key backup to run this cross-check")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading keys: %v", err)
	}
	var kf struct {
		Validators []struct {
			ValidatorID   string `json:"validator_id"`
			BLSPublicKey  string `json:"bls_public_key"`
			BLSPrivateKey string `json:"bls_private_key"`
		} `json:"validators"`
	}
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("parsing keys: %v", err)
	}
	if len(kf.Validators) < 7 {
		t.Fatalf("expected 7 validators, got %d", len(kf.Validators))
	}

	reg := map[string]ValidatorRegistryEntry{}
	var vs []testValidator
	for i, v := range kf.Validators[:7] {
		skb, err := hexBytes(v.BLSPrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		sk, err := bls.PrivateKeyFromBytes(skb)
		if err != nil {
			t.Fatal(err)
		}
		addr := testAddrs[i]
		vs = append(vs, testValidator{addr: addr, sk: sk, pk: sk.PublicKey()})
		reg[addr] = ValidatorRegistryEntry{
			EVMAddress:   addr,
			PublicKeyHex: sk.PublicKey().Hex(),
			VotingPower:  big.NewInt(100),
		}
	}

	msg := msgFor(0xBB)
	for _, k := range []int{5, 6, 7} {
		var atts []BatchAttestationEntry
		for i := 0; i < k; i++ {
			atts = append(atts, attest(t, vs[i], msg))
		}
		agg, err := AggregateBatchAttestations(atts, reg, msg, 2, 3)
		if err != nil {
			t.Fatalf("%d-of-7: %v", k, err)
		}

		// Fold to the commitment the CIRCUIT will produce. ComputePubkeyCommitmentV2 is the
		// BN254 variant — the one BuildV2Witness uses and the EVM verifier checks. The BLS381
		// variant exists for Cardano and would yield values no EVM proof can match.
		aggPub, err := publicKeyFromHex(agg.AggregatePublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		var g2 bls12381.G2Affine
		if _, err := g2.SetBytes(aggPub.Bytes()[:96]); err != nil {
			t.Fatalf("deserialize aggregate G2: %v", err)
		}
		commit, err := bls_zkp.ComputePubkeyCommitmentV2(g2)
		if err != nil {
			t.Fatalf("fold: %v", err)
		}
		t.Logf("%d-of-7 commitment: 0x%x", k, commit)

		// With CERTEN_TEST_AUTHORIZED_COMMITMENTS supplied (the 29 from subsetcommit, or read
		// off chain), require membership. Without it the commitment is only reported — a
		// mismatch would mean the chain rejects the attestation regardless of how correct the
		// aggregation is.
		if authz := os.Getenv("CERTEN_TEST_AUTHORIZED_COMMITMENTS"); authz != "" {
			want := "0x" + fmt.Sprintf("%x", commit)
			if !strings.Contains(strings.ToLower(authz), want) {
				t.Fatalf("%d-of-7 commitment %s is NOT in the authorized set — the chain would "+
					"reject this attestation", k, want)
			}
			t.Logf("%d-of-7 commitment is authorized ✓", k)
		}
	}
}

func hexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return nil, err
		}
		b[i] = byte(v)
	}
	return b, nil
}
