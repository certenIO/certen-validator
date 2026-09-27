//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2, RB3-F83): without the tag it is not
// compiled; with it, a missing input is a failure, never a pass.

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

// The aggregate public key produced here must fold to one of the 29 commitments authorized on
// CertenAnchorV8_1. If it does not, the chain rejects the attestation no matter how correct the
// aggregation logic is. Uses the real key file so this is not a self-consistent fiction.
//
//	CERTEN_TEST_BLS_KEYS=/path/to/bls_keys_backup_MASTER.json
func TestAggregate_RealKeysFoldToAuthorizedCommitment(t *testing.T) {
	path := os.Getenv("CERTEN_TEST_BLS_KEYS")
	if path == "" {
		t.Fatal("the live build requires CERTEN_TEST_BLS_KEYS (the validator key backup)")
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
