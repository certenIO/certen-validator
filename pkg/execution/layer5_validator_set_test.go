package execution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB5-F4: every V8.2 proof's layer 5 carries the Accumulate validator-set evidence, when that evidence derives the set
// the anchor committed. The fixture is a live Kermit ValidatorSetProof (cmd/vsproof, 2026-10-03; verdict
// validator_set_unbound, as it must be today).

const (
	kermitIncarnationF4 = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"
	kermitSetRootF4     = "afa6bd344b04b6ff9645c97b09254af9c25a214991e0b442538e9084d4136bf5" // RB5 Phase B pinned value
)

func kermitValidatorSetProof(t *testing.T) *certenproof.ValidatorSetProof {
	t.Helper()
	b, err := os.ReadFile("testdata/validator_set_proof_kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var p certenproof.ValidatorSetProof
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func v82Layer5(setRoot, inc string) *Layer5 {
	return &Layer5{Commitment: &AnchorCommitment{Version: string(contracts.BatchAnchorV8_2), AccumulateSetRoot: setRoot, Incarnation: inc}}
}

func TestTheKermitEvidenceDerivesTheCommittedSet(t *testing.T) {
	root, err := AccumulateSetRoot(kermitValidatorSetProof(t))
	if err != nil || root != kermitSetRootF4 {
		t.Fatalf("the live evidence reduces to %s (%v); RB5 pinned Kermit's committed root %s", root, err, kermitSetRootF4)
	}
}

func TestAV8_2ProofCarriesTheValidatorSetEvidenceOfItsCommittedSet(t *testing.T) {
	vsp := kermitValidatorSetProof(t)
	prove := func(context.Context) (*certenproof.ValidatorSetProof, error) { return vsp, nil }

	l5 := v82Layer5("0x"+kermitSetRootF4, "0x"+kermitIncarnationF4)
	got, err := AttachValidatorSetProof(context.Background(), l5, prove)
	if err != nil || got != ValidatorSetAttached || l5.Accumulate == nil || l5.Accumulate.ValidatorSetProof != vsp ||
		l5.Accumulate.ValidatorSetRoot != kermitSetRootF4 || l5.Accumulate.Incarnation != kermitIncarnationF4 {
		t.Fatalf("attach: %v (%v), binding %+v", got, err, l5.Accumulate)
	}

	// A set that changed since the anchor is not offered as evidence of the one that signed.
	changed := v82Layer5("0x"+"11"+kermitSetRootF4[2:], "0x"+kermitIncarnationF4)
	if got, err := AttachValidatorSetProof(context.Background(), changed, prove); err != nil || got != ValidatorSetChanged || changed.Accumulate != nil {
		t.Fatalf("a changed set: %v (%v), binding %+v", got, err, changed.Accumulate)
	}

	// Evidence of another Accumulate chain is refused.
	other := v82Layer5("0x"+kermitSetRootF4, "0x"+"22"+kermitIncarnationF4[2:])
	if _, err := AttachValidatorSetProof(context.Background(), other, prove); err == nil || other.Accumulate != nil {
		t.Fatalf("evidence of another incarnation was attached: %v", err)
	}

	// No V8.2 commitment, nothing to compare with.
	for _, l := range []*Layer5{nil, {}, {Commitment: &AnchorCommitment{Version: string(contracts.BatchAnchorV8_1)}}} {
		if got, err := AttachValidatorSetProof(context.Background(), l, prove); err != nil || got != ValidatorSetNoV8_2Commitment {
			t.Fatalf("no V8.2 commitment: %v (%v)", got, err)
		}
	}

	// A failed build is an error the caller names, never a binding.
	fail := v82Layer5("0x"+kermitSetRootF4, "0x"+kermitIncarnationF4)
	if _, err := AttachValidatorSetProof(context.Background(), fail, func(context.Context) (*certenproof.ValidatorSetProof, error) {
		return nil, errors.New("kermit unreachable")
	}); err == nil || fail.Accumulate != nil {
		t.Fatalf("a failed build: %v", err)
	}
	if _, err := AttachValidatorSetProof(context.Background(), v82Layer5("0x"+kermitSetRootF4, "0x"+kermitIncarnationF4), nil); err == nil {
		t.Fatal("a missing prover was not named")
	}
}

func TestTheValidatorSetEvidenceIsBuiltOncePerWindow(t *testing.T) {
	calls := 0
	cached := CachedValidatorSetProver(func(context.Context) (*certenproof.ValidatorSetProof, error) {
		calls++
		return &certenproof.ValidatorSetProof{}, nil
	}, time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := cached(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("built %d times in one window", calls)
	}
	failing := CachedValidatorSetProver(func(context.Context) (*certenproof.ValidatorSetProof, error) {
		calls++
		return nil, errors.New("down")
	}, time.Hour)
	_, _ = failing(context.Background())
	if _, err := failing(context.Background()); err == nil {
		t.Fatal("a failed build was cached as a success")
	}
}
