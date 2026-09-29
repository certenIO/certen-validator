package accumulateset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

const kermitIncarnation = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

const liteFixtures = "../../accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/testdata/"

// Every fixture proof, single- and multi-partition.
var setRootFixtures = []string{"proof_bvn1.json", "proof_bvn3.json", "proof_multileg_bvn1_bvn2.json"}

func kermitInc(t *testing.T) [32]byte {
	t.Helper()
	var inc [32]byte
	b, _ := hex.DecodeString(kermitIncarnation)
	copy(inc[:], b)
	return inc
}

func loadChained(t *testing.T, name string) *chained_proof.ChainedProof {
	t.Helper()
	b, err := os.ReadFile(liteFixtures + name)
	if err != nil {
		t.Fatalf("fixture %s is required: %v", name, err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(b, cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// The root committed for a proof is the same whether read from the chained proof or from the CompleteProof the
// signer reads (ChainedProofToCompleteProof, the production conversion), and equals an independent construction.
func TestCommittedAccumulateSetRoot_EveryFixture(t *testing.T) {
	inc := kermitInc(t)
	for _, name := range setRootFixtures {
		cp := loadChained(t, name)
		got, err := CommittedAccumulateSetRoot(cp.Layer4DN, inc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		viaComplete, err := CommittedAccumulateSetRoot(proof.ChainedProofToCompleteProof(cp).Layer4DN, inc)
		if err != nil {
			t.Fatalf("%s via CompleteProof: %v", name, err)
		}
		if got != viaComplete {
			t.Fatalf("%s: the chained proof and the CompleteProof commit different roots", name)
		}
		// Independent construction straight from the leg.
		manual := contracts.AccumulateValidatorSetRootInputs{Incarnation: inc,
			ThresholdNumerator: cp.Layer4DN.AcceptThreshold.Numerator, ThresholdDenominator: cp.Layer4DN.AcceptThreshold.Denominator}
		for _, v := range cp.Layer4DN.ValidatorSet {
			var pk [32]byte
			raw, _ := hex.DecodeString(v.PublicKey)
			copy(pk[:], raw)
			manual.Validators = append(manual.Validators, contracts.AccumulateValidator{PublicKey: pk, ActiveOn: v.ActiveOn})
		}
		want, err := contracts.ComputeAccumulateValidatorSetRoot(manual)
		if err != nil || got != want {
			t.Fatalf("%s: committed %x, independent %x (%v)", name, got, want, err)
		}
		// Kermit's real committed root, pinned in contracts.TestV8_2_PinnedVector_KermitIncarnation.
		if hex.EncodeToString(got[:]) != "afa6bd344b04b6ff9645c97b09254af9c25a214991e0b442538e9084d4136bf5" {
			t.Fatalf("%s: committed %x is not Kermit's pinned root", name, got)
		}
		// Kermit's set never changed, so every BVN leg was checked against the committed set.
		legs := []*chained_proof.Layer4{cp.Layer4BVN}
		for _, l := range cp.AdditionalLegs {
			legs = append(legs, l.Layer4BVN)
		}
		for _, l := range legs {
			if l == nil {
				continue
			}
			st, _, err := CompareLegSet(l, got, inc)
			if err != nil || st != LegSetCommitted {
				t.Fatalf("%s: BVN leg %s is %q (%v), want committed", name, l.Partition, st, err)
			}
		}
	}
}

func cloneLeg(l *chained_proof.Layer4) *chained_proof.Layer4 {
	c := *l
	c.ValidatorSet = make([]chained_proof.ValidatorKey, len(l.ValidatorSet))
	for i, v := range l.ValidatorSet {
		v.ActiveOn = append([]string(nil), v.ActiveOn...)
		c.ValidatorSet[i] = v
	}
	return &c
}

func TestCommittedAccumulateSetRoot_Adversarial(t *testing.T) {
	inc := kermitInc(t)
	base := loadChained(t, "proof_bvn1.json").Layer4DN
	want, err := CommittedAccumulateSetRoot(base, inc)
	if err != nil {
		t.Fatal(err)
	}
	differ := map[string]func(l *chained_proof.Layer4){
		"one validator's key":   func(l *chained_proof.Layer4) { l.ValidatorSet[1].PublicKey = "aa" + l.ValidatorSet[1].PublicKey[2:] },
		"one validator removed": func(l *chained_proof.Layer4) { l.ValidatorSet = l.ValidatorSet[:2] },
		"one ActiveOn added":    func(l *chained_proof.Layer4) { l.ValidatorSet[0].ActiveOn = append(l.ValidatorSet[0].ActiveOn, "BVN2") },
		"one ActiveOn removed":  func(l *chained_proof.Layer4) { l.ValidatorSet[2].ActiveOn = l.ValidatorSet[2].ActiveOn[:1] },
		"ActiveOn renamed":      func(l *chained_proof.Layer4) { l.ValidatorSet[0].ActiveOn[1] = "BVN9" },
		"threshold numerator":   func(l *chained_proof.Layer4) { l.AcceptThreshold.Numerator = 1 },
		"threshold denominator": func(l *chained_proof.Layer4) { l.AcceptThreshold.Denominator = 4 },
		"threshold same ratio 4/6": func(l *chained_proof.Layer4) {
			l.AcceptThreshold = chained_proof.Rational{Numerator: 4, Denominator: 6}
		},
	}
	for name, mut := range differ {
		l := cloneLeg(base)
		mut(l)
		got, err := CommittedAccumulateSetRoot(l, inc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == want {
			t.Errorf("%s: the root did not change", name)
		}
	}
	otherInc := inc
	otherInc[0] ^= 1
	if got, _ := CommittedAccumulateSetRoot(base, otherInc); got == want {
		t.Error("a different incarnation produced the same root")
	}

	same := map[string]func(l *chained_proof.Layer4){
		"validators reversed": func(l *chained_proof.Layer4) {
			for i, j := 0, len(l.ValidatorSet)-1; i < j; i, j = i+1, j-1 {
				l.ValidatorSet[i], l.ValidatorSet[j] = l.ValidatorSet[j], l.ValidatorSet[i]
			}
		},
		"ActiveOn reversed": func(l *chained_proof.Layer4) {
			a := l.ValidatorSet[0].ActiveOn
			a[0], a[len(a)-1] = a[len(a)-1], a[0]
		},
		"hex case": func(l *chained_proof.Layer4) {
			for i := range l.ValidatorSet {
				b, _ := hex.DecodeString(l.ValidatorSet[i].PublicKey)
				l.ValidatorSet[i].PublicKey = "0x" + upperHex(b)
			}
		},
	}
	for name, mut := range same {
		l := cloneLeg(base)
		mut(l)
		got, err := CommittedAccumulateSetRoot(l, inc)
		if err != nil || got != want {
			t.Errorf("%s: root %x (%v), want %x", name, got, err, want)
		}
	}

	refused := map[string]func(l *chained_proof.Layer4){
		"a BVN leg":           func(l *chained_proof.Layer4) { l.Partition = "BVN1" },
		"empty set":           func(l *chained_proof.Layer4) { l.ValidatorSet = nil },
		"short key":           func(l *chained_proof.Layer4) { l.ValidatorSet[0].PublicKey = "abcd" },
		"duplicate validator": func(l *chained_proof.Layer4) { l.ValidatorSet[1] = l.ValidatorSet[0] },
		"zero denominator":    func(l *chained_proof.Layer4) { l.AcceptThreshold.Denominator = 0 },
		"numerator above one": func(l *chained_proof.Layer4) {
			l.AcceptThreshold = chained_proof.Rational{Numerator: 4, Denominator: 3}
		},
	}
	for name, mut := range refused {
		l := cloneLeg(base)
		mut(l)
		if _, err := CommittedAccumulateSetRoot(l, inc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := CommittedAccumulateSetRoot(nil, inc); err == nil {
		t.Error("a proof without a Directory leg was accepted")
	}
	if _, err := CommittedAccumulateSetRoot(base, [32]byte{}); err == nil {
		t.Error("a zero incarnation was accepted")
	}
}

// A BVN leg checked against a different set is named, with its own root, never folded into the committed one.
func TestCompareLegSet_NamesAnUncommittedBVNSet(t *testing.T) {
	inc := kermitInc(t)
	cp := loadChained(t, "proof_bvn1.json")
	committed, err := CommittedAccumulateSetRoot(cp.Layer4DN, inc)
	if err != nil {
		t.Fatal(err)
	}
	l := cloneLeg(cp.Layer4BVN)
	l.ValidatorSet = l.ValidatorSet[:2]
	st, root, err := CompareLegSet(l, committed, inc)
	if err != nil || st != LegSetNotCommitted || root == committed {
		t.Fatalf("got %q root %x (%v)", st, root, err)
	}
}

func upperHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
