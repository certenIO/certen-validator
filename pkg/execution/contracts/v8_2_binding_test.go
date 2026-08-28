package contracts

import (
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixed vectors. These same inputs are used by
// certen-contracts/evm/test/CertenAnchorV8_2_Binding.t.sol, which recomputes the
// message on-chain and asserts the identical result. If either side changes, one
// of the two tests fails — which is the point. Do not "fix" a failure by
// updating the expected value on one side only.
// ---------------------------------------------------------------------------

func b32(s string) [32]byte {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	copy(out[:], raw)
	return out
}

var (
	vecChainID     = int64(84532) // base-sepolia
	vecAnchorID    = b32("1111111111111111111111111111111111111111111111111111111111111111")
	vecExecCommit  = b32("2222222222222222222222222222222222222222222222222222222222222222")
	vecOperationID = b32("3333333333333333333333333333333333333333333333333333333333333333")
	vecCertenRoot  = b32("4444444444444444444444444444444444444444444444444444444444444444")

	// Kermit's genesis root anchor — anchor(directory)-root[0], measured live.
	vecIncarnation = b32("e3f3119213a1ead44647659d67e47f4269a2affb13f150aa87b20baacf93cf81")
)

// vecAccSet is a three-validator set shaped like Kermit's: 2/3 threshold, each
// validator active on the Directory and one BVN. Deliberately supplied OUT of
// sorted order so the test proves the encoder sorts.
func vecAccSet() AccumulateValidatorSetRootInputs {
	return AccumulateValidatorSetRootInputs{
		Incarnation:          vecIncarnation,
		ThresholdNumerator:   2,
		ThresholdDenominator: 3,
		Validators: []AccumulateValidator{
			{PublicKey: b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), ActiveOn: []string{"BVN3", "Directory"}},
			{PublicKey: b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ActiveOn: []string{"Directory", "BVN1"}},
			{PublicKey: b32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), ActiveOn: []string{"BVN2", "Directory"}},
		},
	}
}

// TestV8_2_FixedVectors pins the two values the Solidity test asserts against.
// It prints them so a mismatch is diagnosable rather than merely red.
func TestV8_2_FixedVectors(t *testing.T) {
	accRoot, err := ComputeAccumulateValidatorSetRoot(vecAccSet())
	if err != nil {
		t.Fatalf("accumulate set root: %v", err)
	}
	msg := ComputeEvmMessageHashV8_2_Pre(
		vecChainID, vecAnchorID, vecExecCommit, vecOperationID, vecCertenRoot,
		accRoot, vecIncarnation,
	)

	const (
		wantAccRoot = "0074e2d6a7b1388c113c4f9f3621b3988d4aae715df060b395a181aaafced0f2"
		wantMsg     = "85d3623ce19d4453f9df1077e6d7b29c10892db6916289eecca246644f59cb2d"
	)
	t.Logf("accumulateValidatorSetRoot = %x", accRoot)
	t.Logf("messageHash (v2:pre)       = %x", msg)

	if got := hex.EncodeToString(accRoot[:]); got != wantAccRoot {
		t.Errorf("accumulateValidatorSetRoot drifted: got %s want %s -- if this is a deliberate encoding change, update certen-contracts/evm/test/CertenAnchorV8_2Binding.t.sol too", got, wantAccRoot)
	}
	if got := hex.EncodeToString(msg[:]); got != wantMsg {
		t.Errorf("V8.2 pre-exec messageHash drifted: got %s want %s -- if this is a deliberate encoding change, update certen-contracts/evm/test/CertenAnchorV8_2Binding.t.sol too", got, wantMsg)
	}
}

// TestV8_2_SortingIsCanonical proves the encoder is order-independent: the same
// set supplied in a different order, with partitions in a different order, must
// produce the identical root. Rule 12 — two validators reading identical chain
// data must produce identical bytes, or the result is an intermittent,
// unreproducible on-chain revert.
func TestV8_2_SortingIsCanonical(t *testing.T) {
	a, err := ComputeAccumulateValidatorSetRoot(vecAccSet())
	if err != nil {
		t.Fatal(err)
	}

	shuffled := vecAccSet()
	shuffled.Validators[0], shuffled.Validators[2] = shuffled.Validators[2], shuffled.Validators[0]
	for i := range shuffled.Validators {
		p := shuffled.Validators[i].ActiveOn
		for l, r := 0, len(p)-1; l < r; l, r = l+1, r-1 {
			p[l], p[r] = p[r], p[l]
		}
	}
	b, err := ComputeAccumulateValidatorSetRoot(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("root is order-dependent:\n  %x\n  %x", a, b)
	}
}

// TestV8_2_InputsAreNotMutated guards the sort-a-copy contract.
func TestV8_2_InputsAreNotMutated(t *testing.T) {
	in := vecAccSet()
	first := in.Validators[0].PublicKey
	firstPart := in.Validators[0].ActiveOn[0]
	if _, err := ComputeAccumulateValidatorSetRoot(in); err != nil {
		t.Fatal(err)
	}
	if in.Validators[0].PublicKey != first {
		t.Fatalf("caller's validator slice was reordered")
	}
	if in.Validators[0].ActiveOn[0] != firstPart {
		t.Fatalf("caller's ActiveOn slice was reordered")
	}
}

// TestV8_2_LengthPrefixesDisambiguate is the reason every variable-length field
// is length-prefixed. Without the prefixes, a validator active on
// {"BVN1","BVN2"} and one active on {"BVN1BVN2"} would concatenate to the same
// bytes and collide.
func TestV8_2_LengthPrefixesDisambiguate(t *testing.T) {
	mk := func(parts ...string) [32]byte {
		in := AccumulateValidatorSetRootInputs{
			Incarnation:          vecIncarnation,
			ThresholdNumerator:   2,
			ThresholdDenominator: 3,
			Validators: []AccumulateValidator{
				{PublicKey: b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ActiveOn: parts},
			},
		}
		r, err := ComputeAccumulateValidatorSetRoot(in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if mk("BVN1", "BVN2") == mk("BVN1BVN2") {
		t.Fatal("length prefixes do not disambiguate: concatenation collision")
	}
}

// TestV8_2_ThresholdIsCommitted is the missing denominator from the runbook's
// 2B.4c: the root must change when only the threshold changes. A commitment to
// who signed, without a commitment to how many were eligible, cannot tell a real
// quorum from three arbitrary keys.
func TestV8_2_ThresholdIsCommitted(t *testing.T) {
	a, err := ComputeAccumulateValidatorSetRoot(vecAccSet())
	if err != nil {
		t.Fatal(err)
	}
	other := vecAccSet()
	other.ThresholdNumerator = 1
	b, err := ComputeAccumulateValidatorSetRoot(other)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("threshold is not committed: 2/3 and 1/3 produce the same root")
	}
}

// TestV8_2_IncarnationIsCommitted: the same validator set on two different
// Accumulate incarnations must not produce the same root.
func TestV8_2_IncarnationIsCommitted(t *testing.T) {
	a, err := ComputeAccumulateValidatorSetRoot(vecAccSet())
	if err != nil {
		t.Fatal(err)
	}
	other := vecAccSet()
	// MainNet's genesis root anchor, measured live.
	other.Incarnation = b32("672f89ffc3cc87cff9a7fea1529ec893ec775e49e0cf4da1ab9c927979176e17")
	b, err := ComputeAccumulateValidatorSetRoot(other)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("incarnation is not committed: two chains produce the same root")
	}
}

// TestV8_2_RejectsUnusableInputs — there is deliberately no "unknown" encoding.
// A zero root would be a weaker claim wearing the same shape as a real one.
func TestV8_2_RejectsUnusableInputs(t *testing.T) {
	cases := map[string]func(*AccumulateValidatorSetRootInputs){
		"zero incarnation":     func(i *AccumulateValidatorSetRootInputs) { i.Incarnation = [32]byte{} },
		"zero numerator":       func(i *AccumulateValidatorSetRootInputs) { i.ThresholdNumerator = 0 },
		"zero denominator":     func(i *AccumulateValidatorSetRootInputs) { i.ThresholdDenominator = 0 },
		"numerator > denom":    func(i *AccumulateValidatorSetRootInputs) { i.ThresholdNumerator = 4 },
		"empty validator set":  func(i *AccumulateValidatorSetRootInputs) { i.Validators = nil },
		"duplicate public key": func(i *AccumulateValidatorSetRootInputs) { i.Validators[1] = i.Validators[0] },
		"duplicate partition": func(i *AccumulateValidatorSetRootInputs) {
			i.Validators[0].ActiveOn = []string{"Directory", "Directory"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := vecAccSet()
			mutate(&in)
			if _, err := ComputeAccumulateValidatorSetRoot(in); err == nil {
				t.Fatalf("accepted an input it must refuse: %s", name)
			}
		})
	}
}

// TestV8_2_DomainSeparation: pre and post must never collide, and the V8.2
// message must differ from V6.1's for otherwise-identical inputs. A bumped tag
// that did not actually change the digest would be decoration.
func TestV8_2_DomainSeparation(t *testing.T) {
	accRoot, err := ComputeAccumulateValidatorSetRoot(vecAccSet())
	if err != nil {
		t.Fatal(err)
	}
	pre := ComputeEvmMessageHashV8_2_Pre(vecChainID, vecAnchorID, vecExecCommit, vecOperationID, vecCertenRoot, accRoot, vecIncarnation)
	post := ComputeEvmMessageHashV8_2_Post(vecChainID, vecAnchorID, vecExecCommit, vecOperationID, vecCertenRoot, accRoot, vecIncarnation)
	if pre == post {
		t.Fatal("pre and post messages collide")
	}
	old := ComputeEvmMessageHashV6_1_Pre(vecChainID, vecAnchorID, vecExecCommit, vecOperationID, vecCertenRoot)
	if pre == old {
		t.Fatal("V8.2 message equals V6.1's: an old signature could replay")
	}
}

// TestV8_2_BundleIDFoldsTheAccumulateFields. The BLS quorum signs bundleId, so
// anything stored beside it rather than bound into it could be substituted by a
// rogue validator front-running with a different Accumulate set.
func TestV8_2_BundleIDFoldsTheAccumulateFields(t *testing.T) {
	commits := V6_1Commitments{
		OperationCommitment:  vecOperationID,
		CrossChainCommitment: vecExecCommit,
		GovernanceRoot:       vecCertenRoot,
		ExecutionCommitment:  vecExecCommit,
	}
	a := DeriveV8_2BundleID(vecChainID, vecAnchorID, commits, vecOperationID, 42, vecCertenRoot, vecIncarnation)
	b := DeriveV8_2BundleID(vecChainID, vecAnchorID, commits, vecOperationID, 42, vecExecCommit, vecIncarnation)
	if a == b {
		t.Fatal("bundleId does not commit accumulateValidatorSetRoot")
	}
	c := DeriveV8_2BundleID(vecChainID, vecAnchorID, commits, vecOperationID, 42, vecCertenRoot, vecCertenRoot)
	if a == c {
		t.Fatal("bundleId does not commit accumulateIncarnation")
	}
	old := DeriveV6_1BundleID(vecChainID, vecAnchorID, commits, vecOperationID, 42)
	if a == old {
		t.Fatal("V8.2 bundleId equals V6.1's: the tag bump did not take effect")
	}

	batchA := DeriveV8_2BatchBundleID(vecChainID, vecExecCommit, 7, vecOperationID, 42, vecCertenRoot, vecIncarnation)
	batchB := DeriveV8_2BatchBundleID(vecChainID, vecExecCommit, 7, vecOperationID, 42, vecExecCommit, vecIncarnation)
	if batchA == batchB {
		t.Fatal("batch bundleId does not commit accumulateValidatorSetRoot")
	}
}
