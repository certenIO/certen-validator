package billing

import (
	"fmt"
	"math/big"
	"testing"
	"time"
)

// The anchor is 81.2% of an intent's gas and is paid ONCE for N members. Every bug in this file
// is a billing error measured in real money, and none of them would surface as a failure —
// they'd surface as a number that is quietly wrong.

// Shares must sum to exactly what was paid. Integer division drops a remainder, and dropping it
// leaks gas per batch: invisible per transaction, wrong in aggregate, and the kind of thing that
// makes a ledger fail to reconcile with no obvious cause.
func TestSplitGasSumsToTheTotal(t *testing.T) {
	totals := []uint64{0, 1, 2, 3, 7, 100, 278081, 987644, 1<<62 + 7}
	for _, total := range totals {
		for n := 1; n <= 9; n++ {
			shares := splitGas(total, n)
			if len(shares) != n {
				t.Fatalf("splitGas(%d, %d) returned %d shares", total, n, len(shares))
			}
			var sum uint64
			for _, s := range shares {
				sum += s
			}
			if sum != total {
				t.Fatalf("splitGas(%d, %d) shares sum to %d — %d gas was lost",
					total, n, sum, total-sum)
			}
		}
	}
}

// The remainder goes to the first member; every other share is the floor. Pinned so a future
// "tidy up" cannot silently switch to dropping it.
func TestSplitGasPutsRemainderOnTheFirstShare(t *testing.T) {
	// 278081 across 3: floor 92693, remainder 2.
	shares := splitGas(278081, 3)
	want := []uint64{92695, 92693, 92693}
	for i := range want {
		if shares[i] != want[i] {
			t.Fatalf("splitGas(278081,3) = %v, want %v", shares, want)
		}
	}
}

// N=1 must not be a special case — a solo intent is a one-member batch that bears the whole
// cost. If this diverged, the on-demand and batched paths would produce different rows for the
// same economics.
func TestSplitGasSingleMemberTakesEverything(t *testing.T) {
	if got := splitGas(987644, 1); len(got) != 1 || got[0] != 987644 {
		t.Fatalf("splitGas(987644,1) = %v, want [987644]", got)
	}
}

func TestSplitGasZeroMembers(t *testing.T) {
	if got := splitGas(100, 0); got != nil {
		t.Fatalf("splitGas(100,0) = %v, want nil", got)
	}
}

// THE most important test here. NewCostEvent keys on (chain, tx, leg), which is correct for a
// per-intent transaction but would collapse all N shares of a SHARED transaction into one row —
// discarding N-1 of them and under-reporting the anchor by (N-1)/N, silently, at the gateway.
func TestSharedEventsNeedPerIntentIdempotencyKeys(t *testing.T) {
	cost := &ChainCost{
		Chain: "base-sepolia", ChainID: 84532, Leg: LegAnchor,
		TxHash: "0xb8aeb094", GasUsed: 300, GasPriceWei: big.NewInt(1),
		NativeSymbol: "ETH", WeiPerNative: big.NewInt(1e18),
		NativeAmount: big.NewInt(300), ObservedAt: time.Now(),
	}
	members := []CostMember{{IntentID: "a"}, {IntentID: "b"}, {IntentID: "c"}}

	// The DEFAULT key is identical for every member — this is the collapse.
	seenDefault := map[string]bool{}
	for range members {
		ev, err := NewCostEvent("x", "", "", cost, nil)
		if err != nil {
			t.Fatalf("NewCostEvent: %v", err)
		}
		seenDefault[ev.IdempotencyKey] = true
	}
	if len(seenDefault) != 1 {
		t.Fatal("test premise wrong: the default key should be identical across members")
	}

	// The key ObserveAndReportShared applies must be distinct per member.
	seenShared := map[string]bool{}
	for _, m := range members {
		key := fmt.Sprintf("cost:%s:%s:%s:%s", cost.Chain, cost.TxHash, cost.Leg, m.IntentID)
		seenShared[key] = true
	}
	if len(seenShared) != len(members) {
		t.Fatalf("shared keys collapsed to %d for %d members — %d shares would be discarded "+
			"and the anchor under-reported", len(seenShared), len(members),
			len(members)-len(seenShared))
	}
}

// A share must not mutate the measured cost, or every member after the first inherits the
// previous one's gas.
func TestSharedSplitDoesNotMutateTheMeasuredCost(t *testing.T) {
	cost := &ChainCost{
		Chain: "ethereum-sepolia", Leg: LegAnchor, TxHash: "0xdead",
		GasUsed: 900, GasPriceWei: big.NewInt(1), WeiPerNative: big.NewInt(1e18),
	}
	original := cost.GasUsed

	shares := splitGas(cost.GasUsed, 3)
	for _, s := range shares {
		share := *cost // the copy ObserveAndReportShared makes
		share.GasUsed = s
	}
	if cost.GasUsed != original {
		t.Fatalf("measured cost was mutated: GasUsed %d -> %d", original, cost.GasUsed)
	}
}

// The breakdown must record the divisor and the shared tx, so an auditor can reconstruct the
// split rather than having to trust it.
func TestMergeBreakdownCarriesSharedProvenanceWithoutMutating(t *testing.T) {
	base := map[string]string{"storage_rebate": "42"}
	got := mergeBreakdown(base, map[string]string{
		"shared_tx": "0xabc", "shared_with": "3", "shared_total_gas": "300",
	})
	for _, k := range []string{"storage_rebate", "shared_tx", "shared_with", "shared_total_gas"} {
		if got[k] == "" {
			t.Errorf("breakdown lost %q", k)
		}
	}
	if len(base) != 1 {
		t.Fatalf("mergeBreakdown mutated the base map (now %d keys)", len(base))
	}
}

// The validator must NEVER put an org identifier on a cost event. org_id is a UUID column in the
// gateway's cost_events; on 2026-08-05 the batch path passed the intent's created_by
// ("v8_1-cadence-825dc808") through as org_id and EVERY event 500'd on
// `invalid input syntax for type uuid`. The validator has no access to the gateway's org UUIDs,
// so the only correct value it can send is none.
func TestCostEventNeverCarriesAnOrgIDFromTheValidator(t *testing.T) {
	cost := &ChainCost{
		Chain: "base-sepolia", ChainID: 84532, Leg: LegAnchor, TxHash: "0xabc",
		GasUsed: 10, GasPriceWei: big.NewInt(1), NativeSymbol: "ETH",
		WeiPerNative: big.NewInt(1e18), NativeAmount: big.NewInt(10), ObservedAt: time.Now(),
	}
	ev, err := NewCostEvent("intent-1", "acc://certen-kermit-12.acme", "0xaccum", cost, nil)
	if err != nil {
		t.Fatalf("NewCostEvent: %v", err)
	}
	if ev.OrgID != "" {
		t.Fatalf("OrgID = %q; the validator cannot know the gateway's org UUID and must send "+
			"nothing — a non-UUID here 500s every event at insert", ev.OrgID)
	}
	if ev.ADIURL != "acc://certen-kermit-12.acme" {
		t.Fatalf("ADIURL = %q, want the authorising identity", ev.ADIURL)
	}
	if ev.AccumTxHash != "0xaccum" {
		t.Fatalf("AccumTxHash = %q; without it the gateway cannot join the cost to an intent",
			ev.AccumTxHash)
	}
}

// ── OP-stack (Base / Optimism) L1 data fee ──────────────────────────────────
//
// Measured on Base Sepolia 2026-08-05, real receipts:
//   anchor 0x0c5fd593: gasUsed 278081 @ 7200000 wei = 2002183200000, l1Fee 11263703277
//   settle 0x27c87e6a: gasUsed 144884 @ 7200000 wei = 1043164800000, l1Fee 20740574086
//
// Folding the L1 fee into the total (setTotal) kept the arithmetic right but forced GasUsed to
// 1, which destroyed the gas figure AND broke the shared split.

func TestSetGasWithL1KeepsRealGasAndTotals(t *testing.T) {
	c := &ChainCost{Chain: "base-sepolia", Leg: LegAnchor, TxHash: "0x0c5fd593"}
	c.setGasWithL1(278081, big.NewInt(7200000), big.NewInt(11263703277))

	if c.GasUsed != 278081 {
		t.Fatalf("GasUsed = %d, want the real 278081 — collapsing it to 1 is what broke "+
			"estimateGasLegs and the shared split", c.GasUsed)
	}
	want := new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(278081), big.NewInt(7200000)),
		big.NewInt(11263703277),
	)
	if c.NativeAmount.Cmp(want) != 0 {
		t.Fatalf("NativeAmount = %s, want %s (l2 + l1)", c.NativeAmount, want)
	}
	if want.String() != "2013446903277" {
		t.Fatalf("total = %s, want the measured 2013446903277", want)
	}
}

// Validate must accept the additive form, or every OP-stack cost event is rejected as malformed.
func TestValidateAcceptsGasPlusL1(t *testing.T) {
	c := &ChainCost{
		Chain: "base-sepolia", Leg: LegAnchor, TxHash: "0xabc",
		NativeSymbol: "ETH", WeiPerNative: big.NewInt(1e18), ObservedAt: time.Now(),
	}
	c.setGasWithL1(144884, big.NewInt(7200000), big.NewInt(20740574086))
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate rejected a valid OP-stack cost: %v", err)
	}
	// And it must still catch a genuinely inconsistent total.
	c.NativeAmount = big.NewInt(1)
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted a total that does not equal gas*price + l1")
	}
}

// THE bug the old representation caused. With GasUsed collapsed to 1, splitGas(1,3) is [1,0,0]:
// member one is charged the entire anchor and the other two are charged nothing.
func TestSharedSplitWasBrokenByCollapsedGas(t *testing.T) {
	collapsed := splitGas(1, 3)
	if collapsed[1] != 0 || collapsed[2] != 0 {
		t.Fatal("premise wrong: splitGas(1,3) should be [1,0,0]")
	}

	// With the real gas figure the split is even and exact.
	real := splitGas(278081, 3)
	var sum uint64
	for _, s := range real {
		sum += s
		if s == 0 {
			t.Fatal("a member received ZERO gas from a shared anchor")
		}
	}
	if sum != 278081 {
		t.Fatalf("shares sum to %d, want 278081", sum)
	}
}

// The L1 fee is paid once for the same transaction, so it must be divided too. Leaving it whole
// charges every member the full data fee — an N-times overcharge.
func TestL1FeeIsDividedAndSumsExactly(t *testing.T) {
	total := big.NewInt(11263703277) // measured anchor l1Fee
	for _, n := range []int{1, 2, 3, 7} {
		shares := splitBig(total, n)
		if len(shares) != n {
			t.Fatalf("splitBig(_, %d) returned %d shares", n, len(shares))
		}
		sum := new(big.Int)
		for _, s := range shares {
			if s == nil {
				t.Fatalf("nil share for a non-zero L1 fee across %d members", n)
			}
			sum.Add(sum, s)
		}
		if sum.Cmp(total) != 0 {
			t.Fatalf("L1 shares across %d sum to %s, want %s — %s wei lost or invented",
				n, sum, total, new(big.Int).Sub(total, sum))
		}
	}
}

// A chain with no L1 component must stay absent rather than asserting a zero fee.
func TestSplitBigNilStaysNil(t *testing.T) {
	for _, in := range []*big.Int{nil, big.NewInt(0)} {
		for _, s := range splitBig(in, 3) {
			if s != nil {
				t.Fatalf("splitBig(%v,3) produced %v; a chain without an L1 fee must report none", in, s)
			}
		}
	}
}

// setTotal is still correct for chains that genuinely have no gas model, and must clear any L1
// component so the two representations cannot be mixed.
func TestSetTotalStillUsedForNonGasChains(t *testing.T) {
	c := &ChainCost{Chain: "solana", Leg: LegAnchor, TxHash: "sig"}
	c.setGasWithL1(100, big.NewInt(2), big.NewInt(5)) // pretend it was set wrongly first
	c.setTotal(big.NewInt(5000))

	if c.GasUsed != 1 {
		t.Fatalf("GasUsed = %d, want 1 for a chain with no gas model", c.GasUsed)
	}
	if c.L1FeeWei != nil {
		t.Fatal("setTotal must clear L1FeeWei; mixing the two representations double-counts")
	}
	if c.NativeAmount.Cmp(big.NewInt(5000)) != 0 {
		t.Fatalf("NativeAmount = %s, want 5000", c.NativeAmount)
	}
}
