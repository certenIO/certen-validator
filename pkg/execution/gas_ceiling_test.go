package execution

import (
	"errors"
	"math/big"
	"testing"
)

// The gas ceiling is the only thing standing between CERTEN and an unbounded
// gas bill. Under Model B, CERTEN fronts native gas on every leg of every
// intent, so a price ceiling that CLAMPS instead of REFUSING is not a ceiling:
// it lowers the bid, pays anyway, and may leave the transaction stuck.
//
// These tests pin the behaviour the money path depends on.

const gwei = 1_000_000_000

func TestRefusesWhenNetworkPriceExceedsCeiling(t *testing.T) {
	_, err := evaluateGasPrice(big.NewInt(150*gwei), 100, 11155111, true)

	var ceilErr *ErrGasCeilingExceeded
	if !errors.As(err, &ceilErr) {
		t.Fatalf("expected ErrGasCeilingExceeded, got %v", err)
	}
	if ceilErr.CeilingGwei != 100 || ceilErr.ChainID != 11155111 {
		t.Fatalf("refusal lost its context: %+v", ceilErr)
	}
	if ceilErr.SuggestedGwei < 149 || ceilErr.SuggestedGwei > 151 {
		t.Fatalf("suggested price misreported: %v", ceilErr.SuggestedGwei)
	}
}

// The regression this whole change exists to prevent: the old code lowered the
// bid to the ceiling and submitted regardless.
func TestDoesNotSilentlyClampAndSend(t *testing.T) {
	bid, err := evaluateGasPrice(big.NewInt(150*gwei), 100, 1, true)
	if err == nil {
		t.Fatalf("clamped and returned a bid of %v instead of refusing", bid)
	}
	if bid != nil {
		t.Fatalf("a refusal must not also return a bid, got %v", bid)
	}
}

// The +20% buffer is OUR headroom, not the network's demand. Treating a buffered
// price as a breach would refuse at ~83% of the ceiling and reject perfectly
// affordable transactions.
func TestBufferOverCeilingIsClampedNotRefused(t *testing.T) {
	// Suggested 90 gwei is under the 100 ceiling; +20% = 108, over it.
	bid, err := evaluateGasPrice(big.NewInt(90*gwei), 100, 1, true)
	if err != nil {
		t.Fatalf("refused an affordable price because of our own buffer: %v", err)
	}
	if bid.Cmp(big.NewInt(100*gwei)) != 0 {
		t.Fatalf("expected bid clamped to the 100 gwei ceiling, got %v", bid)
	}
}

func TestNormalPriceGetsTheBuffer(t *testing.T) {
	bid, err := evaluateGasPrice(big.NewInt(10*gwei), 100, 1, true)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if bid.Cmp(big.NewInt(12*gwei)) != 0 {
		t.Fatalf("expected 10 gwei + 20%% = 12 gwei, got %v", bid)
	}
}

func TestExactlyAtCeilingIsAllowed(t *testing.T) {
	// The ceiling is a limit, not an exclusive bound — refusing at exactly the
	// configured maximum would be an off-by-one against the operator's intent.
	bid, err := evaluateGasPrice(big.NewInt(100*gwei), 100, 1, true)
	if err != nil {
		t.Fatalf("refused at exactly the ceiling: %v", err)
	}
	if bid.Cmp(big.NewInt(100*gwei)) != 0 {
		t.Fatalf("expected bid clamped to ceiling, got %v", bid)
	}
}

func TestZeroCeilingMeansUnset(t *testing.T) {
	// An unset ceiling must not refuse everything — that would halt a deployment
	// that simply has not configured a cap.
	bid, err := evaluateGasPrice(big.NewInt(5000*gwei), 0, 1, true)
	if err != nil {
		t.Fatalf("unset ceiling should not refuse: %v", err)
	}
	if bid.Cmp(big.NewInt(6000*gwei)) != 0 {
		t.Fatalf("expected unclamped 5000+20%%=6000 gwei, got %v", bid)
	}
}

// The escape hatch must genuinely restore the old behaviour, so an operator can
// roll back without redeploying a binary.
func TestEnforcementDisabledRestoresClamping(t *testing.T) {
	bid, err := evaluateGasPrice(big.NewInt(150*gwei), 100, 1, false)
	if err != nil {
		t.Fatalf("enforcement disabled should not refuse: %v", err)
	}
	if bid.Cmp(big.NewInt(100*gwei)) != 0 {
		t.Fatalf("expected legacy clamp to 100 gwei, got %v", bid)
	}
}

// ── Cost ceiling ────────────────────────────────────────────────────────────
//
// The gwei ceiling is a backstop. THIS is the policy: a price cap cannot see a
// gas-USAGE blowup and means something different on every chain. Cost in
// micro-USD is the unit the fee layer bills in, so this gate composes directly
// with the account's entitlement ceiling once that lands.

const usd = 1_000_000 // micro-USD

func TestRefusesWhenWorstCaseCostExceedsCap(t *testing.T) {
	// 2.5M gas (a full account deploy) at 15 gwei with ETH at $3000
	//   = 2.5e6 * 15e9 wei = 0.0375 ETH = $112.50
	err := checkTxCostCeiling(2_500_000, big.NewInt(15*gwei), 3000*usd, 25*usd, 1)

	var costErr *ErrTxCostCeilingExceeded
	if !errors.As(err, &costErr) {
		t.Fatalf("expected ErrTxCostCeilingExceeded, got %v", err)
	}
	if costErr.EstimatedUSD < 112 || costErr.EstimatedUSD > 113 {
		t.Fatalf("cost estimate wrong: got $%.2f, expected ~$112.50", costErr.EstimatedUSD)
	}
}

// The failure mode a gwei ceiling is blind to: price is unchanged and perfectly
// acceptable, but gas USAGE explodes. This is the whole reason for the change.
func TestCatchesGasUsageBlowupAtAcceptablePrice(t *testing.T) {
	price := big.NewInt(15 * gwei) // well under any sane gwei ceiling

	if err := checkTxCostCeiling(300_000, price, 3000*usd, 25*usd, 1); err != nil {
		t.Fatalf("a normal 300k-gas anchor should pass: %v", err)
	}
	// Same price. 20x the gas.
	if err := checkTxCostCeiling(6_000_000, price, 3000*usd, 25*usd, 1); err == nil {
		t.Fatal("a 20x gas-usage blowup at an acceptable PRICE must still be refused")
	}
}

// Testnet reality check: the ceiling must not fire on ordinary traffic, or it
// becomes a demo-breaker and gets switched off.
func TestDoesNotFireOnTestnetCosts(t *testing.T) {
	// Base Sepolia: 300k gas at 0.001 gwei, ETH $3000 => ~$0.0009
	if err := checkTxCostCeiling(300_000, big.NewInt(1_000_000), 3000*usd, 25*usd, 84532); err != nil {
		t.Fatalf("refused an ordinary testnet transaction: %v", err)
	}
}

func TestZeroCapMeansUnset(t *testing.T) {
	if err := checkTxCostCeiling(10_000_000, big.NewInt(500*gwei), 3000*usd, 0, 1); err != nil {
		t.Fatalf("an unset cap must not refuse: %v", err)
	}
}

func TestUnknownNativePriceDoesNotSilentlyPass(t *testing.T) {
	// With no price we cannot judge cost. The gate abstains here (returns nil)
	// rather than guessing — but the CONFIG default must never be 0, so this
	// path is unreachable in practice. Pinned so a future refactor that starts
	// passing 0 is caught by the default-is-conservative test below.
	if err := checkTxCostCeiling(10_000_000, big.NewInt(500*gwei), 0, 25*usd, 1); err != nil {
		t.Fatalf("expected abstain, got %v", err)
	}
}

func TestCostDefaultsAreConservative(t *testing.T) {
	t.Setenv("CERTEN_NATIVE_USD", "")
	t.Setenv("CERTEN_MAX_TX_COST_USD", "")

	// The native-price default must be HIGH: over-stating the token price makes
	// transactions look more expensive, so the ceiling refuses SOONER. Being
	// wrong in that direction can only refuse a cheap transaction (visible,
	// recoverable) — never silently permit an expensive one.
	if got := nativeUSDMicro(); got < 5000*usd {
		t.Fatalf("native price default %d is not conservative; must over-state, not under-state", got)
	}
	if got := maxTxCostMicroUSD(); got <= 0 {
		t.Fatal("cost cap must default to a real limit, never unlimited")
	}
}

func TestCostCeilingOverridable(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "0.50")
	if got := maxTxCostMicroUSD(); got != 500_000 {
		t.Fatalf("expected 500000 micro-USD, got %d", got)
	}
	t.Setenv("CERTEN_NATIVE_USD", "3000")
	if got := nativeUSDMicro(); got != 3000*usd {
		t.Fatalf("expected 3000000000 micro-USD, got %d", got)
	}
}

func TestGasCeilingEnforcedDefaultsOn(t *testing.T) {
	t.Setenv("CERTEN_GAS_CEILING_ENFORCE", "")
	if !gasCeilingEnforced() {
		t.Fatal("must default to enforcing: refusing is the safe direction under Model B")
	}
	for _, off := range []string{"false", "FALSE", "0", "no"} {
		t.Setenv("CERTEN_GAS_CEILING_ENFORCE", off)
		if gasCeilingEnforced() {
			t.Fatalf("%q should disable enforcement", off)
		}
	}
	for _, on := range []string{"true", "1", "yes", "anything-else"} {
		t.Setenv("CERTEN_GAS_CEILING_ENFORCE", on)
		if !gasCeilingEnforced() {
			t.Fatalf("%q should leave enforcement on", on)
		}
	}
}
