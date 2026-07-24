package execution

import "testing"

// The credit constants are denominated in credit UNITS (1/100 credit) so they can be
// compared directly against Accumulate's raw `creditBalance`. These tests pin the
// protocol-true values from protocol/fee_schedule.go so a future edit that silently
// reintroduces the old ~100x over-estimate fails here instead of in production.

func TestCreditConstantsMatchProtocolFeeSchedule(t *testing.T) {
	if CreditUnitsPerCredit != 100 {
		t.Fatalf("CreditUnitsPerCredit = %d, want 100 (protocol.CreditPrecision)", CreditUnitsPerCredit)
	}
	if FeeDataPerChunk != 10 {
		t.Fatalf("FeeDataPerChunk = %d, want 10 (FeeData, 0.1 credit per 256 B)", FeeDataPerChunk)
	}
	if FeeSignature != 1 {
		t.Fatalf("FeeSignature = %d, want 1 (0.01 credit)", FeeSignature)
	}
	if WriteDataBaseCost != 11 {
		t.Fatalf("WriteDataBaseCost = %d, want 11 units (0.11 credit)", WriteDataBaseCost)
	}
	// A minimal write-back must cost a tenth of a cent, not a dollar.
	if got := CreditUnitsToUSD(WriteDataBaseCost); got < 0.0010 || got > 0.0012 {
		t.Fatalf("minimal WriteData costs $%.6f, want ~$0.0011", got)
	}
}

func TestMinCreditsForWriteDataIsATenfoldSafetyMargin(t *testing.T) {
	want := WriteDataBaseCost * 10
	if MinCreditsForWriteData != want {
		t.Fatalf("MinCreditsForWriteData = %d, want %d (10x the true cost)", MinCreditsForWriteData, want)
	}
	// Guard against drift back toward the old 1000-unit floor.
	if MinCreditsForWriteData > 200 {
		t.Fatalf("MinCreditsForWriteData = %d units ($%.4f) — over-provisioned",
			MinCreditsForWriteData, CreditUnitsToUSD(MinCreditsForWriteData))
	}
}

func TestCreditUnitsToUSDIsDollarPegged(t *testing.T) {
	// 500 credits = 50,000 units = $5.00 (the ADI creation fee).
	if got := CreditUnitsToUSD(50_000); got != 5.0 {
		t.Fatalf("CreditUnitsToUSD(50000) = %v, want 5.0", got)
	}
	// 1 credit = 100 units = $0.01.
	if got := CreditUnitsToUSD(100); got != 0.01 {
		t.Fatalf("CreditUnitsToUSD(100) = %v, want 0.01", got)
	}
}

func TestCreditUnitsToACMEUsesOraclePriceWithFallback(t *testing.T) {
	// 50,000 units = $5.00; at $0.03/ACME that is ~166.67 ACME.
	got := CreditUnitsToACME(50_000, 0.03)
	if got < 166.6 || got > 166.7 {
		t.Fatalf("CreditUnitsToACME(50000, 0.03) = %v, want ~166.67", got)
	}
	// A non-positive price falls back to the default rather than dividing by zero.
	if fallback := CreditUnitsToACME(50_000, 0); fallback != got {
		t.Fatalf("fallback = %v, want the default-price result %v", fallback, got)
	}
}

func TestEstimateCreditsNeededScalesWithChunksNotFields(t *testing.T) {
	c := &CreditChecker{}

	// 1,000 single-chunk write-backs: 1,000 x 11 units x 1.1 margin = 12,100 units = $1.21.
	est := c.EstimateCreditsNeeded(1000, 1)
	if est.RequiredCredits != 12_100 {
		t.Fatalf("RequiredCredits = %d, want 12100", est.RequiredCredits)
	}
	if usd := CreditUnitsToUSD(est.RequiredCredits); usd > 2.0 {
		t.Fatalf("1,000 write-backs estimated at $%.2f — should be about a dollar", usd)
	}

	// A two-chunk body charges one extra FeeDataPerChunk, not double everything.
	two := c.EstimateCreditsNeeded(1000, 2)
	if two.RequiredCredits != 23_100 {
		t.Fatalf("two-chunk RequiredCredits = %d, want 23100", two.RequiredCredits)
	}

	// avgChunksPerTx below 1 is clamped rather than producing a signature-only estimate.
	if clamped := c.EstimateCreditsNeeded(1000, 0); clamped.RequiredCredits != est.RequiredCredits {
		t.Fatalf("clamped = %d, want %d", clamped.RequiredCredits, est.RequiredCredits)
	}
}
