package execution

import "testing"

// A reverted transaction is still a transaction.
//
// It has a hash, it consumed gas, and CERTEN paid for that gas. The failure
// paths used to replace that hash with "verify_failed_<chain>", so the cost
// reporter concluded "no measurable tx hash was found" and the spend never
// reached the ledger.
//
// Observed 2026-08-09 on arbitrum-sepolia: step 2 reverted in tx 0x3d477ca1…
// having burned 107,129 gas at 20 gwei, step 1 had a perfectly good hash, and
// BOTH were overwritten by placeholders. Every margin figure was understated by
// exactly the gas nobody could see.
func TestFailedTxLabelKeepsRealHash(t *testing.T) {
	real := "0x3d477ca1c3bdeef7d665f2737e1c0f57b46c1c58c931677f941b6a2e1f413674"
	if got := failedTxLabel(real, "verify", "Arbitrum Sepolia"); got != real {
		t.Fatalf("a reverted tx hash must be preserved for billing, got %q", got)
	}
}

// Only when no transaction was ever sent is a placeholder correct — that keeps
// "never left the ground" distinguishable from "landed badly", which are
// different bills: nothing spent versus gas spent.
func TestFailedTxLabelFallsBackWhenNoTxExists(t *testing.T) {
	for _, empty := range []string{"", "   ", "0x"} {
		got := failedTxLabel(empty, "create", "Arbitrum Sepolia")
		if got != "create_failed_Arbitrum Sepolia" {
			t.Fatalf("no tx means no hash to bill; want placeholder, got %q", got)
		}
	}
}

// A placeholder that already leaked in must never be mistaken for a hash.
func TestFailedTxLabelDoesNotLaunderAPlaceholder(t *testing.T) {
	got := failedTxLabel("verify_failed_Arbitrum Sepolia", "verify", "Arbitrum Sepolia")
	if got != "verify_failed_Arbitrum Sepolia" {
		t.Fatalf("placeholder must stay a placeholder, got %q", got)
	}
}
