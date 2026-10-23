// Copyright 2026 Certen Protocol

package legacyhdr_test

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr/isolationtest"
)

// The legacy item is disjoint from every production item and prefix of the shared capture table, in both directions.
func TestLegacyItemIsDisjointFromEveryProductionItemOfTheCaptureTable(t *testing.T) {
	if err := isolationtest.Disjoint(); err != nil {
		t.Fatal(err)
	}
	// the guard can fail: an item under a production prefix, or that is a prefix of a production item, is refused
	for _, bad := range []string{"hdr/legacy", "gap/header", "runtime/header", "idx/legacy", "tx", "spine", "g", "batch/"} {
		if err := isolationtest.DisjointFrom(bad, isolationtest.ProductionItems); err == nil {
			t.Errorf("the guard accepted %q", bad)
		}
	}
	if !strings.HasPrefix(legacyhdr.ItemLegacyHeader, "legacyleg/") {
		t.Fatalf("the legacy item %q left its own family", legacyhdr.ItemLegacyHeader)
	}
	if err := finality.CheckCaptureItem(legacyhdr.ItemLegacyHeader); err != nil {
		t.Fatal(err)
	}
}

// Legacy rows at rollup block heights (Base 46.4M, Arbitrum 313.9M) and inside the Ethereum Sepolia numbering space change nothing a
// production reader sees: coverage, block bounds, window scans and every prefix scan.
func TestLegacyRowsDoNotChangeWhatAnyProductionReaderSeesInMemory(t *testing.T) {
	isolationtest.Check(t, finality.NewMemCaptureStore(), isolationtest.Real)
}

// The snapshot has teeth: rows of an item that production scans WOULD list (here one under the inbox prefix) are caught, so the
// equality above is not the equality of two blind answers.
func TestIsolationCheckCatchesAnItemTheReadersWouldSee(t *testing.T) {
	problems := isolationtest.Run(finality.NewMemCaptureStore(), isolationtest.Real, "inbox/leak", false)
	if len(problems) == 0 {
		t.Fatal("rows under the inbox prefix went unnoticed")
	}
	if got := isolationtest.Run(finality.NewMemCaptureStore(), isolationtest.Real, "hdr/leak", true); len(got) != 1 || !strings.Contains(got[0], "prefix") {
		t.Fatalf("a non-disjoint item was not refused up front: %v", got)
	}
}

// Completeness guard: every capture item name or prefix defined in the Go sources of pkg/finality is covered by ProductionItems, so a
// family added to the code cannot go unguarded (the isolation proof and the disjointness check run over exactly that list).
func TestEveryCaptureItemFamilyDefinedInTheCodeIsInTheProductionList(t *testing.T) {
	missing, err := isolationtest.Undeclared("..", isolationtest.ProductionItems)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Fatalf("capture item names defined in pkg/finality that isolationtest.ProductionItems does not cover (add them to the list and to the seed): %v", missing)
	}
}

// The guard has teeth: the four families that an earlier version of the list lacked (arbposted/capture/records.go) are reported.
func TestTheCompletenessGuardFailsOnTheFourFamiliesAnEarlierListMissed(t *testing.T) {
	dropped := map[string]bool{"calldata/": true, "delayedproof/": true, "unavailable/": true, "blobunavailable/": true}
	var short []string
	for _, p := range isolationtest.ProductionItems {
		if !dropped[p] {
			short = append(short, p)
		}
	}
	if len(short) != len(isolationtest.ProductionItems)-4 {
		t.Fatalf("the production list does not hold the four families: %v", isolationtest.ProductionItems)
	}
	missing, err := isolationtest.Undeclared("..", short)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(missing, " ")
	for fam := range dropped {
		if !strings.Contains(joined, fam) {
			t.Errorf("the guard did not report %q; reported: %v", fam, missing)
		}
	}
}
