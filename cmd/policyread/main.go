// Command policyread prints the entitlement policy SEALED in a validator's
// ledger, without starting a validator.
//
// # WHY THIS EXISTS
//
// The sealed policy is the only authority on what a chain actually enforces.
// The environment is consulted once, at genesis, and ignored forever after — so
// reading CERTEN_ENTITLEMENT_* tells you what an operator INTENDED, not what the
// chain does. The two diverge silently, and the divergence only becomes visible
// when a PolicyUpdate is refused or, worse, when enforcement behaves other than
// expected.
//
// The specific question it was written to answer: a chain seals AdminKeys and
// AdminThreshold at genesis, and a chain sealed BEFORE admin keys were
// configured has an empty admin set — which makes its rule immutable for the
// life of the chain, with no break-glass and no way to reach enforce. Whether
// that happened is not knowable from the environment or from any log that has
// survived rotation. It is only knowable from the ledger.
//
// # READ-ONLY, AND POINT IT AT A COPY
//
// A running validator holds an exclusive lock on its ledger. Copy the database
// directory out first and read the copy — the policy key is written exactly once
// at genesis and never updated, so a copy taken while the node runs still holds
// the authoritative value.
//
//	docker cp certen-validator-1:/app/data/validator-ledger/validator-1 ./ledger-copy
//	policyread --dir ./ledger-copy --name validator-ledger
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/certen/independant-validator/pkg/kvdb"
	"github.com/certen/independant-validator/pkg/ledger"
)

func main() {
	dir := flag.String("dir", "", "directory holding the ledger database (a COPY, not a live one)")
	name := flag.String("name", "validator-ledger", "database name, without the .db suffix")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "--dir is required")
		os.Exit(2)
	}

	db, err := dbm.NewGoLevelDB(*name, *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open ledger: %v\n(if this is a lock error, the database is live — copy it first)\n", err)
		os.Exit(1)
	}
	defer db.Close()

	store := ledger.NewLedgerStore(kvdb.NewKVAdapter(db))
	policy, err := store.LoadEntitlementPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load policy: %v\n", err)
		os.Exit(1)
	}
	if policy == nil {
		fmt.Println("NO POLICY SEALED — this chain is still at genesis and will seal from the environment on next start.")
		return
	}

	fmt.Printf("mode:              %s\n", policy.Mode)
	fmt.Printf("version:           %d\n", policy.Version)
	fmt.Printf("sealedAtHeight:    %d\n", policy.SealedAtHeight)
	fmt.Printf("entitlement keys:  %d\n", len(policy.Keys))
	for id := range policy.Keys {
		fmt.Printf("  - %s\n", id)
	}

	// The decisive part. An empty admin set, or a threshold of zero, means no
	// PolicyUpdate can ever be accepted: the rule is fixed for the life of the
	// chain and the only way to change it is to start a new one.
	fmt.Printf("admin keys:        %d\n", len(policy.AdminKeys))
	for id, pub := range policy.AdminKeys {
		fmt.Printf("  - %s = %s\n", id, pub)
	}
	fmt.Printf("admin threshold:   %d\n", policy.AdminThreshold)

	switch {
	case len(policy.AdminKeys) == 0 || policy.AdminThreshold <= 0:
		fmt.Println("\nVERDICT: IMMUTABLE. No admin quorum was sealed, so no PolicyUpdate can be accepted.")
		fmt.Println("Reaching enforce, or backing out of it, would require starting a new chain.")
	case policy.AdminThreshold > len(policy.AdminKeys):
		fmt.Printf("\nVERDICT: UNSATISFIABLE. Threshold %d exceeds the %d sealed admin keys — no quorum is reachable.\n",
			policy.AdminThreshold, len(policy.AdminKeys))
	default:
		fmt.Printf("\nVERDICT: MUTABLE. %d of %d admin signatures can change the rule at an activation height.\n",
			policy.AdminThreshold, len(policy.AdminKeys))
	}

	if raw, err := json.MarshalIndent(policy, "", "  "); err == nil {
		fmt.Printf("\nsealed policy:\n%s\n", raw)
	}
}
