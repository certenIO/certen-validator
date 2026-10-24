// Copyright 2026 Certen Protocol

package runtime

import (
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// RB12-SEPOLIA-SPINE: the Sepolia prover is wired with the durable capture store (so a spine fetched by one attempt, process or validator
// is found by the next), a logger, and a request gap on its execution endpoints; without them the resumable spine would run in one process only.
func TestRTSepoliaProverIsWiredWithTheCaptureStoreTheLoggerAndARequestGap(t *testing.T) {
	rtProviderEnv(t)
	_, reg, _ := rtWire(t)
	var p *ethsepolia.Prover
	for _, pr := range reg.Provers(finality.ChainSepolia) {
		if sp, ok := pr.(*ethsepolia.Prover); ok {
			p = sp
		}
	}
	if p == nil {
		t.Fatal("no Sepolia finalized prover is registered")
	}
	if p.Store == nil {
		t.Fatal("the Sepolia prover has no capture store: its spine would not survive an attempt")
	}
	if _, wrapped := p.Store.(*BudgetedStore); !wrapped {
		t.Fatalf("the Sepolia prover's store is %T, not the budgeted capture store every other builder writes through", p.Store)
	}
	if p.Logf == nil {
		t.Fatal("the Sepolia prover has no logger")
	}
	h, ok := p.Exec.(*ethsepolia.RPCHeaders)
	if !ok || h.MinGap != 100*time.Millisecond || len(h.Endpoints) == 0 {
		t.Fatalf("the Sepolia header source is %+v", p.Exec)
	}
}
