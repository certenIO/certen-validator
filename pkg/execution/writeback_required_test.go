// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB3-F75: write-back is part of every proof cycle. An orchestrator that could not write its results
// back used to be built anyway and ran every cycle to the end with Phase 9 recorded as "disabled by
// configuration" - attested results that never reached Accumulate. It is now refused at construction.
func TestOrchestratorWithoutWriteBackIsRefused(t *testing.T) {
	db := s1OpenDB(t)
	repos := database.NewRepositories(database.NewClientFromDB(db))
	outbox, err := NewFileMemberOutcomeOutbox(filepath.Join(t.TempDir(), "outcomes"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := OpenNonSettlementQueue(filepath.Join(t.TempDir(), "ns.json"))
	if err != nil {
		t.Fatal(err)
	}
	completions, err := NewFileProofCompletionOutbox(filepath.Join(t.TempDir(), "completions"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	base := func() *UnifiedOrchestratorConfig {
		return &UnifiedOrchestratorConfig{
			ValidatorID: "v", Registry: strategy.NewRegistry(),
			ResultQuorumRegistry: func(context.Context, string) (map[string]consensus.ValidatorRegistryEntry, error) {
				return nil, nil
			},
			MemberLookup:       func(int64, [32]byte) (*PendingBatchIntent, bool) { return nil, false },
			NonSettlementChain: nsChainPast(nsCommit), NonSettlements: q,
			ResultsPrincipal: "acc://results.acme/data", Ed25519Key: key, AccumulateClient: &recordingSubmitter{},
			Repos: repos, UnifiedRepo: repos.Unified, MemberOutcomes: outbox, ProofCompletions: completions,
		}
	}
	if _, err := NewUnifiedOrchestrator(base()); err != nil {
		t.Fatalf("a complete configuration: %v", err)
	}
	for name, strip := range map[string]func(*UnifiedOrchestratorConfig){
		"no results principal": func(c *UnifiedOrchestratorConfig) { c.ResultsPrincipal = "" },
		"no signing key":       func(c *UnifiedOrchestratorConfig) { c.Ed25519Key = nil },
		"no Accumulate client": func(c *UnifiedOrchestratorConfig) { c.AccumulateClient = nil },
	} {
		c := base()
		strip(c)
		if _, err := NewUnifiedOrchestrator(c); err == nil || !strings.Contains(err.Error(), "write-back") {
			t.Fatalf("%s: an orchestrator that cannot write back was built (%v)", name, err)
		}
	}
	// RB3-F73: nor without the store its evidence is kept in.
	for name, strip := range map[string]func(*UnifiedOrchestratorConfig){
		"no repositories":            func(c *UnifiedOrchestratorConfig) { c.Repos = nil },
		"no unified repository":      func(c *UnifiedOrchestratorConfig) { c.UnifiedRepo = nil },
		"no member outcome outbox":   func(c *UnifiedOrchestratorConfig) { c.MemberOutcomes = nil },
		"no proof completion outbox": func(c *UnifiedOrchestratorConfig) { c.ProofCompletions = nil },
	} {
		c := base()
		strip(c)
		if _, err := NewUnifiedOrchestrator(c); err == nil || !strings.Contains(err.Error(), "required") {
			t.Fatalf("%s: an orchestrator that cannot store its evidence was built (%v)", name, err)
		}
	}
}

// recordingSubmitter is an Accumulate client that records what it is asked to submit.
type recordingSubmitter struct{ submitted []*SyntheticTransaction }

func (r *recordingSubmitter) SubmitTransaction(_ context.Context, tx *SyntheticTransaction) (string, error) {
	r.submitted = append(r.submitted, tx)
	return "recorded", nil
}

func (r *recordingSubmitter) GetTransactionStatus(context.Context, string) (string, error) {
	return "delivered", nil
}
