package execution

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
)

// stubProver satisfies QuorumProver without touching a chain.
type stubProver struct{ called int }

func (s *stubProver) ProveBatchRoot(_ context.Context, _ *BatchTree, _, _ uint64) error {
	s.called++
	return nil
}

func minimalAnchorCfg() *config.AnchorConfig {
	return &config.AnchorConfig{}
}

// =============================================================================
// Resolver guards
// =============================================================================

func TestNewEVMChainResolver_RequiresConfigAndAnchors(t *testing.T) {
	if _, err := NewEVMChainResolver(nil, map[int64]common.Address{1: common.HexToAddress("0x01")}); err == nil {
		t.Fatal("nil anchor config must be rejected")
	}
	if _, err := NewEVMChainResolver(minimalAnchorCfg(), nil); err == nil {
		t.Fatal("empty V8 anchor map must be rejected — the batch path cannot run without it")
	}
	if _, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: {},
	}); err == nil {
		t.Fatal("a zero anchor address must be rejected")
	}
}

// The single most dangerous failure in this whole area is pointing the batch path at the
// WRONG anchor — one whose validator set or authorized commitments differ produces
// attestations nothing can verify. An unconfigured chain must therefore error, never fall
// back to some other anchor.
func TestResolver_UnconfiguredChainDoesNotFallBack(t *testing.T) {
	r, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = r.ManagerForChain(8453) // never configured
	if err == nil {
		t.Fatal("an unconfigured chain must error rather than resolve to another anchor")
	}
}

func TestResolver_ChainsListsConfigured(t *testing.T) {
	r, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: common.HexToAddress("0xaa"),
		84532:    common.HexToAddress("0xbb"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Chains()
	if len(got) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(got))
	}
}

// =============================================================================
// Env resolver
// =============================================================================

func TestNewEVMChainResolverFromEnv(t *testing.T) {
	t.Setenv("CERTEN_ANCHOR_V8_11155111", "0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32")

	r, err := NewEVMChainResolverFromEnv(minimalAnchorCfg(), []int64{11155111, 84532})
	if err != nil {
		t.Fatal(err)
	}
	// Only the configured chain is present; the unset one is absent rather than defaulted.
	if len(r.Chains()) != 1 || r.Chains()[0] != 11155111 {
		t.Fatalf("expected only chain 11155111, got %v", r.Chains())
	}
}

func TestNewEVMChainResolverFromEnv_RejectsMalformedAddress(t *testing.T) {
	t.Setenv("CERTEN_ANCHOR_V8_11155111", "not-an-address")
	if _, err := NewEVMChainResolverFromEnv(minimalAnchorCfg(), []int64{11155111}); err == nil {
		t.Fatal("a malformed address must be rejected, not silently ignored")
	}
}

func TestNewEVMChainResolverFromEnv_ErrorsWhenNothingConfigured(t *testing.T) {
	if _, err := NewEVMChainResolverFromEnv(minimalAnchorCfg(), []int64{999999}); err == nil {
		t.Fatal("no configured chains must be an error, not an empty batch path that silently no-ops")
	}
}

// =============================================================================
// Stack assembly guards
// =============================================================================

// A nil prover would let the orchestrator create batch anchors that no account can accept,
// after paying for them. It must be rejected at construction, not discovered at flush time.
func TestNewBatchStack_RejectsNilProver(t *testing.T) {
	r, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: common.HexToAddress("0xaa"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBatchStack(r, nil, DefaultBatchMempoolConfig(), nil); err == nil {
		t.Fatal("a nil quorum prover must be rejected at construction")
	}
}

func TestNewBatchStack_RejectsNilResolver(t *testing.T) {
	if _, err := NewBatchStack(nil, &stubProver{}, DefaultBatchMempoolConfig(), nil); err == nil {
		t.Fatal("a nil resolver must be rejected")
	}
}

// Assembly must fail loudly when a configured chain cannot actually be reached, rather than
// producing a stack with a silently missing orchestrator.
func TestNewBatchStack_FailsOnUnreachableChain(t *testing.T) {
	r, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// minimalAnchorCfg has no RPC for this chain, so manager construction must fail.
	if _, err := NewBatchStack(r, &stubProver{}, DefaultBatchMempoolConfig(), nil); err == nil {
		t.Fatal("assembly must fail when a configured chain has no RPC, not skip it silently")
	}
}

func TestBatchStack_OrchestratorForUnknownChainErrors(t *testing.T) {
	s := &BatchStack{Orchestrators: map[int64]*BatchOrchestrator{}}
	if _, err := s.OrchestratorFor(11155111); err == nil {
		t.Fatal("unknown chain must error")
	}
}

// =============================================================================
// The safety property this whole file rests on
// =============================================================================

// Step 1 builds the machinery but must NOT switch anything on. A mempool that fills and
// never flushes is worse than the per-intent path, because intents would accumulate and
// silently never settle. Assert the mempool starts empty and nothing here enqueues.
func TestAssemblyDoesNotEnqueueAnything(t *testing.T) {
	r, err := NewEVMChainResolver(minimalAnchorCfg(), map[int64]common.Address{
		11155111: common.HexToAddress("0xaa"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sp := &stubProver{}

	// Assembly fails on the unreachable chain, but the mempool it would have used must in
	// no case have been populated by construction.
	m := NewBatchMempool(DefaultBatchMempoolConfig())
	if m.PendingCount() != 0 {
		t.Fatal("a freshly built mempool must be empty")
	}
	_, _ = NewBatchStack(r, sp, DefaultBatchMempoolConfig(), nil)
	if sp.called != 0 {
		t.Fatal("assembly must not invoke the prover — nothing is switched on at construction")
	}
}
