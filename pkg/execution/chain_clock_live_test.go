// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func unsetEnvForTest(k string) error { return os.Unsetenv(k) }

func newBig(n uint64) *big.Int { return new(big.Int).SetUint64(n) }

func chainNameForTest(id int64) string { return strconv.FormatInt(id, 10) }

// RB7 D7 on the three live chains: their blocks never stop, so they never heartbeat, and routing their rules through the
// chain clock changes no decision and no byte.

var liveChains = []int64{11155111, 84532, 421614}

func TestTheLiveChainsHaveNoHeartbeat(t *testing.T) {
	for _, id := range liveChains {
		env := ChainHeartbeatEnv(id)
		t.Setenv(env, "")
		if err := unsetEnvForTest(env); err != nil {
			t.Fatal(err)
		}
		if on, err := chainHeartbeatOn(id); on || err != nil {
			t.Fatalf("chain %d: heartbeat on=%v err=%v", id, on, err)
		}
		t.Setenv(env, "on")
		if on, err := chainHeartbeatOn(id); on || err == nil || !strings.Contains(err.Error(), env) {
			t.Fatalf("chain %d with %s=on: on=%v err=%v; refused by name", id, env, on, err)
		}
		if err := newChainClock(id, newSimIdleChain(id, 1)).setHeartbeat(&chainHeartbeat{}); err == nil {
			t.Fatalf("chain %d took a heartbeat", id)
		}
		// The orchestrator gives it none (NewBatchStack's path).
		t.Setenv(env, "")
		_ = unsetEnvForTest(env)
		o := &BatchOrchestrator{logf: t.Logf}
		clock := newChainClock(id, newSimIdleChain(id, 1))
		if b, err := o.attachHeartbeat(clock); b != nil || err != nil || clock.heartbeat() != nil {
			t.Fatalf("chain %d: heartbeat %v err %v", id, b, err)
		}
		// A rule's horizon on a live chain arms nothing.
		clock.AwaitTime("anything", 1)
		clock.AwaitBlock("anything", 1)
		if clock.heartbeat() != nil {
			t.Fatalf("chain %d armed a heartbeat", id)
		}
	}
}

// Adiri is settled on only with its heartbeat on, named.
func TestAdiriRequiresItsHeartbeat(t *testing.T) {
	env := ChainHeartbeatEnv(adiriID)
	for _, v := range []string{"", "off", "yes", "ON "} {
		t.Setenv(env, v)
		on, err := chainHeartbeatOn(adiriID)
		if v == "ON " {
			if !on || err != nil {
				t.Fatalf("%q: on=%v err=%v", v, on, err)
			}
			continue
		}
		if on || err == nil || !strings.Contains(err.Error(), env+"=on") {
			t.Fatalf("%q: on=%v err=%v; refused by name", v, on, err)
		}
	}
	_ = unsetEnvForTest(env)
	if _, err := chainHeartbeatOn(adiriID); err == nil {
		t.Fatal("an unset heartbeat switch on Adiri was accepted")
	}
}

// directNSChain is the non-settlement reads as they were before the clock: straight from the chain's own client.
type directNSChain struct{ c *simIdleChain }

func (d directNSChain) FinalizedHeader(ctx context.Context, _ int64) (*types.Header, error) {
	return d.c.HeaderByNumber(ctx, rpcFinalized)
}
func (d directNSChain) HeaderAt(ctx context.Context, _ int64, n uint64) (*types.Header, error) {
	return d.c.HeaderByNumber(ctx, newBig(n))
}
func (d directNSChain) LeafConsumedAt(context.Context, int64, common.Address, [32]byte, uint64) (bool, error) {
	return false, nil
}

// On a live chain every routed rule reads exactly what the chain's client read: the same headers, the same claims and
// result hashes, the same states - and no heartbeat is ever armed.
func TestTheLiveChainsRulesDecideTheSameBytesThroughTheClock(t *testing.T) {
	ctx := context.Background()
	for _, id := range liveChains {
		t.Run(chainNameForTest(id), func(t *testing.T) {
			commit := time.Unix(1_800_000_000, 0).UTC()
			m := certifiedForTest(odMember(1, id, 100))
			m.CommitTime = commit
			facts, err := memberFacts(m)
			if err != nil {
				t.Fatal(err)
			}
			chain := newSimIdleChain(id, uint64(commit.Add(-time.Hour).Unix()))
			for ts := commit.Add(-30 * time.Minute); !ts.After(facts.Deadline.Add(10 * time.Minute)); ts = ts.Add(12 * time.Second) {
				chain.mine(uint64(ts.Unix()))
			}
			clock := installSimClock(t, id, chain)
			ecm := &EthereumContractManager{client: chain.serve(t), config: &CertenContractConfig{ChainID: id}}
			viaClock := NonSettlementChainFromResolver(simResolver{id: ecm})
			direct := directNSChain{chain}

			// The clock's headers are the client's.
			for _, n := range []uint64{0, 5, chain.head().Number.Uint64()} {
				a, _ := clock.HeaderAt(ctx, n)
				b, _ := chain.HeaderByNumber(ctx, newBig(n))
				if a.Hash() != b.Hash() {
					t.Fatalf("block %d differs through the clock", n)
				}
			}
			// A non-settlement: the same claim, the same result hash.
			c1, o1, err1 := observeNonSettlementAt(ctx, viaClock, facts, "cause", 0)
			c2, o2, err2 := observeNonSettlementAt(ctx, direct, facts, "cause", 0)
			if err1 != nil || err2 != nil {
				t.Fatalf("%v / %v", err1, err2)
			}
			j1, _ := json.Marshal(c1)
			j2, _ := json.Marshal(c2)
			if string(j1) != string(j2) || o1.ResultHash != o2.ResultHash || !reflect.DeepEqual(o1, o2) {
				t.Fatalf("the claim differs:\n%s\n%s", j1, j2)
			}
			// Pinned at an earlier block, too.
			p1, _, _ := observeNonSettlementAt(ctx, viaClock, facts, "cause", c1.Block-1)
			p2, _, _ := observeNonSettlementAt(ctx, direct, facts, "cause", c1.Block-1)
			if !reflect.DeepEqual(p1, p2) {
				t.Fatalf("the pinned claim differs: %+v / %+v", p1, p2)
			}
			// Not yet attestable: the same refusal, and nothing armed.
			early := facts
			early.Deadline = facts.Deadline.Add(time.Hour)
			_, _, e1 := observeNonSettlementAt(ctx, viaClock, early, "cause", 0)
			_, _, e2 := observeNonSettlementAt(ctx, direct, early, "cause", 0)
			if !errors.Is(e1, errNotYetAttestable) || e1.Error() != e2.Error() || clock.heartbeat() != nil {
				t.Fatalf("not yet: %v / %v", e1, e2)
			}
			// A successor: the same state.
			succ := successor(false)
			succ.CommitTime = commit
			succ.After.ChainID, succ.After.Deadline = id, facts.Deadline.Add(-time.Minute)
			s1, k1, x1 := sequenceReadiness(ctx, viaClock, succ)
			s2, k2, x2 := sequenceReadiness(ctx, direct, succ)
			if s1 != s2 || k1 != k2 || (x1 == nil) != (x2 == nil) || s1 != sequenceStopped {
				t.Fatalf("readiness %d %q %v / %d %q %v", s1, k1, x1, s2, k2, x2)
			}
			// The orchestrator's head and finalized times, and the expired-batch rule.
			o := &BatchOrchestrator{ecm: ecm, logf: t.Logf}
			ht, _ := o.headTime(ctx)
			ft, _ := o.finalizedTime(ctx)
			if ht.Unix() != int64(chain.head().Time) || ft.Unix() != int64(chain.head().Time) {
				t.Fatalf("head %v finalized %v, the chain's %d", ht, ft, chain.head().Time)
			}
			expired, err := o.allPendingPastDeadline(ctx, []*PendingBatchIntent{m})
			if err != nil || expired != allPastDeadlineAt([]*PendingBatchIntent{m}, int64(chain.head().Time)) {
				t.Fatalf("expired=%v err=%v", expired, err)
			}
			if clock.heartbeat() != nil {
				t.Fatal("a live chain's clock armed a heartbeat")
			}
		})
	}
}
