package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB5-F49: a peer whose view of the chain has not finalized the block YET is asked again, not counted as a refusal.
// Live 2026-10-02 the validators' load-balanced RPC backends disagreed on the finalized head by minutes: peers answered
// "not finalized here" once, Phase 8 never asked again, and a settled member's proof failed short of its quorum.
func TestPhase8AsksAPeerAgainUntilItsChainHasFinalizedTheBlock(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)

	nodes := make([]*UnifiedOrchestrator, 4)
	keys := make([]*attestation.BLSStrategy, 4)
	registry := map[string]consensus.ValidatorRegistryEntry{}
	var asked [4]int32
	for i := range nodes {
		view := c
		if i > 0 {
			// Each peer reads its own backend, still 100 blocks behind the claim's block.
			view = nsChainPast(f.Deadline)
			view.finalized = 400
		}
		nodes[i] = nsOrchestrator(t, own, view)
		s, _ := nodes[i].config.Registry.GetAttestationStrategy(attestation.AttestationSchemeBLS12381)
		keys[i] = s.(*attestation.BLSStrategy)
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: hex.EncodeToString(keys[i].PublicKey()), VotingPower: big.NewInt(100)}
	}
	var peers []string
	for i, p := range nodes[1:] {
		i, peer, view := i+1, p, p.config.NonSettlementChain.(*fakeNSChain)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req PeerAttestationRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp, _ := peer.HandlePeerAttestationRequest(r.Context(), &req)
			if atomic.AddInt32(&asked[i], 1) == 1 {
				view.finalized = 520 // its backend catches up after the first answer
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		t.Cleanup(srv.Close)
		peers = append(peers, srv.URL)
	}
	req := nodes[0]
	req.config.AttestationPeers = peers
	req.config.AttestationTimeout = 2 * time.Minute
	req.config.ResultQuorumRegistry = func(context.Context, string) (map[string]consensus.ValidatorRegistryEntry, error) {
		return registry, nil
	}
	req.config.ThresholdConfig = attestation.DefaultThresholdConfig()
	req.httpClient = &http.Client{Timeout: 10 * time.Second}

	claim, obs, err := observeNonSettlement(context.Background(), c, f, "its batch quorum was never reached")
	if err != nil {
		t.Fatal(err)
	}
	rec := &NonSettlementRecord{Facts: f, Cause: claim.Cause, MemberChains: []int64{odChain}, MemberLegs: 1}
	cycle := nonSettlementCycle(rec, claim)
	cycle.Result.ObservationResults = []*chain.ObservationResult{obs}
	err = req.executePhase8(context.Background(), cycle, keys[0])
	for i := 1; i < 4; i++ {
		if n := atomic.LoadInt32(&asked[i]); n != 2 {
			t.Errorf("validator %d was asked %d time(s); want twice - once before its chain finalized the block, once after", i+1, n)
		}
	}
	if err != nil {
		t.Fatalf("THE regression: peers whose chain had not yet finalized the block were never asked again: %v", err)
	}
	if !cycle.Result.ThresholdMet || cycle.Result.AggregatedAttestation.AchievedWeight != 400 {
		t.Fatalf("threshold met %v, achieved %d of 400", cycle.Result.ThresholdMet, cycle.Result.AggregatedAttestation.AchievedWeight)
	}
}

// A refusal that is a verdict - here, a peer that does not hold the member - is final: never asked again.
func TestPhase8DoesNotAskAgainAfterARealRefusal(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)
	var asked int32
	stranger := nsOrchestrator(t, nil, c)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&asked, 1)
		var req PeerAttestationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, _ := stranger.HandlePeerAttestationRequest(r.Context(), &req)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	o := nsOrchestrator(t, own, c)
	o.config.AttestationPeers = []string{srv.URL}
	o.httpClient = &http.Client{Timeout: 10 * time.Second}
	s, _ := o.config.Registry.GetAttestationStrategy(attestation.AttestationSchemeBLS12381)
	msg, _ := nsMessage(t, own, c)
	got, err := o.collectPeerAttestations(context.Background(), &activeCycle{CycleID: "c"}, msg, s)
	if err != nil || len(got) != 0 || atomic.LoadInt32(&asked) != 1 {
		t.Fatalf("attestations %d, err %v, asked %d time(s); want none, once", len(got), err, asked)
	}
}
