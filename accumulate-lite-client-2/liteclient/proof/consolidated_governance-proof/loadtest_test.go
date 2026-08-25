// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Gate 4A.6 final item - load test at 3x the observed peak.
//
// The nine lost proofs correlated with LOAD, not recency: eight of nine fell in
// the single highest-volume week (69 proofs against a typical 13-32). The
// mechanism was contention - RPC calls timing out, each timeout silently
// removing a signature from the count, the threshold then evaluated over what
// survived.
//
// A sequential re-run cannot reproduce that. This drives many proofs
// concurrently against live Kermit to induce the same contention, and asserts
// the property that must now hold no matter how bad it gets:
//
//	NO run may report an unmet threshold while having found signatures.
//
// Failures are expected under load. What must never happen is a failure
// SHAPED LIKE A GOVERNANCE VERDICT. Every failure must be an outage.
//
//	go test -run TestLoad_ -loadtest -v ./proof/consolidated_governance-proof/
var (
	loadTestEnabled = flag.Bool("loadtest", false, "run the concurrent load test (slow, hits live Kermit)")
	loadTestRuns    = flag.Int("loadruns", 207, "total proof runs (3x the 69/week peak of 2026-08-03)")
	loadTestWorkers = flag.Int("loadworkers", 24, "concurrent workers")
)

// Real Kermit transactions, all of which prove cleanly in isolation.
var loadFixtures = []struct{ account, txHash, keyPage string }{
	{"acc://carp-buyer-62431.acme/data", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0", "acc://carp-buyer-62431.acme/book/1"},
	{"acc://certen-panel-carp-v7.acme/data", "37e28c94ce760872db514b22ffb483dbfc288204b94b22ad1d9c1c022357c750", "acc://certen-panel-carp-v7.acme/book/1"},
	{"acc://carp-seller-40996.acme/data", "3970b4cbc47a50e5156370dc366d1f7b14da9226b810253955d793ae7aeefce7", "acc://carp-seller-40996.acme/book/1"},
	{"acc://carp-buyer-62431.acme/data", "8cc2bbf22b91aaf8b1e24ba7792dbb6b7431c9e867db03e557a3ae202df86ec4", "acc://carp-buyer-62431.acme/book/1"},
	{"acc://carp-seller-40996.acme/data", "e0d54ced7c801e816a6456296b0c6a297be487e5f8eaec8bf0780d75d7c01319", "acc://carp-seller-40996.acme/book/1"},
	{"acc://certen-kermit-12.acme/data", "f6c353ddbee816be8d25c2a1ccb169230c77e6c829b5e01b52ee5ff0b1ae53e5", "acc://certen-kermit-12.acme/book/1"},
	{"acc://certen-kermit-12.acme/batchb/data", "499e0f5760445ad4fffedf423159de96b3a3861b3b1e28f6f7706ccc1ff3b113", "acc://certen-kermit-12.acme/book/1"},
	{"acc://feeverify-083314.acme/data", "5404b3f5eec14ca14d3eb9b9fa6d6151b48449d3d3046ae7c0d52172d6bd47c2", "acc://feeverify-083314.acme/book/1"},
	{"acc://feeverify-083314.acme/data", "22da14ae699c2aead644eca4ba3801840e01250b4b32fda754b73cc207583973", "acc://feeverify-083314.acme/book/1"},
}

type loadOutcome struct {
	index      int
	ok         bool
	outage     bool // failure was an evidence outage - acceptable under load
	disagree   bool // routes disagreed - a finding, not acceptable
	verdict    bool // FAILURE SHAPED AS A GOVERNANCE VERDICT - the defect
	uniqueKeys int
	threshold  uint64
	detail     string
	elapsed    time.Duration
}

func TestLoad_ConcurrentProofsNeverProduceFalseThresholdVerdicts(t *testing.T) {
	if !*loadTestEnabled {
		t.Skip("load test disabled; pass -loadtest to enable")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = faultV3Endpoint
	}

	total, workers := *loadTestRuns, *loadTestWorkers
	t.Logf("load test: %d runs, %d concurrent workers, endpoint %s", total, workers, ep)
	t.Logf("target property: zero failures shaped as an unmet threshold")

	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	results := make(chan loadOutcome, total)
	var wg sync.WaitGroup
	var completed int64

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				fx := loadFixtures[idx%len(loadFixtures)]

				real := NewRPCClient(RPCConfig{Endpoint: ep, Timeout: 90 * time.Second, Backend: "http", UseHTTP: true})
				am, err := NewArtifactManager(t.TempDir())
				if err != nil {
					results <- loadOutcome{index: idx, outage: true, detail: "artifact manager: " + err.Error()}
					continue
				}
				g1 := NewG1Layer(real, am, "")

				runStart := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
				res, err := g1.ProveG1(ctx, G1Request{
					G0Request: G0Request{Account: fx.account, TxHash: fx.txHash, Chain: "main"},
					KeyPage:   fx.keyPage,
				})
				cancel()
				out := loadOutcome{index: idx, elapsed: time.Since(runStart)}

				switch {
				case err == nil:
					out.ok = true
					out.uniqueKeys = res.UniqueValidKeys
					out.threshold = res.RequiredThreshold
					// The defect's exact shape: signatures found, threshold
					// arithmetically satisfiable, recorded as unmet.
					if !res.ThresholdSatisfied && res.UniqueValidKeys > 0 {
						out.ok, out.verdict = false, true
						out.detail = fmt.Sprintf("threshold recorded unmet with %d unique keys against threshold %d",
							res.UniqueValidKeys, res.RequiredThreshold)
					}
				case isOutageErr(err):
					out.outage = true
					out.detail = truncate(err.Error(), 200)
				case isDisagreementErr(err):
					out.disagree = true
					out.detail = truncate(err.Error(), 200)
				default:
					// Any other error must be inspected: if it reads as a
					// threshold verdict it is the defect returning.
					out.detail = truncate(err.Error(), 240)
					if mentionsThreshold(err.Error()) {
						out.verdict = true
					} else {
						out.outage = true
					}
				}
				results <- out
				if n := atomic.AddInt64(&completed, 1); n%25 == 0 {
					t.Logf("  progress: %d/%d in %s", n, total, time.Since(start).Truncate(time.Second))
				}
			}
		}()
	}
	wg.Wait()
	close(results)

	var ok, outages, disagreements, verdicts int
	var slowest time.Duration
	var verdictDetails, disagreeDetails []string
	for r := range results {
		switch {
		case r.ok:
			ok++
		case r.verdict:
			verdicts++
			verdictDetails = append(verdictDetails, fmt.Sprintf("[run %d] %s", r.index, r.detail))
		case r.disagree:
			disagreements++
			disagreeDetails = append(disagreeDetails, fmt.Sprintf("[run %d] %s", r.index, r.detail))
		default:
			outages++
		}
		if r.elapsed > slowest {
			slowest = r.elapsed
		}
	}

	elapsed := time.Since(start)
	t.Logf("---")
	t.Logf("completed %d runs in %s (%.1f proofs/sec sustained, slowest run %s)",
		total, elapsed.Truncate(time.Second), float64(total)/elapsed.Seconds(), slowest.Truncate(time.Millisecond))
	t.Logf("  succeeded            : %d", ok)
	t.Logf("  evidence outages     : %d  (acceptable: infrastructure, fails closed)", outages)
	t.Logf("  route disagreements  : %d  (must be zero)", disagreements)
	t.Logf("  FALSE THRESHOLD      : %d  (must be zero)", verdicts)

	for _, d := range disagreeDetails {
		t.Logf("  disagreement: %s", d)
	}
	for _, d := range verdictDetails {
		t.Logf("  VERDICT: %s", d)
	}

	if verdicts > 0 {
		t.Fatalf("CRITICAL DEFECT: %d of %d runs produced a governance verdict under load. "+
			"This is the exact failure that cost nine proofs.", verdicts, total)
	}
	if disagreements > 0 {
		t.Fatalf("CRITICAL: %d runs had the two signature routes disagree. "+
			"That is a finding about the evidence, not a load symptom.", disagreements)
	}
	if ok == 0 {
		t.Fatal("no run succeeded - the load test proves nothing about correctness")
	}
}

func isOutageErr(err error) bool {
	_, ok := IsEvidenceIncomplete(err)
	return ok
}

func isDisagreementErr(err error) bool {
	_, ok := err.(*RouteDisagreement)
	return ok
}

// mentionsThreshold reports whether an error reads as a governance verdict
// about signature sufficiency.
func mentionsThreshold(s string) bool {
	for _, needle := range []string{"Threshold not satisfied", "threshold_met", "threshold not satisfied"} {
		if containsFold(s, needle) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) == 0 || len(h) < len(n) {
		return len(n) == 0
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		match := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
