// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package testing

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// StressTest performs concurrent verification to test system limits
func (ts *TestSuite) StressTest(t Testing, concurrency int, duration time.Duration) {
	fmt.Printf("\n🔥 Stress Testing with %d concurrent workers for %v\n", concurrency, duration)
	fmt.Println(strings.Repeat("═", 60))

	if len(ts.accounts) == 0 {
		ts.accounts = []string{"acc://dn.acme"}
	}

	var (
		totalRequests atomic.Int64
		totalErrors   atomic.Int64
		totalSuccess  atomic.Int64
	)

	// Create workers
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Pick random account
					account := ts.accounts[rand.Intn(len(ts.accounts))]
					accountURL, _ := url.Parse(account)

					totalRequests.Add(1)

					// Try to verify
					verified, err := ts.verifier.VerifyAccountSimple(accountURL)
					if err != nil {
						totalErrors.Add(1)
					} else if verified {
						totalSuccess.Add(1)
					}

					// Show progress every 1000 requests
					if totalRequests.Load()%1000 == 0 {
						fmt.Printf("  Progress: %d requests, %d successful, %d errors\n",
							totalRequests.Load(), totalSuccess.Load(), totalErrors.Load())
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Display results
	fmt.Printf("\n📊 Stress Test Results:\n")
	fmt.Printf("  • Total Requests: %d\n", totalRequests.Load())
	fmt.Printf("  • Successful: %d (%.1f%%)\n",
		totalSuccess.Load(),
		float64(totalSuccess.Load())/float64(totalRequests.Load())*100)
	fmt.Printf("  • Errors: %d\n", totalErrors.Load())
	fmt.Printf("  • Requests/sec: %.2f\n",
		float64(totalRequests.Load())/duration.Seconds())
	fmt.Printf("  • Success rate: %.1f%%\n",
		float64(totalSuccess.Load())/float64(totalRequests.Load())*100)

	if float64(totalSuccess.Load())/float64(totalRequests.Load()) < 0.95 {
		t.Logf("Warning: Success rate below 95%%")
	}
}
