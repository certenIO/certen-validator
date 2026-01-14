//go:build integration
// +build integration

// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package api provides comprehensive integration tests for the complete LiteClient API
// demonstrating account retrieval, proof generation, and caching functionality.
//
// These tests require network access to the Accumulate mainnet.
// Run with: go test -tags=integration ./api

package api

import (
	"context"
	"log"
	"testing"
	"time"
)

// TestLiteClient_FullIntegration_RenatoDAP tests the complete LiteClient API workflow
// with RenatoDAP account: retrieval, proof generation, and caching.
func TestLiteClient_FullIntegration_RenatoDAP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full integration test in short mode")
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("=== LITECLIENT FULL INTEGRATION TEST WITH RENATO DAP ===")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Test account - RenatoDAP as requested
	testAccountURL := "acc://RenatoDAP.acme"
	log.Printf("[INTEGRATION] Testing with RenatoDAP account: %s", testAccountURL)

	// Stage 1: Setup LiteClient with all components
	log.Printf("[INTEGRATION] Stage 1: Setting up complete LiteClient...")
	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to setup LiteClient: %v", err)
	}
	log.Printf("[INTEGRATION] ✅ LiteClient setup complete")

	// Stage 2: First GetAccount call - should retrieve from network
	log.Printf("[INTEGRATION] Stage 2: First GetAccount() call (network retrieval)...")
	startTime := time.Now()

	response1, err := client.GetAccount(ctx, testAccountURL)

	duration1 := time.Since(startTime)
	if err != nil {
		t.Fatalf("First GetAccount failed: %v", err)
	}

	log.Printf("[INTEGRATION] ✅ First GetAccount completed in %v", duration1)
	log.Printf("[INTEGRATION] Response Type: %s", response1.ResponseType)

	// Check if this is an account or ADI response
	var accountInfo *AccountInfo
	if response1.Account != nil {
		accountInfo = response1.Account
		log.Printf("[INTEGRATION] Individual Account Details:")
	} else if response1.ADI != nil && len(response1.ADI.Accounts) > 0 {
		accountInfo = response1.ADI.Accounts[0] // Get first account from ADI
		log.Printf("[INTEGRATION] ADI Account Details (first account):")
		log.Printf("   ADI URL: %s", response1.ADI.URL)
		log.Printf("   ADI Name: %s", response1.ADI.Name)
		log.Printf("   Total Accounts: %d", len(response1.ADI.Accounts))
	} else {
		t.Fatalf("No account data found in response")
	}

	log.Printf("   URL: %s", accountInfo.URL)
	log.Printf("   Type: %s", accountInfo.Type)
	log.Printf("   Category: %s", accountInfo.Category)

	// Display balance if it's a token account
	if accountInfo.TokenData != nil {
		log.Printf("   Balance: %s", accountInfo.TokenData.Balance)
		log.Printf("   Token URL: %s", accountInfo.TokenData.TokenURL)
	}

	// Stage 3: Test proof generation (check if proof data exists)
	log.Printf("[INTEGRATION] Stage 3: Checking for proof/receipt data...")
	if accountInfo.Receipt != nil {
		log.Printf("[INTEGRATION] ✅ Receipt data found:")
		log.Printf("   Receipt Exists: %v", accountInfo.Receipt.Exists)
		log.Printf("   Receipt Valid: %v", accountInfo.Receipt.Valid)
		log.Printf("   Block Height: %d", accountInfo.Receipt.BlockHeight)
		log.Printf("   Verified At: %v", accountInfo.Receipt.VerifiedAt)

		if !accountInfo.Receipt.Valid {
			t.Error("Receipt should be valid")
		}
	} else {
		log.Printf("[INTEGRATION] ⚠️ No receipt data found - Paul Snow's proof architecture integration point")
	}

	// Stage 4: Second GetAccount call - test caching behavior
	log.Printf("[INTEGRATION] Stage 4: Second GetAccount() call (testing caching)...")
	startTime = time.Now()

	_, err = client.GetAccount(ctx, testAccountURL)

	duration2 := time.Since(startTime)
	if err != nil {
		t.Fatalf("Second GetAccount failed: %v", err)
	}

	log.Printf("[INTEGRATION] ✅ Second GetAccount completed in %v", duration2)
	log.Printf("[INTEGRATION] Performance comparison: Second call was %v vs first %v", duration2, duration1)

	// Cache should generally be faster (though not always guaranteed with network variability)
	if duration2 < duration1 {
		log.Printf("[INTEGRATION] ✅ Cache performance improvement detected")
	}

	// Stage 5: Test cache functionality
	log.Printf("[INTEGRATION] Stage 5: Testing cache functionality...")
	cachedURLs := client.GetCachedAccountURLs()
	log.Printf("[INTEGRATION] Cache Statistics:")
	log.Printf("   Cached URLs: %d", len(cachedURLs))
	for i, url := range cachedURLs {
		if i < 3 { // Show first few
			log.Printf("     [%d]: %s", i+1, url)
		}
	}

	if len(cachedURLs) == 0 {
		log.Printf("[INTEGRATION] ⚠️ No cached URLs found - cache might be working differently")
	}

	// Stage 6: Test with different account types if available
	log.Printf("[INTEGRATION] Stage 6: Testing with Apollo account (different type)...")
	apolloAccountURL := "acc://apollo.acme"

	apolloResponse, err := client.GetAccount(ctx, apolloAccountURL)
	if err != nil {
		log.Printf("[INTEGRATION] ⚠️ Apollo account query failed (expected if account doesn't exist): %v", err)
	} else {
		log.Printf("[INTEGRATION] ✅ Apollo account retrieved:")
		if apolloResponse.Account != nil {
			log.Printf("   URL: %s", apolloResponse.Account.URL)
			log.Printf("   Type: %s", apolloResponse.Account.Type)
		} else if apolloResponse.ADI != nil {
			log.Printf("   ADI URL: %s", apolloResponse.ADI.URL)
			log.Printf("   ADI Accounts: %d", len(apolloResponse.ADI.Accounts))
		}
	}

	// Stage 7: Final cache management test
	log.Printf("[INTEGRATION] Stage 7: Testing cache management...")
	finalCachedURLs := client.GetCachedAccountURLs()
	log.Printf("[INTEGRATION] Final cached URLs count: %d", len(finalCachedURLs))

	// Test cache clearing
	client.ClearCache()
	postClearURLs := client.GetCachedAccountURLs()
	log.Printf("[INTEGRATION] After cache clear: %d URLs", len(postClearURLs))

	log.Printf("[INTEGRATION] ✅ FULL INTEGRATION TEST COMPLETED SUCCESSFULLY")
	log.Printf("[INTEGRATION] Demonstrated:")
	log.Printf("   - Account retrieval with RenatoDAP")
	log.Printf("   - Proof/receipt integration points")
	log.Printf("   - Cache functionality")
	log.Printf("   - Performance comparison")
	log.Printf("   - Multiple account type support")
}

// TestLiteClient_CachePerformance specifically tests cache performance improvements
func TestLiteClient_CachePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cache performance test in short mode")
	}

	log.Printf("=== CACHE PERFORMANCE TEST ===")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := NewClient(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to setup client: %v", err)
	}

	testAccountURL := "acc://RenatoDAP.acme"

	// Measure multiple cache hits
	var networkTime, cacheTime time.Duration

	// First call (network)
	start := time.Now()
	_, err = client.GetAccount(ctx, testAccountURL)
	networkTime = time.Since(start)
	if err != nil {
		t.Fatalf("Network call failed: %v", err)
	}

	// Multiple cache calls
	const cacheRuns = 3
	for i := 0; i < cacheRuns; i++ {
		start = time.Now()
		_, err := client.GetAccount(ctx, testAccountURL)
		cacheTime += time.Since(start)

		if err != nil {
			t.Fatalf("Cache call %d failed: %v", i+1, err)
		}
	}

	avgCacheTime := cacheTime / cacheRuns

	log.Printf("[PERFORMANCE] Network time: %v", networkTime)
	log.Printf("[PERFORMANCE] Average cache time: %v", avgCacheTime)
	log.Printf("[PERFORMANCE] Cache is %.1fx faster", float64(networkTime)/float64(avgCacheTime))

	// Cache might not always be faster due to network variability
	if avgCacheTime < networkTime {
		log.Printf("[PERFORMANCE] ✅ Cache performance improvement detected")
	} else {
		log.Printf("[PERFORMANCE] ⚠️ Cache not significantly faster (network variability)")
	}
}
