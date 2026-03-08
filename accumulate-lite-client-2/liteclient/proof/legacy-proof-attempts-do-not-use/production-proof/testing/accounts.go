// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package testing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// CreateTestAccounts creates multiple test accounts in devnet
func (ts *TestSuite) CreateTestAccounts(t Testing, count int, prefix string) error {
	fmt.Printf("\n🏗️  Creating %d test accounts with prefix '%s'\n", count, prefix)
	fmt.Println(strings.Repeat("─", 60))

	// First, ensure the sponsor account has tokens
	sponsorURL := protocol.AccountUrl("alice")

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent creations

	startTime := time.Now()

	for i := 0; i < count; i++ {
		wg.Add(1)
		accountName := fmt.Sprintf("%s%d", prefix, i)

		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			err := ts.createSingleAccount(sponsorURL, name)
			if err != nil {
				ts.addError(fmt.Sprintf("Failed to create %s: %v", name, err))
			} else {
				ts.createdCount.Add(1)
				ts.addAccount(fmt.Sprintf("acc://%s.acme", name))

				// Progress indicator
				created := ts.createdCount.Load()
				if created%10 == 0 {
					fmt.Printf("  ✅ Created %d/%d accounts\n", created, count)
				}
			}
		}(accountName)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	fmt.Printf("\n📊 Account Creation Summary:\n")
	fmt.Printf("  • Total Requested: %d\n", count)
	fmt.Printf("  • Successfully Created: %d\n", ts.createdCount.Load())
	fmt.Printf("  • Failed: %d\n", count-int(ts.createdCount.Load()))
	fmt.Printf("  • Time Taken: %.2f seconds\n", elapsed.Seconds())
	fmt.Printf("  • Rate: %.2f accounts/second\n", float64(ts.createdCount.Load())/elapsed.Seconds())

	if len(ts.errors) > 0 && len(ts.errors) < 10 {
		fmt.Printf("\n⚠️  Creation Errors:\n")
		for _, err := range ts.errors {
			fmt.Printf("  • %s\n", err)
		}
	}

	return nil
}

// createSingleAccount creates a single test account
func (ts *TestSuite) createSingleAccount(sponsorURL *url.URL, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate a new key for the account
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Build the create account transaction
	accountURL := protocol.AccountUrl(name)
	keyHash := sha256.Sum256(pubKey)

	txn := new(build.TransactionBuilder).
		For(sponsorURL).
		Body(&protocol.CreateIdentity{
			Url:        accountURL,
			KeyBookUrl: accountURL.JoinPath("book"),
			KeyHash:    keyHash[:],
		}).
		SignWith(sponsorURL.JoinPath("book", "1")).
		Version(1).
		Timestamp(time.Now().Unix()).
		PrivateKey(privKey)

	// Submit the transaction
	envelope, err := txn.Done()
	if err != nil {
		return fmt.Errorf("transaction build failed: %w", err)
	}
	submissions, err := ts.client.Submit(ctx, envelope, api.SubmitOptions{})
	if err != nil {
		// Check if account already exists (not an error for our test)
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}

	// Check if submission was successful
	if len(submissions) == 0 {
		return fmt.Errorf("no submission response")
	}

	// Wait briefly for account to be created
	time.Sleep(100 * time.Millisecond)

	return nil
}

// addAccount adds an account to the test suite
func (ts *TestSuite) addAccount(account string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.accounts = append(ts.accounts, account)
}
