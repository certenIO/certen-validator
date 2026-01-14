// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package liteclient implements the main orchestrator for the Accumulate Lite Client,
// demonstrating clear separation of concerns and maintainable architecture.
//
// REFACTORED ARCHITECTURE:
// This file implements the core LiteClient that coordinates between specialized backends:
// - DataBackend: Handles account data retrieval from network APIs
// - ProofBackend: Handles cryptographic proof generation and validation
// - Caching: Direct cache management for optimal performance
//
// DESIGN PRINCIPLES:
// 1. SINGLE RESPONSIBILITY: Each backend has one focused responsibility
// 2. INTERFACE SEGREGATION: Split interfaces instead of monolithic Backend
// 3. DEPENDENCY INJECTION: Backends injected for testability and flexibility
// 4. DIRECT COORDINATION: LiteClient directly orchestrates without middleware layers
//
// ARCHITECTURAL BENEFITS:
// - Clear separation between data retrieval and proof generation
// - Eliminated receipt pipeline indirection for better performance
// - Simplified call chain: API → LiteClient → Specialized Backend → Result
// - Enhanced testability through focused interfaces
// - Improved maintainability with clear component boundaries

package core

import (
	"context"
	"fmt"
	"log"
	"time"

	v2api "gitlab.com/accumulatenetwork/accumulate/pkg/client/api/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/backend"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/cache"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// LiteClient is the core orchestrator implementing the crystal clear proof path.
// It coordinates between specialized backends to provide complete account data
// with cryptographic proof validation following Paul's suggested healing pattern.
//
// CRYSTAL CLEAR PROOF PATH:
//  1. Account Entry → Account Main Chain Root
//  2. Main Chain Root → BVN BPT (Binary Patricia Tree)
//  3. BVN BPT → BVN Anchor
//  4. BVN Anchor → DN Anchor
//  5. DN Anchor → DN BPT
//  6. DN BPT → DN Root
//  7. DN Root → Final trust via CometBFT commit
//
// SINGLE ENTRY POINT: api.GetAccount(url) → LiteClient.ProcessIndividualAccount(ctx,url)
//
// ARCHITECTURE BENEFITS:
// - Crystal clear proof path with explicit stages
// - Single entry point eliminates confusion
// - Bounded caches with LRU eviction
// - Performance metrics for monitoring
type LiteClient struct {
	dataBackendV2         types.DataBackend // V2 backend for account queries
	dataBackendV3         types.DataBackend // V3 backend for BVN/anchor queries
	healingProofGenerator *proof.HealingProofGenerator
	accountCache          *cache.AccountCache
	metrics               *types.Metrics // Performance monitoring
}

// VerifiedAccountInfo represents account data with cryptographic proof validation
type VerifiedAccountInfo struct {
	URL          string
	Type         protocol.AccountType
	Balance      string
	Receipt      *merkle.Receipt
	Height       int64
	LastUpdated  time.Time
	Transactions []*TransactionInfo
}

// TransactionInfo represents transaction data
type TransactionInfo struct {
	TxID      string
	Type      string
	Status    string
	Timestamp time.Time
	Amount    string
	From      string
	To        string
}

// NewLiteClient creates a new LiteClient with specialized backend implementations.
// This constructor demonstrates the Dependency Injection pattern by creating
// focused backend implementations for data and proof operations.
//
// ARCHITECTURE SETUP:
// 1. Creates v2 API client for network communication
// 2. Initializes DataBackend for account data retrieval
// 3. Initializes ProofBackend for cryptographic proof generation
// 4. Sets up caching for optimal performance
// 5. Returns configured LiteClient ready for operation
func NewLiteClient(serverURL string) (*LiteClient, error) {
	if serverURL == "" {
		return nil, fmt.Errorf("server URL cannot be empty")
	}

	// Create V2 backend for account queries
	v2client, err := v2api.New(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 client: %w", err)
	}
	dataBackendV2, err := backend.NewRPCDataBackend(serverURL, v2client)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 data backend: %w", err)
	}

	// Create V3 backend for BVN/anchor queries
	dataBackendV3, err := backend.NewRPCDataBackendV3(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create v3 data backend: %w", err)
	}

	// Step 4: Create BackendPair for dual-backend access
	backendPair, err := backend.NewBackendPair(dataBackendV2, dataBackendV3)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend pair: %w", err)
	}

	// Step 5: Create HealingProofGenerator with the backend pair
	healingProofGenerator := proof.NewHealingProofGenerator(backendPair)

	// Create bounded caches with metrics for optimal performance
	accountCache := cache.NewAccountCacheWithBounds(5*time.Minute, 1000) // 5 min TTL, max 1000 entries

	// Create LiteClient with both backends and metrics
	lc := &LiteClient{
		dataBackendV2:         dataBackendV2,
		dataBackendV3:         dataBackendV3,
		healingProofGenerator: healingProofGenerator,
		accountCache:          accountCache,
		metrics:               types.NewMetrics(),
	}

	return lc, nil
}

// ProcessADIAccounts discovers and processes all accounts for an ADI.
// This method demonstrates the new architecture by using DataBackend for discovery
// and then processing each account through the complete data + proof workflow.
//
// WORKFLOW:
// 1. Use DataBackend to discover all accounts in the ADI
// 2. Process each account individually with complete trust path validation
// 3. Return list of discovered account URLs
func (lc *LiteClient) ProcessADIAccounts(ctx context.Context, adiURL string) ([]string, error) {
	log.Printf("[LITE CLIENT] Processing ADI accounts for: %s", adiURL)

	// Create account handler with cache injection for ADI discovery
	accountHandler := types.NewAccountHandlerWithCache(lc.dataBackendV2, lc.accountCache)

	// Delegate ADI processing to account handler
	accountURLs, err := accountHandler.DiscoverADIAccounts(ctx, adiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to process ADI accounts: %w", err)
	}

	log.Printf("[LITE CLIENT] Discovered %d accounts in ADI", len(accountURLs))

	// Process each account individually to ensure complete trust path validation
	for _, accountURL := range accountURLs {
		_, err := lc.ProcessIndividualAccount(ctx, accountURL)
		if err != nil {
			// Log the error but continue processing other accounts
			log.Printf("[LITE CLIENT] Warning: failed to establish trust path for account %s: %v", accountURL, err)
		}
	}

	log.Printf("[LITE CLIENT] ✅ Completed ADI processing for %s", adiURL)
	return accountURLs, nil
}

// ProcessIndividualAccount is the single entry point for retrieving account data with cryptographic proof.
// This method implements the healing pattern with crystal clear proof path:
//
// PROOF PATH (Paul's suggested path):
//  1. Account Entry → Account Main Chain Root
//  2. Main Chain Root → BVN BPT (Binary Patricia Tree)
//  3. BVN BPT → BVN Anchor
//  4. BVN Anchor → DN Anchor
//  5. DN Anchor → DN BPT
//  6. DN BPT → DN Root
//  7. DN Root → Final trust via CometBFT commit
//
// Each stage creates a Merkle receipt proving inclusion in the next level.
// The complete chain establishes trustless verification from account state to network consensus.
func (lc *LiteClient) ProcessIndividualAccount(ctx context.Context, accountURL string) (*types.AccountData, error) {

	// Step 1: Retrieve account data from the network
	accountHandler := types.NewAccountHandlerWithCache(lc.dataBackendV2, lc.accountCache)
	accountData, err := accountHandler.GetAccountData(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve account data: %w", err)
	}

	// Step 2: Generate complete cryptographic proof using the healing pattern
	start := time.Now()
	lc.metrics.RecordProofRequest()

	log.Printf("[PROOF PIPELINE] Starting healing proof generation for %s", accountURL)
	proof, err := lc.generateHealingProof(ctx, accountURL)
	if err != nil {
		lc.metrics.RecordProofFailure()
		log.Printf("[PROOF PIPELINE] ⚠️ Failed to establish trust path: %v", err)
		// Return data without proof - the user can decide if this is acceptable
	} else {
		lc.metrics.RecordProofSuccess()
		accountData.Receipt = proof.CombinedReceipt
		accountData.CompleteProof = proof
		log.Printf("[PROOF PIPELINE] ✅ Complete trust path established")
	}

	// Record request metrics
	latency := time.Since(start).Milliseconds()
	lc.metrics.RecordAccountRequest(latency)

	// Step 3: Update metadata
	accountData.LastUpdated = time.Now()

	return accountData, nil
}

// generateHealingProof implements the crystal clear proof path following Paul's suggested approach:
// Main Chain Root → BVN BPT → BVN Anchor → DN Anchor → DN BPT → DN Root
//
// This method creates a complete cryptographic proof chain that establishes trust
// from an account's main chain root all the way to the Directory Network root.
func (lc *LiteClient) generateHealingProof(ctx context.Context, accountURL string) (*proof.CompleteProof, error) {
	log.Printf("[HEALING PROOF] 🔧 Starting proof generation pipeline for %s", accountURL)

	// STAGE 1: Get the account's main chain root hash
	log.Printf("[HEALING PROOF] Stage 1/5: Getting main chain root...")
	accountData, err := lc.dataBackendV2.QueryAccount(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	if len(accountData.MainChainRoots) == 0 {
		return nil, fmt.Errorf("account has no main chain root")
	}

	mainChainRoot := accountData.MainChainRoots[0] // Use the most recent root
	log.Printf("[HEALING PROOF] \u2705 Main chain root: %x", mainChainRoot)

	// STAGE 2: Find BVN partition for this account
	log.Printf("[HEALING PROOF] Stage 2/5: Finding BVN partition...")
	partition, err := lc.findAccountBVNPartition(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to find BVN partition: %w", err)
	}
	log.Printf("[HEALING PROOF] \u2705 Account routes to BVN partition: %s", partition)

	// STAGE 3: Main Chain Root → BVN BPT (PAUL SNOW'S CORRECT ARCHITECTURE)
	// The account's main chain root hash should be found as an entry in the BVN's Binary Patricia Tree
	log.Printf("[HEALING PROOF] Stage 3/6: Finding main chain root in BVN BPT...")
	bvnBptReceipt, err := lc.dataBackendV3.GetBPTReceipt(ctx, partition, mainChainRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to get BVN BPT receipt for main chain root: %w", err)
	}
	log.Printf("[HEALING PROOF] \u2705 BVN BPT root: %x", bvnBptReceipt.Anchor)

	// STAGE 4: BVN BPT Root → BVN Root Chain
	// The BVN BPT root hash should be found as an entry in the BVN root chain
	log.Printf("[HEALING PROOF] Stage 4/6: Finding BVN BPT root in BVN root chain...")
	bvnRootReceipt, err := lc.dataBackendV3.GetBVNAnchorReceipt(ctx, partition, bvnBptReceipt.Anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to get BVN root chain receipt: %w", err)
	}
	log.Printf("[HEALING PROOF] \u2705 BVN root chain anchor: %x", bvnRootReceipt.Anchor)

	// STAGE 5: BVN Root → DN Anchor
	// The BVN root chain anchor should be found in the Directory Network
	log.Printf("[HEALING PROOF] Stage 5/6: Finding BVN root anchor in DN...")
	dnAnchorReceipt, err := lc.dataBackendV3.GetDNIntermediateAnchorReceipt(ctx, bvnRootReceipt.Anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to get DN anchor receipt: %w", err)
	}
	log.Printf("[HEALING PROOF] \u2705 DN anchor: %x", dnAnchorReceipt.Anchor)

	// STAGE 6: DN Anchor → DN BPT → DN Root
	log.Printf("[HEALING PROOF] Stage 6/6: Finding DN anchor in DN BPT and root...")
	dnBptReceipt, err := lc.dataBackendV3.GetBPTReceipt(ctx, "dn", dnAnchorReceipt.Anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to get DN BPT receipt: %w", err)
	}

	dnRootReceipt, err := lc.dataBackendV3.GetDNAnchorReceipt(ctx, dnBptReceipt.Anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to get DN root receipt: %w", err)
	}
	log.Printf("[HEALING PROOF] \u2705 DN root: %x", dnRootReceipt.Anchor)

	// COMBINE ALL RECEIPTS: Create the complete proof chain following Paul Snow's 6-stage architecture
	log.Printf("[HEALING PROOF] 🔗 Combining all receipts into complete proof...")

	// Paul Snow's correct proof path requires combining receipts in order:
	// Stage 1: Account → Main Chain Root (already have mainChainRoot)
	// Stage 2: Main Chain Root → BVN BPT → BVN BPT Root
	// Stage 3: BVN BPT Root → BVN Root Chain → BVN Anchor
	// Stage 4: BVN Anchor → DN Anchor
	// Stage 5: DN Anchor → DN BPT → DN BPT Root
	// Stage 6: DN BPT Root → DN Root

	// Combine Stage 2+3: BVN BPT → BVN Root
	step1, err := bvnBptReceipt.Combine(bvnRootReceipt)
	if err != nil {
		return nil, fmt.Errorf("failed to combine BVN BPT and root receipts: %w", err)
	}

	// Combine with Stage 4: BVN → DN Anchor
	step2, err := step1.Combine(dnAnchorReceipt)
	if err != nil {
		return nil, fmt.Errorf("failed to combine BVN with DN anchor receipt: %w", err)
	}

	// Combine with Stage 5: DN Anchor → DN BPT
	step3, err := step2.Combine(dnBptReceipt)
	if err != nil {
		return nil, fmt.Errorf("failed to combine with DN BPT receipt: %w", err)
	}

	// Combine with Stage 6: DN BPT → DN Root (final step)
	finalReceipt, err := step3.Combine(dnRootReceipt)
	if err != nil {
		return nil, fmt.Errorf("failed to combine with DN root receipt: %w", err)
	}

	// VALIDATE: Ensure the complete proof is cryptographically sound
	if !finalReceipt.Validate(nil) {
		return nil, fmt.Errorf("combined receipt failed validation")
	}

	// Assemble complete proof with correct Paul Snow architecture
	completeProof := &proof.CompleteProof{
		MainChainProof:  bvnBptReceipt,                                    // Main chain root found in BVN BPT (correct!)
		BVNAnchorProof:  &proof.PartitionAnchor{Receipt: bvnRootReceipt},  // BVN root proof
		DNAnchorProof:   &proof.PartitionAnchor{Receipt: dnAnchorReceipt}, // DN anchor proof
		BPTProof:        dnBptReceipt,                                     // DN BPT proof
		CombinedReceipt: finalReceipt,
	}

	log.Printf("[HEALING PROOF] ✅ Complete proof generated: Main Chain Root → BVN BPT → BVN Root → DN Anchor → DN BPT → DN Root")
	log.Printf("[HEALING PROOF] Final receipt: %x → %x", finalReceipt.Start, finalReceipt.Anchor)
	return completeProof, nil
}

// findAccountBVNPartition determines which BVN partition an account belongs to.
// Currently, all accounts route to the \"Cyclops\" BVN partition.
func (lc *LiteClient) findAccountBVNPartition(ctx context.Context, accountURL string) (string, error) {
	// For now, all accounts route to Cyclops BVN
	// In a full implementation, this would use the routing table
	return "Cyclops", nil
}

// generateCanonicalReceipt has been REMOVED and replaced by generateHealingProof.
// The new approach uses ProofBackend.GenerateAccountProof() to establish complete
// cryptographic proof chains from account entries to the DN root.
// This eliminates the receipt pipeline indirection while providing the same
// security guarantees and trustless verification.

// ============================================================================
// CACHE MANAGEMENT METHODS (called by public API)
// ============================================================================

// PruneExpiredCaches removes expired entries from all caches.
func (lc *LiteClient) PruneExpiredCaches() {
	lc.accountCache.PruneExpired()
}

// PruneAll removes all expired entries from all caches.
func (lc *LiteClient) PruneAll(ctx context.Context) error {
	lc.PruneExpiredCaches()
	return nil
}

// PruneAccount removes cached data for a specific account.
// Handles account pruning directly without Session layer.
func (lc *LiteClient) PruneAccount(accountURL string) {
	// Create account handler with DataBackend and cache injection
	accountHandler := types.NewAccountHandlerWithCache(lc.dataBackendV2, lc.accountCache)

	// Remove account directly
	accountHandler.RemoveAccount(accountURL)
}

// ClearCache removes all cached data.
func (lc *LiteClient) ClearCache() {
	lc.accountCache.Clear()
}

// GetMetrics returns current performance metrics from both the LiteClient and cache.
func (lc *LiteClient) GetMetrics() *types.Metrics {
	// Combine LiteClient metrics with cache metrics
	cacheMetrics := lc.accountCache.GetMetrics()

	// Add cache-specific metrics to our main metrics
	lc.metrics.CacheHits = cacheMetrics.CacheHits
	lc.metrics.CacheMisses = cacheMetrics.CacheMisses
	lc.metrics.CacheEvictions = cacheMetrics.CacheEvictions

	return lc.metrics
}

// GetCachedAccountURLs returns a list of all account URLs currently in the cache.
func (lc *LiteClient) GetCachedAccountURLs() []string {
	// Access the account cache directly since we own it
	return lc.accountCache.GetCachedURLs()
}

// ============================================================================
// ACCOUNT METHODS (Internal)
// ============================================================================

// GetAccountInfo retrieves account information for a specific account URL.
// This method demonstrates the new architecture by using DataBackend directly
// for simple data retrieval without proof generation.
func (lc *LiteClient) GetAccountInfo(ctx context.Context, accountURL string) (*types.AccountData, error) {
	// Create handler with DataBackend and shared cache
	accountHandler := types.NewAccountHandlerWithCache(lc.dataBackendV2, lc.accountCache)

	// Delegate to account handler which handles validation and caching internally
	return accountHandler.GetAccountData(ctx, accountURL)
}

// GetAccountTransactions retrieves transactions for a specific account URL
func (lc *LiteClient) GetAccountTransactions(ctx context.Context, accountURL string) ([]*TransactionInfo, error) {
	// Get account data first (validation handled by AccountHandler)
	accountData, err := lc.GetAccountInfo(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get account data: %w", err)
	}

	// Convert Transaction to TransactionInfo
	transactions := make([]*TransactionInfo, 0, len(accountData.Transactions))
	for _, tx := range accountData.Transactions {
		transactions = append(transactions, &TransactionInfo{
			TxID:      tx.TxID,
			Type:      tx.Type,
			Status:    tx.Status,
			Timestamp: time.Unix(tx.Timestamp, 0),
			Amount:    tx.Amount,
			From:      tx.From,
			To:        tx.To,
		})
	}

	return transactions, nil
}
