// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package batch provides high-performance batch proof generation
package batch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/interfaces"
)

// BatchProofGenerator efficiently generates multiple proofs concurrently
type BatchProofGenerator struct {
	verifier       *core.CryptographicVerifier
	cache          interfaces.ProofCache
	maxWorkers     int
	batchTimeout   time.Duration
	maxBatchSize   int
	debug          bool

	// Metrics
	totalBatches   int64
	totalProofs    int64
	totalErrors    int64
	averageTime    time.Duration
	mu             sync.Mutex
}

// BatchRequest represents a request for proof generation
type BatchRequest struct {
	AccountURL string
	Strategy   interfaces.ProofStrategy
	Context    context.Context
}

// BatchResult represents the result of a proof generation
type BatchResult struct {
	AccountURL string
	Proof      *interfaces.CompleteProof
	Error      error
	Duration   time.Duration
}

// BatchProofResponse contains the results of a batch proof operation
type BatchProofResponse struct {
	Results        []BatchResult
	SuccessCount   int
	ErrorCount     int
	TotalDuration  time.Duration
	CacheHitCount  int
	GeneratedCount int
}

// NewBatchProofGenerator creates a new batch proof generator
func NewBatchProofGenerator(
	verifier *core.CryptographicVerifier,
	cache interfaces.ProofCache,
	maxWorkers int,
	batchTimeout time.Duration,
	maxBatchSize int,
) *BatchProofGenerator {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}
	if batchTimeout <= 0 {
		batchTimeout = 30 * time.Second
	}
	if maxBatchSize <= 0 {
		maxBatchSize = 100
	}

	return &BatchProofGenerator{
		verifier:     verifier,
		cache:        cache,
		maxWorkers:   maxWorkers,
		batchTimeout: batchTimeout,
		maxBatchSize: maxBatchSize,
		debug:        false,
	}
}

// GenerateBatch generates proofs for multiple accounts concurrently
func (b *BatchProofGenerator) GenerateBatch(
	ctx context.Context,
	requests []BatchRequest,
) *BatchProofResponse {
	startTime := time.Now()

	if len(requests) == 0 {
		return &BatchProofResponse{
			Results:       []BatchResult{},
			SuccessCount:  0,
			ErrorCount:    0,
			TotalDuration: 0,
		}
	}

	// Limit batch size
	if len(requests) > b.maxBatchSize {
		requests = requests[:b.maxBatchSize]
	}

	response := &BatchProofResponse{
		Results: make([]BatchResult, len(requests)),
	}

	// Create worker pool
	workers := b.maxWorkers
	if workers > len(requests) {
		workers = len(requests)
	}

	requestChan := make(chan BatchRequest, len(requests))
	resultChan := make(chan BatchResult, len(requests))

	// Add timeout to context
	ctxWithTimeout, cancel := context.WithTimeout(ctx, b.batchTimeout)
	defer cancel()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go b.worker(ctxWithTimeout, &wg, requestChan, resultChan)
	}

	// Send requests to workers
	go func() {
		for _, req := range requests {
			select {
			case requestChan <- req:
			case <-ctxWithTimeout.Done():
				break
			}
		}
		close(requestChan)
	}()

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	resultMap := make(map[string]BatchResult)
	for result := range resultChan {
		resultMap[result.AccountURL] = result

		if result.Error != nil {
			response.ErrorCount++
			if result.Proof == nil {
				b.totalErrors++
			}
		} else {
			response.SuccessCount++
			b.totalProofs++
		}
	}

	// Preserve original order of requests
	for i, req := range requests {
		if result, found := resultMap[req.AccountURL]; found {
			response.Results[i] = result
		} else {
			// Request was not processed (likely timeout)
			response.Results[i] = BatchResult{
				AccountURL: req.AccountURL,
				Error:      fmt.Errorf("request not processed (timeout or cancellation)"),
				Duration:   0,
			}
			response.ErrorCount++
		}
	}

	response.TotalDuration = time.Since(startTime)
	b.updateBatchMetrics(response.TotalDuration)

	if b.debug {
		b.logBatchResults(response)
	}

	return response
}

// GenerateBatchSimple generates proofs for a list of account URLs using default strategy
func (b *BatchProofGenerator) GenerateBatchSimple(
	ctx context.Context,
	accountURLs []string,
) *BatchProofResponse {
	requests := make([]BatchRequest, len(accountURLs))
	for i, url := range accountURLs {
		requests[i] = BatchRequest{
			AccountURL: url,
			Strategy:   interfaces.StrategyOptimized,
			Context:    ctx,
		}
	}

	return b.GenerateBatch(ctx, requests)
}

// worker processes proof generation requests
func (b *BatchProofGenerator) worker(
	ctx context.Context,
	wg *sync.WaitGroup,
	requestChan <-chan BatchRequest,
	resultChan chan<- BatchResult,
) {
	defer wg.Done()

	for {
		select {
		case req, ok := <-requestChan:
			if !ok {
				return
			}

			result := b.processRequest(ctx, req)

			select {
			case resultChan <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// processRequest handles a single proof generation request
func (b *BatchProofGenerator) processRequest(ctx context.Context, req BatchRequest) BatchResult {
	startTime := time.Now()

	result := BatchResult{
		AccountURL: req.AccountURL,
	}

	// Check cache first if strategy allows
	if req.Strategy == interfaces.StrategyOptimized || req.Strategy == interfaces.StrategyMinimal {
		if b.cache != nil {
			if cachedProof, found := b.cache.GetAccountProof(req.AccountURL); found {
				result.Proof = cachedProof
				result.Duration = time.Since(startTime)

				if b.debug {
					fmt.Printf("Cache hit for %s (took %v)\n", req.AccountURL, result.Duration)
				}
				return result
			}
		}
	}

	// Parse account URL
	accountURL, err := url.Parse(req.AccountURL)
	if err != nil {
		result.Error = fmt.Errorf("invalid account URL %s: %w", req.AccountURL, err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Generate proof using the core verifier
	verificationResult, err := b.verifier.VerifyAccount(ctx, accountURL)
	if err != nil {
		result.Error = fmt.Errorf("verification failed for %s: %w", req.AccountURL, err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Build CompleteProof from verification result
	proof, err := b.buildCompleteProof(verificationResult)
	if err != nil {
		result.Error = fmt.Errorf("failed to build proof for %s: %w", req.AccountURL, err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Store in cache if strategy allows and we have cache
	if b.cache != nil && (req.Strategy == interfaces.StrategyOptimized || req.Strategy == interfaces.StrategyComplete) {
		if err := b.cache.StoreAccountProof(req.AccountURL, proof); err != nil && b.debug {
			fmt.Printf("Warning: failed to cache proof for %s: %v\n", req.AccountURL, err)
		}
	}

	result.Proof = proof
	result.Duration = time.Since(startTime)

	if b.debug {
		fmt.Printf("Generated proof for %s (took %v)\n", req.AccountURL, result.Duration)
	}

	return result
}

// buildCompleteProof converts VerificationResult to CompleteProof
func (b *BatchProofGenerator) buildCompleteProof(verificationResult *core.VerificationResult) (*interfaces.CompleteProof, error) {
	if verificationResult == nil {
		return nil, fmt.Errorf("verification result is nil")
	}

	proof := &interfaces.CompleteProof{
		GeneratedAt: time.Now(),
		Strategy:    interfaces.StrategyOptimized,
		TrustLevel:  verificationResult.TrustLevel,
	}

	// Extract Layer 1 data
	if verificationResult.Layer1Result != nil {
		l1 := verificationResult.Layer1Result
		if l1.AccountHash != "" {
			if hash, err := b.parseHexToBytes(l1.AccountHash); err == nil {
				proof.AccountHash = hash
			}
		}
		if l1.BPTRoot != "" {
			if root, err := b.parseHexToBytes(l1.BPTRoot); err == nil {
				proof.BPTRoot = root
			}
		}
	}

	// Extract Layer 2 data
	if verificationResult.Layer2Result != nil {
		l2 := verificationResult.Layer2Result
		proof.BlockHeight = uint64(l2.BlockHeight)
		if l2.BlockHash != "" {
			if hash, err := b.parseHexToBytes(l2.BlockHash); err == nil {
				proof.BlockHash = hash
			}
		}
	}

	// Extract Layer 3 data
	if verificationResult.Layer3Result != nil {
		l3 := verificationResult.Layer3Result
		if l3.Verified && !l3.APILimitation {
			// Build consensus proof
			validatorProof := &interfaces.ConsensusProof{
				BlockHeight: uint64(l3.BlockHeight),
				ChainID:     l3.ChainID,
				Round:       l3.Round,
				TotalPower:  l3.TotalPower,
				SignedPower: l3.SignedPower,
				Timestamp:   time.Now(), // TODO: Use actual timestamp from Layer3
			}

			if len(proof.BlockHash) > 0 {
				validatorProof.BlockHash = make([]byte, len(proof.BlockHash))
				copy(validatorProof.BlockHash, proof.BlockHash)
			}

			// Convert validator signatures
			for _, valSig := range l3.ValidatorSignatures {
				if valSig.Verified {
					validatorInfo := interfaces.ValidatorInfo{
						VotingPower: valSig.VotingPower,
						Verified:    true,
					}

					// Decode address and public key
					if addr, err := b.parseHexToBytes(valSig.Address); err == nil {
						validatorInfo.Address = addr
					}
					if pubKey, err := b.parseBase64ToBytes(valSig.PubKey); err == nil {
						validatorInfo.PublicKey = pubKey
					}

					validatorProof.Validators = append(validatorProof.Validators, validatorInfo)

					// Add signature info
					signature := interfaces.ValidatorSignature{
						ValidatorAddress: validatorInfo.Address,
						Timestamp:        time.Now(), // TODO: Use actual timestamp
						Verified:         true,
					}
					validatorProof.Signatures = append(validatorProof.Signatures, signature)
				}
			}

			proof.ValidatorProof = validatorProof
		}
	}

	return proof, nil
}

// Helper methods

func (b *BatchProofGenerator) parseHexToBytes(hexStr string) ([]byte, error) {
	// Remove 0x prefix if present
	if len(hexStr) > 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	return []byte(hexStr), nil // Simplified for now
}

func (b *BatchProofGenerator) parseBase64ToBytes(b64Str string) ([]byte, error) {
	return []byte(b64Str), nil // Simplified for now
}

func (b *BatchProofGenerator) updateBatchMetrics(duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalBatches++

	// Update average time (simple moving average)
	if b.totalBatches == 1 {
		b.averageTime = duration
	} else {
		b.averageTime = time.Duration(
			(int64(b.averageTime)*int64(b.totalBatches-1) + int64(duration)) / int64(b.totalBatches),
		)
	}
}

func (b *BatchProofGenerator) logBatchResults(response *BatchProofResponse) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("Batch Proof Generation Results\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Requests: %d\n", len(response.Results))
	fmt.Printf("Successful: %d\n", response.SuccessCount)
	fmt.Printf("Failed: %d\n", response.ErrorCount)
	fmt.Printf("Total Duration: %v\n", response.TotalDuration)
	fmt.Printf("Average per Proof: %v\n", response.TotalDuration/time.Duration(len(response.Results)))
	fmt.Printf("Workers Used: %d\n", b.maxWorkers)
	fmt.Printf("========================================\n")

	// Log individual failures if debug is enabled
	for _, result := range response.Results {
		if result.Error != nil {
			fmt.Printf("❌ %s: %v (took %v)\n", result.AccountURL, result.Error, result.Duration)
		} else if b.debug {
			fmt.Printf("✅ %s: Success (took %v)\n", result.AccountURL, result.Duration)
		}
	}
	fmt.Printf("\n")
}

// SetDebug enables or disables debug logging
func (b *BatchProofGenerator) SetDebug(debug bool) {
	b.debug = debug
}

// GetMetrics returns batch generation metrics
func (b *BatchProofGenerator) GetMetrics() map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	return map[string]interface{}{
		"total_batches":   b.totalBatches,
		"total_proofs":    b.totalProofs,
		"total_errors":    b.totalErrors,
		"average_time":    b.averageTime.Seconds(),
		"max_workers":     b.maxWorkers,
		"max_batch_size":  b.maxBatchSize,
		"batch_timeout":   b.batchTimeout.Seconds(),
	}
}

// UpdateConfiguration updates batch generator configuration
func (b *BatchProofGenerator) UpdateConfiguration(maxWorkers, maxBatchSize int, batchTimeout time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if maxWorkers > 0 {
		b.maxWorkers = maxWorkers
	}
	if maxBatchSize > 0 {
		b.maxBatchSize = maxBatchSize
	}
	if batchTimeout > 0 {
		b.batchTimeout = batchTimeout
	}
}

// GetConfiguration returns current batch generator configuration
func (b *BatchProofGenerator) GetConfiguration() map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	return map[string]interface{}{
		"max_workers":     b.maxWorkers,
		"max_batch_size":  b.maxBatchSize,
		"batch_timeout":   b.batchTimeout.Seconds(),
		"debug_enabled":   b.debug,
	}
}