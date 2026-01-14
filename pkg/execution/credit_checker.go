// Copyright 2025 Certen Protocol
//
// Credit Checker - Fee Management for Accumulate Transactions
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
//
// This module manages credit checking for Accumulate transactions.
// Accumulate uses a credit-based fee system where credits are purchased
// with ACME tokens and consumed when submitting transactions.

package execution

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// =============================================================================
// CREDIT CONSTANTS
// =============================================================================

const (
	// MinCreditsForWriteData is the minimum credits needed for a WriteData transaction
	// WriteData costs approximately 100 credits per entry
	MinCreditsForWriteData uint64 = 1000

	// MinCreditsLowThreshold triggers a warning when credits fall below this level
	MinCreditsLowThreshold uint64 = 5000

	// CreditsPerACME is the approximate conversion rate (varies by oracle)
	CreditsPerACME uint64 = 100000

	// WriteDataBaseCost is the base cost for a WriteData transaction
	WriteDataBaseCost uint64 = 100

	// WriteDataPerEntryCost is the cost per data entry field
	WriteDataPerEntryCost uint64 = 10
)

// =============================================================================
// CREDIT CHECKER
// =============================================================================

// CreditChecker manages credit balance checking for Accumulate accounts
type CreditChecker struct {
	mu sync.RWMutex

	// Signer URL to check credits for
	signerURL string

	// Accumulate client for querying credits
	client *accumulate.LiteClientAdapter

	// Cached credit balance
	cachedBalance     uint64
	lastBalanceQuery  time.Time
	cacheValidDuration time.Duration

	// Low credit callback
	onLowCredits func(balance uint64)

	// Logging
	logger *log.Logger
}

// CreditCheckerConfig contains configuration for CreditChecker
type CreditCheckerConfig struct {
	SignerURL          string
	Client             *accumulate.LiteClientAdapter
	CacheValidDuration time.Duration
	OnLowCredits       func(balance uint64)
	Logger             *log.Logger
}

// NewCreditChecker creates a new credit checker
func NewCreditChecker(signerURL string, client *accumulate.LiteClientAdapter, logger *log.Logger) *CreditChecker {
	if logger == nil {
		logger = log.New(log.Writer(), "[CreditChecker] ", log.LstdFlags)
	}

	return &CreditChecker{
		signerURL:          signerURL,
		client:             client,
		cacheValidDuration: 30 * time.Second,
		logger:             logger,
	}
}

// NewCreditCheckerWithConfig creates a credit checker with custom configuration
func NewCreditCheckerWithConfig(cfg *CreditCheckerConfig) *CreditChecker {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[CreditChecker] ", log.LstdFlags)
	}

	cacheValid := cfg.CacheValidDuration
	if cacheValid == 0 {
		cacheValid = 30 * time.Second
	}

	return &CreditChecker{
		signerURL:          cfg.SignerURL,
		client:             cfg.Client,
		cacheValidDuration: cacheValid,
		onLowCredits:       cfg.OnLowCredits,
		logger:             logger,
	}
}

// HasSufficientCredits checks if the account has enough credits for a transaction
func (c *CreditChecker) HasSufficientCredits(ctx context.Context, requiredCredits uint64) (bool, uint64, error) {
	balance, err := c.GetCreditBalance(ctx)
	if err != nil {
		return false, 0, err
	}

	hasSufficient := balance >= requiredCredits

	// Check for low credits warning
	if balance < MinCreditsLowThreshold && c.onLowCredits != nil {
		go c.onLowCredits(balance)
	}

	return hasSufficient, balance, nil
}

// GetCreditBalance returns the current credit balance
func (c *CreditChecker) GetCreditBalance(ctx context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached value if still valid
	if time.Since(c.lastBalanceQuery) < c.cacheValidDuration {
		return c.cachedBalance, nil
	}

	// Query fresh balance from Accumulate
	c.logger.Printf("🔄 Querying credit balance for: %s", c.signerURL)

	balance, err := c.client.GetCreditBalance(ctx, c.signerURL)
	if err != nil {
		return 0, fmt.Errorf("failed to query credits: %w", err)
	}

	c.cachedBalance = balance
	c.lastBalanceQuery = time.Now()
	c.logger.Printf("💰 Credit balance: %d", balance)

	// Check for low credits
	if balance < MinCreditsLowThreshold {
		c.logger.Printf("⚠️ Low credits warning: %d (threshold: %d)", balance, MinCreditsLowThreshold)
	}

	return balance, nil
}

// EstimateTransactionCost estimates the credit cost for a synthetic transaction
func (c *CreditChecker) EstimateTransactionCost(tx *SyntheticTransaction) uint64 {
	if tx == nil || tx.Body == nil {
		return WriteDataBaseCost
	}

	// Base cost
	cost := WriteDataBaseCost

	// Add per-entry cost
	entryCount := len(tx.Body.DataEntry.ToAccumulateFormat())
	cost += uint64(entryCount) * WriteDataPerEntryCost

	return cost
}

// SetOnLowCredits sets the callback for low credits warning
func (c *CreditChecker) SetOnLowCredits(callback func(balance uint64)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onLowCredits = callback
}

// InvalidateCache forces a refresh on the next query
func (c *CreditChecker) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBalanceQuery = time.Time{}
}

// ForceRefresh immediately refreshes the credit balance
func (c *CreditChecker) ForceRefresh(ctx context.Context) (uint64, error) {
	c.InvalidateCache()
	return c.GetCreditBalance(ctx)
}

// =============================================================================
// CREDIT PURCHASE HELPER
// =============================================================================

// CreditPurchaseEstimate provides information about purchasing credits
type CreditPurchaseEstimate struct {
	CurrentBalance  uint64  `json:"current_balance"`
	RequiredCredits uint64  `json:"required_credits"`
	Shortfall       uint64  `json:"shortfall"`
	EstimatedACME   float64 `json:"estimated_acme"`
	OraclePrice     float64 `json:"oracle_price"`
}

// EstimateCreditsNeeded estimates how many credits are needed for N transactions
func (c *CreditChecker) EstimateCreditsNeeded(txCount int, avgEntriesPerTx int) *CreditPurchaseEstimate {
	c.mu.RLock()
	currentBalance := c.cachedBalance
	c.mu.RUnlock()

	// Calculate required credits
	perTxCost := WriteDataBaseCost + uint64(avgEntriesPerTx)*WriteDataPerEntryCost
	requiredCredits := uint64(txCount) * perTxCost

	// Add safety margin (10%)
	requiredCredits = requiredCredits * 110 / 100

	shortfall := uint64(0)
	if requiredCredits > currentBalance {
		shortfall = requiredCredits - currentBalance
	}

	return &CreditPurchaseEstimate{
		CurrentBalance:  currentBalance,
		RequiredCredits: requiredCredits,
		Shortfall:       shortfall,
		EstimatedACME:   float64(shortfall) / float64(CreditsPerACME),
		OraclePrice:     0.0, // Would need oracle query
	}
}

// =============================================================================
// CREDIT MONITOR
// =============================================================================

// CreditMonitor monitors credit balance and alerts when low
type CreditMonitor struct {
	checker       *CreditChecker
	checkInterval time.Duration
	stopChan      chan struct{}
	logger        *log.Logger
}

// NewCreditMonitor creates a background credit monitor
func NewCreditMonitor(checker *CreditChecker, checkInterval time.Duration, logger *log.Logger) *CreditMonitor {
	if logger == nil {
		logger = log.New(log.Writer(), "[CreditMonitor] ", log.LstdFlags)
	}
	if checkInterval == 0 {
		checkInterval = 5 * time.Minute
	}

	return &CreditMonitor{
		checker:       checker,
		checkInterval: checkInterval,
		stopChan:      make(chan struct{}),
		logger:        logger,
	}
}

// Start begins the credit monitoring loop
func (m *CreditMonitor) Start(ctx context.Context) {
	m.logger.Printf("🚀 Credit monitor started (interval: %s)", m.checkInterval)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Printf("🛑 Credit monitor stopped (context cancelled)")
			return
		case <-m.stopChan:
			m.logger.Printf("🛑 Credit monitor stopped")
			return
		case <-ticker.C:
			balance, err := m.checker.ForceRefresh(ctx)
			if err != nil {
				m.logger.Printf("⚠️ Failed to refresh credits: %v", err)
				continue
			}

			if balance < MinCreditsLowThreshold {
				m.logger.Printf("⚠️ LOW CREDITS ALERT: %d credits remaining", balance)
			} else if balance < MinCreditsForWriteData {
				m.logger.Printf("🚨 CRITICAL: Insufficient credits for transactions: %d", balance)
			}
		}
	}
}

// Stop stops the credit monitor
func (m *CreditMonitor) Stop() {
	close(m.stopChan)
}
