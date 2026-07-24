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

// UNITS — read this before changing any constant below.
//
// Accumulate stores credits at a precision of 1/100 credit (protocol.CreditPrecision
// = 100), and the protocol fee schedule is denominated in those same units. So:
//
//	1 credit        = 100 credit units = $0.01   (CreditsPerDollar = 100, dollar-pegged)
//	1 credit unit   = $0.0001
//
// The balance returned by LiteClientAdapter.GetCreditBalance is the raw
// `account.creditBalance` field — i.e. credit UNITS, not credits. Every constant and
// every estimate in this file is therefore in credit units so the comparison against
// that balance is apples-to-apples.
//
// Historically these constants were written as if they were whole credits and then
// compared against a unit-denominated balance, which over-estimated the cost of a
// WriteData by ~100x and drove the (equally over-sized) sponsored credit grants on the
// gateway side. The protocol-true values from protocol/fee_schedule.go are below.
const (
	// CreditUnitsPerCredit is the protocol's credit precision (protocol.CreditPrecision).
	CreditUnitsPerCredit uint64 = 100

	// FeeDataPerChunk is protocol FeeData: 10 credit units (= 0.1 credit = $0.001) per
	// 256-byte chunk of the transaction body.
	FeeDataPerChunk uint64 = 10

	// DataChunkBytes is the body size, in bytes, covered by one FeeDataPerChunk charge.
	DataChunkBytes int = 256

	// FeeSignature is protocol FeeSignature: 1 credit unit (= 0.01 credit) per signature.
	FeeSignature uint64 = 1

	// WriteDataBaseCost is the protocol-true cost of a minimal (<=256 B) WriteData plus
	// its signature: 10 + 1 = 11 credit units = 0.11 credit = $0.0011.
	WriteDataBaseCost uint64 = FeeDataPerChunk + FeeSignature

	// WriteDataPerChunkCost is the marginal cost of each additional 256-byte chunk.
	WriteDataPerChunkCost uint64 = FeeDataPerChunk

	// CreditSafetyMultiple pads every estimate to absorb body-size growth and the
	// WriteToState 2x multiplier. 10x of the true cost, not 1000x.
	CreditSafetyMultiple uint64 = 10

	// MinCreditsForWriteData is the pre-flight floor for submitting one WriteData:
	// 110 credit units = 1.1 credits = $0.011. Below this we refuse to submit rather
	// than have the transaction rejected on-chain.
	MinCreditsForWriteData uint64 = WriteDataBaseCost * CreditSafetyMultiple

	// MinCreditsLowThreshold triggers a top-up warning. 5,000 credit units = 50 credits
	// = $0.50, roughly 450 further write-backs of headroom.
	MinCreditsLowThreshold uint64 = 5000

	// DefaultACMEPriceUSD is the fallback ACME price used to convert a credit shortfall
	// into an ACME amount when no oracle price has been supplied. Credits are
	// dollar-pegged; only this conversion floats.
	DefaultACMEPriceUSD float64 = 0.03
)

// CreditUnitsToUSD converts credit units to dollars. Credits are dollar-pegged by
// protocol, so this is exact.
func CreditUnitsToUSD(units uint64) float64 {
	return float64(units) / float64(CreditUnitsPerCredit) / 100.0
}

// CreditUnitsToACME converts a credit-unit amount to the ACME needed to buy it at the
// given oracle price. Falls back to DefaultACMEPriceUSD when price <= 0.
func CreditUnitsToACME(units uint64, acmePriceUSD float64) float64 {
	if acmePriceUSD <= 0 {
		acmePriceUSD = DefaultACMEPriceUSD
	}
	return CreditUnitsToUSD(units) / acmePriceUSD
}

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

	// Cached credit balance, in credit units (1/100 credit) — see the UNITS note above.
	cachedBalance     uint64
	lastBalanceQuery  time.Time
	cacheValidDuration time.Duration

	// Oracle ACME price (USD) for credit->ACME conversion; 0 means use the default.
	acmePriceUSD float64

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

// EstimateTransactionCost estimates the credit-unit cost of a synthetic transaction.
//
// Protocol charges FeeDataPerChunk per 256-byte chunk of the body plus FeeSignature
// per signature — it is a function of SIZE, not of how many fields the entry happens
// to be split into. The entries are carried as hex, so raw body size is half the hex
// length.
func (c *CreditChecker) EstimateTransactionCost(tx *SyntheticTransaction) uint64 {
	if tx == nil || tx.Body == nil {
		return WriteDataBaseCost
	}

	hexBytes := 0
	for _, entry := range tx.Body.DataEntry.ToAccumulateFormat() {
		hexBytes += len(entry)
	}
	rawBytes := hexBytes / 2

	chunks := uint64(1)
	if rawBytes > DataChunkBytes {
		chunks = uint64((rawBytes + DataChunkBytes - 1) / DataChunkBytes)
	}

	return chunks*FeeDataPerChunk + FeeSignature
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

// EstimateCreditsNeeded estimates the credit units needed for N write-backs.
//
// avgChunksPerTx is the average number of 256-byte body chunks per transaction; pass 1
// for the typical CERTEN write-back, which fits in a single chunk.
func (c *CreditChecker) EstimateCreditsNeeded(txCount int, avgChunksPerTx int) *CreditPurchaseEstimate {
	c.mu.RLock()
	currentBalance := c.cachedBalance
	acmePrice := c.acmePriceUSD
	c.mu.RUnlock()

	if avgChunksPerTx < 1 {
		avgChunksPerTx = 1
	}
	if acmePrice <= 0 {
		acmePrice = DefaultACMEPriceUSD
	}

	perTxCost := uint64(avgChunksPerTx)*FeeDataPerChunk + FeeSignature
	requiredCredits := uint64(txCount) * perTxCost

	// Safety margin (10%) on top of the protocol-true cost.
	requiredCredits = requiredCredits * 110 / 100

	shortfall := uint64(0)
	if requiredCredits > currentBalance {
		shortfall = requiredCredits - currentBalance
	}

	return &CreditPurchaseEstimate{
		CurrentBalance:  currentBalance,
		RequiredCredits: requiredCredits,
		Shortfall:       shortfall,
		EstimatedACME:   CreditUnitsToACME(shortfall, acmePrice),
		OraclePrice:     acmePrice,
	}
}

// SetACMEPrice supplies the oracle ACME price (USD) used for credit->ACME conversion.
func (c *CreditChecker) SetACMEPrice(priceUSD float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acmePriceUSD = priceUSD
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
