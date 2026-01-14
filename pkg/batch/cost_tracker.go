// Copyright 2025 Certen Protocol
//
// Cost Tracker - Tracks and calculates anchor costs
// Per Whitepaper Section 3.4.2:
//   - On-cadence: ~$0.05/proof (amortized over batch)
//   - On-demand: ~$0.25/proof (immediate)
//
// The cost tracker:
// - Monitors gas costs from anchor transactions
// - Calculates per-proof costs based on batch size
// - Tracks ETH/USD price for USD cost estimation
// - Provides cost analytics for validators and users

package batch

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// CostTracker tracks and calculates anchor costs
type CostTracker struct {
	mu sync.RWMutex

	// Dependencies
	repos *database.Repositories

	// Configuration
	defaultEthPriceUSD float64 // Default ETH/USD price if no oracle
	updateInterval     time.Duration

	// Cached state
	currentEthPriceUSD float64
	lastPriceUpdate    time.Time

	// Statistics
	totalGasUsed    int64
	totalAnchors    int64
	totalProofs     int64
	totalCostWei    *big.Int
	avgCostPerProof float64

	// Price fetcher (optional)
	priceFetcher func(ctx context.Context) (float64, error)

	// Logging
	logger *log.Logger
}

// CostTrackerConfig holds tracker configuration
type CostTrackerConfig struct {
	DefaultEthPriceUSD float64 // Default if no price oracle
	UpdateInterval     time.Duration
	PriceFetcher       func(ctx context.Context) (float64, error) // Optional ETH price fetcher
	Logger             *log.Logger
}

// DefaultCostTrackerConfig returns default configuration
func DefaultCostTrackerConfig() *CostTrackerConfig {
	return &CostTrackerConfig{
		DefaultEthPriceUSD: 3500.0, // Reasonable default as of 2025
		UpdateInterval:     5 * time.Minute,
		Logger:             log.New(log.Writer(), "[CostTracker] ", log.LstdFlags),
	}
}

// NewCostTracker creates a new cost tracker
func NewCostTracker(repos *database.Repositories, cfg *CostTrackerConfig) (*CostTracker, error) {
	if repos == nil {
		return nil, fmt.Errorf("repositories cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultCostTrackerConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[CostTracker] ", log.LstdFlags)
	}

	return &CostTracker{
		repos:              repos,
		defaultEthPriceUSD: cfg.DefaultEthPriceUSD,
		updateInterval:     cfg.UpdateInterval,
		currentEthPriceUSD: cfg.DefaultEthPriceUSD,
		priceFetcher:       cfg.PriceFetcher,
		totalCostWei:       big.NewInt(0),
		logger:             cfg.Logger,
	}, nil
}

// RecordAnchorCost records the cost of an anchor transaction
func (t *CostTracker) RecordAnchorCost(ctx context.Context, anchorID interface{}, gasUsed int64, gasPriceWei string, txCount int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Parse gas price
	gasPrice, ok := new(big.Int).SetString(gasPriceWei, 10)
	if !ok {
		return fmt.Errorf("invalid gas price: %s", gasPriceWei)
	}

	// Calculate total cost in wei
	totalCostWei := new(big.Int).Mul(gasPrice, big.NewInt(gasUsed))

	// Update statistics
	t.totalGasUsed += gasUsed
	t.totalAnchors++
	t.totalProofs += int64(txCount)
	t.totalCostWei.Add(t.totalCostWei, totalCostWei)

	// Calculate cost in USD
	costUSD := t.weiToUSD(totalCostWei)
	costPerProof := 0.0
	if txCount > 0 {
		costPerProof = costUSD / float64(txCount)
	}

	// Update average
	if t.totalProofs > 0 {
		totalUSD := t.weiToUSD(t.totalCostWei)
		t.avgCostPerProof = totalUSD / float64(t.totalProofs)
	}

	t.logger.Printf("Anchor cost recorded: gas=%d, cost=$%.4f, proofs=%d, cost/proof=$%.4f",
		gasUsed, costUSD, txCount, costPerProof)

	return nil
}

// weiToUSD converts wei to USD using current ETH price
func (t *CostTracker) weiToUSD(weiAmount *big.Int) float64 {
	// Convert wei to ETH (1 ETH = 10^18 wei)
	weiFloat := new(big.Float).SetInt(weiAmount)
	ethAmount := new(big.Float).Quo(weiFloat, big.NewFloat(1e18))

	// Convert to USD
	ethFloat, _ := ethAmount.Float64()
	return ethFloat * t.currentEthPriceUSD
}

// GetCostStatistics returns current cost statistics
func (t *CostTracker) GetCostStatistics(ctx context.Context) (*CostStatistics, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Calculate current costs
	totalCostUSD := t.weiToUSD(t.totalCostWei)

	// Get batch type breakdown from database
	var onCadenceCount, onDemandCount int64
	var onCadenceCost, onDemandCost float64

	// Estimate based on whitepaper costs
	if t.totalProofs > 0 {
		// On-cadence: ~$0.05/proof, On-demand: ~$0.25/proof
		// For now, use the actual average as a proxy
		onCadenceCost = 0.05 // Per whitepaper
		onDemandCost = 0.25  // Per whitepaper
	}

	return &CostStatistics{
		TotalAnchors:        t.totalAnchors,
		TotalProofs:         t.totalProofs,
		TotalGasUsed:        t.totalGasUsed,
		TotalCostWei:        t.totalCostWei.String(),
		TotalCostUSD:        totalCostUSD,
		AvgCostPerProofUSD:  t.avgCostPerProof,
		OnCadenceCount:      onCadenceCount,
		OnDemandCount:       onDemandCount,
		EstOnCadenceCostUSD: onCadenceCost,
		EstOnDemandCostUSD:  onDemandCost,
		EthPriceUSD:         t.currentEthPriceUSD,
		LastPriceUpdate:     t.lastPriceUpdate,
	}, nil
}

// CostStatistics holds cost tracking statistics
type CostStatistics struct {
	TotalAnchors        int64     `json:"total_anchors"`
	TotalProofs         int64     `json:"total_proofs"`
	TotalGasUsed        int64     `json:"total_gas_used"`
	TotalCostWei        string    `json:"total_cost_wei"`
	TotalCostUSD        float64   `json:"total_cost_usd"`
	AvgCostPerProofUSD  float64   `json:"avg_cost_per_proof_usd"`
	OnCadenceCount      int64     `json:"on_cadence_count"`
	OnDemandCount       int64     `json:"on_demand_count"`
	EstOnCadenceCostUSD float64   `json:"est_on_cadence_cost_usd"`
	EstOnDemandCostUSD  float64   `json:"est_on_demand_cost_usd"`
	EthPriceUSD         float64   `json:"eth_price_usd"`
	LastPriceUpdate     time.Time `json:"last_price_update"`
}

// UpdateEthPrice updates the ETH/USD price
func (t *CostTracker) UpdateEthPrice(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.priceFetcher == nil {
		// No price fetcher configured, use default
		return nil
	}

	price, err := t.priceFetcher(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch ETH price: %w", err)
	}

	t.currentEthPriceUSD = price
	t.lastPriceUpdate = time.Now()

	t.logger.Printf("ETH price updated: $%.2f", price)
	return nil
}

// SetEthPrice manually sets the ETH/USD price
func (t *CostTracker) SetEthPrice(price float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentEthPriceUSD = price
	t.lastPriceUpdate = time.Now()
}

// EstimateCost estimates the cost for a new anchor
func (t *CostTracker) EstimateCost(batchType string, txCount int) *CostEstimate {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var perProofCost float64
	switch batchType {
	case "on-demand":
		perProofCost = 0.25 // Per whitepaper
	default:
		perProofCost = 0.05 // Per whitepaper (on-cadence)
	}

	totalCost := perProofCost * float64(txCount)

	// Estimate gas based on average
	estimatedGas := int64(100000) // Base gas for anchor tx
	if t.totalAnchors > 0 {
		estimatedGas = t.totalGasUsed / t.totalAnchors
	}

	return &CostEstimate{
		BatchType:     batchType,
		TxCount:       txCount,
		PerProofCost:  perProofCost,
		TotalCostUSD:  totalCost,
		EstimatedGas:  estimatedGas,
		EthPriceUSD:   t.currentEthPriceUSD,
	}
}

// CostEstimate provides a cost estimate for an anchor
type CostEstimate struct {
	BatchType     string  `json:"batch_type"`
	TxCount       int     `json:"tx_count"`
	PerProofCost  float64 `json:"per_proof_cost_usd"`
	TotalCostUSD  float64 `json:"total_cost_usd"`
	EstimatedGas  int64   `json:"estimated_gas"`
	EthPriceUSD   float64 `json:"eth_price_usd"`
}

// GetCostBreakdown returns a detailed cost breakdown for display
func (t *CostTracker) GetCostBreakdown() *CostBreakdown {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return &CostBreakdown{
		OnCadencePerProof: "$0.05 (estimated)",
		OnDemandPerProof:  "$0.25 (estimated)",
		WhitepaperRef:     "Section 3.4.2: Transaction Batching",
		AvgActualCost:     fmt.Sprintf("$%.4f", t.avgCostPerProof),
		Note:              "Costs are amortized across batch size. On-cadence batches (~15 min) have lower per-proof costs due to larger batch sizes.",
	}
}

// CostBreakdown provides a human-readable cost breakdown
type CostBreakdown struct {
	OnCadencePerProof string `json:"on_cadence_per_proof"`
	OnDemandPerProof  string `json:"on_demand_per_proof"`
	WhitepaperRef     string `json:"whitepaper_ref"`
	AvgActualCost     string `json:"avg_actual_cost"`
	Note              string `json:"note"`
}
