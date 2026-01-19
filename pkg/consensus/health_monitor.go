// Copyright 2025 Certen Protocol
//
// Consensus Health Monitor - Detects stalls and alerts
// Per BFT Resiliency Task 1: Automatic Health Monitoring & Recovery

package consensus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

var (
	// ErrConsensusStalled indicates consensus has not progressed
	ErrConsensusStalled = errors.New("consensus stalled: no new blocks")
	// ErrInsufficientPeers indicates not enough connected peers
	ErrInsufficientPeers = errors.New("insufficient connected peers")
	// ErrHeightMismatch indicates app height doesn't match CometBFT
	ErrHeightMismatch = errors.New("height mismatch between app and CometBFT")
)

// ConsensusHealthMonitor monitors the health of the CometBFT consensus
type ConsensusHealthMonitor struct {
	mu sync.RWMutex

	// Block tracking
	lastBlockHeight int64
	lastBlockTime   time.Time

	// Configuration
	stallThreshold     time.Duration // Alert if no block for this duration
	minPeers           int           // Minimum required peers
	checkInterval      time.Duration // How often to check health

	// Status tracking
	isStalled          bool
	stallStartTime     time.Time
	consecutiveStalls  int
	lastCheckTime      time.Time
	connectedPeers     int

	// Callbacks
	onStallDetected    func(height int64, stallDuration time.Duration)
	onRecovery         func(height int64)
	onPeerCountLow     func(count int)

	// CometBFT status fetcher (injected)
	statusFetcher      StatusFetcher

	// Logger
	logger             *log.Logger

	// Control
	ctx                context.Context
	cancel             context.CancelFunc
	running            bool
}

// StatusFetcher interface for getting CometBFT status
type StatusFetcher interface {
	GetStatus(ctx context.Context) (*ConsensusStatus, error)
}

// ConsensusStatus represents the current consensus state
type ConsensusStatus struct {
	LatestBlockHeight int64
	LatestBlockTime   time.Time
	CatchingUp        bool
	NumPeers          int
	VotingPower       int64
}

// HealthMonitorConfig configures the health monitor
type HealthMonitorConfig struct {
	StallThreshold  time.Duration // Default: 2 minutes
	MinPeers        int           // Default: 2
	CheckInterval   time.Duration // Default: 10 seconds
}

// DefaultHealthMonitorConfig returns default configuration
func DefaultHealthMonitorConfig() HealthMonitorConfig {
	return HealthMonitorConfig{
		StallThreshold:  2 * time.Minute,
		MinPeers:        2,
		CheckInterval:   10 * time.Second,
	}
}

// NewConsensusHealthMonitor creates a new health monitor
func NewConsensusHealthMonitor(cfg HealthMonitorConfig, fetcher StatusFetcher) *ConsensusHealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &ConsensusHealthMonitor{
		stallThreshold:   cfg.StallThreshold,
		minPeers:         cfg.MinPeers,
		checkInterval:    cfg.CheckInterval,
		statusFetcher:    fetcher,
		logger:           log.New(log.Writer(), "[HealthMonitor] ", log.LstdFlags),
		ctx:              ctx,
		cancel:           cancel,
	}
}

// SetOnStallDetected sets callback for stall detection
func (m *ConsensusHealthMonitor) SetOnStallDetected(fn func(height int64, stallDuration time.Duration)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStallDetected = fn
}

// SetOnRecovery sets callback for recovery from stall
func (m *ConsensusHealthMonitor) SetOnRecovery(fn func(height int64)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRecovery = fn
}

// SetOnPeerCountLow sets callback for low peer count
func (m *ConsensusHealthMonitor) SetOnPeerCountLow(fn func(count int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPeerCountLow = fn
}

// Start begins the health monitoring loop
func (m *ConsensusHealthMonitor) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("health monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Printf("🏥 Starting consensus health monitor (stall threshold: %v, min peers: %d)",
		m.stallThreshold, m.minPeers)

	go m.monitorLoop()
	return nil
}

// Stop halts the health monitoring
func (m *ConsensusHealthMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	m.logger.Printf("🛑 Stopping consensus health monitor")
	m.cancel()
	m.running = false
}

// Check performs a single health check and returns any issues
func (m *ConsensusHealthMonitor) Check() error {
	if m.statusFetcher == nil {
		return fmt.Errorf("status fetcher not configured")
	}

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	status, err := m.statusFetcher.GetStatus(ctx)
	if err != nil {
		m.logger.Printf("⚠️ Failed to get consensus status: %v", err)
		return fmt.Errorf("failed to get consensus status: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.lastCheckTime = now
	m.connectedPeers = status.NumPeers

	// Check for stall
	if status.LatestBlockHeight == m.lastBlockHeight {
		// Height hasn't changed
		stallDuration := now.Sub(m.lastBlockTime)

		if stallDuration > m.stallThreshold {
			if !m.isStalled {
				// Just became stalled
				m.isStalled = true
				m.stallStartTime = m.lastBlockTime
				m.consecutiveStalls++

				m.logger.Printf("🚨 CONSENSUS STALLED! Height=%d, Duration=%v, Consecutive=%d",
					m.lastBlockHeight, stallDuration, m.consecutiveStalls)

				if m.onStallDetected != nil {
					go m.onStallDetected(m.lastBlockHeight, stallDuration)
				}
			}
			return ErrConsensusStalled
		}
	} else {
		// Block height increased
		wasStalled := m.isStalled

		m.lastBlockHeight = status.LatestBlockHeight
		m.lastBlockTime = now
		m.isStalled = false

		if wasStalled {
			m.logger.Printf("✅ Consensus recovered! New height=%d", status.LatestBlockHeight)
			if m.onRecovery != nil {
				go m.onRecovery(status.LatestBlockHeight)
			}
		}
	}

	// Check peer count
	if status.NumPeers < m.minPeers {
		m.logger.Printf("⚠️ Low peer count: %d (minimum: %d)", status.NumPeers, m.minPeers)
		if m.onPeerCountLow != nil {
			go m.onPeerCountLow(status.NumPeers)
		}
		return ErrInsufficientPeers
	}

	return nil
}

// monitorLoop runs the periodic health check
func (m *ConsensusHealthMonitor) monitorLoop() {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	// Initial check
	if err := m.Check(); err != nil {
		m.logger.Printf("⚠️ Initial health check: %v", err)
	}

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.Check(); err != nil {
				// Error already logged in Check()
			}
		}
	}
}

// GetHealthStatus returns the current health status
func (m *ConsensusHealthMonitor) GetHealthStatus() *HealthStatusReport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := "healthy"
	if m.isStalled {
		status = "stalled"
	} else if m.connectedPeers < m.minPeers {
		status = "degraded"
	}

	var stallDuration time.Duration
	if m.isStalled {
		stallDuration = time.Since(m.stallStartTime)
	}

	return &HealthStatusReport{
		Status:            status,
		LastBlockHeight:   m.lastBlockHeight,
		LastBlockTime:     m.lastBlockTime,
		IsStalled:         m.isStalled,
		StallDuration:     stallDuration,
		ConsecutiveStalls: m.consecutiveStalls,
		ConnectedPeers:    m.connectedPeers,
		MinPeers:          m.minPeers,
		LastCheckTime:     m.lastCheckTime,
	}
}

// HealthStatusReport contains the current health status
type HealthStatusReport struct {
	Status            string        `json:"status"`
	LastBlockHeight   int64         `json:"last_block_height"`
	LastBlockTime     time.Time     `json:"last_block_time"`
	IsStalled         bool          `json:"is_stalled"`
	StallDuration     time.Duration `json:"stall_duration_ns"`
	ConsecutiveStalls int           `json:"consecutive_stalls"`
	ConnectedPeers    int           `json:"connected_peers"`
	MinPeers          int           `json:"min_peers"`
	LastCheckTime     time.Time     `json:"last_check_time"`
}

// ResetStallCounter resets the consecutive stall counter (call after manual intervention)
func (m *ConsensusHealthMonitor) ResetStallCounter() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveStalls = 0
	m.logger.Printf("🔄 Stall counter reset")
}
