// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package cache provides high-performance caching for proof components
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/interfaces"
)

// MemoryProofCache implements ProofCache using in-memory storage with LRU eviction
type MemoryProofCache struct {
	mu              sync.RWMutex
	accountProofs   map[string]*CachedAccountProof
	bptProofs       map[string]*CachedBPTProof
	receipts        map[string]*CachedReceipt
	maxSize         int
	ttl             time.Duration

	// Access tracking for LRU
	accessTimes     map[string]time.Time

	// Metrics
	metrics         *interfaces.ProofCacheMetrics
	totalHits       int64
	totalMisses     int64
	totalEvictions  int64
	lastCleanup     time.Time
}

// CachedAccountProof wraps a CompleteProof with cache metadata
type CachedAccountProof struct {
	Proof     *interfaces.CompleteProof
	CachedAt  time.Time
	AccessAt  time.Time
	HitCount  int64
	Size      int64
}

// CachedBPTProof wraps a BPTProof with cache metadata
type CachedBPTProof struct {
	Proof     *interfaces.BPTProof
	CachedAt  time.Time
	AccessAt  time.Time
	HitCount  int64
	Size      int64
}

// CachedReceipt wraps a merkle.Receipt with cache metadata
type CachedReceipt struct {
	Receipt   *merkle.Receipt
	CachedAt  time.Time
	AccessAt  time.Time
	HitCount  int64
	Size      int64
}

// NewMemoryProofCache creates a new in-memory proof cache
func NewMemoryProofCache(maxSize int, ttl time.Duration) *MemoryProofCache {
	cache := &MemoryProofCache{
		accountProofs: make(map[string]*CachedAccountProof),
		bptProofs:     make(map[string]*CachedBPTProof),
		receipts:      make(map[string]*CachedReceipt),
		accessTimes:   make(map[string]time.Time),
		maxSize:       maxSize,
		ttl:           ttl,
		lastCleanup:   time.Now(),
		metrics: &interfaces.ProofCacheMetrics{
			LastCleanupTime: time.Now(),
		},
	}

	// Start background cleanup goroutine
	go cache.cleanupRoutine()

	return cache
}

// StoreAccountProof stores a complete proof in the cache
func (c *MemoryProofCache) StoreAccountProof(accountURL string, proof *interfaces.CompleteProof) error {
	if proof == nil {
		return fmt.Errorf("cannot store nil proof")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.accountProofKey(accountURL)
	size := c.estimateProofSize(proof)

	// Check if we need to evict old entries
	c.evictIfNecessary()

	cached := &CachedAccountProof{
		Proof:     proof,
		CachedAt:  time.Now(),
		AccessAt:  time.Now(),
		HitCount:  0,
		Size:      size,
	}

	c.accountProofs[key] = cached
	c.accessTimes[key] = time.Now()
	c.updateMetrics()

	return nil
}

// GetAccountProof retrieves a complete proof from the cache
func (c *MemoryProofCache) GetAccountProof(accountURL string) (*interfaces.CompleteProof, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.accountProofKey(accountURL)
	cached, exists := c.accountProofs[key]

	if !exists {
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	// Check if entry is expired
	if time.Since(cached.CachedAt) > c.ttl {
		delete(c.accountProofs, key)
		delete(c.accessTimes, key)
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	// Update access information
	cached.AccessAt = time.Now()
	cached.HitCount++
	c.accessTimes[key] = time.Now()
	c.totalHits++
	c.updateMetrics()

	return cached.Proof, true
}

// StoreBPTProof stores a BPT proof in the cache
func (c *MemoryProofCache) StoreBPTProof(partition string, hash []byte, proof *interfaces.BPTProof) error {
	if proof == nil {
		return fmt.Errorf("cannot store nil BPT proof")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.bptProofKey(partition, hash)
	size := c.estimateBPTProofSize(proof)

	c.evictIfNecessary()

	cached := &CachedBPTProof{
		Proof:     proof,
		CachedAt:  time.Now(),
		AccessAt:  time.Now(),
		HitCount:  0,
		Size:      size,
	}

	c.bptProofs[key] = cached
	c.accessTimes[key] = time.Now()
	c.updateMetrics()

	return nil
}

// GetBPTProof retrieves a BPT proof from the cache
func (c *MemoryProofCache) GetBPTProof(partition string, hash []byte) (*interfaces.BPTProof, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.bptProofKey(partition, hash)
	cached, exists := c.bptProofs[key]

	if !exists {
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	if time.Since(cached.CachedAt) > c.ttl {
		delete(c.bptProofs, key)
		delete(c.accessTimes, key)
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	cached.AccessAt = time.Now()
	cached.HitCount++
	c.accessTimes[key] = time.Now()
	c.totalHits++
	c.updateMetrics()

	return cached.Proof, true
}

// StoreReceipt stores a merkle receipt in the cache
func (c *MemoryProofCache) StoreReceipt(key []byte, receipt *merkle.Receipt) error {
	if receipt == nil {
		return fmt.Errorf("cannot store nil receipt")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := c.receiptKey(key)
	size := c.estimateReceiptSize(receipt)

	c.evictIfNecessary()

	cached := &CachedReceipt{
		Receipt:  receipt,
		CachedAt: time.Now(),
		AccessAt: time.Now(),
		HitCount: 0,
		Size:     size,
	}

	c.receipts[keyStr] = cached
	c.accessTimes[keyStr] = time.Now()
	c.updateMetrics()

	return nil
}

// GetReceipt retrieves a merkle receipt from the cache
func (c *MemoryProofCache) GetReceipt(key []byte) (*merkle.Receipt, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := c.receiptKey(key)
	cached, exists := c.receipts[keyStr]

	if !exists {
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	if time.Since(cached.CachedAt) > c.ttl {
		delete(c.receipts, keyStr)
		delete(c.accessTimes, keyStr)
		c.totalMisses++
		c.updateMetrics()
		return nil, false
	}

	cached.AccessAt = time.Now()
	cached.HitCount++
	c.accessTimes[keyStr] = time.Now()
	c.totalHits++
	c.updateMetrics()

	return cached.Receipt, true
}

// InvalidateAccountProof removes an account proof from the cache
func (c *MemoryProofCache) InvalidateAccountProof(accountURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.accountProofKey(accountURL)
	delete(c.accountProofs, key)
	delete(c.accessTimes, key)
	c.updateMetrics()

	return nil
}

// ClearProofCache clears all cached proofs
func (c *MemoryProofCache) ClearProofCache() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.accountProofs = make(map[string]*CachedAccountProof)
	c.bptProofs = make(map[string]*CachedBPTProof)
	c.receipts = make(map[string]*CachedReceipt)
	c.accessTimes = make(map[string]time.Time)
	c.totalHits = 0
	c.totalMisses = 0
	c.totalEvictions = 0
	c.updateMetrics()

	return nil
}

// GetProofCacheMetrics returns current cache metrics
func (c *MemoryProofCache) GetProofCacheMetrics() *interfaces.ProofCacheMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Calculate current metrics
	totalRequests := c.totalHits + c.totalMisses
	hitRate := float64(0)
	if totalRequests > 0 {
		hitRate = float64(c.totalHits) / float64(totalRequests)
	}

	totalSize := int64(0)
	totalEntries := len(c.accountProofs) + len(c.bptProofs) + len(c.receipts)

	for _, cached := range c.accountProofs {
		totalSize += cached.Size
	}
	for _, cached := range c.bptProofs {
		totalSize += cached.Size
	}
	for _, cached := range c.receipts {
		totalSize += cached.Size
	}

	return &interfaces.ProofCacheMetrics{
		TotalEntries:    totalEntries,
		AccountProofs:   len(c.accountProofs),
		BPTProofs:       len(c.bptProofs),
		Receipts:        len(c.receipts),
		HitRate:         hitRate,
		MissRate:        1.0 - hitRate,
		EvictionCount:   c.totalEvictions,
		CacheSize:       totalSize,
		MaxCacheSize:    int64(c.maxSize * 1024 * 1024), // Assume maxSize is in MB
		LastCleanupTime: c.lastCleanup,
	}
}

// Helper methods

func (c *MemoryProofCache) accountProofKey(accountURL string) string {
	hash := sha256.Sum256([]byte("account:" + accountURL))
	return hex.EncodeToString(hash[:])
}

func (c *MemoryProofCache) bptProofKey(partition string, hash []byte) string {
	data := fmt.Sprintf("bpt:%s:%x", partition, hash)
	hashSum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hashSum[:])
}

func (c *MemoryProofCache) receiptKey(key []byte) string {
	hash := sha256.Sum256(append([]byte("receipt:"), key...))
	return hex.EncodeToString(hash[:])
}

func (c *MemoryProofCache) estimateProofSize(proof *interfaces.CompleteProof) int64 {
	// Rough estimation of proof size in bytes
	size := int64(0)

	size += int64(len(proof.AccountHash))
	size += int64(len(proof.BPTRoot))
	size += int64(len(proof.BlockHash))

	if proof.ValidatorProof != nil {
		size += int64(len(proof.ValidatorProof.BlockHash))
		size += int64(len(proof.ValidatorProof.ChainID))
		size += int64(len(proof.ValidatorProof.Validators) * 100) // Estimate per validator
		size += int64(len(proof.ValidatorProof.Signatures) * 100) // Estimate per signature
	}

	// Add estimated overhead
	size += 1024

	return size
}

func (c *MemoryProofCache) estimateBPTProofSize(proof *interfaces.BPTProof) int64 {
	size := int64(0)
	size += int64(len(proof.AccountHash))
	size += int64(len(proof.BPTRoot))
	size += int64(len(proof.Partition))

	if proof.Proof != nil {
		size += 512 // Estimate for merkle receipt
	}

	return size + 256 // Overhead
}

func (c *MemoryProofCache) estimateReceiptSize(receipt *merkle.Receipt) int64 {
	if receipt == nil {
		return 0
	}

	size := int64(0)
	size += int64(len(receipt.Start))
	size += int64(len(receipt.Anchor))

	// Estimate entries size
	if len(receipt.Entries) > 0 {
		size += int64(len(receipt.Entries) * 50) // Estimate per entry
	}

	return size + 128 // Overhead
}

func (c *MemoryProofCache) evictIfNecessary() {
	totalEntries := len(c.accountProofs) + len(c.bptProofs) + len(c.receipts)

	if totalEntries >= c.maxSize {
		// Find oldest entry to evict
		oldestTime := time.Now()
		oldestKey := ""

		for key, accessTime := range c.accessTimes {
			if accessTime.Before(oldestTime) {
				oldestTime = accessTime
				oldestKey = key
			}
		}

		if oldestKey != "" {
			// Remove from all possible maps
			delete(c.accountProofs, oldestKey)
			delete(c.bptProofs, oldestKey)
			delete(c.receipts, oldestKey)
			delete(c.accessTimes, oldestKey)
			c.totalEvictions++
		}
	}
}

func (c *MemoryProofCache) updateMetrics() {
	// Update internal metrics state
	c.metrics.TotalEntries = len(c.accountProofs) + len(c.bptProofs) + len(c.receipts)
	c.metrics.AccountProofs = len(c.accountProofs)
	c.metrics.BPTProofs = len(c.bptProofs)
	c.metrics.Receipts = len(c.receipts)
	c.metrics.EvictionCount = c.totalEvictions

	totalRequests := c.totalHits + c.totalMisses
	if totalRequests > 0 {
		c.metrics.HitRate = float64(c.totalHits) / float64(totalRequests)
		c.metrics.MissRate = float64(c.totalMisses) / float64(totalRequests)
	}
}

func (c *MemoryProofCache) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpiredEntries()
	}
}

func (c *MemoryProofCache) cleanupExpiredEntries() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Clean up expired account proofs
	for key, cached := range c.accountProofs {
		if now.Sub(cached.CachedAt) > c.ttl {
			delete(c.accountProofs, key)
			delete(c.accessTimes, key)
		}
	}

	// Clean up expired BPT proofs
	for key, cached := range c.bptProofs {
		if now.Sub(cached.CachedAt) > c.ttl {
			delete(c.bptProofs, key)
			delete(c.accessTimes, key)
		}
	}

	// Clean up expired receipts
	for key, cached := range c.receipts {
		if now.Sub(cached.CachedAt) > c.ttl {
			delete(c.receipts, key)
			delete(c.accessTimes, key)
		}
	}

	c.lastCleanup = now
	c.updateMetrics()
}

// SetTTL updates the cache TTL
func (c *MemoryProofCache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// SetMaxSize updates the maximum cache size
func (c *MemoryProofCache) SetMaxSize(maxSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxSize = maxSize
}

// GetCacheStats returns detailed cache statistics
func (c *MemoryProofCache) GetCacheStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"total_entries":     len(c.accountProofs) + len(c.bptProofs) + len(c.receipts),
		"account_proofs":    len(c.accountProofs),
		"bpt_proofs":        len(c.bptProofs),
		"receipts":          len(c.receipts),
		"total_hits":        c.totalHits,
		"total_misses":      c.totalMisses,
		"total_evictions":   c.totalEvictions,
		"hit_rate":          c.metrics.HitRate,
		"last_cleanup":      c.lastCleanup,
		"ttl_seconds":       c.ttl.Seconds(),
		"max_size":          c.maxSize,
	}
}