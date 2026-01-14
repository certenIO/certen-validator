// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package cache

import (
	"sync"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// CachedAccountData represents cached account data with metadata
type CachedAccountData struct {
	Data      *types.AccountData `json:"data"`
	CachedAt  time.Time          `json:"cachedAt"`
	ExpiresAt time.Time          `json:"expiresAt"`
	URL       string             `json:"url"`
}

// CachedBalance represents cached balance information
type CachedBalance struct {
	Data      *types.TokenBalanceInfo `json:"data"`
	CachedAt  time.Time               `json:"cachedAt"`
	ExpiresAt time.Time               `json:"expiresAt"`
	URL       string                  `json:"url"`
}

// CachedIdentityInfo represents cached identity information
type CachedIdentityInfo struct {
	Data      *types.IdentityInfo `json:"data"`
	CachedAt  time.Time           `json:"cachedAt"`
	ExpiresAt time.Time           `json:"expiresAt"`
	URL       string              `json:"url"`
}

// CachedDataAccountInfo represents cached data account information
type CachedDataAccountInfo struct {
	Data      *types.DataAccountInfo `json:"data"`
	CachedAt  time.Time              `json:"cachedAt"`
	ExpiresAt time.Time              `json:"expiresAt"`
	URL       string                 `json:"url"`
}

// CachedAccountSummary represents cached account summary
type CachedAccountSummary struct {
	Data      *types.AccountSummary `json:"data"`
	CachedAt  time.Time             `json:"cachedAt"`
	ExpiresAt time.Time             `json:"expiresAt"`
	URL       string                `json:"url"`
}

// AccountCache provides unified caching for all types of account data with LRU eviction.
// It supports caching individual accounts as well as account collections (ADIs).
// All cache operations are thread-safe and support TTL-based expiration with size limits.
type AccountCache struct {
	mu               sync.RWMutex
	accountData      map[string]*CachedAccountData
	balances         map[string]*CachedBalance
	identityInfo     map[string]*CachedIdentityInfo
	dataAccountInfo  map[string]*CachedDataAccountInfo
	accountSummaries map[string]*CachedAccountSummary
	defaultTTL       time.Duration

	// LRU management
	maxEntries  int            // Maximum total entries across all caches
	accessOrder []string       // LRU order: most recent at end
	metrics     *types.Metrics // Performance metrics
}

// NewAccountCache creates a new account cache with default TTL and LRU bounds.
// The cache supports all types of account data and automatically handles expiration and eviction.
func NewAccountCache(defaultTTL time.Duration) *AccountCache {
	if defaultTTL == 0 {
		defaultTTL = 5 * time.Minute // Default 5 minute TTL
	}

	return &AccountCache{
		accountData:      make(map[string]*CachedAccountData),
		balances:         make(map[string]*CachedBalance),
		identityInfo:     make(map[string]*CachedIdentityInfo),
		dataAccountInfo:  make(map[string]*CachedDataAccountInfo),
		accountSummaries: make(map[string]*CachedAccountSummary),
		defaultTTL:       defaultTTL,
		maxEntries:       1000, // Default max 1000 total entries
		accessOrder:      make([]string, 0, 1000),
		metrics:          types.NewMetrics(),
	}
}

// NewAccountCacheWithBounds creates a cache with custom size limits.
func NewAccountCacheWithBounds(defaultTTL time.Duration, maxEntries int) *AccountCache {
	cache := NewAccountCache(defaultTTL)
	cache.maxEntries = maxEntries
	cache.accessOrder = make([]string, 0, maxEntries)
	return cache
}

// LRU Management Methods
// These methods handle least-recently-used eviction to maintain cache bounds

// updateAccessOrder moves a URL to the end of the access order (most recent)
func (c *AccountCache) updateAccessOrder(url string) {
	// Remove from current position if exists
	for i, existing := range c.accessOrder {
		if existing == url {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}

	// Add to end (most recent)
	c.accessOrder = append(c.accessOrder, url)
}

// evictLRU removes the least recently used entries if we're over capacity
func (c *AccountCache) evictLRU() {
	totalEntries := len(c.accountData) + len(c.balances) + len(c.identityInfo) +
		len(c.dataAccountInfo) + len(c.accountSummaries)

	for totalEntries > c.maxEntries && len(c.accessOrder) > 0 {
		// Remove least recently used (first in order)
		lruURL := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]

		// Remove from all cache maps
		delete(c.accountData, lruURL)
		delete(c.balances, lruURL)
		delete(c.identityInfo, lruURL)
		delete(c.dataAccountInfo, lruURL)
		delete(c.accountSummaries, lruURL)

		c.metrics.RecordCacheEviction()
		totalEntries--
	}
}

// GetMetrics returns a copy of the current cache metrics
func (c *AccountCache) GetMetrics() *types.Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to avoid races
	metrics := *c.metrics
	return &metrics
}

// Account Data Caching Methods
// These methods handle caching of complete account information

// StoreAccountData stores account data in cache with optional custom TTL
func (c *AccountCache) StoreAccountData(url string, data *types.AccountData, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.defaultTTL
	if len(ttl) > 0 {
		expiry = ttl[0]
	}

	c.accountData[url] = &CachedAccountData{
		Data:      data,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		URL:       url,
	}

	// Update LRU order and evict if necessary
	c.updateAccessOrder(url)
	c.evictLRU()
}

// GetAccountData retrieves account data from cache
func (c *AccountCache) GetAccountData(url string) (*types.AccountData, bool) {
	c.mu.Lock() // Need write lock for LRU update
	defer c.mu.Unlock()

	cached, exists := c.accountData[url]
	if !exists || time.Now().After(cached.ExpiresAt) {
		c.metrics.RecordCacheMiss()
		return nil, false
	}

	// Update access order for LRU
	c.updateAccessOrder(url)
	c.metrics.RecordCacheHit()
	return cached.Data, true
}

// Balance Caching Methods
// These methods handle caching of account balance information

// StoreBalance stores balance information in cache with optional custom TTL
func (c *AccountCache) StoreBalance(url string, balance *types.TokenBalanceInfo, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.defaultTTL
	if len(ttl) > 0 {
		expiry = ttl[0]
	}

	c.balances[url] = &CachedBalance{
		Data:      balance,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		URL:       url,
	}
}

// GetBalance retrieves balance from cache
func (c *AccountCache) GetBalance(url string) (*types.TokenBalanceInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.balances[url]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.Data, true
}

// Identity Info Caching Methods
// These methods handle caching of account identity information

// StoreIdentityInfo stores identity information in cache with optional custom TTL
func (c *AccountCache) StoreIdentityInfo(url string, info *types.IdentityInfo, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.defaultTTL
	if len(ttl) > 0 {
		expiry = ttl[0]
	}

	c.identityInfo[url] = &CachedIdentityInfo{
		Data:      info,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		URL:       url,
	}
}

// GetIdentityInfo retrieves identity info from cache
func (c *AccountCache) GetIdentityInfo(url string) (*types.IdentityInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.identityInfo[url]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.Data, true
}

// Data Account Info Caching Methods
// These methods handle caching of data account specific information

// StoreDataAccountInfo stores data account information in cache with optional custom TTL
func (c *AccountCache) StoreDataAccountInfo(url string, info *types.DataAccountInfo, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.defaultTTL
	if len(ttl) > 0 {
		expiry = ttl[0]
	}

	c.dataAccountInfo[url] = &CachedDataAccountInfo{
		Data:      info,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		URL:       url,
	}
}

// GetDataAccountInfo retrieves data account info from cache
func (c *AccountCache) GetDataAccountInfo(url string) (*types.DataAccountInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.dataAccountInfo[url]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.Data, true
}

// Account Summary Caching Methods
// These methods handle caching of account summary information

// StoreAccountSummary stores account summary in cache with optional custom TTL
func (c *AccountCache) StoreAccountSummary(url string, summary *types.AccountSummary, ttl ...time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.defaultTTL
	if len(ttl) > 0 {
		expiry = ttl[0]
	}

	c.accountSummaries[url] = &CachedAccountSummary{
		Data:      summary,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(expiry),
		URL:       url,
	}
}

// GetAccountSummary retrieves account summary from cache
func (c *AccountCache) GetAccountSummary(url string) (*types.AccountSummary, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.accountSummaries[url]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil, false
	}

	return cached.Data, true
}

// Cache Management Methods
// These methods provide utilities for managing the entire cache

// Clear removes all cached data across all cache types
func (c *AccountCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.accountData = make(map[string]*CachedAccountData)
	c.balances = make(map[string]*CachedBalance)
	c.identityInfo = make(map[string]*CachedIdentityInfo)
	c.dataAccountInfo = make(map[string]*CachedDataAccountInfo)
	c.accountSummaries = make(map[string]*CachedAccountSummary)
}

// RemoveAccount removes all cached data for a specific account URL.
// This will remove the account from all cache types (data, balance, identity, etc.)
func (c *AccountCache) RemoveAccount(accountURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.accountData, accountURL)
	delete(c.balances, accountURL)
	delete(c.identityInfo, accountURL)
	delete(c.dataAccountInfo, accountURL)
	delete(c.accountSummaries, accountURL)
}

// PruneExpired removes all expired entries from the cache
func (c *AccountCache) PruneExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Remove expired account data
	for url, cached := range c.accountData {
		if now.After(cached.ExpiresAt) {
			delete(c.accountData, url)
		}
	}

	// Remove expired balances
	for url, cached := range c.balances {
		if now.After(cached.ExpiresAt) {
			delete(c.balances, url)
		}
	}

	// Remove expired identity info
	for url, cached := range c.identityInfo {
		if now.After(cached.ExpiresAt) {
			delete(c.identityInfo, url)
		}
	}

	// Remove expired data account info
	for url, cached := range c.dataAccountInfo {
		if now.After(cached.ExpiresAt) {
			delete(c.dataAccountInfo, url)
		}
	}

	// Remove expired account summaries
	for url, cached := range c.accountSummaries {
		if now.After(cached.ExpiresAt) {
			delete(c.accountSummaries, url)
		}
	}
}

// GetCachedURLs returns all account URLs that have cached data across all cache types.
// This provides a unified view of all accounts currently in the cache.
func (c *AccountCache) GetCachedURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	urlSet := make(map[string]bool)

	// Collect URLs from all cache maps
	for url := range c.accountData {
		urlSet[url] = true
	}
	for url := range c.balances {
		urlSet[url] = true
	}
	for url := range c.identityInfo {
		urlSet[url] = true
	}
	for url := range c.dataAccountInfo {
		urlSet[url] = true
	}
	for url := range c.accountSummaries {
		urlSet[url] = true
	}

	// Convert set to slice
	urls := make([]string, 0, len(urlSet))
	for url := range urlSet {
		urls = append(urls, url)
	}

	return urls
}

// GetAccount returns a specific account's data from the cache if it exists and is not expired.
// Returns nil if the account is not cached or has expired.
func (c *AccountCache) GetAccount(accountURL string) *types.AccountData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.accountData[accountURL]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil
	}

	return cached.Data
}
