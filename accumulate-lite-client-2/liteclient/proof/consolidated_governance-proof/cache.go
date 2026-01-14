// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// CacheEntry represents a cached RPC response
type CacheEntry struct {
	Response  map[string]interface{}
	Timestamp time.Time
	TTL       time.Duration
}

// IsExpired returns true if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Since(e.Timestamp) > e.TTL
}

// RPCCache provides intelligent caching for RPC responses
type RPCCache struct {
	cache      map[string]*CacheEntry
	mutex      sync.RWMutex
	defaultTTL time.Duration
	maxSize    int
	hits       int64
	misses     int64
}

// NewRPCCache creates a new RPC cache with specified configuration
func NewRPCCache(defaultTTL time.Duration, maxSize int) *RPCCache {
	return &RPCCache{
		cache:      make(map[string]*CacheEntry, maxSize),
		defaultTTL: defaultTTL,
		maxSize:    maxSize,
	}
}

// Global cache instance
var globalRPCCache *RPCCache
var cacheOnce sync.Once

// InitRPCCache initializes the global RPC cache
func InitRPCCache() *RPCCache {
	cacheOnce.Do(func() {
		// Default: 5-minute TTL, max 1000 entries
		globalRPCCache = NewRPCCache(5*time.Minute, 1000)

		// Start cleanup goroutine
		go globalRPCCache.cleanupRoutine()
	})
	return globalRPCCache
}

// GetRPCCache returns the global RPC cache instance
func GetRPCCache() *RPCCache {
	if globalRPCCache == nil {
		return InitRPCCache()
	}
	return globalRPCCache
}

// generateCacheKey creates a cache key from scope and query
func (c *RPCCache) generateCacheKey(scope string, query map[string]interface{}) string {
	// Use pooled JSON marshaling for cache key generation
	queryJSON, err := JSONMarshalPooled(query)
	if err != nil {
		// Fallback to simple string concatenation if JSON fails
		return fmt.Sprintf("%s:%v", scope, query)
	}

	// Create hash of scope + query for consistent, compact keys
	hasher := sha256.New()
	hasher.Write([]byte(scope))
	hasher.Write(queryJSON)
	hash := hasher.Sum(nil)

	return hex.EncodeToString(hash)
}

// Get retrieves a cached response if available and not expired
func (c *RPCCache) Get(scope string, query map[string]interface{}) (map[string]interface{}, bool) {
	key := c.generateCacheKey(scope, query)

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		c.misses++
		return nil, false
	}

	if entry.IsExpired() {
		c.misses++
		// Don't delete here to avoid write lock, cleanup routine will handle it
		return nil, false
	}

	c.hits++
	return entry.Response, true
}

// Set stores a response in the cache
func (c *RPCCache) Set(scope string, query map[string]interface{}, response map[string]interface{}, customTTL ...time.Duration) {
	key := c.generateCacheKey(scope, query)
	ttl := c.defaultTTL
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	}

	// Don't cache error responses or empty responses
	if response == nil {
		return
	}

	// Check for error in response
	if errField, exists := response["error"]; exists && errField != nil {
		return // Don't cache errors
	}

	entry := &CacheEntry{
		Response:  response,
		Timestamp: time.Now(),
		TTL:       ttl,
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Evict old entries if cache is full
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[key] = entry
}

// evictOldest removes the oldest entry from cache (must be called with write lock)
func (c *RPCCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.cache {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// cleanupRoutine periodically removes expired entries
func (c *RPCCache) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute) // Cleanup every minute
	defer ticker.Stop()

	for range ticker.C {
		c.cleanupExpired()
	}
}

// cleanupExpired removes expired entries from cache
func (c *RPCCache) cleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for key, entry := range c.cache {
		if entry.IsExpired() {
			delete(c.cache, key)
		}
	}
}

// GetStats returns cache statistics
func (c *RPCCache) GetStats() (hits, misses int64, size int, hitRate float64) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	hits = c.hits
	misses = c.misses
	size = len(c.cache)

	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return hits, misses, size, hitRate
}

// Clear removes all entries from cache
func (c *RPCCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string]*CacheEntry, c.maxSize)
	c.hits = 0
	c.misses = 0
}

// ShouldCache determines if a query should be cached based on its characteristics
func ShouldCache(scope string, query map[string]interface{}) bool {
	// Cache queries that are likely to be repeated
	if queryType, exists := query["queryType"]; exists {
		switch queryType {
		case "chain":
			// Chain queries are good candidates for caching
			return true
		case "message":
			// Message queries can be cached if they're not streaming
			return true
		default:
			// Default to not caching unknown query types
			return false
		}
	}

	// Cache by default if no queryType specified
	return true
}

// RPCClientInterface defines the interface that RPC clients must implement
type RPCClientInterface interface {
	Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error)
	QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error)
	GetEndpoint() string
}

// CachedRPCClient wraps an RPC client with caching capabilities
type CachedRPCClient struct {
	client RPCClientInterface
	cache  *RPCCache
}

// NewCachedRPCClient creates a new cached RPC client
func NewCachedRPCClient(client RPCClientInterface) *CachedRPCClient {
	return &CachedRPCClient{
		client: client,
		cache:  GetRPCCache(),
	}
}

// Query performs an RPC query with caching
func (c *CachedRPCClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	// Check cache first if caching is appropriate
	if ShouldCache(scope, query) {
		if cached, found := c.cache.Get(scope, query); found {
			if IsDebugEnabled() {
				LogDebug("CACHE", "Cache hit for scope: %s", SafeTruncate(scope, 32))
			}
			return cached, nil
		}
	}

	// Cache miss or non-cacheable - perform actual RPC call
	response, err := c.client.Query(ctx, scope, query)
	if err != nil {
		return nil, err
	}

	// Cache successful responses
	if ShouldCache(scope, query) && response != nil {
		c.cache.Set(scope, query, response)
		if IsDebugEnabled() {
			LogDebug("CACHE", "Cached response for scope: %s", SafeTruncate(scope, 32))
		}
	}

	return response, nil
}

// QueryRaw performs an RPC query and returns raw bytes (bypassing cache for raw responses)
func (c *CachedRPCClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	// Raw queries bypass cache since they return bytes, not structured data
	return c.client.QueryRaw(ctx, scope, query)
}

// GetEndpoint returns the RPC endpoint
func (c *CachedRPCClient) GetEndpoint() string {
	return c.client.GetEndpoint()
}