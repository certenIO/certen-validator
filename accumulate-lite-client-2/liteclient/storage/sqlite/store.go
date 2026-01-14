// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	// Note: modernc.org/sqlite import removed for vendor compatibility
	// Add back: _ "modernc.org/sqlite" // Pure Go SQLite driver
)

// Store provides SQLite-backed storage for proof artifacts with migrations
type Store struct {
	db   *sql.DB
	path string
}

// Config configures the SQLite store
type Config struct {
	Path            string        `json:"path"`              // Database file path
	MaxConnections  int           `json:"max_connections"`   // Max concurrent connections
	BusyTimeout     time.Duration `json:"busy_timeout"`      // SQLite busy timeout
	CacheSize       int           `json:"cache_size"`        // SQLite cache size (KB)
	JournalMode     string        `json:"journal_mode"`      // WAL, DELETE, TRUNCATE
	SynchronousMode string        `json:"synchronous_mode"`  // FULL, NORMAL, OFF
	ForeignKeys     bool          `json:"foreign_keys"`      // Enable foreign key constraints
}

// DefaultConfig returns a production-ready configuration
func DefaultConfig() *Config {
	return &Config{
		Path:            "liteclient.db",
		MaxConnections:  10,
		BusyTimeout:     5 * time.Second,
		CacheSize:       10000, // 10MB cache
		JournalMode:     "WAL",
		SynchronousMode: "NORMAL",
		ForeignKeys:     true,
	}
}

// NewStore creates a new SQLite store with the given configuration
func NewStore(config *Config) (*Store, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	// Open database with configuration
	db, err := sql.Open("sqlite", config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	// Configure connection pool
	db.SetMaxOpenConns(config.MaxConnections)
	db.SetMaxIdleConns(config.MaxConnections)
	db.SetConnMaxLifetime(time.Hour)
	
	// Apply SQLite pragmas
	if err := configureSQLite(db, config); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure SQLite: %w", err)
	}
	
	// Initialize schema
	if err := InitSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}
	
	return &Store{
		db:   db,
		path: config.Path,
	}, nil
}

// configureSQLite applies SQLite configuration pragmas
func configureSQLite(db *sql.DB, config *Config) error {
	pragmas := []string{
		fmt.Sprintf("PRAGMA busy_timeout = %d", int(config.BusyTimeout.Milliseconds())),
		fmt.Sprintf("PRAGMA cache_size = -%d", config.CacheSize), // Negative for KB
		fmt.Sprintf("PRAGMA journal_mode = %s", config.JournalMode),
		fmt.Sprintf("PRAGMA synchronous = %s", config.SynchronousMode),
	}
	
	if config.ForeignKeys {
		pragmas = append(pragmas, "PRAGMA foreign_keys = ON")
	}
	
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("failed to execute pragma %s: %w", pragma, err)
		}
	}
	
	return nil
}

// Close closes the database connection
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Bundle represents a stored proof bundle
type Bundle struct {
	ID               int       `json:"id"`
	AccountURL       string    `json:"account_url"`
	Strategy         string    `json:"strategy"`
	SchemaVersion    string    `json:"schema_version"`
	BundleHash       []byte    `json:"bundle_hash"`
	BundleData       []byte    `json:"bundle_data"`
	VerificationStatus string  `json:"verification_status"`
	VerificationError string   `json:"verification_error,omitempty"`
	ComponentsCount  int       `json:"components_count"`
	MissingComponents []string `json:"missing_components,omitempty"`
	ProvenAt         time.Time `json:"proven_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	SourceEndpoints  []string  `json:"source_endpoints"`
	HealingActions   []string  `json:"healing_actions,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// SaveBundle stores a proof bundle in the database
func (s *Store) SaveBundle(bundle *Bundle) error {
	// Ensure account exists
	accountID, err := s.ensureAccount(bundle.AccountURL)
	if err != nil {
		return fmt.Errorf("failed to ensure account: %w", err)
	}
	
	// Serialize JSON arrays
	missingComponentsJSON, err := json.Marshal(bundle.MissingComponents)
	if err != nil {
		return fmt.Errorf("failed to marshal missing components: %w", err)
	}
	
	sourceEndpointsJSON, err := json.Marshal(bundle.SourceEndpoints)
	if err != nil {
		return fmt.Errorf("failed to marshal source endpoints: %w", err)
	}
	
	healingActionsJSON, err := json.Marshal(bundle.HealingActions)
	if err != nil {
		return fmt.Errorf("failed to marshal healing actions: %w", err)
	}
	
	query := `
		INSERT INTO bundles (
			account_id, strategy, schema_version, bundle_hash, bundle_data,
			verification_status, verification_error, components_count, missing_components,
			proven_at, expires_at, source_endpoints, healing_actions
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	result, err := s.db.Exec(query,
		accountID, bundle.Strategy, bundle.SchemaVersion, bundle.BundleHash, bundle.BundleData,
		bundle.VerificationStatus, bundle.VerificationError, bundle.ComponentsCount, missingComponentsJSON,
		bundle.ProvenAt, bundle.ExpiresAt, sourceEndpointsJSON, healingActionsJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to insert bundle: %w", err)
	}
	
	bundleID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get bundle ID: %w", err)
	}
	
	bundle.ID = int(bundleID)
	return nil
}

// GetBundle retrieves a bundle by hash
func (s *Store) GetBundle(bundleHash []byte) (*Bundle, error) {
	query := `
		SELECT b.id, a.url, b.strategy, b.schema_version, b.bundle_hash, b.bundle_data,
			   b.verification_status, b.verification_error, b.components_count, b.missing_components,
			   b.proven_at, b.expires_at, b.source_endpoints, b.healing_actions, b.created_at
		FROM bundles b
		JOIN accounts a ON b.account_id = a.id
		WHERE b.bundle_hash = ?
	`
	
	var bundle Bundle
	var missingComponentsJSON, sourceEndpointsJSON, healingActionsJSON string
	
	err := s.db.QueryRow(query, bundleHash).Scan(
		&bundle.ID, &bundle.AccountURL, &bundle.Strategy, &bundle.SchemaVersion,
		&bundle.BundleHash, &bundle.BundleData, &bundle.VerificationStatus,
		&bundle.VerificationError, &bundle.ComponentsCount, &missingComponentsJSON,
		&bundle.ProvenAt, &bundle.ExpiresAt, &sourceEndpointsJSON,
		&healingActionsJSON, &bundle.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("bundle not found")
		}
		return nil, fmt.Errorf("failed to query bundle: %w", err)
	}
	
	// Deserialize JSON arrays
	if err := json.Unmarshal([]byte(missingComponentsJSON), &bundle.MissingComponents); err != nil {
		return nil, fmt.Errorf("failed to unmarshal missing components: %w", err)
	}
	
	if err := json.Unmarshal([]byte(sourceEndpointsJSON), &bundle.SourceEndpoints); err != nil {
		return nil, fmt.Errorf("failed to unmarshal source endpoints: %w", err)
	}
	
	if err := json.Unmarshal([]byte(healingActionsJSON), &bundle.HealingActions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal healing actions: %w", err)
	}
	
	return &bundle, nil
}

// GetBundlesByAccount retrieves all bundles for an account
func (s *Store) GetBundlesByAccount(accountURL string) ([]*Bundle, error) {
	query := `
		SELECT b.id, a.url, b.strategy, b.schema_version, b.bundle_hash, b.bundle_data,
			   b.verification_status, b.verification_error, b.components_count, b.missing_components,
			   b.proven_at, b.expires_at, b.source_endpoints, b.healing_actions, b.created_at
		FROM bundles b
		JOIN accounts a ON b.account_id = a.id
		WHERE a.url = ?
		ORDER BY b.created_at DESC
	`
	
	rows, err := s.db.Query(query, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query bundles: %w", err)
	}
	defer rows.Close()
	
	var bundles []*Bundle
	
	for rows.Next() {
		var bundle Bundle
		var missingComponentsJSON, sourceEndpointsJSON, healingActionsJSON string
		
		err := rows.Scan(
			&bundle.ID, &bundle.AccountURL, &bundle.Strategy, &bundle.SchemaVersion,
			&bundle.BundleHash, &bundle.BundleData, &bundle.VerificationStatus,
			&bundle.VerificationError, &bundle.ComponentsCount, &missingComponentsJSON,
			&bundle.ProvenAt, &bundle.ExpiresAt, &sourceEndpointsJSON,
			&healingActionsJSON, &bundle.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bundle: %w", err)
		}
		
		// Deserialize JSON arrays
		if err := json.Unmarshal([]byte(missingComponentsJSON), &bundle.MissingComponents); err != nil {
			return nil, fmt.Errorf("failed to unmarshal missing components: %w", err)
		}
		
		if err := json.Unmarshal([]byte(sourceEndpointsJSON), &bundle.SourceEndpoints); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source endpoints: %w", err)
		}
		
		if err := json.Unmarshal([]byte(healingActionsJSON), &bundle.HealingActions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal healing actions: %w", err)
		}
		
		bundles = append(bundles, &bundle)
	}
	
	return bundles, nil
}

// ensureAccount ensures an account record exists and returns its ID
func (s *Store) ensureAccount(accountURL string) (int, error) {
	// Try to get existing account
	var accountID int
	query := "SELECT id FROM accounts WHERE url = ?"
	err := s.db.QueryRow(query, accountURL).Scan(&accountID)
	if err == nil {
		return accountID, nil
	}
	
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query account: %w", err)
	}
	
	// Account doesn't exist, create it
	accountType, authority, localName := parseAccountURL(accountURL)
	
	insertQuery := `
		INSERT INTO accounts (url, type, authority, local_name)
		VALUES (?, ?, ?, ?)
	`
	
	result, err := s.db.Exec(insertQuery, accountURL, accountType, authority, localName)
	if err != nil {
		return 0, fmt.Errorf("failed to insert account: %w", err)
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get account ID: %w", err)
	}
	
	return int(id), nil
}

// parseAccountURL parses an Accumulate URL into components
func parseAccountURL(url string) (accountType, authority, localName string) {
	// Simple parsing - in production this would use the URL parser
	// For now, return defaults
	return "unknown", "unknown", "unknown"
}

// CacheEntry represents a cached item with TTL
type CacheEntry struct {
	Key         string    `json:"key"`
	Type        string    `json:"type"`
	Data        []byte    `json:"data"`
	TTLSeconds  int       `json:"ttl_seconds"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	AccessCount int       `json:"access_count"`
	LastAccess  time.Time `json:"last_access"`
}

// SetCache stores a cache entry with TTL
func (s *Store) SetCache(key, cacheType string, data []byte, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl)
	
	query := `
		INSERT OR REPLACE INTO cache_entries (cache_key, cache_type, data, ttl_seconds, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`
	
	_, err := s.db.Exec(query, key, cacheType, data, int(ttl.Seconds()), expiresAt)
	if err != nil {
		return fmt.Errorf("failed to set cache entry: %w", err)
	}
	
	return nil
}

// GetCache retrieves a cache entry if it hasn't expired
func (s *Store) GetCache(key string) (*CacheEntry, error) {
	query := `
		SELECT cache_key, cache_type, data, ttl_seconds, created_at, expires_at, access_count, last_access
		FROM cache_entries
		WHERE cache_key = ? AND expires_at > datetime('now')
	`
	
	var entry CacheEntry
	err := s.db.QueryRow(query, key).Scan(
		&entry.Key, &entry.Type, &entry.Data, &entry.TTLSeconds,
		&entry.CreatedAt, &entry.ExpiresAt, &entry.AccessCount, &entry.LastAccess,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}
	
	// Update access count
	updateQuery := `
		UPDATE cache_entries 
		SET access_count = access_count + 1, last_access = datetime('now')
		WHERE cache_key = ?
	`
	s.db.Exec(updateQuery, key)
	
	return &entry, nil
}

// CleanupExpiredCache removes expired cache entries
func (s *Store) CleanupExpiredCache() error {
	query := "DELETE FROM cache_entries WHERE expires_at <= datetime('now')"
	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired cache: %w", err)
	}
	
	return nil
}

// GetStats returns database statistics
func (s *Store) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Table counts
	tables := map[string]string{
		"accounts": "SELECT COUNT(*) FROM accounts",
		"bundles":  "SELECT COUNT(*) FROM bundles",
		"chains":   "SELECT COUNT(*) FROM chains",
		"entries":  "SELECT COUNT(*) FROM entries",
		"anchors":  "SELECT COUNT(*) FROM anchors",
		"cache":    "SELECT COUNT(*) FROM cache_entries",
	}
	
	for table, query := range tables {
		var count int
		if err := s.db.QueryRow(query).Scan(&count); err != nil {
			return nil, fmt.Errorf("failed to get %s count: %w", table, err)
		}
		stats[table+"_count"] = count
	}
	
	// Database size
	var pageCount, pageSize int
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pageCount); err == nil {
		if err := s.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err == nil {
			stats["database_size_bytes"] = pageCount * pageSize
		}
	}
	
	return stats, nil
}