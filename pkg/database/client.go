// Copyright 2025 Certen Protocol
//
// Database Client for Certen Proof Artifact Storage
// Provides connection pooling, health checks, and migration support

package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/certen/independant-validator/pkg/config"
)

// Client represents a database client with connection pooling and automatic reconnection
type Client struct {
	db     *sql.DB
	config *config.Config
	logger *log.Logger
	stopCh chan struct{}
}

// ClientOption is a functional option for configuring the client
type ClientOption func(*Client)

// WithLogger sets a custom logger for the client
func WithLogger(logger *log.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// NewClient creates a new database client with connection pooling
func NewClient(cfg *config.Config, opts ...ClientOption) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("database URL cannot be empty")
	}

	client := &Client{
		config: cfg,
		logger: log.New(log.Writer(), "[Database] ", log.LstdFlags),
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Open database connection
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool with aggressive recycling to survive DB restarts
	db.SetMaxOpenConns(cfg.DatabaseMaxConns)
	db.SetMaxIdleConns(cfg.DatabaseMinConns)
	idleTime := time.Duration(cfg.DatabaseMaxIdleTime) * time.Second
	if idleTime > 60*time.Second {
		idleTime = 60 * time.Second
	}
	lifetime := time.Duration(cfg.DatabaseMaxLifetime) * time.Second
	if lifetime > 5*time.Minute {
		lifetime = 5 * time.Minute
	}
	db.SetConnMaxIdleTime(idleTime)
	db.SetConnMaxLifetime(lifetime)

	client.db = db

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	client.logger.Printf("Connected to database (max_conns=%d, min_conns=%d, max_lifetime=%s, max_idle=%s)",
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, lifetime, idleTime)

	client.stopCh = make(chan struct{})
	go client.connectionHealthMonitor()

	return client, nil
}

// connectionHealthMonitor periodically pings the DB and forces pool reset on failure.
func (c *Client) connectionHealthMonitor() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.db.PingContext(ctx)
			cancel()

			if err != nil {
				consecutiveFailures++
				c.logger.Printf("⚠️ [DB-HEALTH] Ping failed (%d consecutive): %v", consecutiveFailures, err)
				if consecutiveFailures >= 2 {
					c.logger.Printf("🔄 [DB-HEALTH] Forcing connection pool reset after %d failures", consecutiveFailures)
					c.db.SetMaxIdleConns(0)
					time.Sleep(100 * time.Millisecond)
					c.db.SetMaxIdleConns(c.config.DatabaseMinConns)
				}
			} else {
				if consecutiveFailures > 0 {
					c.logger.Printf("✅ [DB-HEALTH] Connection recovered after %d failures", consecutiveFailures)
				}
				consecutiveFailures = 0
			}
		}
	}
}

// DB returns the underlying *sql.DB for direct access
func (c *Client) DB() *sql.DB {
	return c.db
}

// NewClientFromDB wraps an already-open *sql.DB so the repositories that take a
// *Client can be driven against a connection this package did not open.
//
// Deliberately does NOT start the connection health monitor and does not own the
// handle: Close is the caller's job. Exists because the repositories are split
// between those taking a raw *sql.DB (ProofArtifacts, Unified, MultiLeg) and
// those taking a *Client (IntentLifecycle among them), and a round-trip gate has
// to drive the REAL repository — re-implementing the write path would prove
// nothing about the write path.
func NewClientFromDB(db *sql.DB) *Client {
	return &Client{
		db:     db,
		logger: log.New(log.Writer(), "[Database] ", log.LstdFlags),
	}
}

// Close closes the database connection and stops the health monitor
func (c *Client) Close() error {
	if c.stopCh != nil {
		close(c.stopCh)
	}
	if c.db != nil {
		c.logger.Println("Closing database connection")
		return c.db.Close()
	}
	return nil
}

// Ping verifies the database connection is alive
func (c *Client) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// Health returns database health information
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	status := &HealthStatus{
		CheckedAt: time.Now(),
	}

	// Check connection
	if err := c.db.PingContext(ctx); err != nil {
		status.Healthy = false
		status.Error = err.Error()
		return status, nil
	}

	// Get connection pool stats
	stats := c.db.Stats()
	status.Healthy = true
	status.OpenConnections = stats.OpenConnections
	status.InUse = stats.InUse
	status.Idle = stats.Idle
	status.WaitCount = stats.WaitCount
	status.WaitDuration = stats.WaitDuration
	status.MaxOpenConnections = stats.MaxOpenConnections

	// Get database version
	var version string
	if err := c.db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err == nil {
		status.Version = version
	}

	return status, nil
}

// HealthStatus represents the health status of the database
type HealthStatus struct {
	Healthy            bool          `json:"healthy"`
	Error              string        `json:"error,omitempty"`
	Version            string        `json:"version,omitempty"`
	OpenConnections    int           `json:"open_connections"`
	InUse              int           `json:"in_use"`
	Idle               int           `json:"idle"`
	WaitCount          int64         `json:"wait_count"`
	WaitDuration       time.Duration `json:"wait_duration"`
	MaxOpenConnections int           `json:"max_open_connections"`
	CheckedAt          time.Time     `json:"checked_at"`
}

// ============================================================================
// TRANSACTION SUPPORT
// ============================================================================

// Tx represents a database transaction
type Tx struct {
	tx *sql.Tx
}

// BeginTx starts a new transaction
func (c *Client) BeginTx(ctx context.Context) (*Tx, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &Tx{tx: tx}, nil
}

// Commit commits the transaction
func (t *Tx) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *Tx) Rollback() error {
	return t.tx.Rollback()
}

// Tx returns the underlying *sql.Tx for direct access
func (t *Tx) Tx() *sql.Tx {
	return t.tx
}

// ============================================================================
// QUERY HELPERS
// ============================================================================

// ExecContext executes a query that doesn't return rows
func (c *Client) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return c.db.ExecContext(ctx, query, args...)
}

// QueryContext executes a query that returns rows
func (c *Client) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return c.db.QueryContext(ctx, query, args...)
}

// QueryRowContext executes a query that returns at most one row
func (c *Client) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return c.db.QueryRowContext(ctx, query, args...)
}
