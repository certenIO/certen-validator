// Copyright 2025 Certen Protocol
//
// Database Client for Certen Proof Artifact Storage
// Provides connection pooling, health checks, and migration support

package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/certen/independant-validator/pkg/config"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Client represents a database client with connection pooling
type Client struct {
	db     *sql.DB
	config *config.Config
	logger *log.Logger
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

	// Configure connection pool
	db.SetMaxOpenConns(cfg.DatabaseMaxConns)
	db.SetMaxIdleConns(cfg.DatabaseMinConns)
	db.SetConnMaxIdleTime(time.Duration(cfg.DatabaseMaxIdleTime) * time.Second)
	db.SetConnMaxLifetime(time.Duration(cfg.DatabaseMaxLifetime) * time.Second)

	client.db = db

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	client.logger.Printf("Connected to database (max_conns=%d, min_conns=%d)",
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns)

	return client, nil
}

// DB returns the underlying *sql.DB for direct access
func (c *Client) DB() *sql.DB {
	return c.db
}

// Close closes the database connection
func (c *Client) Close() error {
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
// MIGRATION SUPPORT
// ============================================================================

// MigrateUp runs all pending database migrations
func (c *Client) MigrateUp(ctx context.Context) error {
	c.logger.Println("Running database migrations...")

	// Get all migration files
	migrations, err := c.getMigrations()
	if err != nil {
		return fmt.Errorf("failed to get migrations: %w", err)
	}

	// Get already applied migrations
	applied, err := c.getAppliedMigrations(ctx)
	if err != nil {
		// If table doesn't exist, that's fine - first migration will create it
		if !strings.Contains(err.Error(), "does not exist") {
			return fmt.Errorf("failed to get applied migrations: %w", err)
		}
		applied = make(map[string]bool)
	}

	// Apply pending migrations
	for _, migration := range migrations {
		if applied[migration.Version] {
			c.logger.Printf("  Skipping %s (already applied)", migration.Version)
			continue
		}

		c.logger.Printf("  Applying %s...", migration.Version)
		if err := c.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
		c.logger.Printf("  Applied %s successfully", migration.Version)
	}

	c.logger.Println("Migrations complete")
	return nil
}

// Migration represents a database migration
type Migration struct {
	Version  string
	Filename string
	SQL      string
}

// getMigrations reads all migration files from the embedded filesystem
func (c *Client) getMigrations() ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sql") {
			return nil
		}

		content, err := migrationsFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Extract version from filename (e.g., "001_initial_schema.sql" -> "001_initial_schema")
		filename := d.Name()
		version := strings.TrimSuffix(filename, ".sql")

		migrations = append(migrations, Migration{
			Version:  version,
			Filename: filename,
			SQL:      string(content),
		})
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// getAppliedMigrations returns a map of already applied migration versions
func (c *Client) getAppliedMigrations(ctx context.Context) (map[string]bool, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, rows.Err()
}

// applyMigration applies a single migration in a transaction
func (c *Client) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute the migration SQL
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// The migration SQL should record itself in schema_migrations
	// But if it's the first migration, we need to handle that specially
	// (The migration SQL handles this via INSERT ... ON CONFLICT DO NOTHING)

	return tx.Commit()
}

// MigrationStatus returns the status of all migrations
func (c *Client) MigrationStatus(ctx context.Context) ([]MigrationInfo, error) {
	migrations, err := c.getMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to get migrations: %w", err)
	}

	applied, err := c.getAppliedMigrations(ctx)
	if err != nil {
		if !strings.Contains(err.Error(), "does not exist") {
			return nil, fmt.Errorf("failed to get applied migrations: %w", err)
		}
		applied = make(map[string]bool)
	}

	var status []MigrationInfo
	for _, m := range migrations {
		status = append(status, MigrationInfo{
			Version:  m.Version,
			Applied:  applied[m.Version],
		})
	}

	return status, nil
}

// MigrationInfo represents the status of a single migration
type MigrationInfo struct {
	Version string `json:"version"`
	Applied bool   `json:"applied"`
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
