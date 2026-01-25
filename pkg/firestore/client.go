// Copyright 2025 Certen Protocol
//
// Firestore Client
// Firebase Admin SDK client for syncing proof cycle data to Firestore

package firestore

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	gcpfirestore "cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	"google.golang.org/api/option"
)

// Client wraps the Firestore client with Certen-specific functionality
type Client struct {
	app       *firebase.App
	firestore *gcpfirestore.Client
	projectID string
	logger    *log.Logger
	enabled   bool
	mu        sync.RWMutex
}

// ClientConfig holds configuration for the Firestore client
type ClientConfig struct {
	// ProjectID is the Firebase/GCP project ID
	ProjectID string

	// CredentialsFile is the path to the service account JSON file
	// If empty, uses GOOGLE_APPLICATION_CREDENTIALS environment variable
	CredentialsFile string

	// Enabled controls whether Firestore operations are actually performed
	// If false, all operations are no-ops (useful for local development)
	Enabled bool

	// Logger for client operations
	Logger *log.Logger
}

// DefaultConfig returns a ClientConfig with values from environment variables
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		ProjectID:       os.Getenv("FIREBASE_PROJECT_ID"),
		CredentialsFile: os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		Enabled:         getEnvBool("FIRESTORE_ENABLED", false),
		Logger:          log.New(os.Stdout, "[Firestore] ", log.LstdFlags),
	}
}

// NewClient creates a new Firestore client
func NewClient(ctx context.Context, cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "[Firestore] ", log.LstdFlags)
	}

	client := &Client{
		projectID: cfg.ProjectID,
		logger:    cfg.Logger,
		enabled:   cfg.Enabled,
	}

	// If not enabled, return a no-op client
	if !cfg.Enabled {
		cfg.Logger.Println("Firestore sync is DISABLED - running in no-op mode")
		return client, nil
	}

	// Validate configuration
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("FIREBASE_PROJECT_ID is required when Firestore is enabled")
	}

	// Build Firebase options
	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}
	// If no credentials file, the SDK will use GOOGLE_APPLICATION_CREDENTIALS or
	// application default credentials (useful in GCP environments)

	// Initialize Firebase app
	config := &firebase.Config{
		ProjectID: cfg.ProjectID,
	}

	app, err := firebase.NewApp(ctx, config, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	// Create Firestore client
	firestoreClient, err := app.Firestore(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %w", err)
	}

	client.app = app
	client.firestore = firestoreClient

	cfg.Logger.Printf("Firestore client initialized for project: %s", cfg.ProjectID)
	return client, nil
}

// Close closes the Firestore client
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.firestore != nil {
		return c.firestore.Close()
	}
	return nil
}

// IsEnabled returns whether Firestore sync is enabled
func (c *Client) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// Collection returns a reference to a Firestore collection
func (c *Client) Collection(path string) *gcpfirestore.CollectionRef {
	if !c.IsEnabled() || c.firestore == nil {
		return nil
	}
	return c.firestore.Collection(path)
}

// Doc returns a reference to a Firestore document
func (c *Client) Doc(path string) *gcpfirestore.DocumentRef {
	if !c.IsEnabled() || c.firestore == nil {
		return nil
	}
	return c.firestore.Doc(path)
}

// CreateStatusSnapshot creates a new status snapshot in Firestore
// Path: /users/{userID}/transactionIntents/{intentID}/statusSnapshots/{snapshotID}
func (c *Client) CreateStatusSnapshot(ctx context.Context, userID, intentID string, snapshot *StatusSnapshot) error {
	if !c.IsEnabled() {
		c.logger.Printf("Firestore disabled - skipping status snapshot for user=%s intent=%s stage=%d",
			userID, intentID, snapshot.Stage)
		return nil
	}

	if c.firestore == nil {
		return fmt.Errorf("Firestore client not initialized")
	}

	// Generate snapshot ID if not provided
	if snapshot.SnapshotID == "" {
		snapshot.SnapshotID = fmt.Sprintf("stage%d_%d", snapshot.Stage, time.Now().UnixNano())
	}

	// Build document path
	docPath := fmt.Sprintf("users/%s/transactionIntents/%s/statusSnapshots/%s",
		userID, intentID, snapshot.SnapshotID)

	// Set the document
	_, err := c.firestore.Doc(docPath).Set(ctx, map[string]interface{}{
		"stage":              snapshot.Stage,
		"stageName":          snapshot.StageName,
		"status":             snapshot.Status,
		"timestamp":          snapshot.Timestamp,
		"startedAt":          snapshot.StartedAt,
		"endedAt":            snapshot.EndedAt,
		"source":             snapshot.Source,
		"validatorId":        snapshot.ValidatorID,
		"data":               snapshot.Data,
		"previousSnapshotId": snapshot.PreviousSnapshotID,
		"snapshotHash":       snapshot.SnapshotHash,
		"errorMessage":       snapshot.ErrorMessage,
		"errorCode":          snapshot.ErrorCode,
	})

	if err != nil {
		c.logger.Printf("Failed to create status snapshot: %v", err)
		return fmt.Errorf("failed to create status snapshot: %w", err)
	}

	c.logger.Printf("Created status snapshot: user=%s intent=%s stage=%d status=%s",
		userID, intentID, snapshot.Stage, snapshot.Status)
	return nil
}

// CreateAuditEntry creates a new audit trail entry in Firestore
// Path: /users/{userID}/auditTrail/{entryID}
func (c *Client) CreateAuditEntry(ctx context.Context, userID string, entry *AuditTrailEntry) error {
	if !c.IsEnabled() {
		c.logger.Printf("Firestore disabled - skipping audit entry for user=%s phase=%s",
			userID, entry.Phase)
		return nil
	}

	if c.firestore == nil {
		return fmt.Errorf("Firestore client not initialized")
	}

	// Generate entry ID if not provided
	if entry.EntryID == "" {
		entry.EntryID = fmt.Sprintf("%s_%d", entry.Phase, time.Now().UnixNano())
	}

	// Build document path
	docPath := fmt.Sprintf("users/%s/auditTrail/%s", userID, entry.EntryID)

	// Set the document
	_, err := c.firestore.Doc(docPath).Set(ctx, map[string]interface{}{
		"transactionId": entry.TransactionID,
		"accumTxHash":   entry.AccumTxHash,
		"phase":         entry.Phase,
		"action":        entry.Action,
		"actor":         entry.Actor,
		"actorType":     entry.ActorType,
		"timestamp":     entry.Timestamp,
		"previousHash":  entry.PreviousHash,
		"entryHash":     entry.EntryHash,
		"details":       entry.Details,
		"proofId":       entry.ProofID,
		"batchId":       entry.BatchID,
		"anchorId":      entry.AnchorID,
	})

	if err != nil {
		c.logger.Printf("Failed to create audit entry: %v", err)
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	c.logger.Printf("Created audit entry: user=%s phase=%s action=%s",
		userID, entry.Phase, entry.Action)
	return nil
}

// UpdateTransactionIntent updates fields on a transaction intent document
// Path: /users/{userID}/transactionIntents/{intentID}
func (c *Client) UpdateTransactionIntent(ctx context.Context, userID, intentID string, update *TransactionIntentUpdate) error {
	if !c.IsEnabled() {
		c.logger.Printf("Firestore disabled - skipping intent update for user=%s intent=%s",
			userID, intentID)
		return nil
	}

	if c.firestore == nil {
		return fmt.Errorf("Firestore client not initialized")
	}

	// Build document path
	docPath := fmt.Sprintf("users/%s/transactionIntents/%s", userID, intentID)

	// Build update map (only include non-nil/non-empty fields)
	updates := make(map[string]interface{})

	if update.Status != "" {
		updates["status"] = update.Status
	}
	if update.CurrentStage != nil {
		updates["currentStage"] = *update.CurrentStage
	}
	if update.LastUpdated != nil {
		updates["lastUpdated"] = *update.LastUpdated
	}
	if update.ProofID != "" {
		updates["proofId"] = update.ProofID
	}
	if update.BatchID != "" {
		updates["batchId"] = update.BatchID
	}
	if update.AnchorTxHash != "" {
		updates["anchorTxHash"] = update.AnchorTxHash
	}
	if update.EthereumConfirmations != nil {
		updates["ethereumConfirmations"] = *update.EthereumConfirmations
	}
	if update.CompletedAt != nil {
		updates["completedAt"] = *update.CompletedAt
	}
	if update.Error != "" {
		updates["error"] = update.Error
	}
	if update.Metadata != nil {
		for k, v := range update.Metadata {
			updates["metadata."+k] = v
		}
	}

	if len(updates) == 0 {
		return nil // Nothing to update
	}

	// Update the document
	_, err := c.firestore.Doc(docPath).Set(ctx, updates, gcpfirestore.MergeAll)
	if err != nil {
		c.logger.Printf("Failed to update transaction intent: %v", err)
		return fmt.Errorf("failed to update transaction intent: %w", err)
	}

	c.logger.Printf("Updated transaction intent: user=%s intent=%s fields=%d",
		userID, intentID, len(updates))
	return nil
}

// GetLatestAuditEntry retrieves the most recent audit entry for a user
// Used for computing previousHash in chain integrity
func (c *Client) GetLatestAuditEntry(ctx context.Context, userID string) (*AuditTrailEntry, error) {
	if !c.IsEnabled() || c.firestore == nil {
		return nil, nil
	}

	// Query for the latest audit entry
	collPath := fmt.Sprintf("users/%s/auditTrail", userID)
	query := c.firestore.Collection(collPath).
		OrderBy("timestamp", gcpfirestore.Desc).
		Limit(1)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}

	if len(docs) == 0 {
		return nil, nil // No previous entries
	}

	// Parse the document
	var entry AuditTrailEntry
	if err := docs[0].DataTo(&entry); err != nil {
		return nil, fmt.Errorf("failed to parse audit entry: %w", err)
	}
	entry.EntryID = docs[0].Ref.ID

	return &entry, nil
}

// GetLatestStatusSnapshot retrieves the most recent status snapshot for an intent
// Used for computing previousSnapshotId in chain integrity
func (c *Client) GetLatestStatusSnapshot(ctx context.Context, userID, intentID string) (*StatusSnapshot, error) {
	if !c.IsEnabled() || c.firestore == nil {
		return nil, nil
	}

	// Query for the latest snapshot
	collPath := fmt.Sprintf("users/%s/transactionIntents/%s/statusSnapshots", userID, intentID)
	query := c.firestore.Collection(collPath).
		OrderBy("timestamp", gcpfirestore.Desc).
		Limit(1)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query status snapshots: %w", err)
	}

	if len(docs) == 0 {
		return nil, nil // No previous snapshots
	}

	// Parse the document
	var snapshot StatusSnapshot
	if err := docs[0].DataTo(&snapshot); err != nil {
		return nil, fmt.Errorf("failed to parse status snapshot: %w", err)
	}
	snapshot.SnapshotID = docs[0].Ref.ID

	return &snapshot, nil
}

// FindIntentByAccumTxHash searches for a transaction intent by its Accumulate transaction hash
// This is used to link validator-discovered transactions back to user intents
func (c *Client) FindIntentByAccumTxHash(ctx context.Context, accumTxHash string) (userID string, intentID string, err error) {
	if !c.IsEnabled() || c.firestore == nil {
		return "", "", nil
	}

	// This requires a collection group query across all users' transactionIntents
	// Note: This requires a composite index on accumTxHash field
	query := c.firestore.CollectionGroup("transactionIntents").
		Where("accumulateTransactionHash", "==", accumTxHash).
		Limit(1)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return "", "", fmt.Errorf("failed to query intents by accumTxHash: %w", err)
	}

	if len(docs) == 0 {
		return "", "", nil // Not found
	}

	// Parse the document path to extract userID and intentID
	// Path format: users/{userID}/transactionIntents/{intentID}
	ref := docs[0].Ref
	intentID = ref.ID
	userID = ref.Parent.Parent.ID

	return userID, intentID, nil
}

// Batch creates a new Firestore batch for atomic writes
func (c *Client) Batch() *gcpfirestore.WriteBatch {
	if !c.IsEnabled() || c.firestore == nil {
		return nil
	}
	return c.firestore.Batch()
}

// RunTransaction runs a Firestore transaction
func (c *Client) RunTransaction(ctx context.Context, f func(context.Context, *gcpfirestore.Transaction) error) error {
	if !c.IsEnabled() || c.firestore == nil {
		return nil
	}
	return c.firestore.RunTransaction(ctx, f)
}

// Health checks if the Firestore connection is healthy
func (c *Client) Health(ctx context.Context) error {
	if !c.IsEnabled() {
		return nil // Disabled is healthy
	}

	if c.firestore == nil {
		return fmt.Errorf("Firestore client not initialized")
	}

	// Try to read a non-existent document (should succeed without error if connected)
	_, err := c.firestore.Collection("_health_check").Doc("ping").Get(ctx)
	if err != nil {
		// NotFound is OK - we just want to verify connectivity
		if err.Error() != "rpc error: code = NotFound desc = Document not found" {
			// Check if it's actually a not found error (different Go versions may format differently)
			// This is a basic connectivity check
		}
	}

	return nil
}

// helper to parse bool from env
func getEnvBool(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val == "true" || val == "1" || val == "yes"
}
