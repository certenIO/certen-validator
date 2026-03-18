package consensus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBboltReplayStore_BasicOperations(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_replay.db")

	store, err := NewBboltReplayStore(dbPath)
	if err != nil {
		t.Fatalf("NewBboltReplayStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	nonce := "test_nonce_12345"
	expiresAt := time.Now().Add(1 * time.Hour).Unix()

	// Should not exist yet
	exists, err := store.HasNonce(ctx, nonce)
	if err != nil {
		t.Fatalf("HasNonce: %v", err)
	}
	if exists {
		t.Fatal("Nonce should not exist yet")
	}

	// Mark it
	err = store.MarkNonce(ctx, nonce, expiresAt)
	if err != nil {
		t.Fatalf("MarkNonce: %v", err)
	}

	// Should exist now
	exists, err = store.HasNonce(ctx, nonce)
	if err != nil {
		t.Fatalf("HasNonce after mark: %v", err)
	}
	if !exists {
		t.Fatal("Nonce should exist after marking")
	}

	// Double-mark should fail
	err = store.MarkNonce(ctx, nonce, expiresAt)
	if err == nil {
		t.Fatal("Expected error on duplicate nonce")
	}
}

func TestBboltReplayStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist_test.db")

	// Open, write, close
	store1, err := NewBboltReplayStore(dbPath)
	if err != nil {
		t.Fatalf("Open store1: %v", err)
	}
	ctx := context.Background()
	err = store1.MarkNonce(ctx, "persist_nonce", time.Now().Add(1*time.Hour).Unix())
	if err != nil {
		t.Fatalf("MarkNonce store1: %v", err)
	}
	store1.Close()

	// Reopen and verify
	store2, err := NewBboltReplayStore(dbPath)
	if err != nil {
		t.Fatalf("Open store2: %v", err)
	}
	defer store2.Close()

	exists, err := store2.HasNonce(ctx, "persist_nonce")
	if err != nil {
		t.Fatalf("HasNonce store2: %v", err)
	}
	if !exists {
		t.Fatal("Nonce should persist across close/reopen")
	}
}

func TestBboltReplayStore_CleanExpired(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "clean_test.db")

	store, err := NewBboltReplayStore(dbPath)
	if err != nil {
		t.Fatalf("NewBboltReplayStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().Unix()

	// Add expired nonce (expired 1 hour ago)
	store.MarkNonce(ctx, "expired_nonce", now-3600)
	// Add valid nonce (expires in 1 hour)
	store.MarkNonce(ctx, "valid_nonce", now+3600)

	// Clean expired
	err = store.CleanExpired(ctx, now)
	if err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}

	// Expired should be gone
	exists, _ := store.HasNonce(ctx, "expired_nonce")
	if exists {
		t.Fatal("Expired nonce should have been cleaned")
	}

	// Valid should remain
	exists, _ = store.HasNonce(ctx, "valid_nonce")
	if !exists {
		t.Fatal("Valid nonce should still exist")
	}
}

func TestBboltReplayStore_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nestedPath := filepath.Join(dir, "deep", "nested", "replay.db")

	store, err := NewBboltReplayStore(nestedPath)
	if err != nil {
		t.Fatalf("NewBboltReplayStore with nested path: %v", err)
	}
	defer store.Close()

	// Verify file was created
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Fatal("Database file should exist")
	}
}
