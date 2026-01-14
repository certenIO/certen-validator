// account_test.go
//
// Tests for the shared types and data structures of the Accumulate Lite Client.
// Focuses on type conversions, data validation, and interface implementations.

package types

import (
	"context"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// TestAccountData tests the AccountData structure and methods
func TestAccountData(t *testing.T) {
	t.Run("Basic AccountData creation", func(t *testing.T) {
		accountData := &AccountData{
			URL:       "acc://test.acme/token",
			Type:      protocol.AccountTypeTokenAccount,
			Data:      nil,
			FromCache: false,
		}

		if accountData.URL != "acc://test.acme/token" {
			t.Errorf("Expected URL 'acc://test.acme/token', got '%s'", accountData.URL)
		}

		if accountData.Type != protocol.AccountTypeTokenAccount {
			t.Errorf("Expected token account type, got %v", accountData.Type)
		}

		if accountData.FromCache {
			t.Error("Expected FromCache to be false for new AccountData")
		}
	})

	t.Run("AccountData with cache flag", func(t *testing.T) {
		accountData := &AccountData{
			URL:       "acc://test.acme/adi",
			Type:      protocol.AccountTypeIdentity,
			Data:      nil,
			FromCache: true,
		}

		if !accountData.FromCache {
			t.Error("Expected FromCache to be true")
		}

		if accountData.Type != protocol.AccountTypeIdentity {
			t.Errorf("Expected identity account type, got %v", accountData.Type)
		}
	})
}

// TestNetworkStatus tests the NetworkStatus structure
func TestNetworkStatus(t *testing.T) {
	t.Run("Basic NetworkStatus creation", func(t *testing.T) {
		status := &NetworkStatus{
			Partitions: []PartitionInfo{
				{
					ID:   "partition-1",
					Type: "test-partition",
				},
				{
					ID:   "partition-2",
					Type: "another-partition",
				},
			},
		}

		if len(status.Partitions) != 2 {
			t.Errorf("Expected 2 partitions, got %d", len(status.Partitions))
		}

		if status.Partitions[0].ID != "partition-1" {
			t.Errorf("Expected partition ID 'partition-1', got '%s'", status.Partitions[0].ID)
		}

		if status.Partitions[1].Type != "another-partition" {
			t.Errorf("Expected partition name 'Another Partition', got '%s'", status.Partitions[1].Type)
		}
	})

	t.Run("Empty NetworkStatus", func(t *testing.T) {
		status := &NetworkStatus{
			Partitions: []PartitionInfo{},
		}

		if len(status.Partitions) != 0 {
			t.Errorf("Expected 0 partitions, got %d", len(status.Partitions))
		}
	})
}

// TestPartitionInfo tests the PartitionInfo structure
func TestPartitionInfo(t *testing.T) {
	t.Run("PartitionInfo creation", func(t *testing.T) {
		partition := PartitionInfo{
			ID:   "test-partition",
			Type: "test-partition-type",
		}

		if partition.ID != "test-partition" {
			t.Errorf("Expected ID 'test-partition', got '%s'", partition.ID)
		}

		if partition.Type != "test-partition-type" {
			t.Errorf("Expected Name 'Test Partition Name', got '%s'", partition.Type)
		}
	})
}

// TestMetrics tests the Metrics structure
func TestMetrics(t *testing.T) {
	t.Run("Basic Metrics creation", func(t *testing.T) {
		metrics := &Metrics{}

		// Verify the structure was created successfully
		// (metrics is guaranteed to be non-nil since we used &Metrics{})
		_ = metrics // Use the variable to avoid unused variable warning

		// Add metrics fields as they're implemented
		// For now, just verify the structure exists
	})
}

// TestAccountHandlerWithCache tests the NewAccountHandlerWithCache function
func TestAccountHandlerWithCache(t *testing.T) {
	// Mock backend implementation
	mockBackend := &MockDataBackend{
		accounts: make(map[string]*AccountData),
	}

	// Mock cache implementation
	mockCache := &MockAccountCache{
		accounts: make(map[string]*AccountData),
	}

	t.Run("Create AccountHandler with cache", func(t *testing.T) {
		handler := NewAccountHandlerWithCache(mockBackend, mockCache)

		if handler == nil {
			t.Fatal("Expected non-nil AccountHandler")
		}

		// Test that the handler was created (internal structure not exposed)
		// In a real implementation, we'd test the actual functionality
	})

	t.Run("AccountHandler delegation to backend", func(t *testing.T) {
		// Test that AccountHandler properly delegates to backend and cache
		testAccountData := &AccountData{
			URL:       "acc://test.acme/token",
			Type:      protocol.AccountTypeTokenAccount,
			FromCache: false,
		}

		mockBackend.accounts["acc://test.acme/token"] = testAccountData
		handler := NewAccountHandlerWithCache(mockBackend, mockCache)

		ctx := context.Background()
		accountData, err := handler.GetAccountData(ctx, "acc://test.acme/token")

		if err != nil {
			t.Fatalf("Expected successful account retrieval, got error: %v", err)
		}

		if accountData.URL != "acc://test.acme/token" {
			t.Errorf("Expected URL 'acc://test.acme/token', got '%s'", accountData.URL)
		}

		if accountData.Type != protocol.AccountTypeTokenAccount {
			t.Errorf("Expected token account type, got %v", accountData.Type)
		}
	})
}

// MockDataBackend provides a test implementation of DataBackend interface
type MockDataBackend struct {
	accounts    map[string]*AccountData
	shouldError bool
	errorMsg    string
}

func (m *MockDataBackend) QueryAccount(ctx context.Context, url string) (*AccountData, error) {
	if m.shouldError {
		return nil, &mockError{msg: m.errorMsg}
	}

	if account, exists := m.accounts[url]; exists {
		return account, nil
	}
	return nil, &mockError{msg: "account not found: " + url}
}

func (m *MockDataBackend) GetNetworkStatus(ctx context.Context) (*NetworkStatus, error) {
	if m.shouldError {
		return nil, &mockError{msg: m.errorMsg}
	}
	return &NetworkStatus{Partitions: []PartitionInfo{}}, nil
}

func (m *MockDataBackend) GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

func (m *MockDataBackend) GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error) {
	return nil, &mockError{msg: "not implemented in mock"}
}

// MockAccountCache provides a test implementation of AccountCache interface
type MockAccountCache struct {
	accounts map[string]*AccountData
}

func (m *MockAccountCache) GetAccountData(url string) (*AccountData, bool) {
	account, exists := m.accounts[url]
	if exists {
		// Mark as from cache
		cachedAccount := *account
		cachedAccount.FromCache = true
		return &cachedAccount, true
	}
	return nil, false
}

func (m *MockAccountCache) StoreAccountData(url string, data *AccountData, ttl ...time.Duration) {
	if m.accounts == nil {
		m.accounts = make(map[string]*AccountData)
	}
	m.accounts[url] = data
}

func (m *MockAccountCache) RemoveAccount(accountURL string) {
	delete(m.accounts, accountURL)
}

func (m *MockAccountCache) GetBalance(url string) (*TokenBalanceInfo, bool) {
	return nil, false
}

func (m *MockAccountCache) StoreBalance(url string, balance *TokenBalanceInfo, ttl ...time.Duration) {
}

func (m *MockAccountCache) GetIdentityInfo(url string) (*IdentityInfo, bool) {
	return nil, false
}

func (m *MockAccountCache) StoreIdentityInfo(url string, identity *IdentityInfo, ttl ...time.Duration) {
}

func (m *MockAccountCache) PruneExpired() {
}

func (m *MockAccountCache) Clear() {
	m.accounts = make(map[string]*AccountData)
}

func (m *MockAccountCache) GetCachedURLs() []string {
	urls := make([]string, 0, len(m.accounts))
	for url := range m.accounts {
		urls = append(urls, url)
	}
	return urls
}

func (m *MockAccountCache) GetMetrics() *Metrics {
	return &Metrics{}
}

// mockError implements error interface
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// TestTokenBalanceInfo tests the TokenBalanceInfo structure
func TestTokenBalanceInfo(t *testing.T) {
	t.Run("TokenBalanceInfo creation", func(t *testing.T) {
		balance := &TokenBalanceInfo{
			Balance:  "1000000",
			TokenURL: "acc://ACME",
		}

		if balance.Balance != "1000000" {
			t.Errorf("Expected balance '1000000', got '%s'", balance.Balance)
		}

		if balance.TokenURL != "acc://ACME" {
			t.Errorf("Expected token URL 'acc://ACME', got '%s'", balance.TokenURL)
		}
	})
}

// TestIdentityInfo tests the IdentityInfo structure
func TestIdentityInfo(t *testing.T) {
	t.Run("IdentityInfo creation", func(t *testing.T) {
		identity := &IdentityInfo{
			AccountURL:  "acc://test.acme/account",
			IdentityURL: "acc://test.acme",
			KeyBook:     "acc://test.acme/book",
		}

		if identity.AccountURL != "acc://test.acme/account" {
			t.Errorf("Expected AccountURL 'acc://test.acme/account', got '%s'", identity.AccountURL)
		}

		if identity.IdentityURL != "acc://test.acme" {
			t.Errorf("Expected IdentityURL 'acc://test.acme', got '%s'", identity.IdentityURL)
		}

		if identity.KeyBook != "acc://test.acme/book" {
			t.Errorf("Expected KeyBook 'acc://test.acme/book', got '%s'", identity.KeyBook)
		}
	})
}
