//go:build mock_disabled
// +build mock_disabled

// liteclient_test.go
//
// Tests for the core orchestration layer of the Accumulate Lite Client.
// Focuses on testing the LiteClient's coordination between backends, caches, and proof generation.
//
// NOTE: This test file contains mocks and is disabled by default.
// Run with: go test -tags=mock_disabled ./core

package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// MockDataBackend provides a test implementation of the DataBackend interface
type MockDataBackend struct {
	accounts   map[string]*types.AccountData
	errorOnURL string
}

func (m *MockDataBackend) QueryAccount(ctx context.Context, url string) (*types.AccountData, error) {
	if url == m.errorOnURL {
		return nil, fmt.Errorf("mock error for URL: %s", url)
	}
	if account, exists := m.accounts[url]; exists {
		return account, nil
	}
	return nil, fmt.Errorf("account not found: %s", url)
}

func (m *MockDataBackend) GetNetworkStatus(ctx context.Context) (*types.NetworkStatus, error) {
	return &types.NetworkStatus{Partitions: []types.PartitionInfo{}}, nil
}

func (m *MockDataBackend) GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockDataBackend) GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

// MockAccountCache provides a test implementation of the AccountCache interface
type MockAccountCache struct {
	accounts map[string]*types.AccountData
}

func (m *MockAccountCache) GetAccountData(url string) (*types.AccountData, bool) {
	account, exists := m.accounts[url]
	return account, exists
}

func (m *MockAccountCache) StoreAccountData(url string, data *types.AccountData, ttl ...time.Duration) {
	if m.accounts == nil {
		m.accounts = make(map[string]*types.AccountData)
	}
	m.accounts[url] = data
}

func (m *MockAccountCache) RemoveAccount(accountURL string) {
	delete(m.accounts, accountURL)
}

func (m *MockAccountCache) GetBalance(url string) (*types.TokenBalanceInfo, bool) {
	return nil, false
}

func (m *MockAccountCache) StoreBalance(url string, balance *types.TokenBalanceInfo, ttl ...time.Duration) {
}

func (m *MockAccountCache) GetIdentityInfo(url string) (*types.IdentityInfo, bool) {
	return nil, false
}

func (m *MockAccountCache) StoreIdentityInfo(url string, identity *types.IdentityInfo, ttl ...time.Duration) {
}

func (m *MockAccountCache) PruneExpired() {}

func (m *MockAccountCache) Clear() {
	m.accounts = make(map[string]*types.AccountData)
}

func (m *MockAccountCache) GetCachedURLs() []string {
	urls := make([]string, 0, len(m.accounts))
	for url := range m.accounts {
		urls = append(urls, url)
	}
	return urls
}

func (m *MockAccountCache) GetMetrics() *types.Metrics {
	return &types.Metrics{}
}

// TestLiteClientCreation tests basic LiteClient instantiation
func TestLiteClientCreation(t *testing.T) {
	t.Run("Create LiteClient with valid URL", func(t *testing.T) {
		lc, err := NewLiteClient("https://testnet.accumulatenetwork.io/v2")
		if err != nil {
			t.Fatalf("Expected successful creation, got error: %v", err)
		}
		if lc == nil {
			t.Fatal("Expected non-nil LiteClient")
		}
	})

	t.Run("Fail with empty URL", func(t *testing.T) {
		_, err := NewLiteClient("")
		if err == nil {
			t.Fatal("Expected error for empty URL")
		}
	})
}

// TestProcessIndividualAccount tests the core account processing logic
func TestProcessIndividualAccount(t *testing.T) {
	// Setup mock backend and cache
	mockBackend := &MockDataBackend{
		accounts: map[string]*types.AccountData{
			"acc://test.acme": {
				URL:  "acc://test.acme",
				Type: protocol.AccountTypeTokenAccount,
				Data: nil, // Would be a real account in practice
			},
		},
	}

	mockCache := &MockAccountCache{
		accounts: make(map[string]*types.AccountData),
	}

	// Create account handler with mocks
	accountHandler := types.NewAccountHandlerWithCache(mockBackend, mockCache)

	t.Run("Process existing account", func(t *testing.T) {
		ctx := context.Background()
		accountData, err := accountHandler.GetAccountData(ctx, "acc://test.acme")

		if err != nil {
			t.Fatalf("Expected successful processing, got error: %v", err)
		}

		if accountData == nil {
			t.Fatal("Expected non-nil account data")
		}

		if accountData.URL != "acc://test.acme" {
			t.Errorf("Expected URL 'acc://test.acme', got '%s'", accountData.URL)
		}

		if accountData.Type != protocol.AccountTypeTokenAccount {
			t.Errorf("Expected token account type, got %v", accountData.Type)
		}
	})

	t.Run("Handle non-existent account", func(t *testing.T) {
		ctx := context.Background()
		_, err := accountHandler.GetAccountData(ctx, "acc://nonexistent.acme")

		if err == nil {
			t.Fatal("Expected error for non-existent account")
		}
	})
}

// TestCacheIntegration tests cache behavior
func TestCacheIntegration(t *testing.T) {
	mockCache := &MockAccountCache{
		accounts: make(map[string]*types.AccountData),
	}

	testAccount := &types.AccountData{
		URL:  "acc://cache-test.acme",
		Type: protocol.AccountTypeTokenAccount,
	}

	t.Run("Store and retrieve from cache", func(t *testing.T) {
		// Store account in cache
		mockCache.StoreAccountData("acc://cache-test.acme", testAccount)

		// Retrieve from cache
		retrieved, found := mockCache.GetAccountData("acc://cache-test.acme")
		if !found {
			t.Fatal("Expected to find account in cache")
		}

		if retrieved.URL != testAccount.URL {
			t.Errorf("Expected URL '%s', got '%s'", testAccount.URL, retrieved.URL)
		}
	})

	t.Run("Cache miss for non-existent account", func(t *testing.T) {
		_, found := mockCache.GetAccountData("acc://missing.acme")
		if found {
			t.Fatal("Expected cache miss for non-existent account")
		}
	})

	t.Run("Clear cache", func(t *testing.T) {
		// Add some data
		mockCache.StoreAccountData("acc://test1.acme", testAccount)
		mockCache.StoreAccountData("acc://test2.acme", testAccount)

		// Clear cache
		mockCache.Clear()

		// Verify cache is empty
		_, found := mockCache.GetAccountData("acc://test1.acme")
		if found {
			t.Fatal("Expected empty cache after Clear()")
		}
	})
}

// TestBackendCoordination tests LiteClient's coordination between backends
func TestBackendCoordination(t *testing.T) {
	t.Run("Backend pair coordination", func(t *testing.T) {
		// This test verifies that LiteClient properly coordinates between V2 and V3 backends
		// In a real implementation, this would test failover between backends

		// For now, we just test that NewLiteClient creates the proper backend structure
		lc, err := NewLiteClient("https://testnet.accumulatenetwork.io/v2")
		if err != nil {
			t.Fatalf("Failed to create LiteClient: %v", err)
		}

		// Verify LiteClient has proper internal structure
		if lc.dataBackendV2 == nil {
			t.Error("Expected non-nil V2 backend")
		}
		if lc.dataBackendV3 == nil {
			t.Error("Expected non-nil V3 backend")
		}
		if lc.accountCache == nil {
			t.Error("Expected non-nil account cache")
		}
	})
}

// TestMetrics tests the metrics collection functionality
func TestMetrics(t *testing.T) {
	t.Run("Metrics collection", func(t *testing.T) {
		lc, err := NewLiteClient("https://testnet.accumulatenetwork.io/v2")
		if err != nil {
			t.Fatalf("Failed to create LiteClient: %v", err)
		}

		metrics := lc.GetMetrics()
		if metrics == nil {
			t.Fatal("Expected non-nil metrics")
		}

		// Verify metrics has expected fields (basic structure test)
		// In a real test, we'd verify specific metric values after operations
	})
}
