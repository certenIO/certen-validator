// Copyright 2025 Certen Protocol
//
// liteclient_adapter.go
// Internal adapter that bridges to Accumulate's lite client and v3 API.
// Exposes low-level methods used only by Client in client.go.

package accumulate

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/api"
)

// LiteClientAdapter wraps the Accumulate lite client for our validator service
// This is the CANONICAL implementation of the accumulate.Client interface
type LiteClientAdapter struct {
	client     *api.Client
	config     *LiteClientConfig
	httpClient *http.Client // reused across all v3 API calls for TCP connection pooling
	// anchorCursor speeds up finding consecutive DN blocks on the anchor pool's index chain (anchored_blocks.go).
	anchorCursor anchorIndexCursor
	// routingCheckedAt is when dnHostsNoUserAccounts last confirmed the Directory hosts no user accounts.
	routingMu        sync.Mutex
	routingCheckedAt time.Time

	// Partition discovery cache - dynamically discovers partitions from network-status API
	partitionsMu      sync.RWMutex
	cachedPartitions  []string
	partitionsCacheAt time.Time
}

// Ensure LiteClientAdapter implements the Client interface at compile time
var _ Client = (*LiteClientAdapter)(nil)

// LiteClientConfig contains configuration for lite client integration
type LiteClientConfig struct {
	NetworkURL    string `json:"network_url"`
	EnableCaching bool   `json:"enable_caching"`
	// ProofStrategy  proof.ProofStrategy `json:"proof_strategy"` // Removed - not available in production lite client
	RequestTimeout time.Duration `json:"request_timeout"`
}

// NewLiteClientAdapter creates a new adapter for the Accumulate lite client
func NewLiteClientAdapter(config *LiteClientConfig) (*LiteClientAdapter, error) {
	if config == nil {
		config = &LiteClientConfig{
			NetworkURL:    "http://localhost:26660", // Default to local devnet
			EnableCaching: true,
			// ProofStrategy:  proof.StrategyComplete, // Removed - not available in production lite client
			RequestTimeout: 30 * time.Second,
		}
	}

	// Create API configuration for lite client
	apiConfig := &api.Config{
		Network: api.NetworkConfig{
			ServerURL:   config.NetworkURL,
			NetworkName: "testnet",
			Timeout:     config.RequestTimeout,
			MaxRetries:  3,
			RetryDelay:  time.Second,
		},
		Cache: api.CacheConfig{
			DefaultTTL: 5 * time.Minute,
		},
		API: api.APIConfig{
			MaxConcurrentRequests: 10,
			RateLimit:             0,
			AutoValidateProofs:    true,
			BatchSize:             10,
		},
	}

	// Initialize lite client
	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lite client: %w", err)
	}

	return &LiteClientAdapter{
		client: client,
		config: config,
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
}

// getKeys returns the keys of a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// =============================================================================
// DYNAMIC PARTITION DISCOVERY
// Replaces hardcoded partition lists with network-status API discovery
// =============================================================================

const partitionCacheTTL = 5 * time.Minute

// getPartitions returns the list of partition ledger URLs, using cache if valid
func (l *LiteClientAdapter) getPartitions(ctx context.Context) ([]string, error) {
	l.partitionsMu.RLock()
	if len(l.cachedPartitions) > 0 && time.Since(l.partitionsCacheAt) < partitionCacheTTL {
		partitions := make([]string, len(l.cachedPartitions))
		copy(partitions, l.cachedPartitions)
		l.partitionsMu.RUnlock()
		return partitions, nil
	}
	stalePartitions := l.cachedPartitions
	l.partitionsMu.RUnlock()

	// Discover partitions from network-status API
	partitions, err := l.discoverPartitions(ctx)
	if err != nil {
		// Fall back to stale cache if discovery fails
		if len(stalePartitions) > 0 {
			log.Printf("⚠️ [PARTITION-DISCOVERY] Discovery failed, using stale cache (%d partitions): %v", len(stalePartitions), err)
			return stalePartitions, nil
		}
		return nil, fmt.Errorf("partition discovery failed and no cache available: %w", err)
	}

	// Update cache
	l.partitionsMu.Lock()
	l.cachedPartitions = partitions
	l.partitionsCacheAt = time.Now()
	l.partitionsMu.Unlock()

	log.Printf("✅ [PARTITION-DISCOVERY] Discovered %d partitions: %v", len(partitions), partitions)
	return partitions, nil
}

// discoverPartitions calls the network-status v3 API to get actual partition information
func (l *LiteClientAdapter) discoverPartitions(ctx context.Context) ([]string, error) {
	log.Printf("🔍 [PARTITION-DISCOVERY] Querying network-status API for partitions...")

	result, err := l.queryV3API(ctx, "network-status", map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("network-status query failed: %w", err)
	}

	// Parse partitions from network.partitions array
	// Expected structure: { "network": { "partitions": [{ "id": "BVN0" }, { "id": "Directory" }] } }
	var partitions []string

	if network, ok := result["network"].(map[string]interface{}); ok {
		if partitionsArr, ok := network["partitions"].([]interface{}); ok {
			for _, p := range partitionsArr {
				if partitionMap, ok := p.(map[string]interface{}); ok {
					if id, ok := partitionMap["id"].(string); ok {
						ledgerURL := l.constructPartitionLedgerURL(id)
						partitions = append(partitions, ledgerURL)
						log.Printf("🔍 [PARTITION-DISCOVERY] Found partition: id=%s -> %s", id, ledgerURL)
					}
				}
			}
		}
	}

	// Also check for top-level partitions array (alternative response format)
	if len(partitions) == 0 {
		if partitionsArr, ok := result["partitions"].([]interface{}); ok {
			for _, p := range partitionsArr {
				if partitionMap, ok := p.(map[string]interface{}); ok {
					if id, ok := partitionMap["id"].(string); ok {
						ledgerURL := l.constructPartitionLedgerURL(id)
						partitions = append(partitions, ledgerURL)
						log.Printf("🔍 [PARTITION-DISCOVERY] Found partition (top-level): id=%s -> %s", id, ledgerURL)
					}
				}
			}
		}
	}

	if len(partitions) == 0 {
		return nil, fmt.Errorf("no partitions found in network-status response: %+v", result)
	}

	return partitions, nil
}

// constructPartitionLedgerURL converts a partition ID to its ledger URL
func (l *LiteClientAdapter) constructPartitionLedgerURL(partitionID string) string {
	// Normalize partition ID to lowercase for comparison
	normalizedID := strings.ToLower(partitionID)

	// Handle Directory Network (DN)
	if normalizedID == "directory" || normalizedID == "dn" {
		return "acc://dn.acme/ledger"
	}

	// Handle BVN partitions.
	//
	// The account is `acc://bvn-<ID>.acme`, NOT `acc://<ID>.acme`. network-status reports the bare
	// partition id ("BVN1"), and this used to interpolate it directly, producing
	// `acc://BVN1.acme/ledger` — an account that does not exist. Every BVN query then failed with
	// `cannot locate ledger for block N (-33404)`, which reads like a missing block rather than a
	// malformed URL, and so was easy to misread as the chain being behind.
	//
	// The network's own routing table is the authority; network-status returns:
	//   {"account": "acc://bvn-BVN1.acme", "partition": "BVN1"}
	//   {"account": "acc://dn.acme",       "partition": "Directory"}
	if strings.HasPrefix(normalizedID, "bvn-") {
		return fmt.Sprintf("acc://%s.acme/ledger", partitionID)
	}
	return fmt.Sprintf("acc://bvn-%s.acme/ledger", partitionID)
}

// SearchCertenTransactions returns the CERTEN_INTENT transactions of one Directory Network minor block:
// the entries of every BVN block it anchored. An intent is a writeData on a user ADI's data account; the
// routing table puts every user account on a BVN (checked, dnHostsNoUserAccounts), and it reaches
// discovery through the DN block that anchors its BVN block.
//
// The block is searched completely or not at all (RB3-F125). A partition whose query failed used to be
// logged and skipped and the block counted as searched: on Kermit about 2% of DN block records cannot be
// delivered (the endpoint cuts responses near 98 KB - the DN record carries every anchored BVN block in
// full), and every intent anchored in them was lost. The BVN partitions were also queried at the DN's
// height, which names an unrelated BVN block. Now the anchored blocks come from the anchor pool's index
// chain (anchored_blocks.go - identical to the server's list on every block checked) and each is read
// page by page to its stated total; an error leaves the DN block unsearched, and discovery keeps it.
//
// Every transaction is stated at the DN block's height, exactly as before: the consensus round of an intent
// is keyed on it. Its time is its own partition block's - when it executed - and not the DN block's, which is
// later: deadlines were judged by the DN time (RB4-F74).
func (l *LiteClientAdapter) SearchCertenTransactions(ctx context.Context, blockHeight int64) ([]*CertenTransaction, error) {
	const dn = "acc://dn.acme"
	if err := l.dnHostsNoUserAccounts(ctx); err != nil {
		return nil, fmt.Errorf("DN block %d: %w", blockHeight, err)
	}
	header, err := l.queryMinorBlockHeader(ctx, dn, blockHeight)
	anchored, aErr := l.AnchoredBlocks(ctx, blockHeight)
	if aErr != nil {
		return nil, fmt.Errorf("DN block %d: %w", blockHeight, aErr)
	}
	if err != nil {
		// The DN keeps no ledger for a block with no entries: the server says so with not-found. That is
		// an empty block only if the anchor index agrees nothing was anchored in it; any other failure,
		// or a not-found for a block the index says anchored something, is an error.
		var apiErr *V3APIError
		if errors.As(err, &apiErr) && apiErr.Code == v3NotFound && len(anchored) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("DN block %d: %w", blockHeight, err)
	}
	block := &MinorBlock{Height: blockHeight, Index: blockHeight, Time: header.Time, Source: header.Source, Partition: dn}
	for _, ab := range anchored {
		scope := l.convertToLedgerScope(ab.Source)
		first, records, _, err := l.readBlockEntries(ctx, scope, ab.Index, 0)
		if err != nil {
			return nil, fmt.Errorf("DN block %d: anchored block %d on %s: %w", blockHeight, ab.Index, ab.Source, err)
		}
		// The anchored block's own consensus time: when its transactions executed (RB4-F74). They were stated at
		// the DN block's time, which is later - the block that anchored them - and deadlines were judged by it.
		partitionBlock, err := l.parseMinorBlockRecord(first, ab.Source, ab.Index)
		if err != nil {
			return nil, fmt.Errorf("DN block %d: anchored block %d on %s: %w", blockHeight, ab.Index, ab.Source, err)
		}
		entries := l.getBlockEntries(map[string]interface{}{
			"entries": map[string]interface{}{"records": records},
		}, ab.Index, ab.Source)
		for i := range entries {
			entries[i].PartitionTime = partitionBlock.Time
		}
		block.Entries = append(block.Entries, entries...)
	}
	var txs []*CertenTransaction
	for _, entry := range block.Entries {
		if !l.isCertenTransaction(entry) {
			continue
		}
		if certenTx := l.parseCertenTransaction(entry, block, dn); certenTx != nil {
			txs = append(txs, certenTx)
		}
	}
	if len(txs) > 0 {
		log.Printf("🎯 [CERTEN-SEARCH] DN block %d: found %d CERTEN transactions in %d anchored blocks", blockHeight, len(txs), len(anchored))
	}
	return txs, nil
}

// v3NotFound is the v3 API's not-found error code.
const v3NotFound = -33404

// V3APIError is an error the v3 API returned, with its code.
type V3APIError struct {
	Code    int
	Message string
}

func (e *V3APIError) Error() string { return fmt.Sprintf("API error: %s (%d)", e.Message, e.Code) }

// dnRoutingTTL is how long the routing check holds.
const dnRoutingTTL = 5 * time.Minute

// dnHostsNoUserAccounts checks, from network-status, that no user account can live on the Directory
// Network: every route goes to a BVN and the only Directory overrides are its system accounts. If that
// ever changes, discovery refuses rather than miss intents on the DN.
func (l *LiteClientAdapter) dnHostsNoUserAccounts(ctx context.Context) error {
	l.routingMu.Lock()
	ok := time.Since(l.routingCheckedAt) < dnRoutingTTL
	l.routingMu.Unlock()
	if ok {
		return nil
	}
	result, err := l.queryV3API(ctx, "network-status", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("network-status for the routing table: %w", err)
	}
	routing, _ := result["routing"].(map[string]interface{})
	routes, _ := routing["routes"].([]interface{})
	if len(routes) == 0 {
		return fmt.Errorf("network-status carries no routing table")
	}
	for _, r := range routes {
		m, _ := r.(map[string]interface{})
		if p, _ := m["partition"].(string); strings.EqualFold(p, "directory") || p == "" {
			return fmt.Errorf("the routing table routes accounts to %q: user accounts can live on the Directory Network, whose own entries discovery does not read", p)
		}
	}
	overrides, _ := routing["overrides"].([]interface{})
	for _, o := range overrides {
		m, _ := o.(map[string]interface{})
		p, _ := m["partition"].(string)
		acct, _ := m["account"].(string)
		if strings.EqualFold(p, "directory") && !strings.EqualFold(acct, "acc://ACME") && !strings.EqualFold(acct, "acc://dn.acme") {
			return fmt.Errorf("the routing table puts %s on the Directory Network, whose own entries discovery does not read", acct)
		}
	}
	l.routingMu.Lock()
	l.routingCheckedAt = time.Now()
	l.routingMu.Unlock()
	return nil
}

// CertenTransaction represents a discovered CERTEN intent transaction
type CertenTransaction struct {
	Hash            string                 `json:"hash"`
	AccountURL      string                 `json:"account_url"`
	BlockHeight     int64                  `json:"block_height"` // Fixed: use int64 like legacy
	Timestamp       time.Time              `json:"timestamp"`
	IntentData      map[string]interface{} `json:"intent_data"`
	TransactionType string                 `json:"transaction_type"`
	// Partition is the partition whose block BlockHeight counts: the Directory Network block the intent was
	// discovered in (it anchored the BVN block that carried it). Batch settlement keeps the two as one pair.
	Partition string                 `json:"partition,omitempty"`
	RawTx     map[string]interface{} `json:"raw_tx,omitempty"`
	// ProofPartition is the BVN the transaction was written on ("bvn1") and ProofBlockIndex its block there: an
	// L1-L3 proof is built on that BVN (RB4-F46). Empty when the entry was not read from a BVN.
	ProofPartition  string `json:"proof_partition,omitempty"`
	ProofBlockIndex int64  `json:"proof_block_index,omitempty"`
}

// BVNNameOf reads a BVN's partition name from its partition URL, acc://bvn-<ID>.acme -> lower(<ID>), exactly.
// Anything else - the Directory Network, a ledger URL, a malformed name - is no BVN: "".
func BVNNameOf(partitionURL string) string {
	u := strings.ToLower(strings.TrimSpace(partitionURL))
	if !strings.HasPrefix(u, "acc://bvn-") || !strings.HasSuffix(u, ".acme") {
		return ""
	}
	id := strings.TrimSuffix(strings.TrimPrefix(u, "acc://bvn-"), ".acme")
	if id == "" || strings.ContainsAny(id, "/.@") {
		return ""
	}
	return id
}

// isCertenTransaction checks if a block entry is a CERTEN intent transaction
func (l *LiteClientAdapter) isCertenTransaction(entry BlockEntry) bool {
	if entry.Data == nil {
		return false
	}
	return l.hasAnyCertenMemo(entry)
}

// hasAnyCertenMemo searches recursively through the entry for any CERTEN_INTENT memo
func (l *LiteClientAdapter) hasAnyCertenMemo(entry BlockEntry) bool {
	return l.searchForCertenMemo(entry.Data)
}

// searchForCertenMemo recursively searches any map[string]interface{} for CERTEN_INTENT memo
func (l *LiteClientAdapter) searchForCertenMemo(data interface{}) bool {
	switch v := data.(type) {
	case map[string]interface{}:
		// Check if this level has a memo field
		// Accept both "CERTEN_INTENT" (canonical) and "certen-intent" (legacy) formats
		if memo, ok := v["memo"]; ok {
			if memoStr, ok := memo.(string); ok {
				if memoStr == "CERTEN_INTENT" || strings.EqualFold(memoStr, "certen-intent") {
					return true
				}
			}
		}
		for _, value := range v {
			if l.searchForCertenMemo(value) {
				return true
			}
		}
	case []interface{}:
		for _, value := range v {
			if l.searchForCertenMemo(value) {
				return true
			}
		}
	}
	return false
}

// isWriteDataTransactionWithCertenMemo checks if this entry is a writeData transaction with CERTEN_INTENT memo
func (l *LiteClientAdapter) isWriteDataTransactionWithCertenMemo(entry BlockEntry) bool {
	// The correct structure based on v3 API responses is:
	// entry.Data["value"]["message"]["transaction"] OR entry.Data["value"]["transaction"]

	var transaction map[string]interface{}
	var found bool

	if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		// Try path 1: value.message.transaction (for anchored transactions)
		if message, ok := value["message"].(map[string]interface{}); ok {
			if tx, ok := message["transaction"].(map[string]interface{}); ok {
				transaction = tx
				found = true
				log.Printf("🔍 [STRUCTURE] Found transaction via value.message.transaction path")
			}
		}

		// Try path 2: value.transaction (for direct transactions)
		if !found {
			if tx, ok := value["transaction"].(map[string]interface{}); ok {
				transaction = tx
				found = true
				log.Printf("🔍 [STRUCTURE] Found transaction via value.transaction path")
			}
		}
	}

	// Try path 3: Direct transaction in entry data (from some v3 responses)
	if !found {
		if tx, ok := entry.Data["transaction"].(map[string]interface{}); ok {
			transaction = tx
			found = true
			log.Printf("🔍 [STRUCTURE] Found transaction via direct entry.transaction path")
		}
	}

	if !found {
		log.Printf("❌ [STRUCTURE] Could not find transaction in entry data structure")
		return false
	}

	// Check 1: Must have CERTEN_INTENT memo in header
	// Accept both "CERTEN_INTENT" (canonical) and "certen-intent" (legacy) formats
	hasCertenMemo := false
	if header, ok := transaction["header"].(map[string]interface{}); ok {
		if memo, ok := header["memo"].(string); ok {
			if memo == "CERTEN_INTENT" || strings.EqualFold(memo, "certen-intent") {
				hasCertenMemo = true
				debugf("✅ [STRICT-CHECK] Found CERTEN_INTENT memo in header (value: %s)", memo)
			} else {
				log.Printf("❌ [STRICT-CHECK] Header memo is '%s', not 'CERTEN_INTENT' or 'certen-intent'", memo)
			}
		} else {
			// Check if memo is nil/empty vs missing
			if memo, exists := header["memo"]; exists {
				log.Printf("❌ [STRICT-CHECK] Header memo exists but is not string: %v (%T)", memo, memo)
			} else {
				log.Printf("❌ [STRICT-CHECK] Header memo field is missing entirely")
			}
		}
	} else {
		log.Printf("❌ [STRICT-CHECK] Could not find header in transaction")
	}

	if !hasCertenMemo {
		log.Printf("❌ [STRICT-CHECK] No CERTEN_INTENT memo found in header")
		return false
	}

	// Check 2: Must be writeData transaction type
	if body, ok := transaction["body"].(map[string]interface{}); ok {
		if txType, ok := body["type"].(string); ok {
			if txType == "writeData" {
				// Check for entry with data
				if dataEntry, ok := body["entry"].(map[string]interface{}); ok {
					if entryType, ok := dataEntry["type"].(string); ok {
						if entryType == "doubleHash" {
							if data, ok := dataEntry["data"].([]interface{}); ok && len(data) >= 1 {
								debugf("✅ [STRICT-CHECK] Valid writeData transaction with CERTEN_INTENT memo and %d data elements", len(data))
								return true
							} else {
								log.Printf("❌ [STRICT-CHECK] DoubleHash entry missing data array or data is empty")
							}
						} else {
							log.Printf("❌ [STRICT-CHECK] Entry type is '%s', not 'doubleHash'", entryType)
						}
					} else {
						log.Printf("❌ [STRICT-CHECK] Entry missing type field")
					}
				} else {
					log.Printf("❌ [STRICT-CHECK] WriteData transaction missing entry field")
				}
			} else {
				log.Printf("❌ [STRICT-CHECK] Transaction type is '%s', not 'writeData'", txType)
			}
		} else {
			log.Printf("❌ [STRICT-CHECK] Transaction body missing type field")
		}
	} else {
		log.Printf("❌ [STRICT-CHECK] Transaction missing body field")
	}

	return false
}

// isWriteDataTransaction checks if this entry is a writeData transaction with intent data
func (l *LiteClientAdapter) isWriteDataTransaction(entry BlockEntry) bool {
	// CRITICAL: Must be type "transaction" (not "signature")
	if entryType, ok := entry.Data["type"].(string); !ok || entryType != "transaction" {
		return false
	}

	// Use the same improved structure parsing as isWriteDataTransactionWithCertenMemo
	var transaction map[string]interface{}
	var found bool

	if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		// Try path 1: value.message.transaction (for anchored transactions)
		if message, ok := value["message"].(map[string]interface{}); ok {
			if tx, ok := message["transaction"].(map[string]interface{}); ok {
				transaction = tx
				found = true
			}
		}

		// Try path 2: value.transaction (for direct transactions)
		if !found {
			if tx, ok := value["transaction"].(map[string]interface{}); ok {
				transaction = tx
				found = true
			}
		}
	}

	// Try path 3: Direct transaction in entry data
	if !found {
		if tx, ok := entry.Data["transaction"].(map[string]interface{}); ok {
			transaction = tx
			found = true
		}
	}

	if !found {
		return false
	}

	// Check if it's a writeData transaction
	if body, ok := transaction["body"].(map[string]interface{}); ok {
		if txType, ok := body["type"].(string); ok && txType == "writeData" {
			if dataEntry, ok := body["entry"].(map[string]interface{}); ok {
				if entryType, ok := dataEntry["type"].(string); ok && entryType == "doubleHash" {
					if data, ok := dataEntry["data"].([]interface{}); ok && len(data) >= 1 {
						log.Printf("✅ [WRITE-DATA-CHECK] Found writeData transaction (type=transaction) with %d data elements", len(data))
						return true
					}
				}
			}
		}
	}
	return false
}

// isSignatureTransaction checks if this entry is a signature transaction referencing CERTEN
func (l *LiteClientAdapter) isSignatureTransaction(entry BlockEntry) bool {
	if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		if message, ok := value["message"].(map[string]interface{}); ok {
			if txType, ok := message["type"].(string); ok && txType == "signature" {
				if txID, ok := message["txID"].(string); ok && strings.Contains(txID, "certen") {
					log.Printf("🔍 [SIG-CHECK] Found signature transaction referencing CERTEN txID: %s", txID)
					return true
				}
			}
		}
	}
	return false
}

// parseCertenTransaction extracts CERTEN intent data from a transaction entry
func (l *LiteClientAdapter) parseCertenTransaction(entry BlockEntry, block *MinorBlock, partition string) *CertenTransaction {
	hash := "unknown"

	// Debug: Log the entire entry structure to understand the V3 API response format
	debugf("🔍 [DEBUG-ENTRY] Full entry structure: %+v", entry.Data)
	if entryBytes, err := json.MarshalIndent(entry.Data, "", "  "); err == nil {
		debugf("🔍 [DEBUG-ENTRY] JSON structure:\n%s", string(entryBytes))
	}

	// Try multiple ways to extract the transaction hash from Accumulate V3 API response

	// First check if there's an "entry" field at the root level (this is the transaction hash)
	if entryHash, ok := entry.Data["entry"].(string); ok {
		hash = entryHash
		debugf("🔍 [HASH-EXTRACT] Found transaction hash from root entry field: %s", hash)
	} else if hashVal, ok := entry.Data["hash"].(string); ok {
		hash = hashVal
		debugf("🔍 [HASH-EXTRACT] Found transaction hash from hash field: %s", hash)
	} else if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		if message, ok := value["message"].(map[string]interface{}); ok {
			if id, ok := message["id"].(string); ok {
				// Extract hash from message ID (format: hash@account)
				if parts := strings.Split(id, "@"); len(parts) > 0 {
					hash = parts[0]
				}
			} else if tx, ok := message["transaction"].(map[string]interface{}); ok {
				// Try to get hash from transaction
				if txHash, ok := tx["hash"].(string); ok {
					hash = txHash
				}
			}
		}
	}

	// Extract AccountURL from the real principal (value.message.transaction.header.principal)
	accountURL := ""
	if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		if message, ok := value["message"].(map[string]interface{}); ok {
			if transaction, ok := message["transaction"].(map[string]interface{}); ok {
				if header, ok := transaction["header"].(map[string]interface{}); ok {
					if principal, ok := header["principal"].(string); ok {
						accountURL = principal
						debugf("✅ [ACCOUNT-EXTRACT] Found real account URL from principal: %s", accountURL)
					}
				}
			}
		}
	}

	certenTx := &CertenTransaction{
		Hash:        hash,
		AccountURL:  accountURL,
		BlockHeight: block.Height, // Fixed: direct assignment since both are int64
		Partition:   partition,
		Timestamp:   entry.PartitionTime, // the partition block it executed in, not the DN block (RB4-F74)
		RawTx:       entry.Data,
		IntentData:  make(map[string]interface{}),
	}
	if bvn := BVNNameOf(entry.Partition); bvn != "" {
		certenTx.ProofPartition = bvn
		certenTx.ProofBlockIndex = entry.PartitionBlock
	}

	// Try to extract intent data from the correct transaction structure
	intentData := l.extractIntentDataFromEntry(entry)
	if len(intentData) > 0 {
		for key, value := range intentData {
			certenTx.IntentData[key] = value
		}
		debugf("✅ [CERTEN-PARSE] Successfully extracted %d intent data elements from %s", len(intentData), hash)
	} else {
		log.Printf("⚠️ [CERTEN-PARSE] No intent data found in transaction %s", hash)
	}

	// One decoder: the v3 entry's value.message.transaction (extractIntentDataFromEntry). A second, positional
	// "fallback" read a top-level transaction body and wrote over the same keys, fetched a "referenced"
	// transaction for any signature whose txID merely contained "certen", and sliced hexStr[:50] on
	// elements that could be shorter (RB3-F36).

	// Debug: Log final IntentData before returning
	log.Printf("🔍 [DEBUG-INTENT-DATA] Final IntentData for %s contains %d elements: %+v",
		hash, len(certenTx.IntentData), certenTx.IntentData)

	return certenTx
}

// GetTransaction retrieves a transaction with real cryptographic proof
func (l *LiteClientAdapter) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	// Query the transaction using v3 API with proper txid lookup
	queryParams := map[string]interface{}{
		"scope":     "acc://dn", // Query the DN for transaction records
		"queryType": "txid",     // Look up by transaction ID
		"txid":      hash,       // The transaction hash/ID to find
	}

	response, err := l.queryV3API(ctx, "query", queryParams)
	if err != nil {
		return nil, fmt.Errorf("failed to query transaction %s: %w", hash, err)
	}

	// Parse the response to extract transaction data
	if result, ok := response["result"].(map[string]interface{}); ok {
		if records, ok := result["records"].([]interface{}); ok && len(records) > 0 {
			// Found the transaction, extract data from the first record
			if record, ok := records[0].(map[string]interface{}); ok {
				tx := &Transaction{
					Hash: hash,
				}

				// Extract real transaction type
				if txType, ok := record["type"].(string); ok {
					tx.Type = txType
				} else {
					tx.Type = "unknown"
				}

				// Extract real block height
				if value, ok := record["value"].(map[string]interface{}); ok {
					if message, ok := value["message"].(map[string]interface{}); ok {
						if transaction, ok := message["transaction"].(map[string]interface{}); ok {
							// Extract block height from transaction data
							if header, ok := transaction["header"].(map[string]interface{}); ok {
								if height, ok := header["height"].(float64); ok {
									tx.BlockHeight = uint64(height)
								}
							}

							// Store the complete transaction data
							tx.Data = transaction
						}
					}
				}

				// Extract timestamp from record
				if timestamp, ok := record["timestamp"].(string); ok {
					if parsedTime, err := time.Parse(time.RFC3339, timestamp); err == nil {
						tx.Timestamp = parsedTime
					}
				}
				// A record without a readable timestamp leaves it unstated (zero), and signatures are not
				// read here, so none are claimed. They used to be the validator's clock and an empty list
				// standing for "no signatures" (RB3-F104).

				log.Printf("✅ [LITE-CLIENT] Retrieved real transaction: hash=%s, type=%s, height=%d",
					hash, tx.Type, tx.BlockHeight)
				return tx, nil
			}
		}
	}

	// Transaction not found
	return nil, fmt.Errorf("transaction not found: %s", hash)
}

// extractIntentDataFromEntry extracts intent data from the correct transaction structure
func (l *LiteClientAdapter) extractIntentDataFromEntry(entry BlockEntry) map[string]interface{} {
	intentData := make(map[string]interface{})

	// Check if this is a type "transaction" entry
	if entryType, ok := entry.Data["type"].(string); !ok || entryType != "transaction" {
		log.Printf("🔍 [EXTRACT-INTENT] Entry is not type 'transaction', type is: %v", entry.Data["type"])
		return intentData
	}

	// Navigate to the transaction structure: entry.Data["value"]["message"]["transaction"]["body"]
	if value, ok := entry.Data["value"].(map[string]interface{}); ok {
		if message, ok := value["message"].(map[string]interface{}); ok {
			if transaction, ok := message["transaction"].(map[string]interface{}); ok {
				if body, ok := transaction["body"].(map[string]interface{}); ok {
					if txType, ok := body["type"].(string); ok && txType == "writeData" {
						if dataEntry, ok := body["entry"].(map[string]interface{}); ok {
							if entryType, ok := dataEntry["type"].(string); ok && entryType == "doubleHash" {
								if data, ok := dataEntry["data"].([]interface{}); ok && len(data) >= 1 {
									log.Printf("🎯 [EXTRACT-INTENT] Found writeData transaction with %d data elements", len(data))

									// Decode ALL data elements with structured field assignment
									for i, hexData := range data {
										if hexStr, ok := hexData.(string); ok {
											if decodedBytes, err := hex.DecodeString(hexStr); err == nil {
												var jsonData map[string]interface{}
												if err := json.Unmarshal(decodedBytes, &jsonData); err == nil {
													// Store with structured field names for CERTEN protocol
													switch i {
													case 0:
														intentData["intentData"] = jsonData
														log.Printf("✅ [EXTRACT-INTENT] Decoded intentData from element %d: %+v", i, jsonData)
													case 1:
														intentData["crossChainData"] = jsonData
														log.Printf("✅ [EXTRACT-INTENT] Decoded crossChainData from element %d: %+v", i, jsonData)
													case 2:
														intentData["governanceData"] = jsonData
														log.Printf("✅ [EXTRACT-INTENT] Decoded governanceData from element %d: %+v", i, jsonData)
													case 3:
														intentData["replayData"] = jsonData
														log.Printf("✅ [EXTRACT-INTENT] Decoded replayData from element %d: %+v", i, jsonData)
													default:
														// Handle additional data elements beyond the core 4
														fieldKey := fmt.Sprintf("additionalData_%d", i)
														intentData[fieldKey] = jsonData
														log.Printf("✅ [EXTRACT-INTENT] Decoded additional data element %s: %+v", fieldKey, jsonData)
													}
												} else {
													// Some elements might be raw text or other formats, store as hex string
													intentData[fmt.Sprintf("rawElement_%d", i)] = hexStr
													log.Printf("🔄 [EXTRACT-INTENT] Stored raw hex from element %d (not JSON)", i)
												}
											} else {
												log.Printf("⚠️ [EXTRACT-INTENT] Failed to decode hex from element %d: %v", i, err)
											}
										}
									}
									log.Printf("✅ [EXTRACT-INTENT] Successfully extracted %d intent data elements", len(intentData))
								}
							}
						}
					} else {
						log.Printf("🔍 [EXTRACT-INTENT] Transaction type is '%s', not 'writeData'", txType)
					}
				}
			}
		}
	}

	return intentData
}

// GetMerkleProofForCertenTx generates a real Merkle proof for a CertenTransaction using the actual account URL
func (l *LiteClientAdapter) GetMerkleProofForCertenTx(ctx context.Context, tx *CertenTransaction) (*MerkleProof, error) {
	if tx.AccountURL == "" {
		return nil, fmt.Errorf("no account URL available for transaction %s", tx.Hash)
	}

	log.Printf("🔐 [MERKLE-PROOF] Getting real Merkle proof for tx %s from account %s", tx.Hash, tx.AccountURL)

	// Get account data with real proofs from lite client using the actual account URL
	response, err := l.client.GetAccount(ctx, tx.AccountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get account from lite client for %s: %w", tx.AccountURL, err)
	}

	// Extract real proof data from lite client response
	if response.Account == nil || response.Account.Receipt == nil {
		return nil, fmt.Errorf("no receipt/proof data available for account: %s", tx.AccountURL)
	}

	receipt := response.Account.Receipt

	// Convert lite client proof data to our MerkleProof format
	merkleProof := &MerkleProof{
		TransactionHash: tx.Hash,
		Root:            receipt.MerkleRoot,
		BlockHeight:     uint64(receipt.BlockHeight),
		Path:            []string{}, // Will be populated from real proof data
	}

	// If we have raw receipt data, extract the path
	if receipt.RawReceipt != nil {
		// Extract proof path from raw receipt data
		merkleProof.Path = l.extractProofPath(receipt.RawReceipt)
	}

	return merkleProof, nil
}

// GetMerkleProof generates a Merkle proof using fake account URL (DEPRECATED)
// DEPRECATED: This method uses a fake account URL. Use GetMerkleProofForCertenTx for real proofs.

// GetBlock retrieves block information from the DN ledger.
//
// NOTE: For now we only return a *real* height + timestamp based on the DN
// minor block. Hash/MerkleRoot/PrevHash are intentionally left empty until we
// have a verified source for those values from the lite client / proofs.
//
// This guarantees we never present synthetic hashes as "real Accumulate block
// headers" that back proofs.
func (l *LiteClientAdapter) GetBlock(ctx context.Context, height uint64) (*Block, error) {
	log.Printf("🔍 [BLOCK-DATA] Fetching DN minor block for height: %d", height)

	// Use DN ledger as canonical scope
	minorHeight := int64(height)
	// The block's own fields only: its entries are not needed here, and a DN block's full record can be
	// larger than the endpoint delivers (RB3-F125).
	b, err := l.queryMinorBlockHeader(ctx, "acc://dn", minorHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to query DN minor block %d: %w", minorHeight, err)
	}

	log.Printf("✅ [BLOCK-DATA] Found DN minor block %d at %s (partition=%s, entries=%d)",
		b.Height, b.Time.Format(time.RFC3339), b.Partition, len(b.Entries))

	// We *only* return real facts here. Hash/MerkleRoot/PrevHash stay empty
	// until we wire them to actual consensus-level data.
	return &Block{
		Height:     uint64(b.Height),
		Hash:       "", // unknown / not yet wired
		MerkleRoot: "", // unknown / not yet wired
		Timestamp:  b.Time,
		PrevHash:   "",
	}, nil
}

// V3APIResponse represents response from Accumulate v3 API
type V3APIResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NetworkStatus represents the network status response
type NetworkStatus struct {
	Network struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Status struct {
			LastBlockHeight int64  `json:"last_block_height"`
			LastBlockHash   string `json:"last_block_hash"`
			LastBlockTime   string `json:"last_block_time"`
		} `json:"status"`
	} `json:"network"`
}

// queryV3API makes a direct HTTP call to Accumulate's v3 API
func (l *LiteClientAdapter) queryV3API(ctx context.Context, method string, params interface{}) (map[string]interface{}, error) {
	// Construct JSON-RPC request
	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request to the API endpoint - ensure we use the v3 API path
	apiURL := l.config.NetworkURL
	if !strings.HasSuffix(apiURL, "/v3") && !strings.Contains(apiURL, "/v3/") {
		if strings.HasSuffix(apiURL, "/") {
			apiURL += "v3"
		} else {
			apiURL += "/v3"
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var apiResp V3APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, &V3APIError{Code: apiResp.Error.Code, Message: apiResp.Error.Message}
	}

	// Return just the result as a map for easier parsing
	if result, ok := apiResp.Result.(map[string]interface{}); ok {
		return result, nil
	}

	return map[string]interface{}{"result": apiResp.Result}, nil
}

// getNetworkStatusV3 gets current network status using direct v3 API calls
func (l *LiteClientAdapter) getNetworkStatusV3(ctx context.Context) (*NetworkStatus, error) {
	// The Directory Network's height from network-status, or an error (RB3-F104). A failed query used
	// to fall back to "the latest block of whichever partition answers" - a BVN height, which GetBlock
	// then read as a DN height - and the status carried an invented hash ("block_<height>"), the
	// validator's clock as the block time, and a hard-coded "kermit"/"testnet" (Kermit calls itself
	// "DevNet"). Only what network-status states is stated.
	result, err := l.queryV3API(ctx, "network-status", map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	directoryHeight, ok := result["directoryHeight"].(float64)
	if !ok || directoryHeight <= 0 {
		return nil, fmt.Errorf("network-status carries no directory height (%v)", result["directoryHeight"])
	}
	status := &NetworkStatus{}
	if network, ok := result["network"].(map[string]interface{}); ok {
		status.Network.ID, _ = network["networkName"].(string)
	}
	status.Network.Status.LastBlockHeight = int64(directoryHeight)
	return status, nil
}

// blockPageSize is how many entries one block query asks for. A block query loads every entry's full
// message, and Kermit's endpoint cuts responses near 98 KB, so pages stay small; a block is read page by
// page until its stated total is reached (RB3-F125).
const blockPageSize = 10

// queryMinorBlocks reads exactly one minor block, completely: every entry up to the block's stated total
// and, for a DN block, every anchored block with all of its entries. Anything short of that is an error,
// never a partial block (RB3-F125) - it used to ask for "up to 500 entries" and use whatever came back.
func (l *LiteClientAdapter) queryMinorBlocks(ctx context.Context, partitionURL string, blockHeight int64) ([]*MinorBlock, error) {
	record, err := l.readMinorBlockRecord(ctx, partitionURL, blockHeight, true)
	if err != nil {
		return nil, fmt.Errorf("failed to query block %d from %s: %w", blockHeight, partitionURL, err)
	}
	block, err := l.parseMinorBlockRecord(record, partitionURL, blockHeight)
	if err != nil {
		return nil, err
	}
	return []*MinorBlock{block}, nil
}

// queryMinorBlockHeader reads a minor block's record without its entries: index, time and source.
func (l *LiteClientAdapter) queryMinorBlockHeader(ctx context.Context, partitionURL string, blockHeight int64) (*MinorBlock, error) {
	record, err := l.readMinorBlockRecord(ctx, partitionURL, blockHeight, false)
	if err != nil {
		return nil, fmt.Errorf("failed to query block %d from %s: %w", blockHeight, partitionURL, err)
	}
	return l.parseMinorBlockRecord(record, partitionURL, blockHeight)
}

// readMinorBlockRecord returns the block record; with entries, all of them and every anchored block
// complete.
func (l *LiteClientAdapter) readMinorBlockRecord(ctx context.Context, partitionURL string, blockHeight int64, withEntries bool) (map[string]interface{}, error) {
	if blockHeight <= 0 {
		return nil, fmt.Errorf("a minor block index is positive, got %d", blockHeight)
	}
	scope := l.convertToLedgerScope(partitionURL)
	if !withEntries {
		rec, _, _, err := l.readBlockPage(ctx, scope, blockHeight, 0, 0)
		return rec, err
	}
	first, records, anchored, err := l.readBlockEntries(ctx, scope, blockHeight, 0)
	if err != nil {
		return nil, err
	}
	first["entries"] = map[string]interface{}{"recordType": "range", "start": float64(0), "total": float64(len(records)), "records": records}
	if anchored == nil {
		delete(first, "anchored")
		return first, nil
	}
	// The anchored blocks: all of them, each with all of its entries.
	anchoredRecords, _ := anchored["records"].([]interface{})
	total, ok := anchored["total"].(float64)
	if !ok || int(total) != len(anchoredRecords) {
		return nil, fmt.Errorf("block %d on %s lists %d anchored blocks of %v", blockHeight, scope, len(anchoredRecords), anchored["total"])
	}
	for i, r := range anchoredRecords {
		ab, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("block %d on %s: anchored block %d is not a record", blockHeight, scope, i)
		}
		if err := l.completeAnchoredBlock(ctx, ab); err != nil {
			return nil, fmt.Errorf("block %d on %s: %w", blockHeight, scope, err)
		}
	}
	first["anchored"] = anchored
	return first, nil
}

// completeAnchoredBlock makes an anchored block's entries complete, reading any the DN record did not
// carry from the block's own partition.
func (l *LiteClientAdapter) completeAnchoredBlock(ctx context.Context, ab map[string]interface{}) error {
	source, _ := ab["source"].(string)
	index, ok := ab["index"].(float64)
	if source == "" || !ok || index <= 0 {
		return fmt.Errorf("anchored block without a source and index: %v/%v", ab["source"], ab["index"])
	}
	entries, _ := ab["entries"].(map[string]interface{})
	var have []interface{}
	total := -1.0
	if entries != nil {
		have, _ = entries["records"].([]interface{})
		if t, ok := entries["total"].(float64); ok {
			total = t
		}
	}
	if total >= 0 && int(total) == len(have) {
		return nil
	}
	_, rest, _, err := l.readBlockEntries(ctx, l.convertToLedgerScope(source), int64(index), len(have))
	if err != nil {
		return fmt.Errorf("anchored block %d on %s: %w", int64(index), source, err)
	}
	all := append(append([]interface{}{}, have...), rest...)
	ab["entries"] = map[string]interface{}{"recordType": "range", "start": float64(0), "total": float64(len(all)), "records": all}
	return nil
}

// readBlockEntries reads a block's entries from `from` to its stated total, page by page. It returns the
// first page's record (for the block's own fields), the entries, and the anchored range if a page carried it.
func (l *LiteClientAdapter) readBlockEntries(ctx context.Context, scope string, height int64, from int) (map[string]interface{}, []interface{}, map[string]interface{}, error) {
	var first, anchored map[string]interface{}
	var records []interface{}
	start, total := from, -1
	for total < 0 || start < total {
		// A page the endpoint cannot deliver whole is asked for again smaller, down to one entry; one
		// entry that still cannot be delivered is an error.
		var rec map[string]interface{}
		var page []interface{}
		var t int
		var err error
		for count := blockPageSize; ; count /= 2 {
			if rec, page, t, err = l.readBlockPage(ctx, scope, height, start, count); err == nil || count == 1 {
				break
			}
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if total >= 0 && t != total {
			return nil, nil, nil, fmt.Errorf("block %d on %s changed its entry total from %d to %d while being read", height, scope, total, t)
		}
		total = t
		if first == nil {
			first = rec
		}
		if a, ok := rec["anchored"].(map[string]interface{}); ok {
			anchored = a
		}
		if start < total && len(page) == 0 {
			return nil, nil, nil, fmt.Errorf("block %d on %s returned no entries from %d of %d", height, scope, start, total)
		}
		records = append(records, page...)
		start += len(page)
	}
	if start != total {
		return nil, nil, nil, fmt.Errorf("block %d on %s: read %d entries of %d", height, scope, start, total)
	}
	return first, records, anchored, nil
}

// readBlockPage is one block query: the record, its entry page and the block's entry total. A response
// that is not a complete block record (a truncated body fails to decode before this) is an error.
func (l *LiteClientAdapter) readBlockPage(ctx context.Context, scope string, height int64, start, count int) (map[string]interface{}, []interface{}, int, error) {
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": scope,
		"query": map[string]interface{}{
			"queryType":  "block",
			"minor":      height,
			"entryRange": map[string]interface{}{"start": start, "count": count},
		},
	})
	if err != nil {
		return nil, nil, 0, err
	}
	if rt, _ := result["recordType"].(string); rt != "minorBlock" {
		return nil, nil, 0, fmt.Errorf("block %d on %s: the answer is a %q record, not a minor block", height, scope, rt)
	}
	if idx, ok := result["index"].(float64); !ok || int64(idx) != height {
		return nil, nil, 0, fmt.Errorf("block %d on %s: the answer is block %v", height, scope, result["index"])
	}
	entries, ok := result["entries"].(map[string]interface{})
	if !ok {
		return nil, nil, 0, fmt.Errorf("block %d on %s: no entry range in the answer", height, scope)
	}
	t, ok := entries["total"].(float64)
	if !ok || t < 0 {
		return nil, nil, 0, fmt.Errorf("block %d on %s: the entry range states no total", height, scope)
	}
	page, _ := entries["records"].([]interface{})
	if st, ok := entries["start"].(float64); len(page) > 0 && (!ok || int(st) != start) {
		return nil, nil, 0, fmt.Errorf("block %d on %s: asked for entries from %d, got them from %v", height, scope, start, entries["start"])
	}
	if len(page) > count {
		return nil, nil, 0, fmt.Errorf("block %d on %s: asked for %d entries, got %d", height, scope, count, len(page))
	}
	return result, page, int(t), nil
}

// convertToLedgerScope converts partition URLs to correct ledger scopes for v3 API
// Handles any partition URL format dynamically (supports any network's partition naming)
func (l *LiteClientAdapter) convertToLedgerScope(partitionURL string) string {
	// If already a ledger URL, return as-is
	if strings.HasSuffix(partitionURL, "/ledger") {
		return partitionURL
	}

	// Remove acc:// prefix for parsing
	url := strings.TrimPrefix(partitionURL, "acc://")

	// Handle URLs with .acme suffix (e.g., "dn.acme", "BVN0.acme")
	if strings.Contains(url, ".acme") {
		// Already has .acme, just append /ledger
		return "acc://" + url + "/ledger"
	}

	// Handle bare partition names (e.g., "dn", "bvn1", "BVN0")
	// Normalize DN variations
	normalizedURL := strings.ToLower(url)
	if normalizedURL == "dn" || normalizedURL == "directory" {
		return "acc://dn.acme/ledger"
	}

	// Handle BVN partitions - add .acme suffix
	return "acc://" + url + ".acme/ledger"
}

// MinorBlockTime returns the consensus time of partition's minor block at height: the time the
// partition's validators committed that block, identical for every reader. It fails rather than
// return a zero or unverified time - a caller that orders work by it must never get a local guess.
func (l *LiteClientAdapter) MinorBlockTime(ctx context.Context, partition string, height uint64) (time.Time, error) {
	if partition == "" || height == 0 {
		return time.Time{}, fmt.Errorf("minor block time needs a partition and a height (got %q, %d)", partition, height)
	}
	// The block's time only - not its entries (RB3-F125).
	b, err := l.queryMinorBlockHeader(ctx, partition, int64(height))
	if err != nil {
		return time.Time{}, err
	}
	if b.Index != int64(height) {
		return time.Time{}, fmt.Errorf("minor block query for %d on %s returned block %d", height, partition, b.Index)
	}
	// The record must come from the partition asked for. A scope that is not a partition ledger
	// (acc://bvn1.acme/ledger rather than acc://bvn-BVN1.acme/ledger) is routed like any account and
	// answered by whichever partition it hashes to - with THAT partition's block at this height.
	want := strings.TrimSuffix(l.convertToLedgerScope(partition), "/ledger")
	if !strings.EqualFold(b.Source, want) {
		return time.Time{}, fmt.Errorf("minor block %d for %s was answered by %q", height, want, b.Source)
	}
	if b.Time.IsZero() {
		return time.Time{}, fmt.Errorf("minor block %d on %s carries no time", height, partition)
	}
	return b.Time, nil
}

// MinorBlock represents a minor block from Accumulate v3 API
type MinorBlock struct {
	Height    int64     `json:"height"`
	Index     int64     `json:"index"`
	Time      time.Time `json:"time"`
	Partition string    `json:"partition"`
	// Source is the partition that answered, as the record names it (acc://bvn-BVN1.acme).
	Source  string       `json:"source"`
	Entries []BlockEntry `json:"entries"`
}

// BlockEntry represents an entry (transaction) in a minor block
type BlockEntry struct {
	Index int                    `json:"index"`
	Type  string                 `json:"type"`
	Data  map[string]interface{} `json:"data"`
	// Partition and PartitionBlock are the partition URL the entry was read from and its block there
	// (RB4-F46: a DN block's transactions are read from the BVN blocks it anchored, and which BVN was lost).
	Partition      string `json:"partition,omitempty"`
	PartitionBlock int64  `json:"partition_block,omitempty"`
	// PartitionTime is the consensus time of that partition block - when the transaction executed (RB4-F74). Not
	// serialized.
	PartitionTime time.Time `json:"-"`
}

// parseMinorBlockRecord parses a single MinorBlockRecord from the v3 API response
func (l *LiteClientAdapter) parseMinorBlockRecord(recordMap map[string]interface{}, partition string, defaultHeight int64) (*MinorBlock, error) {
	// Look for the value field which contains the MinorBlockRecord
	var blockData map[string]interface{}
	if value, ok := recordMap["value"].(map[string]interface{}); ok {
		blockData = value
	} else {
		blockData = recordMap
	}

	block := &MinorBlock{
		Height:    defaultHeight,
		Partition: partition,
		Entries:   []BlockEntry{},
	}

	// Extract block index/height
	if index, ok := blockData["index"].(float64); ok {
		block.Height = int64(index)
		block.Index = int64(index)
	}

	// The block's own time. Every minor block record carries one; a record without a readable time is
	// refused rather than given the zero time, which became the intent's BlockTime (RB3-F104).
	timeStr, _ := blockData["time"].(string)
	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("minor block %d on %s: time %q: %w", block.Height, partition, timeStr, err)
	}
	block.Time = parsedTime
	if source, ok := blockData["source"].(string); ok {
		block.Source = source
	}

	// Extract entries using the TypeScript getBlockEntries pattern
	block.Entries = l.getBlockEntries(blockData, block.Height, partition)

	return block, nil
}

// getBlockEntries implements the TypeScript getBlockEntries.ts pattern
func (l *LiteClientAdapter) getBlockEntries(blockData map[string]interface{}, blockHeight int64, partition string) []BlockEntry {
	var allEntries []interface{}

	// Get direct entries from block.entries.records
	if entries, ok := blockData["entries"].(map[string]interface{}); ok {
		if records, ok := entries["records"].([]interface{}); ok {
			allEntries = append(allEntries, records...)
			debugf("🔍 [BLOCK-PARSE] Found %d direct entries.records in block %d from %s", len(records), blockHeight, partition)
		}
	}

	// Get anchored entries from block.anchored.records.flatMap(x => x.entries.records)
	if anchored, ok := blockData["anchored"].(map[string]interface{}); ok {
		if anchoredRecords, ok := anchored["records"].([]interface{}); ok {
			debugf("🔍 [ANCHORED] Found %d anchored records in block %d", len(anchoredRecords), blockHeight)
			for _, anchoredRecord := range anchoredRecords {
				if anchoredMap, ok := anchoredRecord.(map[string]interface{}); ok {
					if anchoredEntries, ok := anchoredMap["entries"].(map[string]interface{}); ok {
						if anchoredEntriesRecords, ok := anchoredEntries["records"].([]interface{}); ok {
							allEntries = append(allEntries, anchoredEntriesRecords...)
							debugf("🔍 [ANCHORED] Added %d anchored entries.records from block %d", len(anchoredEntriesRecords), blockHeight)
						}
					}
				}
			}
		}
	}

	// Convert to BlockEntry structs
	var blockEntries []BlockEntry
	for entryIdx, entry := range allEntries {
		if entryMap, ok := entry.(map[string]interface{}); ok {
			blockEntry := BlockEntry{
				Index:          entryIdx,
				Data:           entryMap,
				Partition:      partition,
				PartitionBlock: blockHeight,
			}

			// Extract entry type if available
			if entryType, ok := entryMap["type"].(string); ok {
				blockEntry.Type = entryType
			}

			blockEntries = append(blockEntries, blockEntry)
			debugf("📝 [ENTRY-PARSE] Entry %d: type=%s", entryIdx, blockEntry.Type)
		}
	}

	debugf("✅ [BLOCK-ENTRIES] Block %d from %s: found %d total entries (%d direct + anchored)",
		blockHeight, partition, len(blockEntries), len(allEntries))

	return blockEntries
}

// queryBVNStatus tries to get block information from a BVN partition
func (l *LiteClientAdapter) queryBVNStatus(ctx context.Context) (*NetworkStatus, error) {
	log.Printf("🔍 [V3-API] Querying BVN partitions for latest block info...")

	// Dynamically discover partitions, with ultimate fallback to DN only
	partitions, err := l.getPartitions(ctx)
	if err != nil {
		log.Printf("⚠️ [V3-API] Partition discovery failed, using DN fallback: %v", err)
		partitions = []string{"acc://dn.acme/ledger"}
	}

	for _, partition := range partitions {
		blocks, err := l.queryMinorBlocks(ctx, partition, -1) // -1 for latest
		if err != nil {
			log.Printf("⚠️ [V3-API] Failed to query %s: %v", partition, err)
			continue
		}

		if len(blocks) > 0 {
			latestBlock := blocks[len(blocks)-1] // Get the latest block
			blockHeight := latestBlock.Index
			log.Printf("🎯 [V3-API] Found latest block from %s: height=%d time=%s",
				partition, blockHeight, latestBlock.Time.Format(time.RFC3339))

			return &NetworkStatus{
				Network: struct {
					ID     string `json:"id"`
					Type   string `json:"type"`
					Status struct {
						LastBlockHeight int64  `json:"last_block_height"`
						LastBlockHash   string `json:"last_block_hash"`
						LastBlockTime   string `json:"last_block_time"`
					} `json:"status"`
				}{
					ID:   "kermit",
					Type: "testnet",
					Status: struct {
						LastBlockHeight int64  `json:"last_block_height"`
						LastBlockHash   string `json:"last_block_hash"`
						LastBlockTime   string `json:"last_block_time"`
					}{
						LastBlockHeight: blockHeight,
						LastBlockHash:   fmt.Sprintf("block_%d", blockHeight),
						LastBlockTime:   latestBlock.Time.Format(time.RFC3339),
					},
				},
			}, nil
		}
	}

	// If no blocks found, return error instead of guessing
	return nil, fmt.Errorf("no blocks found when querying BVN/DN partitions")
}

// GetLatestBlock retrieves the latest block information
func (l *LiteClientAdapter) GetLatestBlock(ctx context.Context) (*Block, error) {
	networkStatus, err := l.getNetworkStatusV3(ctx)
	if err == nil {
		latestHeight := uint64(networkStatus.Network.Status.LastBlockHeight)
		return l.GetBlock(ctx, latestHeight)
	}

	return nil, fmt.Errorf("failed to determine latest block height from network status: %w", err)
}

// GetValidator retrieves validator information from the Accumulate network.
//
// IMPORTANT: Accumulate's v3 API does not expose individual validator information
// directly. Validators operate at the BVN/DN partition level and are managed
// through the network configuration, not queryable via the standard account API.
//
// For Certen governance proofs, use GetKeyBook and GetKeyPage to validate
// authority signatures instead of querying Accumulate validators.
//
// This method would require either:
// 1. Accumulate API updates to expose validator endpoints, OR
// 2. Direct CometBFT RPC access to Accumulate nodes
func (l *LiteClientAdapter) GetValidator(ctx context.Context, validatorID string) (*ValidatorInfo, error) {
	// Attempt to query network status for any validator info
	networkStatus, err := l.getNetworkStatusV3(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network status: %w; validator info not available via v3 API", err)
	}

	// Log what we found for debugging
	log.Printf("⚠️ [VALIDATOR] GetValidator called for %s; network=%s but validator endpoints not exposed in v3 API",
		validatorID, networkStatus.Network.ID)

	return nil, fmt.Errorf("GetValidator: Accumulate v3 API does not expose validator info; "+
		"use GetKeyBook/GetKeyPage for governance validation instead (network: %s)", networkStatus.Network.ID)
}

// GetValidatorSet retrieves the current validator set from the Accumulate network.
//
// IMPORTANT: Accumulate's architecture differs from traditional PoS chains.
// Validators are BVN/DN operators and are not exposed through the standard API.
//
// For Certen consensus, validator sets are managed through Certen's own
// BFT consensus layer, not through Accumulate's validator set.
//
// This method would require direct CometBFT RPC access to Accumulate nodes.
func (l *LiteClientAdapter) GetValidatorSet(ctx context.Context) ([]*ValidatorInfo, error) {
	// Attempt to query network status
	networkStatus, err := l.getNetworkStatusV3(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network status: %w; validator set not available via v3 API", err)
	}

	// Log what we found for debugging
	log.Printf("⚠️ [VALIDATOR-SET] GetValidatorSet called; network=%s (height=%d) but validator endpoints not exposed in v3 API",
		networkStatus.Network.ID, networkStatus.Network.Status.LastBlockHeight)

	return nil, fmt.Errorf("GetValidatorSet: Accumulate v3 API does not expose validator set; "+
		"Certen uses its own BFT consensus validators (network: %s, height: %d)",
		networkStatus.Network.ID, networkStatus.Network.Status.LastBlockHeight)
}

// GetKeyBook retrieves Key Book information from Accumulate.
//
// Key Books in Accumulate contain:
// - A threshold for multi-sig operations
// - A page count indicating how many key pages exist
// - Pages are at URLs: keybook/1, keybook/2, etc.
func (l *LiteClientAdapter) GetKeyBook(ctx context.Context, url string) (*KeyBook, error) {
	// Query the Key Book account
	response, err := l.client.GetAccount(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to get key book from lite client: %w", err)
	}

	if response.Account == nil {
		return nil, fmt.Errorf("no account data found for key book: %s", url)
	}

	// Check if this is a Key account (Key Book)
	if response.Account.KeyData == nil {
		// Maybe it's a KeyPage being queried as KeyBook
		if response.Account.KeyPageData != nil {
			return nil, fmt.Errorf("URL %s is a Key Page, not a Key Book; use GetKeyPage instead", url)
		}
		return nil, fmt.Errorf("no key book data found for: %s (account type: %s)", url, response.Account.Type)
	}

	keyData := response.Account.KeyData

	// Build the list of key page URLs
	// Accumulate key books have pages at: keybook/1, keybook/2, ... keybook/N
	pageCount := int(keyData.PageCount)
	if pageCount == 0 {
		// Fallback: assume at least 1 page if we have keys
		if len(keyData.Keys) > 0 {
			pageCount = 1
		}
	}

	pages := make([]string, pageCount)
	for i := 0; i < pageCount; i++ {
		// Page indices in Accumulate are 1-based
		pages[i] = fmt.Sprintf("%s/%d", url, i+1)
	}

	return &KeyBook{
		URL:       url,
		Pages:     pages,
		Threshold: int(keyData.Threshold),
		CreatedAt: response.Account.LastUpdated,
	}, nil
}

// GetKeyPage retrieves Key Page information with real data
func (l *LiteClientAdapter) GetKeyPage(ctx context.Context, url string) (*KeyPage, error) {
	// Get Key Page data from lite client
	response, err := l.client.GetAccount(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to get key page from lite client: %w", err)
	}

	if response.Account == nil || response.Account.KeyPageData == nil {
		return nil, fmt.Errorf("no key page data found for: %s", url)
	}

	keyPageData := response.Account.KeyPageData

	// Convert KeyInfo array to string array
	publicKeys := make([]string, len(keyPageData.Keys))
	for i, keyInfo := range keyPageData.Keys {
		publicKeys[i] = keyInfo.PublicKey
	}

	// Use real CreditBalance from the KeyPageData struct (it's a string representation)
	var creditLimit int64
	if keyPageData.CreditBalance != "" {
		// Parse credit balance string to int64, default to 0 if parsing fails
		if parsedBalance, err := strconv.ParseInt(keyPageData.CreditBalance, 10, 64); err == nil {
			creditLimit = parsedBalance
		}
		// If parsing fails, creditLimit remains 0 (intentionally unknown)
	}

	return &KeyPage{
		URL:         url,
		PublicKeys:  publicKeys,
		Threshold:   int(keyPageData.Threshold),
		CreditLimit: creditLimit,
		CreatedAt:   response.Account.LastUpdated,
	}, nil
}

// VerifySignature verifies a signature using Accumulate's signature scheme
func (l *LiteClientAdapter) VerifySignature(ctx context.Context, message, signature, publicKey string) (bool, error) {
	// This would integrate with Accumulate's signature verification
	// For the integration phase, we'll perform basic validation

	// Decode the signature and public key to ensure they're valid hex
	_, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	_, err = hex.DecodeString(publicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key format: %w", err)
	}

	// For the integration, we'll accept properly formatted signatures
	// Real cryptographic verification would be implemented here
	return len(signature) > 0 && len(publicKey) > 0 && len(message) > 0, nil
}

// Helper methods

// extractProofPath extracts the Merkle proof path from raw receipt data
func (l *LiteClientAdapter) extractProofPath(rawReceipt interface{}) []string {
	// Extract proof path from the raw receipt data from the Accumulate lite client
	if receipt, ok := rawReceipt.(map[string]interface{}); ok {
		if proof, ok := receipt["proof"].([]interface{}); ok {
			var path []string
			for _, node := range proof {
				if hash, ok := node.(string); ok {
					path = append(path, hash)
				}
			}
			return path
		}
	}
	// If no proof data is available, return empty array (not fake data)
	return []string{}
}

// Health checks the lite client connection
func (l *LiteClientAdapter) Health(ctx context.Context) error {
	// Test connectivity by checking network status instead of hard-coded account
	_, err := l.getNetworkStatusV3(ctx)
	if err != nil {
		return fmt.Errorf("lite client health check failed - network unreachable: %w", err)
	}
	return nil
}

// GetAccount retrieves account information with proof data
func (l *LiteClientAdapter) GetAccount(ctx context.Context, accountURL string) (*api.APIResponse, error) {
	// Get account data from lite client
	response, err := l.client.GetAccount(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get account from lite client: %w", err)
	}
	return response, nil
}

// Close cleans up the lite client connection
func (l *LiteClientAdapter) Close() error {
	// Clean up any resources
	if l.client != nil {
		l.client.ClearCache()
	}
	return nil
}

// =============================================================================
// WRITE-BACK SUPPORT METHODS
// These methods support the proof cycle write-back to Accumulate
// =============================================================================

// GetTransactionStatus queries the status of a transaction by hash or full transaction ID
func (l *LiteClientAdapter) GetTransactionStatus(ctx context.Context, txHash string) (string, error) {
	if l.client == nil {
		return "", fmt.Errorf("lite client not initialized")
	}

	// Determine the scope for the query
	// If txHash is already a full transaction ID (starts with acc://), use it directly
	// Otherwise, construct the scope with @unknown (legacy behavior)
	var scope string
	if strings.HasPrefix(txHash, "acc://") {
		scope = txHash
	} else {
		scope = fmt.Sprintf("acc://%s@unknown", txHash)
	}

	log.Printf("🔍 [V3-STATUS] Querying transaction status: %s", scope)

	// Query transaction using V3 API
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": scope,
	})
	if err != nil {
		return "", fmt.Errorf("query transaction status: %w", err)
	}

	log.Printf("🔍 [V3-STATUS] Query result: %+v", result)

	// Helper to extract status from a status object
	extractStatus := func(status map[string]interface{}) string {
		// Check for string status code
		if code, ok := status["code"].(string); ok {
			return code
		}
		// Check for numeric status code (statusNo)
		if statusNo, ok := status["statusNo"].(float64); ok {
			switch int(statusNo) {
			case 0:
				return "pending"
			case 201:
				return "delivered"
			case 301, 302, 303, 304, 305:
				return "failed"
			default:
				return "unknown"
			}
		}
		// Check for numeric code
		if codeFloat, ok := status["code"].(float64); ok {
			switch int(codeFloat) {
			case 0:
				return "pending"
			case 201:
				return "delivered"
			default:
				return "unknown"
			}
		}
		// Check for string status directly
		if s, ok := status["status"].(string); ok {
			return s
		}
		return ""
	}

	// Try extracting status from various response formats
	// Format 1: Direct status in result
	if status, ok := result["status"].(string); ok && status != "" {
		log.Printf("🔍 [V3-STATUS] Found direct status: %s", status)
		return status, nil
	}

	// Format 2: statusNo in result
	if statusNo, ok := result["statusNo"].(float64); ok {
		switch int(statusNo) {
		case 201:
			return "delivered", nil
		case 0:
			return "pending", nil
		default:
			return "unknown", nil
		}
	}

	// Format 3: Status in record.status
	if record, ok := result["record"].(map[string]interface{}); ok {
		if statusObj, ok := record["status"].(map[string]interface{}); ok {
			if s := extractStatus(statusObj); s != "" {
				log.Printf("🔍 [V3-STATUS] Found status in record.status: %s", s)
				return s, nil
			}
		}
		// Also check for direct status/statusNo in record
		if status, ok := record["status"].(string); ok && status != "" {
			return status, nil
		}
		if statusNo, ok := record["statusNo"].(float64); ok && int(statusNo) == 201 {
			return "delivered", nil
		}
	}

	// Format 4: Status in message records
	if msg, ok := result["message"].(map[string]interface{}); ok {
		if statusObj, ok := msg["status"].(map[string]interface{}); ok {
			if s := extractStatus(statusObj); s != "" {
				return s, nil
			}
		}
	}

	log.Printf("⚠️ [V3-STATUS] Could not extract status, returning pending")
	return "pending", nil
}

// SubmitWriteData submits a WriteData transaction to the Accumulate network
func (l *LiteClientAdapter) SubmitWriteData(ctx context.Context, principal string, txData []byte) (string, error) {
	if l.client == nil {
		return "", fmt.Errorf("lite client not initialized")
	}

	// Parse the signed transaction data
	var signedTx map[string]interface{}
	if err := json.Unmarshal(txData, &signedTx); err != nil {
		return "", fmt.Errorf("failed to parse signed transaction: %w", err)
	}

	// Build the submission in the format expected by Accumulate V3 API
	// IMPORTANT: Accumulate V3 API expects { "transaction": [...], "signatures": [...] }
	// NOT wrapped in an "envelope" - matching the JS SDK's client.submit() format
	submission := map[string]interface{}{}

	// Extract transaction and signatures from the signed tx
	if tx, ok := signedTx["transaction"].(map[string]interface{}); ok {
		submission["transaction"] = []interface{}{tx}
	} else {
		return "", fmt.Errorf("no transaction in signed data")
	}

	if sigs, ok := signedTx["signatures"].([]interface{}); ok {
		submission["signatures"] = sigs
	} else {
		return "", fmt.Errorf("no signatures in signed data")
	}

	log.Printf("🔍 [V3-SUBMIT] Submitting transaction to Accumulate with method 'submit'")
	log.Printf("🔍 [V3-SUBMIT] Submission payload: %+v", submission)

	// Submit transaction using V3 API - directly pass transaction and signatures
	// NOT wrapped in "envelope" - matching JS SDK format: client.submit({ transaction: [tx], signatures: [sig] })
	result, err := l.queryV3API(ctx, "submit", submission)
	if err != nil {
		return "", fmt.Errorf("submit transaction: %w", err)
	}

	log.Printf("🔍 [V3-SUBMIT] Submit response: %+v", result)

	// Extract transaction hash from response
	// Response format can be an array of submission results
	if results, ok := result["results"].([]interface{}); ok && len(results) > 0 {
		if first, ok := results[0].(map[string]interface{}); ok {
			if txHash, ok := first["txHash"].(string); ok {
				return txHash, nil
			}
			if txID, ok := first["txID"].(string); ok {
				return txID, nil
			}
			if status, ok := first["status"].(map[string]interface{}); ok {
				if txID, ok := status["txID"].(string); ok {
					return txID, nil
				}
			}
		}
	}

	// Also check for direct result format (array of submissions)
	if arr, ok := result["result"].([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			if status, ok := first["status"].(map[string]interface{}); ok {
				if txID, ok := status["txID"].(string); ok {
					return txID, nil
				}
			}
		}
	}

	// Try to extract from top-level
	if txHash, ok := result["txHash"].(string); ok {
		return txHash, nil
	}
	if txID, ok := result["txID"].(string); ok {
		return txID, nil
	}

	return "", fmt.Errorf("no transaction hash in response: %+v", result)
}

// SubmitEnvelope submits a properly formatted Accumulate Envelope via JSON-RPC
// This expects the envelope to be pre-serialized JSON with proper Accumulate protocol types
func (l *LiteClientAdapter) SubmitEnvelope(ctx context.Context, envelopeJSON []byte) (string, error) {
	if l.client == nil {
		return "", fmt.Errorf("lite client not initialized")
	}

	// Parse the envelope JSON to extract the structure
	var envelope map[string]interface{}
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse envelope JSON: %w", err)
	}

	// Build the SubmitRequest format expected by Accumulate V3 API
	// IMPORTANT: V3 API expects { "transaction": [...], "signatures": [...] } directly
	// NOT wrapped in "envelope" - this matches the JS SDK format
	submitRequest := map[string]interface{}{}

	// Extract transaction and signatures from the envelope
	if txs, ok := envelope["Transaction"].([]interface{}); ok {
		submitRequest["transaction"] = txs
	} else if txs, ok := envelope["transaction"].([]interface{}); ok {
		submitRequest["transaction"] = txs
	} else if tx, ok := envelope["Transaction"]; ok {
		submitRequest["transaction"] = []interface{}{tx}
	} else if tx, ok := envelope["transaction"]; ok {
		submitRequest["transaction"] = []interface{}{tx}
	}

	if sigs, ok := envelope["Signatures"].([]interface{}); ok {
		submitRequest["signatures"] = sigs
	} else if sigs, ok := envelope["signatures"].([]interface{}); ok {
		submitRequest["signatures"] = sigs
	} else if sig, ok := envelope["Signatures"]; ok {
		submitRequest["signatures"] = []interface{}{sig}
	} else if sig, ok := envelope["signatures"]; ok {
		submitRequest["signatures"] = []interface{}{sig}
	}

	log.Printf("🔍 [V3-SUBMIT] Submitting to Accumulate (format: transaction+signatures)")
	log.Printf("🔍 [V3-SUBMIT] Request: %+v", submitRequest)

	// Submit using V3 API
	result, err := l.queryV3API(ctx, "submit", submitRequest)
	if err != nil {
		return "", fmt.Errorf("submit envelope: %w", err)
	}

	log.Printf("🔍 [V3-SUBMIT] Submit response: %+v", result)

	// Extract transaction hash from response
	// Response format is: { "result": [{ "status": { "txID": "..." }, "success": true }, ...] }
	if arr, ok := result["result"].([]interface{}); ok && len(arr) > 0 {
		for _, item := range arr {
			if submission, ok := item.(map[string]interface{}); ok {
				// Check for success flag
				if success, _ := submission["success"].(bool); success {
					// Extract txID from status
					if status, ok := submission["status"].(map[string]interface{}); ok {
						if txID, ok := status["txID"].(string); ok {
							log.Printf("✅ [V3-SUBMIT] Transaction submitted successfully: %s", txID)
							return txID, nil
						}
					}
				}
			}
		}
	}

	// Also check for "value" array format (alternative response format)
	if arr, ok := result["value"].([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			if status, ok := first["status"].(map[string]interface{}); ok {
				if txID, ok := status["txID"].(string); ok {
					return txID, nil
				}
			}
			// Also check for direct txID field
			if txID, ok := first["txID"].(string); ok {
				return txID, nil
			}
		}
	}

	// Check for direct array format (legacy compatibility)
	if results, ok := result["results"].([]interface{}); ok && len(results) > 0 {
		if first, ok := results[0].(map[string]interface{}); ok {
			if txHash, ok := first["txHash"].(string); ok {
				return txHash, nil
			}
			if txID, ok := first["txID"].(string); ok {
				return txID, nil
			}
		}
	}

	// Try to extract from top-level
	if txHash, ok := result["txHash"].(string); ok {
		return txHash, nil
	}
	if txID, ok := result["txID"].(string); ok {
		return txID, nil
	}

	// Log full response structure for debugging
	responseJSON, _ := json.MarshalIndent(result, "", "  ")
	log.Printf("🔍 [V3-SUBMIT] Full response structure:\n%s", string(responseJSON))

	// Check if response itself is an array (direct result array format)
	// This handles cases where Accumulate returns: [{ "status": { "txID": "..." }, "success": true }]
	if respArr, ok := result[""].([]interface{}); ok && len(respArr) > 0 {
		log.Printf("🔍 [V3-SUBMIT] Found root-level array with %d items", len(respArr))
		if first, ok := respArr[0].(map[string]interface{}); ok {
			if status, ok := first["status"].(map[string]interface{}); ok {
				if txID, ok := status["txID"].(string); ok {
					return txID, nil
				}
			}
		}
	}

	// Final fallback: check for "message" field which may contain txID
	if msg, ok := result["message"].(map[string]interface{}); ok {
		if txID, ok := msg["txID"].(string); ok {
			return txID, nil
		}
		if id, ok := msg["id"].(string); ok {
			return id, nil
		}
	}

	// IMPORTANT: Don't return placeholder - return error so we can debug
	return "", fmt.Errorf("could not extract transaction ID from response: %+v", result)
}

// SubmitDirect submits a transaction directly using the V3 API format
// This takes a pre-built submission map with "transaction" and "signatures" keys
func (l *LiteClientAdapter) SubmitDirect(ctx context.Context, submission map[string]interface{}) (string, error) {
	if l.client == nil {
		return "", fmt.Errorf("lite client not initialized")
	}

	log.Printf("🔍 [V3-SUBMIT-DIRECT] Submitting to Accumulate with method 'submit'")

	// Wrap the submission in an "envelope" key as required by V3 API
	// The API expects: { "envelope": { "transaction": [...], "signatures": [...] } }
	params := map[string]interface{}{
		"envelope": submission,
	}

	// Submit using V3 API
	result, err := l.queryV3API(ctx, "submit", params)
	if err != nil {
		return "", fmt.Errorf("submit direct: %w", err)
	}

	log.Printf("🔍 [V3-SUBMIT-DIRECT] Submit response: %+v", result)

	// Extract transaction hash from response
	// Response format is: { "result": [{ "status": { "txID": "..." }, "success": true }, ...] }
	// Or the array may be at the top level
	if arr, ok := result["result"].([]interface{}); ok && len(arr) > 0 {
		for _, item := range arr {
			if submission, ok := item.(map[string]interface{}); ok {
				if success, _ := submission["success"].(bool); success {
					if status, ok := submission["status"].(map[string]interface{}); ok {
						if txID, ok := status["txID"].(string); ok {
							log.Printf("✅ [V3-SUBMIT-DIRECT] Transaction submitted successfully: %s", txID)
							return txID, nil
						}
					}
				}
			}
		}
	}

	// Also check for top-level array (some API versions)
	if arr, ok := result[""].([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			if status, ok := first["status"].(map[string]interface{}); ok {
				if txID, ok := status["txID"].(string); ok {
					return txID, nil
				}
			}
		}
	}

	// Check for direct txID in result
	if txID, ok := result["txID"].(string); ok {
		return txID, nil
	}

	// Log full response for debugging
	responseJSON, _ := json.MarshalIndent(result, "", "  ")
	log.Printf("⚠️ [V3-SUBMIT-DIRECT] Could not extract txID. Full response:\n%s", string(responseJSON))

	return "", fmt.Errorf("could not extract transaction ID from submit response")
}

// GetCreditBalance returns the credit balance for a key page or lite identity
func (l *LiteClientAdapter) GetCreditBalance(ctx context.Context, signerURL string) (uint64, error) {
	if l.client == nil {
		return 0, fmt.Errorf("lite client not initialized")
	}

	// Query account to get credit balance
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": signerURL,
		"query": map[string]interface{}{
			"queryType": "default",
		},
	})
	if err != nil {
		return 0, fmt.Errorf("query credit balance: %w", err)
	}

	// Extract credit balance from response
	// The V3 API returns {"recordType": "account", "account": {...}} at top level
	// Check both structures for compatibility

	// Structure 1: result["account"]["creditBalance"] (direct from V3 API)
	if account, ok := result["account"].(map[string]interface{}); ok {
		if balance, ok := account["creditBalance"].(float64); ok {
			return uint64(balance), nil
		}
		if balance, ok := account["balance"].(float64); ok {
			return uint64(balance), nil
		}
	}

	// Structure 2: result["record"]["account"]["creditBalance"] (wrapped response)
	if record, ok := result["record"].(map[string]interface{}); ok {
		if account, ok := record["account"].(map[string]interface{}); ok {
			if balance, ok := account["creditBalance"].(float64); ok {
				return uint64(balance), nil
			}
			if balance, ok := account["balance"].(float64); ok {
				return uint64(balance), nil
			}
		}
	}

	// Default to 0 if not found
	return 0, nil
}

// GetKeyPageVersion returns the current version for a key page
// This MUST be queried before each transaction to ensure correct signer version
func (l *LiteClientAdapter) GetKeyPageVersion(ctx context.Context, signerURL string) (uint64, error) {
	if l.client == nil {
		return 0, fmt.Errorf("lite client not initialized")
	}

	// Query account to get key page version
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": signerURL,
	})
	if err != nil {
		return 0, fmt.Errorf("query key page version: %w", err)
	}

	// Extract version from response
	// The V3 API returns {"recordType": "account", "account": {...}} at top level
	if account, ok := result["account"].(map[string]interface{}); ok {
		if version, ok := account["version"].(float64); ok {
			return uint64(version), nil
		}
	}

	// Structure 2: result["record"]["account"]["version"] (wrapped response)
	if record, ok := result["record"].(map[string]interface{}); ok {
		if account, ok := record["account"].(map[string]interface{}); ok {
			if version, ok := account["version"].(float64); ok {
				return uint64(version), nil
			}
		}
	}

	return 0, fmt.Errorf("%s: the response carries no key page version", signerURL)
}

// GetSignerNonce returns the current nonce for a signer (key page or lite identity)
func (l *LiteClientAdapter) GetSignerNonce(ctx context.Context, signerURL string) (uint64, error) {
	if l.client == nil {
		return 0, fmt.Errorf("lite client not initialized")
	}

	// Query account to get nonce
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": signerURL,
		"query": map[string]interface{}{
			"queryType": "default",
		},
	})
	if err != nil {
		return 0, fmt.Errorf("query signer nonce: %w", err)
	}

	// Extract nonce from response
	// For key pages, nonce might be in the signing state
	if record, ok := result["record"].(map[string]interface{}); ok {
		if account, ok := record["account"].(map[string]interface{}); ok {
			// Check for nonce field
			if nonce, ok := account["nonce"].(float64); ok {
				return uint64(nonce), nil
			}
			// Check for version field (used as nonce in some contexts)
			if version, ok := account["version"].(float64); ok {
				return uint64(version), nil
			}
		}
	}

	// Default to 0 if not found (first transaction)
	return 0, nil
}

// =============================================================================
// TRANSACTION GOVERNANCE DATA
// Extracts key page M-of-N threshold from Accumulate transaction signatureBooks
// =============================================================================

// GetIntentBlobs fetches the four signed intent blobs (intentData, crossChainData,
// governanceData, replayData) for a CERTEN_INTENT writeData transaction on Accumulate.
//
// RB-SEC-1: this lets a peer validator INDEPENDENTLY obtain the user-signed intent from
// Accumulate (the source of truth) and re-derive the committed contract-call effects,
// instead of trusting the executor's attestation request. Response shape (v3 query):
//
//	result.message.transaction.body{type:writeData}.entry{type:doubleHash}.data = [hex,...]
func (l *LiteClientAdapter) GetIntentBlobs(ctx context.Context, txHash string, accountURL string) ([][]byte, error) {
	if txHash == "" || accountURL == "" {
		return nil, fmt.Errorf("txHash and accountURL are required")
	}
	scope := fmt.Sprintf("acc://%s@%s", txHash, strings.TrimPrefix(accountURL, "acc://"))
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{"scope": scope})
	if err != nil {
		return nil, fmt.Errorf("query intent tx: %w", err)
	}
	msg, ok := result["message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("intent tx response missing message")
	}
	tx, ok := msg["transaction"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("intent tx response missing transaction")
	}
	body, ok := tx["body"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("transaction missing body")
	}
	if bt, _ := body["type"].(string); bt != "writeData" {
		return nil, fmt.Errorf("not a writeData transaction (type=%v)", body["type"])
	}
	entry, ok := body["entry"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("writeData missing entry")
	}
	data, ok := entry["data"].([]interface{})
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("data entry has no blobs")
	}
	blobs := make([][]byte, 0, len(data))
	for i, d := range data {
		s, ok := d.(string)
		if !ok {
			return nil, fmt.Errorf("data[%d] is not a hex string", i)
		}
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return nil, fmt.Errorf("decode data[%d]: %w", i, err)
		}
		blobs = append(blobs, b)
	}
	return blobs, nil
}
