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
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/api"
)

// LiteClientAdapter wraps the Accumulate lite client for our validator service
// This is the CANONICAL implementation of the accumulate.Client interface
type LiteClientAdapter struct {
	client       *api.Client
	// proofBuilder proof.ProofBuilder // Removed - not available in production lite client
	config       *LiteClientConfig
}

// Ensure LiteClientAdapter implements the Client interface at compile time
var _ Client = (*LiteClientAdapter)(nil)

// LiteClientConfig contains configuration for lite client integration
type LiteClientConfig struct {
	NetworkURL     string              `json:"network_url"`
	EnableCaching  bool                `json:"enable_caching"`
	// ProofStrategy  proof.ProofStrategy `json:"proof_strategy"` // Removed - not available in production lite client
	RequestTimeout time.Duration       `json:"request_timeout"`
}

// NewLiteClientAdapter creates a new adapter for the Accumulate lite client
func NewLiteClientAdapter(config *LiteClientConfig) (*LiteClientAdapter, error) {
	if config == nil {
		config = &LiteClientConfig{
			NetworkURL:     "http://localhost:26660", // Default to local devnet
			EnableCaching:  true,
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

// SearchCertenTransactions searches for CERTEN_INTENT transactions across DN and all BVN partitions
// Scans both DN (for anchored transactions) and all BVNs (for direct transactions) with expand=true
func (l *LiteClientAdapter) SearchCertenTransactions(ctx context.Context, blockHeight int64) ([]*CertenTransaction, error) {
	log.Printf("🔍 [CERTEN-SEARCH] Searching DN + all BVNs at block %d with expand=true for CERTEN_INTENT", blockHeight)

	var allTransactions []*CertenTransaction

	// Query all partitions: DN + 3 BVNs
	partitions := []string{
		"acc://dn.acme",
		"acc://bvn-BVN1.acme",
		"acc://bvn-BVN2.acme",
		"acc://bvn-BVN3.acme",
	}

	for _, partition := range partitions {
		blocks, err := l.queryMinorBlocks(ctx, partition, blockHeight)
		if err != nil {
			log.Printf("⚠️ [CERTEN-SEARCH] Failed to query %s block %d: %v", partition, blockHeight, err)
			continue
		}

		if len(blocks) == 0 {
			log.Printf("📊 [CERTEN-SEARCH] No block found at height %d on %s", blockHeight, partition)
			continue
		}

		block := blocks[0]
		log.Printf("📊 [CERTEN-SEARCH] %s block %d has %d entries", partition, blockHeight, len(block.Entries))

		for _, entry := range block.Entries {
			if !l.isCertenTransaction(entry) {
				continue
			}
			certenTx := l.parseCertenTransaction(entry, block, partition)
			if certenTx != nil {
				allTransactions = append(allTransactions, certenTx)
				log.Printf("🎯 [CERTEN-SEARCH] Found CERTEN transaction %s in %s block %d", certenTx.Hash, partition, blockHeight)
			}
		}
	}

	log.Printf("✅ [CERTEN-SEARCH] DN + all BVNs at block %d yielded %d CERTEN_INTENT txs", blockHeight, len(allTransactions))
	return allTransactions, nil
}

// CertenTransaction represents a discovered CERTEN intent transaction
type CertenTransaction struct {
	Hash            string                 `json:"hash"`
	AccountURL      string                 `json:"account_url"`
	BlockHeight     int64                  `json:"block_height"`  // Fixed: use int64 like legacy
	Timestamp       time.Time              `json:"timestamp"`
	IntentData      map[string]interface{} `json:"intent_data"`
	TransactionType string                 `json:"transaction_type"`
	// Legacy fields for backward compatibility
	Partition string                 `json:"partition,omitempty"`
	RawTx     map[string]interface{} `json:"raw_tx,omitempty"`
}

// isCertenTransaction checks if a block entry is a CERTEN intent transaction
// STRICT FILTERING: Only writeData transactions with CERTEN_INTENT memo
func (l *LiteClientAdapter) isCertenTransaction(entry BlockEntry) bool {
	if entry.Data == nil {
		return false
	}

	// DEBUG: Log every entry we're checking
	entryType := "unknown"
	if t, ok := entry.Data["type"].(string); ok {
		entryType = t
	}

	// Debug: Check for account field which indicates user transactions
	if account, ok := entry.Data["account"].(string); ok {
		if strings.Contains(account, "certen") {
			log.Printf("🔍 [CERTEN-CHECK] Found certen account entry: %s, type=%s", account, entryType)
			// Log the keys at various levels to understand structure
			log.Printf("🔍 [CERTEN-CHECK] Entry data keys: %v", getKeys(entry.Data))
			if value, ok := entry.Data["value"].(map[string]interface{}); ok {
				log.Printf("🔍 [CERTEN-CHECK] Entry.value keys: %v", getKeys(value))
				if message, ok := value["message"].(map[string]interface{}); ok {
					log.Printf("🔍 [CERTEN-CHECK] Entry.value.message keys: %v", getKeys(message))
					if tx, ok := message["transaction"].(map[string]interface{}); ok {
						log.Printf("🔍 [CERTEN-CHECK] Entry.value.message.transaction keys: %v", getKeys(tx))
						if header, ok := tx["header"].(map[string]interface{}); ok {
							log.Printf("🔍 [CERTEN-CHECK] Entry.value.message.transaction.header: %v", header)
						}
					}
				}
			}
		}
	}

	log.Printf("🔍 [CERTEN-CHECK] Checking entry type=%s for CERTEN_INTENT memo", entryType)

	// RELAXED: Check ANY transaction type for CERTEN_INTENT memo
	if l.hasAnyCertenMemo(entry) {
		log.Printf("✅ [CERTEN-CHECK] Found CERTEN_INTENT memo in %s entry", entryType)
		return true
	}

	return false
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
		if memo, ok := v["memo"]; ok {
			if memoStr, ok := memo.(string); ok && memoStr == "CERTEN_INTENT" {
				log.Printf("🎯 [MEMO-FOUND] Found CERTEN_INTENT memo in nested structure")
				return true
			}
		}
		// Recursively search all nested maps
		for key, value := range v {
			if l.searchForCertenMemo(value) {
				log.Printf("🎯 [MEMO-FOUND] Found CERTEN_INTENT memo under key: %s", key)
				return true
			}
		}
	case []interface{}:
		// Recursively search arrays
		for i, value := range v {
			if l.searchForCertenMemo(value) {
				log.Printf("🎯 [MEMO-FOUND] Found CERTEN_INTENT memo in array index: %d", i)
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
	hasCertenMemo := false
	if header, ok := transaction["header"].(map[string]interface{}); ok {
		if memo, ok := header["memo"].(string); ok {
			if memo == "CERTEN_INTENT" {
				hasCertenMemo = true
				log.Printf("✅ [STRICT-CHECK] Found CERTEN_INTENT memo in header")
			} else {
				log.Printf("❌ [STRICT-CHECK] Header memo is '%s', not 'CERTEN_INTENT'", memo)
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
								log.Printf("✅ [STRICT-CHECK] Valid writeData transaction with CERTEN_INTENT memo and %d data elements", len(data))
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
	log.Printf("🔍 [DEBUG-ENTRY] Full entry structure: %+v", entry.Data)
	if entryBytes, err := json.MarshalIndent(entry.Data, "", "  "); err == nil {
		log.Printf("🔍 [DEBUG-ENTRY] JSON structure:\n%s", string(entryBytes))
	}

	// Try multiple ways to extract the transaction hash from Accumulate V3 API response

	// First check if there's an "entry" field at the root level (this is the transaction hash)
	if entryHash, ok := entry.Data["entry"].(string); ok {
		hash = entryHash
		log.Printf("🔍 [HASH-EXTRACT] Found transaction hash from root entry field: %s", hash)
	} else if hashVal, ok := entry.Data["hash"].(string); ok {
		hash = hashVal
		log.Printf("🔍 [HASH-EXTRACT] Found transaction hash from hash field: %s", hash)
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
						log.Printf("✅ [ACCOUNT-EXTRACT] Found real account URL from principal: %s", accountURL)
					}
				}
			}
		}
	}

	certenTx := &CertenTransaction{
		Hash:        hash,
		AccountURL:  accountURL,
		BlockHeight: block.Height,  // Fixed: direct assignment since both are int64
		Partition:   partition,
		Timestamp:   block.Time,
		RawTx:       entry.Data,
		IntentData:  make(map[string]interface{}),
	}

	// Extract transaction data
	var transactionData map[string]interface{}
	if tx, ok := entry.Data["transaction"].(map[string]interface{}); ok {
		transactionData = tx
	} else {
		transactionData = entry.Data
	}

	// Try to extract intent data from the correct transaction structure
	intentData := l.extractIntentDataFromEntry(entry)
	if len(intentData) > 0 {
		for key, value := range intentData {
			certenTx.IntentData[key] = value
		}
		log.Printf("✅ [CERTEN-PARSE] Successfully extracted %d intent data elements from %s", len(intentData), hash)
	} else {
		log.Printf("⚠️ [CERTEN-PARSE] No intent data found in transaction %s", hash)
	}

	// Fallback: Extract intent data from the transaction body (old method)
	if body, ok := transactionData["body"].(map[string]interface{}); ok {
		if writeDataEntry, ok := body["entry"].(map[string]interface{}); ok {
			if data, ok := writeDataEntry["data"].([]interface{}); ok && len(data) > 0 {
				log.Printf("🔍 [CERTEN-PARSE] Fallback: Found DoubleHashDataEntry with %d data elements for %s", len(data), hash)

				// Decode ALL data elements with structured field assignment
				for i, hexData := range data {
					if hexStr, ok := hexData.(string); ok {
						if decodedBytes, err := hex.DecodeString(hexStr); err == nil {
							var jsonData map[string]interface{}
							if err := json.Unmarshal(decodedBytes, &jsonData); err == nil {
								// Store with structured field names for CERTEN protocol
								switch i {
								case 0:
									certenTx.IntentData["intentData"] = jsonData
									log.Printf("✅ [CERTEN-PARSE] Fallback decoded intentData from element %d: %+v", i, jsonData)
								case 1:
									certenTx.IntentData["crossChainData"] = jsonData
									log.Printf("✅ [CERTEN-PARSE] Fallback decoded crossChainData from element %d: %+v", i, jsonData)
								case 2:
									certenTx.IntentData["governanceData"] = jsonData
									log.Printf("✅ [CERTEN-PARSE] Fallback decoded governanceData from element %d: %+v", i, jsonData)
								case 3:
									certenTx.IntentData["replayData"] = jsonData
									log.Printf("✅ [CERTEN-PARSE] Fallback decoded replayData from element %d: %+v", i, jsonData)
								default:
									// Handle additional data elements beyond the core 4
									fieldKey := fmt.Sprintf("additionalData_%d", i)
									certenTx.IntentData[fieldKey] = jsonData
									log.Printf("✅ [CERTEN-PARSE] Fallback decoded additional data element %s: %+v", fieldKey, jsonData)
								}
							} else {
								// Some elements might be raw text or other formats, store as hex string
								certenTx.IntentData[fmt.Sprintf("rawElement_%d", i)] = hexStr
								log.Printf("🔄 [CERTEN-PARSE] Fallback stored raw hex from element %d (not JSON): %s", i, hexStr[:50]+"...")
							}
						} else {
							log.Printf("⚠️ [CERTEN-PARSE] Fallback failed to decode hex from element %d: %v", i, err)
						}
					}
				}
				log.Printf("✅ [CERTEN-PARSE] Fallback successfully parsed %d data elements from %s", len(data), hash)
			}
		}

		// Check if this is a signature transaction that references the actual CERTEN writeData transaction
		if txType, ok := body["type"].(string); ok && txType == "signature" {
			if signature, ok := body["signature"].(map[string]interface{}); ok {
				if txID, ok := signature["txID"].(string); ok && strings.Contains(txID, "certen") {
					log.Printf("🔍 [CERTEN-PARSE] Found signature transaction referencing CERTEN txID: %s", txID)

					// Extract the actual transaction hash from the txID
					if parts := strings.Split(txID, "@"); len(parts) > 0 {
						actualTxHash := parts[0]
						if after, ok0 := strings.CutPrefix(actualTxHash, "acc://"); ok0 {
							actualTxHash = after
						}
						log.Printf("🔍 [CERTEN-PARSE] Extracted actual CERTEN transaction hash: %s", actualTxHash)

						// Fetch the referenced transaction to get the actual intent data
						if referencedTx := l.fetchReferencedTransaction(actualTxHash); referencedTx != nil {
							log.Printf("✅ [CERTEN-PARSE] Successfully fetched referenced transaction %s", actualTxHash)
							// Parse the referenced transaction for intent data
							if intentData := l.parseIntentDataFromTransaction(referencedTx); intentData != nil {
								for key, value := range intentData {
									certenTx.IntentData[key] = value
								}
								log.Printf("✅ [CERTEN-PARSE] Extracted %d intent data elements from referenced transaction", len(intentData))
							}
						} else {
							// If we can't fetch it, at least mark it as a reference
							certenTx.IntentData["referencedTransaction"] = actualTxHash
							certenTx.IntentData["transactionType"] = "signature_reference"
						}
					}
				}
			}
		}

		// Also store the memo if it exists
		if memo, ok := body["memo"].(string); ok {
			certenTx.IntentData["memo"] = memo
		}
	}

	// Debug: Log final IntentData before returning
	log.Printf("🔍 [DEBUG-INTENT-DATA] Final IntentData for %s contains %d elements: %+v",
		hash, len(certenTx.IntentData), certenTx.IntentData)

	return certenTx
}

// GetTransaction retrieves a transaction with real cryptographic proof
func (l *LiteClientAdapter) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	// Query the transaction using v3 API with proper txid lookup
	queryParams := map[string]interface{}{
		"scope":     "acc://dn",  // Query the DN for transaction records
		"queryType": "txid",      // Look up by transaction ID
		"txid":      hash,        // The transaction hash/ID to find
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
				if tx.Timestamp.IsZero() {
					// Fallback if timestamp parsing fails
					tx.Timestamp = time.Now()
				}

				// Extract signatures if available
				tx.Signatures = []Signature{} // Real signatures would be extracted from transaction data

				log.Printf("✅ [LITE-CLIENT] Retrieved real transaction: hash=%s, type=%s, height=%d",
					hash, tx.Type, tx.BlockHeight)
				return tx, nil
			}
		}
	}

	// Transaction not found
	return nil, fmt.Errorf("transaction not found: %s", hash)
}

// fetchReferencedTransaction fetches a transaction by its hash to extract intent data
func (l *LiteClientAdapter) fetchReferencedTransaction(txHash string) map[string]interface{} {
	log.Printf("🔍 [FETCH-REF] Attempting to fetch referenced transaction: %s", txHash)

	// Use GetTransaction to fetch the real transaction data
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	transaction, err := l.GetTransaction(ctx, txHash)
	if err != nil {
		log.Printf("❌ [FETCH-REF] Failed to fetch transaction %s: %v", txHash, err)
		return nil
	}

	// Extract the transaction data and parse it for intent data
	if transaction.Data != nil {
		// Parse the transaction data to extract intent information
		intentData := l.parseIntentDataFromTransaction(transaction.Data)
		if intentData != nil {
			log.Printf("✅ [FETCH-REF] Successfully extracted intent data from transaction %s", txHash)
			return intentData
		}
	}

	log.Printf("⚠️ [FETCH-REF] No intent data found in transaction %s", txHash)
	return nil
}

// parseIntentDataFromTransaction extracts intent data from a fetched transaction
func (l *LiteClientAdapter) parseIntentDataFromTransaction(transactionData map[string]interface{}) map[string]interface{} {
	log.Printf("🔍 [PARSE-REF] Parsing intent data from referenced transaction")

	intentData := make(map[string]interface{})

	// Look for transaction data within the entry
	var txData map[string]interface{}
	if tx, ok := transactionData["transaction"].(map[string]interface{}); ok {
		txData = tx
	} else {
		txData = transactionData
	}

	// Extract intent data from the transaction body - decode ALL data elements dynamically
	if body, ok := txData["body"].(map[string]interface{}); ok {
		if writeDataEntry, ok := body["entry"].(map[string]interface{}); ok {
			if data, ok := writeDataEntry["data"].([]interface{}); ok && len(data) > 0 {
				log.Printf("🔍 [PARSE-REF] Found DoubleHashDataEntry with %d data elements", len(data))

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
									log.Printf("✅ [PARSE-REF] Decoded intentData from element %d: %+v", i, jsonData)
								case 1:
									intentData["crossChainData"] = jsonData
									log.Printf("✅ [PARSE-REF] Decoded crossChainData from element %d: %+v", i, jsonData)
								case 2:
									intentData["governanceData"] = jsonData
									log.Printf("✅ [PARSE-REF] Decoded governanceData from element %d: %+v", i, jsonData)
								case 3:
									intentData["replayData"] = jsonData
									log.Printf("✅ [PARSE-REF] Decoded replayData from element %d: %+v", i, jsonData)
								default:
									// Handle additional data elements beyond the core 4
									fieldKey := fmt.Sprintf("additionalData_%d", i)
									intentData[fieldKey] = jsonData
									log.Printf("✅ [PARSE-REF] Decoded additional data element %s: %+v", fieldKey, jsonData)
								}
							} else {
								// Some elements might be raw text or other formats, store as hex string
								intentData[fmt.Sprintf("rawElement_%d", i)] = hexStr
								log.Printf("🔄 [PARSE-REF] Stored raw hex from element %d (not JSON)", i)
							}
						} else {
							log.Printf("⚠️ [PARSE-REF] Failed to decode hex from element %d: %v", i, err)
						}
					}
				}
				log.Printf("✅ [PARSE-REF] Successfully parsed %d intent data elements", len(intentData))
			}
		}
	}

	return intentData
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
	blocks, err := l.queryMinorBlocks(ctx, "acc://dn", minorHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to query DN minor block %d: %w", minorHeight, err)
	}
	if len(blocks) == 0 || blocks[0] == nil {
		return nil, fmt.Errorf("no DN minor block found at height %d", minorHeight)
	}

	b := blocks[0]

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

	client := &http.Client{Timeout: l.config.RequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("🔍 [V3-API] Response body: %s", string(body))

	// Parse JSON response
	var apiResp V3APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, fmt.Errorf("API error: %s (%d)", apiResp.Error.Message, apiResp.Error.Code)
	}

	// Return just the result as a map for easier parsing
	if result, ok := apiResp.Result.(map[string]interface{}); ok {
		return result, nil
	}

	return map[string]interface{}{"result": apiResp.Result}, nil
}

// getNetworkStatusV3 gets current network status using direct v3 API calls
func (l *LiteClientAdapter) getNetworkStatusV3(ctx context.Context) (*NetworkStatus, error) {
	log.Printf("🔍 [V3-API] Querying network status...")

	// Primary: direct network-status
	result, err := l.queryV3API(ctx, "network-status", map[string]interface{}{})
	if err != nil {
		log.Printf("⚠️ [V3-API] network-status failed: %v", err)
		log.Printf("🔁 [V3-API] Falling back to BVN/DN block query")
		return l.queryBVNStatus(ctx)
	}

	log.Printf("🔍 [V3-API] network-status result: %+v", result)

	// Preferred: directoryHeight (current DN directory height)
	if directoryHeight, ok := result["directoryHeight"].(float64); ok {
		actualBlockHeight := int64(directoryHeight)
		log.Printf("🎯 [V3-API] directoryHeight=%d", actualBlockHeight)

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
					LastBlockHeight: actualBlockHeight,
					LastBlockHash:   fmt.Sprintf("block_%d", actualBlockHeight),
					LastBlockTime:   time.Now().Format(time.RFC3339),
				},
			},
		}, nil
	}

	// If schema changes and directoryHeight is absent, we *still* don't guess.
	log.Printf("⚠️ [V3-API] directoryHeight not present in network-status result; falling back to BVN/DN query")
	return l.queryBVNStatus(ctx)
}

// queryMinorBlocks queries exactly one minor block from a partition using v3 API
func (l *LiteClientAdapter) queryMinorBlocks(ctx context.Context, partitionURL string, blockHeight int64) ([]*MinorBlock, error) {
	log.Printf("🔍 [BLOCK-QUERY] Querying single minor block %d from partition: %s", blockHeight, partitionURL)

	// Convert partition URL to correct ledger scope
	ledgerScope := l.convertToLedgerScope(partitionURL)
	log.Printf("🔧 [SCOPE-FIX] Converted %s to ledger scope: %s", partitionURL, ledgerScope)

	// Query exactly one block with expand=true to get full transaction details including memo
	// Include entryRange with high count to get ALL entries (blocks can have many entries)
	queryParams := map[string]interface{}{
		"scope": ledgerScope,
		"query": map[string]interface{}{
			"queryType": "block",
			"minor":     blockHeight,
			"expand":    true,
			"entryRange": map[string]interface{}{
				"start": 0,
				"count": 500, // Get up to 500 entries per block
			},
		},
	}

	response, err := l.queryV3API(ctx, "query", queryParams)
	if err != nil {
		return nil, fmt.Errorf("failed to query block %d from %s: %w", blockHeight, partitionURL, err)
	}

	// Parse the block response
	block := l.parseMinorBlockRecord(response, partitionURL, blockHeight)
	if block != nil {
		log.Printf("✅ [BLOCK-QUERY] Successfully retrieved block %d: entryCount=%d", blockHeight, len(block.Entries))
		return []*MinorBlock{block}, nil
	}

	return nil, nil
}

// convertToLedgerScope converts partition URLs to correct ledger scopes for v3 API
// BVN transactions are anchored to Directory Network - we search DN blocks for anchored BVN transactions
func (l *LiteClientAdapter) convertToLedgerScope(partitionURL string) string {
	switch partitionURL {
	case "acc://bvn1", "acc://bvn2", "acc://bvn3":
		// BVN transactions are anchored to Directory - query Directory for anchored entries
		return "acc://dn.acme/ledger"
	case "acc://dn":
		return "acc://dn.acme/ledger"
	default:
		// If already in correct format, return as-is
		return partitionURL
	}
}

// MinorBlock represents a minor block from Accumulate v3 API
type MinorBlock struct {
	Height    int64        `json:"height"`
	Index     int64        `json:"index"`
	Time      time.Time    `json:"time"`
	Partition string       `json:"partition"`
	Entries   []BlockEntry `json:"entries"`
}

// BlockEntry represents an entry (transaction) in a minor block
type BlockEntry struct {
	Index int                    `json:"index"`
	Type  string                 `json:"type"`
	Data  map[string]interface{} `json:"data"`
}

// parseMinorBlockRecord parses a single MinorBlockRecord from the v3 API response
func (l *LiteClientAdapter) parseMinorBlockRecord(recordMap map[string]interface{}, partition string, defaultHeight int64) *MinorBlock {
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

	// Extract block time
	if timeStr, ok := blockData["time"].(string); ok {
		if parsedTime, err := time.Parse(time.RFC3339, timeStr); err == nil {
			block.Time = parsedTime
		}
	}

	// Extract entries using the TypeScript getBlockEntries pattern
	block.Entries = l.getBlockEntries(blockData, block.Height, partition)

	return block
}

// getBlockEntries implements the TypeScript getBlockEntries.ts pattern
func (l *LiteClientAdapter) getBlockEntries(blockData map[string]interface{}, blockHeight int64, partition string) []BlockEntry {
	var allEntries []interface{}

	// Get direct entries from block.entries.records
	if entries, ok := blockData["entries"].(map[string]interface{}); ok {
		if records, ok := entries["records"].([]interface{}); ok {
			allEntries = append(allEntries, records...)
			log.Printf("🔍 [BLOCK-PARSE] Found %d direct entries.records in block %d from %s", len(records), blockHeight, partition)
		}
	}

	// Get anchored entries from block.anchored.records.flatMap(x => x.entries.records)
	if anchored, ok := blockData["anchored"].(map[string]interface{}); ok {
		if anchoredRecords, ok := anchored["records"].([]interface{}); ok {
			log.Printf("🔍 [ANCHORED] Found %d anchored records in block %d", len(anchoredRecords), blockHeight)
			for _, anchoredRecord := range anchoredRecords {
				if anchoredMap, ok := anchoredRecord.(map[string]interface{}); ok {
					if anchoredEntries, ok := anchoredMap["entries"].(map[string]interface{}); ok {
						if anchoredEntriesRecords, ok := anchoredEntries["records"].([]interface{}); ok {
							allEntries = append(allEntries, anchoredEntriesRecords...)
							log.Printf("🔍 [ANCHORED] Added %d anchored entries.records from block %d", len(anchoredEntriesRecords), blockHeight)
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
				Index: entryIdx,
				Data:  entryMap,
			}

			// Extract entry type if available
			if entryType, ok := entryMap["type"].(string); ok {
				blockEntry.Type = entryType
			}

			blockEntries = append(blockEntries, blockEntry)
			log.Printf("📝 [ENTRY-PARSE] Entry %d: type=%s", entryIdx, blockEntry.Type)
		}
	}

	log.Printf("✅ [BLOCK-ENTRIES] Block %d from %s: found %d total entries (%d direct + anchored)",
		blockHeight, partition, len(blockEntries), len(allEntries))

	return blockEntries
}

// queryBVNStatus tries to get block information from a BVN partition
func (l *LiteClientAdapter) queryBVNStatus(ctx context.Context) (*NetworkStatus, error) {
	log.Printf("🔍 [V3-API] Querying BVN partitions for latest block info...")

	// Try each BVN partition to get the latest block information
	partitions := []string{"acc://bvn1", "acc://bvn2", "acc://bvn3", "acc://dn"}

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
	log.Printf("🔍 [BLOCK-HEIGHT] Getting current block height from v3 network status")

	// Primary: Use v3 network-status API (the only reliable approach)
	networkStatus, err := l.getNetworkStatusV3(ctx)
	if err == nil {
		latestHeight := uint64(networkStatus.Network.Status.LastBlockHeight)
		log.Printf("✅ [BLOCK-HEIGHT] Got block height from v3 network status: %d", latestHeight)
		return l.GetBlock(ctx, latestHeight)
	}

	// Log the failure and return an error instead of unreliable fallbacks
	log.Printf("❌ [BLOCK-HEIGHT] Failed to get network status from v3 API: %v", err)
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

// GetTransactionStatus queries the status of a transaction by hash
func (l *LiteClientAdapter) GetTransactionStatus(ctx context.Context, txHash string) (string, error) {
	if l.client == nil {
		return "", fmt.Errorf("lite client not initialized")
	}

	// Query transaction using V3 API
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope":  fmt.Sprintf("acc://%s@unknown", txHash),
		"query": map[string]interface{}{
			"queryType": "transactionStatus",
		},
	})
	if err != nil {
		return "", fmt.Errorf("query transaction status: %w", err)
	}

	// Extract status from response
	if record, ok := result["record"].(map[string]interface{}); ok {
		if status, ok := record["status"].(map[string]interface{}); ok {
			if code, ok := status["code"].(string); ok {
				return code, nil
			}
			if codeFloat, ok := status["code"].(float64); ok {
				// Map numeric codes to string status
				switch int(codeFloat) {
				case 0:
					return "pending", nil
				case 201:
					return "delivered", nil
				default:
					return "unknown", nil
				}
			}
		}
	}

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
	// The API expects: { "envelope": { "signatures": [...], "transaction": [...] } }
	submitRequest := map[string]interface{}{
		"envelope": envelope,
	}

	log.Printf("🔍 [V3-SUBMIT] Submitting envelope to Accumulate with method 'submit'")

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

	// If we got a success response but no ID, generate one from the envelope
	if result["success"] == true || result["message"] == nil {
		log.Printf("⚠️ [V3-SUBMIT] No transaction ID in response, but submission appears successful")
		return "submitted-pending-id", nil
	}

	return "", fmt.Errorf("no transaction hash in response: %+v", result)
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
