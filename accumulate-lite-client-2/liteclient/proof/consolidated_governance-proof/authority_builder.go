// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CERTEN Governance Proof - Authority Snapshot Builder
// This file implements KPSW-EXEC (Key Page State at Execution) authority snapshot building
// Direct translation of Python authority snapshot building methods from gov_proof_level_G1.py

// =============================================================================
// Authority Snapshot Builder
// =============================================================================

// AuthorityBuilder handles KPSW-EXEC authority snapshot construction
type AuthorityBuilder struct {
	client          RPCClientInterface
	artifactManager *ArtifactManager
	queryBuilder    QueryBuilder
}

// NewAuthorityBuilder creates a new authority snapshot builder
func NewAuthorityBuilder(client RPCClientInterface, artifactManager *ArtifactManager) *AuthorityBuilder {
	return &AuthorityBuilder{
		client:          client,
		artifactManager: artifactManager,
		queryBuilder:    QueryBuilder{},
	}
}

// BuildAuthoritySnapshot builds complete authority snapshot at execution time
// Direct translation of Python build_authority_snapshot
func (ab *AuthorityBuilder) BuildAuthoritySnapshot(ctx context.Context, keyPage string, execMBI int64, execWitness string) (*AuthoritySnapshot, error) {
	fmt.Printf("[AUTHORITY] Building authority snapshot for %s at MBI %d\n", keyPage, execMBI)

	// Use the full keyPage URL for querying main chain entries
	// This is critical: updateKeyPage transactions are on the KEY PAGE's main chain,
	// not the ADI's main chain. Previous bug queried ADI instead of key page.
	keyPageScope := keyPage
	if !strings.HasPrefix(keyPageScope, "acc://") {
		keyPageScope = "acc://" + keyPageScope
	}

	// Get key page's main chain count
	mainCount, err := ab.getMainChainCount(ctx, keyPageScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get main chain count: %v", err)
	}

	fmt.Printf("[AUTHORITY] Key page %s has %d entries on main chain\n", keyPageScope, mainCount)

	// Enumerate all key page's main chain entries
	mainEntries, err := ab.enumerateMainEntries(ctx, keyPageScope, mainCount)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate main entries: %v", err)
	}

	// Classify governance events
	fmt.Printf("[AUTHORITY] [DEBUG] Classifying %d entries for governance events...\n", len(mainEntries))
	genesis, mutations, err := ab.classifyGovernanceEvents(mainEntries, execMBI, keyPage)
	if err != nil {
		return nil, fmt.Errorf("failed to classify governance events: %v", err)
	}

	// Validate exactly one genesis event exists
	if genesis == nil {
		return nil, ValidationError{Msg: "No genesis event found for key page"}
	}

	fmt.Printf("[AUTHORITY] Found genesis at block %d with %d mutations\n", genesis.LocalBlock, len(mutations))

	// Build final state by applying mutations chronologically
	finalState, err := ab.buildFinalState(*genesis, mutations)
	if err != nil {
		return nil, fmt.Errorf("failed to build final state: %v", err)
	}

	// Create validation summary
	validation := ValidationSummary{
		GenesisFound:     true,
		MutationsApplied: len(mutations),
		TotalEntries:     len(mainEntries),
		FinalVersion:     finalState.Version,
		FinalThreshold:   finalState.Threshold,
		FinalKeyCount:    len(finalState.Keys),
	}

	// Build authority snapshot
	snapshot := &AuthoritySnapshot{
		Page: keyPage,
		ExecTerms: ExecTerms{
			MBI:     execMBI,
			Witness: execWitness,
		},
		StateExec:  finalState,
		Genesis:    *genesis,
		Mutations:  mutations,
		Validation: validation,
	}

	fmt.Printf("[AUTHORITY] Authority snapshot complete: version=%d, threshold=%d, keys=%d\n",
		finalState.Version, finalState.Threshold, len(finalState.Keys))

	return snapshot, nil
}

// getMainChainCount gets the total count of main chain entries for the given scope
// Direct translation of Python count query logic
func (ab *AuthorityBuilder) getMainChainCount(ctx context.Context, scopeURL string) (int, error) {
	// Build count query like Python: count=0 returns total count
	query := ab.queryBuilder.BuildChainQuery("main", nil, nil, nil, false, &[]bool{false}[0])

	// scopeURL should already be a full acc:// URL
	response, err := ab.artifactManager.SaveRPCArtifact(
		ctx,
		"g1_authority_count",
		ab.client,
		scopeURL,
		query,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to query main chain count: %v", err)
	}

	// Extract result from RPC response
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(response)
	if err != nil {
		return 0, fmt.Errorf("failed to extract result: %v", err)
	}

	// Extract count field
	countField := pu.CaseInsensitiveGet(result, "count")
	if countField == nil {
		return 0, ValidationError{Msg: "Missing count in chain query response"}
	}

	var totalEntries int
	switch count := countField.(type) {
	case float64:
		totalEntries = int(count)
	case int:
		totalEntries = count
	case int64:
		totalEntries = int(count)
	default:
		return 0, ValidationError{Msg: fmt.Sprintf("Invalid count type: %T", countField)}
	}

	return totalEntries, nil
}

// enumerateMainEntries enumerates all main chain entries with paging for the given scope
func (ab *AuthorityBuilder) enumerateMainEntries(ctx context.Context, scopeURL string, totalCount int) ([]map[string]interface{}, error) {
	var allEntries []map[string]interface{}
	pageSize := 50 // Reasonable page size for enumeration

	for start := 0; start < totalCount; start += pageSize {
		count := pageSize
		if start+count > totalCount {
			count = totalCount - start
		}

		query := ab.queryBuilder.BuildMainChainRangeQuery(start, count)

		// scopeURL should already be a full acc:// URL
		response, err := ab.artifactManager.SaveRPCArtifact(
			ctx,
			fmt.Sprintf("main_entries_%d_%d", start, count),
			ab.client,
			scopeURL,
			query,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate main entries [%d:%d]: %v", start, start+count, err)
		}

		// Extract entries from response (JSON-RPC 2.0 standard format - aligned with Python)
		pu := ProofUtilities{}
		var data interface{}
		if data = pu.CaseInsensitiveGet(response, "result"); data == nil {
			data = pu.CaseInsensitiveGet(response, "data") // Fallback
		}
		if data != nil {
			if dataMap, ok := data.(map[string]interface{}); ok {
				if records := pu.CaseInsensitiveGet(dataMap, "records"); records != nil {
					if recordsArray, ok := records.([]interface{}); ok {
						for _, record := range recordsArray {
							if recordMap, ok := record.(map[string]interface{}); ok {
								allEntries = append(allEntries, recordMap)
							}
						}
					}
				}
			}
		}
	}

	if len(allEntries) != totalCount {
		return nil, ValidationError{Msg: fmt.Sprintf("Entry count mismatch: expected %d, got %d", totalCount, len(allEntries))}
	}

	fmt.Printf("[AUTHORITY] Enumerated %d main chain entries\n", len(allEntries))
	return allEntries, nil
}

// classifyGovernanceEvents classifies main chain entries as governance events
func (ab *AuthorityBuilder) classifyGovernanceEvents(entries []map[string]interface{}, execMBI int64, keyPage string) (*GenesisEvent, []MutationEvent, error) {
	fmt.Printf("[AUTHORITY] [DEBUG] Starting classification of %d entries\n", len(entries))
	var genesis *GenesisEvent
	var mutations []MutationEvent

	pu := ProofUtilities{}

	// Use the full keyPage URL for entry expansion queries
	// This ensures we query the key page's chain, not the ADI's chain
	keyPageScope := keyPage
	if !strings.HasPrefix(keyPageScope, "acc://") {
		keyPageScope = "acc://" + keyPageScope
	}

	// Phase 2: Expand each entry and classify (matching Python approach)
	for i, entry := range entries {
		fmt.Printf("[AUTHORITY] [DEBUG] Processing entry %d/%d\n", i+1, len(entries))

		// Get entry hash from range query result
		entryHash, ok := pu.CaseInsensitiveGet(entry, "entry").(string)
		if !ok {
			fmt.Printf("[AUTHORITY] [WARN] Entry %d: No entry hash found\n", i+1)
			continue
		}

		// Expand entry to get full transaction details (like Python lines 386-402)
		fmt.Printf("[AUTHORITY] [DEBUG] Expanding entry %s...\n", entryHash[:16])
		expandedEntry, err := ab.expandSingleEntry(entryHash, keyPageScope)
		if err != nil {
			fmt.Printf("[AUTHORITY] [WARN] Failed to expand entry %s: %v\n", entryHash[:16], err)
			continue
		}

		// Extract receipt from expanded entry for timing validation
		receipt, err := ab.extractReceiptFromEntry(expandedEntry)
		if err != nil {
			fmt.Printf("[AUTHORITY] [WARN] Entry %d: Failed to extract receipt from expanded entry: %v\n", i+1, err)
			continue
		}

		// Skip entries after execution MBI (like Python line 414)
		if receipt.LocalBlock > execMBI {
			fmt.Printf("[AUTHORITY] [DEBUG] Entry %d: Skipped (localBlock %d > execMBI %d)\n", i+1, receipt.LocalBlock, execMBI)
			continue
		}
		fmt.Printf("[AUTHORITY] [DEBUG] Entry %d: Processing (localBlock %d <= execMBI %d)\n", i+1, receipt.LocalBlock, execMBI)

		// Extract message from expanded entry
		var msg interface{}
		if value := pu.CaseInsensitiveGet(expandedEntry, "value"); value != nil {
			if valueMap, ok := value.(map[string]interface{}); ok {
				msg = pu.CaseInsensitiveGet(valueMap, "message")
				fmt.Printf("[AUTHORITY] [DEBUG] Extracted message from expanded entry %s\n", entryHash[:16])
			}
		}

		if msg == nil {
			continue
		}

		msgMap, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}

		// Debug: Show what transaction type we found
		txType := ab.getTransactionType(msg)
		fmt.Printf("[AUTHORITY] [DEBUG] Entry %s transaction type: %s at block %d\n", entryHash[:16], txType, receipt.LocalBlock)

		// Check for syntheticCreateIdentity (aligned with Python _is_synthetic_create_identity)
		// Pass the entire expanded entry value, which contains the message structure
		entryValue := pu.CaseInsensitiveGet(expandedEntry, "value")
		fmt.Printf("[AUTHORITY] [DEBUG] Checking if entry is syntheticCreateIdentity (entryValue nil: %t)\n", entryValue == nil)
		if ab.isSyntheticCreateIdentity(entryValue) {
			fmt.Printf("[AUTHORITY] [DEBUG] Found syntheticCreateIdentity at block %d\n", receipt.LocalBlock)

			if genesis != nil {
				return nil, nil, ValidationError{Msg: "Multiple genesis events found"}
			}

			// Extract entry hash (aligned with JSON-RPC response format)
			if entryStr, ok := pu.CaseInsensitiveGet(entry, "entry").(string); ok {
				// Parse initial key page state from transaction
				pageState, err := ab.parseGenesisKeyPageState(msgMap, keyPage)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse genesis key page state: %v", err)
				}

				genesis = &GenesisEvent{
					EntryHash:  entryStr,
					LocalBlock: receipt.LocalBlock,
					Receipt:    receipt,
					TxType:     "syntheticCreateIdentity",
					PageState:  pageState,
				}

				fmt.Printf("[AUTHORITY] [GENESIS] Found at block %d, version=%d, threshold=%d, keys=%d\n",
					receipt.LocalBlock, pageState.Version, pageState.Threshold, len(pageState.Keys))
			}
		} else if ab.isUpdateKeyPage(msg) {
			fmt.Printf("[AUTHORITY] [DEBUG] Found updateKeyPage at block %d\n", receipt.LocalBlock)

			// Extract entry hash (aligned with JSON-RPC response format)
			if entryStr, ok := pu.CaseInsensitiveGet(entry, "entry").(string); ok {
				// Parse key page mutation
				prevState, newState, err := ab.parseKeyPageMutation(msgMap)
				if err != nil {
					fmt.Printf("[AUTHORITY] [WARN] Failed to parse key page mutation at block %d: %v\n", receipt.LocalBlock, err)
					continue
				}

				mutation := MutationEvent{
					EntryHash:     entryStr,
					LocalBlock:    receipt.LocalBlock,
					Receipt:       receipt,
					TxType:        "updateKeyPage",
					PreviousState: prevState,
					NewState:      newState,
				}

				mutations = append(mutations, mutation)

				fmt.Printf("[AUTHORITY] [MUTATION] Found at block %d, version %d->%d, threshold %d->%d\n",
					receipt.LocalBlock, prevState.Version, newState.Version, prevState.Threshold, newState.Threshold)
			}
		} else {
			// Skip non-governance transactions (aligned with Python approach)
			fmt.Printf("[AUTHORITY] [DEBUG] Skipping non-governance transaction at block %d\n", receipt.LocalBlock)
		}
	}

	// Sort mutations chronologically with enhanced ordering logic
	sort.Slice(mutations, func(i, j int) bool {
		// Primary sort: by block number
		if mutations[i].LocalBlock != mutations[j].LocalBlock {
			return mutations[i].LocalBlock < mutations[j].LocalBlock
		}

		// Secondary sort: extract and compare chain indices if available
		chainIndexI := ab.extractChainIndex(mutations[i])
		chainIndexJ := ab.extractChainIndex(mutations[j])

		if chainIndexI != chainIndexJ {
			return chainIndexI < chainIndexJ
		}

		// Tertiary sort: fallback to lexicographic entry hash comparison for deterministic ordering
		return mutations[i].EntryHash < mutations[j].EntryHash
	})

	return genesis, mutations, nil
}

// extractChainIndex extracts chain index from authority mutation for proper ordering
// Returns index based on entry hash patterns or falls back to hash-based ordering
func (ab *AuthorityBuilder) extractChainIndex(mutation MutationEvent) int {
	// For deterministic ordering, use the first 8 bytes of the entry hash
	// converted to an integer. This ensures consistent ordering across runs.
	if len(mutation.EntryHash) >= 16 {
		// Use first 8 hex characters (4 bytes) as a pseudo-index
		hashPrefix := mutation.EntryHash[:8]
		// Convert hex to integer for numerical comparison
		if val, err := strconv.ParseUint(hashPrefix, 16, 32); err == nil {
			return int(val)
		}
	}

	// Fallback: use hash code of entry hash for ordering
	hash := 0
	for _, c := range mutation.EntryHash {
		hash = hash*31 + int(c)
	}
	// Ensure positive value
	if hash < 0 {
		hash = -hash
	}
	return hash
}

// normalizeURL normalizes an Accumulate URL for comparison
func normalizeURL(url string) string {
	// Remove any trailing slashes and convert to lowercase for consistent comparison
	url = strings.TrimSpace(url)
	url = strings.ToLower(url)
	url = strings.TrimSuffix(url, "/")
	return url
}

// getTransactionType extracts transaction type for debugging
func (ab *AuthorityBuilder) getTransactionType(msg interface{}) string {
	pu := ProofUtilities{}
	msgMap, ok := msg.(map[string]interface{})
	if !ok {
		return "invalid-message"
	}

	msgType := pu.CaseInsensitiveGet(msgMap, "type")
	if msgType != "transaction" {
		return fmt.Sprintf("non-transaction-%v", msgType)
	}

	transaction := pu.CaseInsensitiveGet(msgMap, "transaction")
	if transaction == nil {
		return "no-transaction-field"
	}

	txMap, ok := transaction.(map[string]interface{})
	if !ok {
		return "invalid-transaction-field"
	}

	body := pu.CaseInsensitiveGet(txMap, "body")
	if body == nil {
		return "no-body-field"
	}

	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		return "invalid-body-field"
	}

	bodyType := pu.CaseInsensitiveGet(bodyMap, "type")
	if bodyType == nil {
		return "no-body-type"
	}

	return fmt.Sprintf("%v", bodyType)
}

// expandSingleEntry expands a chain entry to get full transaction details
func (ab *AuthorityBuilder) expandSingleEntry(entryHash, scopeURL string) (map[string]interface{}, error) {
	// Build query for individual chain entry with expansion (aligned with Python approach)
	query := map[string]interface{}{
		"queryType":     "chain",
		"name":          "main",
		"entry":         entryHash,
		"expand":        true,
		"includeReceipt": true,
	}

	// Execute query
	response, err := ab.client.Query(
		context.Background(),
		scopeURL,
		query,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to expand entry: %v", err)
	}

	// Extract result using JSON-RPC 2.0 format
	pu := ProofUtilities{}
	var data interface{}
	if data = pu.CaseInsensitiveGet(response, "result"); data == nil {
		data = pu.CaseInsensitiveGet(response, "data")
		if data == nil {
			return nil, ValidationError{Msg: "Response missing result{} or data{}"}
		}
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Expanded entry data is not an object"}
	}

	return dataMap, nil
}

// isSyntheticCreateIdentity checks if the message value represents a syntheticCreateIdentity transaction
func (ab *AuthorityBuilder) isSyntheticCreateIdentity(value interface{}) bool {
	fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: Starting check\n")
	valueMap, ok := value.(map[string]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: value not a map\n")
		return false
	}

	pu := ProofUtilities{}
	message := pu.CaseInsensitiveGet(valueMap, "message")
	if message == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: no message field found\n")
		return false
	}

	messageMap, ok := message.(map[string]interface{})
	if !ok {
		return false
	}

	msgType := pu.CaseInsensitiveGet(messageMap, "type")
	msgTypeStr, ok := msgType.(string)
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: message.type not string: %T\n", msgType)
		return false
	}
	fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: message.type = %s\n", msgTypeStr)

	// Check that this is a transaction message
	if !strings.EqualFold(msgTypeStr, "transaction") {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: not a transaction message\n")
		return false
	}

	// Get transaction object
	transaction := pu.CaseInsensitiveGet(messageMap, "transaction")
	if transaction == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: no transaction field\n")
		return false
	}

	transactionMap, ok := transaction.(map[string]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: transaction not a map\n")
		return false
	}

	// Get transaction body
	body := pu.CaseInsensitiveGet(transactionMap, "body")
	if body == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: no body field\n")
		return false
	}

	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: body not a map\n")
		return false
	}

	// Get body type
	bodyType := pu.CaseInsensitiveGet(bodyMap, "type")
	bodyTypeStr, ok := bodyType.(string)
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: body.type not string: %T\n", bodyType)
		return false
	}

	fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: body.type = %s\n", bodyTypeStr)
	result := strings.EqualFold(bodyTypeStr, "syntheticCreateIdentity")
	fmt.Printf("[AUTHORITY] [DEBUG] isSyntheticCreateIdentity: result = %t\n", result)
	return result
}

// isUpdateKeyPage checks if the message value represents an updateKeyPage transaction
func (ab *AuthorityBuilder) isUpdateKeyPage(value interface{}) bool {
	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return false
	}

	pu := ProofUtilities{}
	message := pu.CaseInsensitiveGet(valueMap, "message")
	if message == nil {
		return false
	}

	messageMap, ok := message.(map[string]interface{})
	if !ok {
		return false
	}

	msgType := pu.CaseInsensitiveGet(messageMap, "type")
	msgTypeStr, ok := msgType.(string)
	if !ok {
		return false
	}

	return strings.EqualFold(msgTypeStr, "updateKeyPage")
}

// parseGenesisKeyPageState parses initial key page state from syntheticCreateIdentity
func (ab *AuthorityBuilder) parseGenesisKeyPageState(msg map[string]interface{}, targetKeyPage string) (KeyPageState, error) {
	pu := ProofUtilities{}

	fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: Starting parse\n")

	// Based on Python implementation, navigate to transaction.body.accounts[]
	transaction := pu.CaseInsensitiveGet(msg, "transaction")
	if transaction == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: no transaction field\n")
		return KeyPageState{}, ValidationError{Msg: "No transaction field in genesis message"}
	}

	transactionMap, ok := transaction.(map[string]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: transaction not a map\n")
		return KeyPageState{}, ValidationError{Msg: "Transaction field is not an object"}
	}

	body := pu.CaseInsensitiveGet(transactionMap, "body")
	if body == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: no body field\n")
		return KeyPageState{}, ValidationError{Msg: "No body field in transaction"}
	}

	bodyMap, ok := body.(map[string]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: body not a map\n")
		return KeyPageState{}, ValidationError{Msg: "Body field is not an object"}
	}

	accounts := pu.CaseInsensitiveGet(bodyMap, "accounts")
	if accounts == nil {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: no accounts field\n")
		return KeyPageState{}, ValidationError{Msg: "No accounts array in genesis transaction body"}
	}

	accountsArray, ok := accounts.([]interface{})
	if !ok {
		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: accounts not an array\n")
		return KeyPageState{}, ValidationError{Msg: "Accounts field is not an array"}
	}

	fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: Found %d accounts in genesis\n", len(accountsArray))

	// Search for the target key page in the accounts array (like Python lines 849-856)
	fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: Looking for target keypage: %s\n", targetKeyPage)

	for i, account := range accountsArray {
		accountMap, ok := account.(map[string]interface{})
		if !ok {
			fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: account %d not a map\n", i)
			continue
		}

		accountURL := pu.CaseInsensitiveGet(accountMap, "url")
		accountType := pu.CaseInsensitiveGet(accountMap, "type")

		fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: Account %d: url=%v, type=%v\n", i, accountURL, accountType)

		// Check if this account matches our target keypage URL and is a keypage type
		if accountURL != nil && accountType != nil {
			if accountURLStr, ok := accountURL.(string); ok {
				if accountTypeStr, ok := accountType.(string); ok {
					if normalizeURL(accountURLStr) == normalizeURL(targetKeyPage) &&
					   strings.EqualFold(accountTypeStr, "keypage") {
						fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: Found matching keypage account\n")
						return ab.parseKeyPageStateFromDef(accountMap)
					}
				}
			}
		}
	}

	fmt.Printf("[AUTHORITY] [DEBUG] parseGenesisKeyPageState: No matching keypage found for %s\n", targetKeyPage)
	return KeyPageState{}, ValidationError{Msg: "No key page definition found in genesis"}
}

// parseKeyPageMutation parses previous and new states from updateKeyPage transaction
func (ab *AuthorityBuilder) parseKeyPageMutation(msg map[string]interface{}) (KeyPageState, KeyPageState, error) {
	pu := ProofUtilities{}

	// Extract previous state
	prevState := pu.CaseInsensitiveGet(msg, "previousState")
	if prevState == nil {
		return KeyPageState{}, KeyPageState{}, ValidationError{Msg: "Missing previousState in updateKeyPage"}
	}

	prevStateMap, ok := prevState.(map[string]interface{})
	if !ok {
		return KeyPageState{}, KeyPageState{}, ValidationError{Msg: "previousState is not an object"}
	}

	// Extract new state
	newState := pu.CaseInsensitiveGet(msg, "newState")
	if newState == nil {
		newState = pu.CaseInsensitiveGet(msg, "keyPage") // Alternative path
	}
	if newState == nil {
		return KeyPageState{}, KeyPageState{}, ValidationError{Msg: "Missing newState in updateKeyPage"}
	}

	newStateMap, ok := newState.(map[string]interface{})
	if !ok {
		return KeyPageState{}, KeyPageState{}, ValidationError{Msg: "newState is not an object"}
	}

	// Parse both states
	prev, err := ab.parseKeyPageStateFromDef(prevStateMap)
	if err != nil {
		return KeyPageState{}, KeyPageState{}, fmt.Errorf("failed to parse previous state: %v", err)
	}

	new, err := ab.parseKeyPageStateFromDef(newStateMap)
	if err != nil {
		return KeyPageState{}, KeyPageState{}, fmt.Errorf("failed to parse new state: %v", err)
	}

	return prev, new, nil
}

// parseKeyPageStateFromDef parses KeyPageState from key page definition object
func (ab *AuthorityBuilder) parseKeyPageStateFromDef(keyPageDef map[string]interface{}) (KeyPageState, error) {
	pu := ProofUtilities{}

	// Extract version
	version := pu.CaseInsensitiveGet(keyPageDef, "version")
	var versionNum uint64
	switch v := version.(type) {
	case float64:
		versionNum = uint64(v)
	case int:
		versionNum = uint64(v)
	case int64:
		versionNum = uint64(v)
	case uint64:
		versionNum = v
	default:
		return KeyPageState{}, ValidationError{Msg: "Invalid or missing version in key page definition"}
	}

	// Extract threshold
	threshold := pu.CaseInsensitiveGet(keyPageDef, "threshold")
	var thresholdNum uint64
	switch t := threshold.(type) {
	case float64:
		thresholdNum = uint64(t)
	case int:
		thresholdNum = uint64(t)
	case int64:
		thresholdNum = uint64(t)
	case uint64:
		thresholdNum = t
	default:
		return KeyPageState{}, ValidationError{Msg: "Invalid or missing threshold in key page definition"}
	}

	// Extract keys
	keys := pu.CaseInsensitiveGet(keyPageDef, "keys")
	if keys == nil {
		return KeyPageState{}, ValidationError{Msg: "Missing keys in key page definition"}
	}

	keysArray, ok := keys.([]interface{})
	if !ok {
		return KeyPageState{}, ValidationError{Msg: "Keys is not an array"}
	}

	var keyHashes []string
	for _, key := range keysArray {
		if keyMap, ok := key.(map[string]interface{}); ok {
			// Extract key hash (preferring publicKeyHash over computed hash of publicKey)
			keyHashField := pu.CaseInsensitiveGet(keyMap, "publicKeyHash")
			if keyHashField == nil {
				keyHashField = pu.CaseInsensitiveGet(keyMap, "keyHash")
			}
			if keyHashStr, ok := keyHashField.(string); ok && keyHashStr != "" {
				// Using direct key hash from authority data
				keyHashes = append(keyHashes, keyHashStr)
			} else {
				// Fallback: compute hash from publicKey if no hash fields present
				pubkey := pu.CaseInsensitiveGet(keyMap, "publicKey")
				if pubkeyStr, ok := pubkey.(string); ok && pubkeyStr != "" {
					sv := SignatureVerifier{}
					keyHash, err := sv.ComputeKeyHash(pubkeyStr)
					if err != nil {
						return KeyPageState{}, fmt.Errorf("failed to compute key hash: %v", err)
					}
					keyHashes = append(keyHashes, keyHash)
				}
			}
		} else if keyStr, ok := key.(string); ok && keyStr != "" {
			// Direct key hash
			keyHashes = append(keyHashes, keyStr)
		}
	}

	if len(keyHashes) == 0 {
		return KeyPageState{}, ValidationError{Msg: "No valid keys found in key page definition"}
	}

	return KeyPageState{
		Version:   versionNum,
		Keys:      keyHashes,
		Threshold: thresholdNum,
	}, nil
}

// buildFinalState applies mutations chronologically to build final state
func (ab *AuthorityBuilder) buildFinalState(genesis GenesisEvent, mutations []MutationEvent) (KeyPageState, error) {
	state := genesis.PageState

	// Apply each mutation in order
	for _, mutation := range mutations {
		// Validate previous state matches current state
		if mutation.PreviousState.Version != state.Version {
			return KeyPageState{}, ValidationError{
				Msg: fmt.Sprintf("State version mismatch at mutation block %d: expected %d, got %d",
					mutation.LocalBlock, state.Version, mutation.PreviousState.Version),
			}
		}

		// Validate new state version increments
		if mutation.NewState.Version != state.Version+1 {
			return KeyPageState{}, ValidationError{
				Msg: fmt.Sprintf("Invalid version increment at mutation block %d: %d -> %d",
					mutation.LocalBlock, state.Version, mutation.NewState.Version),
			}
		}

		// Apply mutation
		state = mutation.NewState
		fmt.Printf("[AUTHORITY] Applied mutation: version %d -> %d at block %d\n",
			mutation.PreviousState.Version, mutation.NewState.Version, mutation.LocalBlock)
	}

	return state, nil
}

// extractReceiptFromEntry extracts receipt data from main chain entry
func (ab *AuthorityBuilder) extractReceiptFromEntry(entry map[string]interface{}) (ReceiptData, error) {
	pu := ProofUtilities{}

	receipt := pu.CaseInsensitiveGet(entry, "receipt")
	if receipt == nil {
		return ReceiptData{}, ValidationError{Msg: "Entry missing receipt"}
	}

	receiptMap, ok := receipt.(map[string]interface{})
	if !ok {
		return ReceiptData{}, ValidationError{Msg: "Receipt is not an object"}
	}

	// Extract receipt fields
	var receiptData ReceiptData

	// Start
	if start := pu.CaseInsensitiveGet(receiptMap, "start"); start != nil {
		if startStr, ok := start.(string); ok {
			receiptData.Start = startStr
		}
	}

	// Anchor
	if anchor := pu.CaseInsensitiveGet(receiptMap, "anchor"); anchor != nil {
		if anchorStr, ok := anchor.(string); ok {
			receiptData.Anchor = anchorStr
		}
	}

	// Local block
	if localBlock := pu.CaseInsensitiveGet(receiptMap, "localBlock"); localBlock != nil {
		switch lb := localBlock.(type) {
		case float64:
			receiptData.LocalBlock = int64(lb)
		case int:
			receiptData.LocalBlock = int64(lb)
		case int64:
			receiptData.LocalBlock = lb
		default:
			return ReceiptData{}, ValidationError{Msg: "Invalid localBlock in receipt"}
		}
	} else {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing localBlock"}
	}

	return receiptData, nil
}

// extractPrincipal extracts principal from key page URL
func (ab *AuthorityBuilder) extractPrincipal(keyPageURL string) (string, error) {
	uu := URLUtils{}
	normalizedURL := uu.NormalizeURL(keyPageURL)

	// Extract principal from acc://principal/page/1 format
	if !strings.HasPrefix(normalizedURL, "acc://") {
		return "", ValidationError{Msg: fmt.Sprintf("Invalid key page URL format: %s", keyPageURL)}
	}

	// Remove acc:// prefix
	path := strings.TrimPrefix(normalizedURL, "acc://")

	// Extract principal (everything before first slash)
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", ValidationError{Msg: fmt.Sprintf("Cannot extract principal from URL: %s", keyPageURL)}
	}

	return parts[0], nil
}