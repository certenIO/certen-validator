// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
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

	// ruleMu guards rules, which records the thresholds beyond accept that
	// each parsed page definition carried.
	//
	// Every key page definition in this package is parsed by
	// parseKeyPageStateFromDef, so collecting here catches the principal's
	// replayed page as well as every page reached by delegation. It is kept
	// beside KeyPageState, never on it: see g1_page_rules.go.
	ruleMu sync.Mutex
	rules  map[string]pageThresholds
}

// NewAuthorityBuilder creates a new authority snapshot builder
func NewAuthorityBuilder(client RPCClientInterface, artifactManager *ArtifactManager) *AuthorityBuilder {
	return &AuthorityBuilder{
		client:          client,
		artifactManager: artifactManager,
		queryBuilder:    QueryBuilder{},
		rules:           map[string]pageThresholds{},
	}
}

// notePageRules records what a page definition demanded beyond accept.
//
// Keyed by the page's own url when the definition carries one. A definition
// without a url is recorded under the empty key rather than dropped: a page
// carrying rules we cannot name is still a page carrying rules, and silently
// discarding it is the "narrower claim than advertised" this phase closes.
func (ab *AuthorityBuilder) notePageRules(def map[string]interface{}) {
	t := parsePageThresholds(def)
	if !t.any() {
		return
	}
	pu := ProofUtilities{}
	page, _ := pu.CaseInsensitiveGet(def, "url").(string)

	ab.ruleMu.Lock()
	if ab.rules == nil {
		ab.rules = map[string]pageThresholds{}
	}
	ab.rules[normalizeAccURL(page)] = t
	ab.ruleMu.Unlock()
}

// UnverifiedPageRules returns one note per rule that a parsed page carried and
// this proof did not re-derive. Empty for every page in the corpus and in
// production, none of which set any of them.
func (ab *AuthorityBuilder) UnverifiedPageRules() []PageRuleNote {
	ab.ruleMu.Lock()
	defer ab.ruleMu.Unlock()

	var out []PageRuleNote
	for page, t := range ab.rules {
		out = append(out, pageRuleNotes(page, t)...)
	}
	sortPageRuleNotes(out)
	return out
}

// BuildAuthoritySnapshot builds complete authority snapshot at execution time
// Direct translation of Python build_authority_snapshot
func (ab *AuthorityBuilder) BuildAuthoritySnapshot(ctx context.Context, keyPage string, execMBI int64, execWitness string) (*AuthoritySnapshot, error) {
	return ab.BuildAuthoritySnapshotFor(ctx, keyPage, execMBI, execWitness, "")
}

// BuildAuthoritySnapshotFor builds the snapshot of the page the governed
// transaction executed against.
//
// That is the page after every change recorded at or before the execution
// block - except when the governed transaction is itself one of this page's
// changes (an updateKeyPage or updateKey on the page that signed it). Then the
// state it executed against is the one immediately before it: its own effect,
// and anything after it on this chain, came later. Taking the post-block state
// instead is what refused every self-update as signed at the wrong version.
func (ab *AuthorityBuilder) BuildAuthoritySnapshotFor(ctx context.Context, keyPage string, execMBI int64,
	execWitness, governedTx string) (*AuthoritySnapshot, error) {

	fmt.Printf("[AUTHORITY] Building authority snapshot for %s at MBI %d\n", keyPage, execMBI)
	keyPageScope := normalizeAccURL(keyPage)

	tl, err := ab.BuildPageTimeline(ctx, keyPageScope)
	if err != nil {
		return nil, err
	}
	genesis := tl.Genesis

	execPage := tl.At(execMBI)
	if execPage == nil {
		return nil, ValidationError{Msg: fmt.Sprintf("%s did not exist at block %d: its genesis is at block %d",
			keyPageScope, execMBI, genesis.LocalBlock)}
	}
	cutAt := len(tl.States)
	if governedTx != "" {
		if before, ok := tl.Before(governedTx); ok {
			execPage = before
			for i, s := range tl.States {
				if s.Event != nil && strings.EqualFold(s.Event.EntryHash, governedTx) {
					cutAt = i
				}
			}
		}
	}

	var mutations []MutationEvent
	for i, s := range tl.States {
		if s.Event == nil || s.Block > execMBI || i >= cutAt {
			continue
		}
		mutations = append(mutations, MutationEvent{
			EntryHash:     s.Event.EntryHash,
			LocalBlock:    s.Event.LocalBlock,
			Receipt:       s.Event.Receipt,
			TxType:        s.Event.Txn.Body.Type().String(),
			PreviousState: stateFromPage(s.Prev),
			NewState:      stateFromPage(s.Page),
		})
	}

	fmt.Printf("[AUTHORITY] Found genesis at block %d with %d mutations at or before block %d\n",
		genesis.LocalBlock, len(mutations), execMBI)

	ab.noteRulesOf(execPage)
	finalState := stateFromPage(execPage)

	// Create validation summary
	validation := ValidationSummary{
		GenesisFound:     true,
		MutationsApplied: len(mutations),
		TotalEntries:     tl.Entries,
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
// Handles both V2 and V3 Accumulate API response formats:
//   - V2/V3 chain metadata:  { "recordType":"chain", "count": N, ... }
//   - V3 range response:     { "type":"rangeResponse", "total": N, "records": [...] }
//   - V3 chain state:        { "type":"chainState", "count": N, ... }
func (ab *AuthorityBuilder) getMainChainCount(ctx context.Context, scopeURL string) (int, error) {
	// Build count query — no range params returns chain metadata with count
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

	// Try multiple field names for count (V2/V3 API compatibility)
	// V2 and V3 chain metadata queries return "count"
	countField := pu.CaseInsensitiveGet(result, "count")

	// V3 range responses use "total" instead of "count"
	if countField == nil {
		countField = pu.CaseInsensitiveGet(result, "total")
	}

	// Some V3 responses nest count inside a "range" object
	if countField == nil {
		if rangeObj := pu.CaseInsensitiveGet(result, "range"); rangeObj != nil {
			if rangeMap, ok := rangeObj.(map[string]interface{}); ok {
				countField = pu.CaseInsensitiveGet(rangeMap, "total")
				if countField == nil {
					countField = pu.CaseInsensitiveGet(rangeMap, "count")
				}
			}
		}
	}

	// Fallback: if this is a records-based response, infer from total or records length
	if countField == nil {
		if records := pu.CaseInsensitiveGet(result, "records"); records != nil {
			if recordsArray, ok := records.([]interface{}); ok {
				// If this is a range response with records but no total field,
				// we need to know if this is a complete result. Check for "start" field.
				start := pu.CaseInsensitiveGet(result, "start")
				if start == nil {
					// No pagination — records length IS the total
					fmt.Printf("[AUTHORITY] Using records array length (%d) as chain count\n", len(recordsArray))
					return len(recordsArray), nil
				}
			}
		}
	}

	if countField == nil {
		// Log the actual response keys for debugging
		var keys []string
		for k, v := range result {
			keys = append(keys, fmt.Sprintf("%s(%T)", k, v))
		}
		fmt.Printf("[AUTHORITY] [ERROR] Chain query response keys: %v\n", keys)
		return 0, ValidationError{Msg: fmt.Sprintf("Missing count in chain query response (available fields: %v)", keys)}
	}

	var totalEntries int
	switch count := countField.(type) {
	case float64:
		totalEntries = int(count)
	case int:
		totalEntries = count
	case int64:
		totalEntries = int(count)
	case string:
		// Some API versions return count as string
		parsed, parseErr := strconv.Atoi(count)
		if parseErr != nil {
			return 0, ValidationError{Msg: fmt.Sprintf("Invalid count string: %q", count)}
		}
		totalEntries = parsed
	default:
		return 0, ValidationError{Msg: fmt.Sprintf("Invalid count type: %T", countField)}
	}

	fmt.Printf("[AUTHORITY] Chain count for %s: %d\n", scopeURL, totalEntries)
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

// normalizeURL normalizes an Accumulate URL for comparison
func normalizeURL(url string) string {
	// Remove any trailing slashes and convert to lowercase for consistent comparison
	url = strings.TrimSpace(url)
	url = strings.ToLower(url)
	url = strings.TrimSuffix(url, "/")
	return url
}

// expandSingleEntry expands a chain entry to get full transaction details (with receipt).
// Bounded by a timeout: on Kermit an anchored receipt for an OLD entry can hang indefinitely,
// so the caller falls back to a receipt-free ranged expand (graceful degradation).
func (ab *AuthorityBuilder) expandSingleEntry(entryHash, scopeURL string) (map[string]interface{}, error) {
	// Build query for individual chain entry with expansion (aligned with Python approach)
	query := map[string]interface{}{
		"queryType":      "chain",
		"name":           "main",
		"entry":          entryHash,
		"expand":         true,
		"includeReceipt": true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// Execute query
	response, err := ab.client.Query(
		ctx,
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

// parseKeyPageStateFromDef parses KeyPageState from key page definition object
func (ab *AuthorityBuilder) parseKeyPageStateFromDef(keyPageDef map[string]interface{}) (KeyPageState, error) {
	pu := ProofUtilities{}

	// Record the rules this page carries beyond its accept threshold, before
	// parsing drops them.
	ab.notePageRules(keyPageDef)

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

	// Every entry, not just the ones that carry a key.
	//
	// This loop used to collect key hashes and drop anything else, so a
	// delegated entry vanished and a page whose only entry was a delegate
	// failed with "No valid keys found". The threshold counts ENTRIES, so
	// dropping one does not lose a detail - it makes the arithmetic wrong in
	// the direction that satisfies thresholds too easily.
	var entries []KeyPageEntry
	for i, key := range keysArray {
		switch k := key.(type) {
		case map[string]interface{}:
			entry, err := parseKeyPageEntry(pu, k)
			if err != nil {
				return KeyPageState{}, fmt.Errorf("key page entry %d: %w", i, err)
			}
			if entry.IsEmpty() {
				// An entry naming neither a key nor a delegate cannot be
				// satisfied by anything. Dropping it would make the page look
				// like it has fewer entries than it does; refusing is the only
				// answer that does not quietly change the authority.
				return KeyPageState{}, ValidationError{Msg: fmt.Sprintf(
					"key page entry %d names neither a key nor a delegate; refusing to "+
						"evaluate a threshold over an authority we cannot read", i)}
			}
			entries = append(entries, entry)
		case string:
			if k != "" {
				entries = append(entries, KeyPageEntry{KeyHash: strings.ToLower(k)})
			}
		}
	}

	if len(entries) == 0 {
		return KeyPageState{}, ValidationError{Msg: "No valid entries found in key page definition"}
	}

	return KeyPageState{
		Version:   versionNum,
		Entries:   entries,
		Keys:      deriveKeyHashes(entries),
		Threshold: thresholdNum,
	}, nil
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

	// The merkle path, so the receipt can be recomputed rather than read.
	steps, err := ParseReceiptEntries(receiptMap)
	if err != nil {
		return ReceiptData{}, err
	}
	receiptData.Entries = steps

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
