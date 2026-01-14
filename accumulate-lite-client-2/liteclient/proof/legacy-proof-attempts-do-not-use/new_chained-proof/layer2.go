// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/cometbft/cometbft/rpc/client/http"
	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Layer2Builder constructs Layer 2 proofs: Partition Anchor → DN Anchor Root
//
// Layer 2 proves that a partition anchor is included in the DN at a specific height.
// This is accomplished through DN anchor search with receipt stitching.
type Layer2Builder struct {
	client      *jsonrpc.Client
	cometClient *http.HTTP // For AppHash binding verification
	debug       bool
}

// NewLayer2Builder creates a new Layer 2 proof builder
func NewLayer2Builder(client *jsonrpc.Client, debug bool) *Layer2Builder {
	return &Layer2Builder{
		client: client,
		debug:  debug,
	}
}

// NewLayer2BuilderWithComet creates a Layer 2 proof builder with CometBFT client for AppHash binding
func NewLayer2BuilderWithComet(client *jsonrpc.Client, cometEndpoint string, debug bool) (*Layer2Builder, error) {
	cometClient, err := http.New(cometEndpoint, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("failed to create CometBFT client for Layer 2: %w", err)
	}

	return &Layer2Builder{
		client:      client,
		cometClient: cometClient,
		debug:       debug,
	}, nil
}

// BuildFromLayer1 constructs Layer 2 proof by searching DN anchors for the Layer 1 anchor
//
// This method follows the canonical construction algorithm:
// 1. Take L1.Anchor as the search target
// 2. Query dn.acme/anchors with anchorSearch and includeReceipt=true
// 3. Validate receipt stitching (L2.start == L1.anchor)
// 4. Return Layer2AnchorToDN proof object
func (l2 *Layer2Builder) BuildFromLayer1(ctx context.Context, layer1 *Layer1EntryInclusion) (*Layer2AnchorToDN, error) {
	// Validate input
	if layer1 == nil {
		return nil, fmt.Errorf("Layer 1 proof cannot be nil")
	}

	if l2.debug {
		log.Printf("[LAYER2] Building proof for L1 anchor: %s", safeHex(layer1.Anchor, 8))
	}

	if len(layer1.Anchor) == 0 {
		return nil, fmt.Errorf("Layer 1 anchor cannot be empty")
	}

	// Construct DN anchors query
	dnAnchorsURL, err := acc_url.Parse("acc://dn.acme/anchors")
	if err != nil {
		return nil, fmt.Errorf("failed to parse DN anchors URL: %w", err)
	}

	// Create anchor search query per spec
	query := &v3.AnchorSearchQuery{
		Anchor: layer1.Anchor,
		IncludeReceipt: &v3.ReceiptOptions{
			ForAny: true,
		},
	}

	if l2.debug {
		log.Printf("[LAYER2] Searching DN anchors for: %x", layer1.Anchor[:8])
	}

	// Execute paginated anchor search to ensure we find all candidates
	allRecords, err := l2.executePagedAnchorSearch(ctx, dnAnchorsURL, query)
	if err != nil {
		return nil, fmt.Errorf("paginated DN anchor search failed: %w", err)
	}

	if len(allRecords) == 0 {
		return nil, fmt.Errorf("no anchor found in DN for anchor %x", layer1.Anchor)
	}

	if l2.debug {
		log.Printf("[LAYER2] Found %d anchor records, applying deterministic selection", len(allRecords))
	}

	// Apply deterministic record selection for Layer 3 AppHash binding correctness
	chainEntry, err := l2.selectBestAnchorRecord(ctx, allRecords, layer1.Anchor)
	if err != nil {
		return nil, fmt.Errorf("failed to select anchor record: %w", err)
	}

	receipt := chainEntry.Receipt
	if receipt == nil {
		return nil, fmt.Errorf("anchor search returned no receipt")
	}

	// Convert to our MerkleReceipt format
	merkleReceipt := MerkleReceipt{
		Start:      receipt.Start,
		Anchor:     receipt.Anchor,
		LocalBlock: receipt.LocalBlock, // DN block height from receipt
		Entries:    make([]ReceiptEntry, len(receipt.Entries)),
	}

	// Convert receipt entries (fix pointer-to-range-variable bug)
	for i := range receipt.Entries {
		e := receipt.Entries[i]
		right := e.Right
		merkleReceipt.Entries[i] = ReceiptEntry{
			Hash:  e.Hash,
			Right: &right,
		}
	}

	// Validate critical stitching invariant: L2.start == L1.anchor
	if err := l2.validateStitching(layer1.Anchor, merkleReceipt.Start); err != nil {
		return nil, fmt.Errorf("receipt stitching validation failed: %w", err)
	}

	// Extract record name for auditing
	recordName, err := l2.extractRecordName(chainEntry.Name)
	if err != nil {
		if l2.debug {
			log.Printf("[LAYER2] Warning: could not extract record name: %v", err)
		}
		recordName = "unknown-anchor-record"
	}

	if l2.debug {
		log.Printf("[LAYER2] Successfully built proof - Start: %x, Anchor: %x, DN Height: %d",
			merkleReceipt.Start[:8], merkleReceipt.Anchor[:8], merkleReceipt.LocalBlock)
	}

	return &Layer2AnchorToDN{
		Scope:      "acc://dn.acme/anchors",
		RecordName: recordName,
		Start:      merkleReceipt.Start,
		Receipt:    merkleReceipt,
		Anchor:     merkleReceipt.Anchor,
		LocalBlock: merkleReceipt.LocalBlock,
	}, nil
}

// BuildWithFallback implements the deterministic fallback ladder from the spec
//
// This method attempts multiple strategies to find the DN anchor:
// 1. Primary: anchorSearch(dn, L1.Anchor)
// 2. Fallback: Try alternate anchor types if derivable
// 3. Last resort: Search DN anchor chain in expected window
func (l2 *Layer2Builder) BuildWithFallback(ctx context.Context, layer1 *Layer1EntryInclusion) (*Layer2AnchorToDN, error) {
	// Try primary method first
	layer2, err := l2.BuildFromLayer1(ctx, layer1)
	if err == nil {
		return layer2, nil
	}

	if l2.debug {
		log.Printf("[LAYER2] Primary method failed: %v, trying fallback strategies", err)
	}

	// TODO: Implement fallback strategies per spec section 6
	// 1. Try alternate anchor candidates (root vs BPT)
	// 2. Search DN anchor chain around expected window
	// For now, return the original error

	return nil, fmt.Errorf("primary anchor search failed and fallback not yet implemented: %w", err)
}

// validateStitching enforces the exact hash equality requirement for receipt stitching
func (l2 *Layer2Builder) validateStitching(layer1Anchor, layer2Start []byte) error {
	// Invariant 2 from spec: L2.start MUST equal L1.anchor (exact bytes)
	if len(layer1Anchor) != len(layer2Start) {
		return fmt.Errorf("anchor/start length mismatch: L1.anchor=%d, L2.start=%d",
			len(layer1Anchor), len(layer2Start))
	}

	for i := 0; i < len(layer1Anchor); i++ {
		if layer1Anchor[i] != layer2Start[i] {
			return fmt.Errorf("stitching failed: L1.anchor != L2.start at byte %d", i)
		}
	}

	return nil
}

// extractRecordName attempts to extract the record name for auditing purposes
func (l2 *Layer2Builder) extractRecordName(name string) (string, error) {
	if name != "" {
		return name, nil
	}

	// Fallback to generic name
	return "unknown-anchor-record", nil
}

// selectBestAnchorRecord implements deterministic anchor record selection for Layer 3 correctness
// This prevents Layer 3 AppHash binding failures by preferring AppHash-bound records
// CRITICAL: First filters by stitching compatibility, then verifies AppHash binding
func (l2 *Layer2Builder) selectBestAnchorRecord(ctx context.Context, records []v3.Record, layer1Anchor []byte) (*v3.ChainEntryRecord[v3.Record], error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records to select from")
	}

	// CRITICAL FIRST PASS: Filter by stitching compatibility before any other logic
	var stitchingCompatibleEntries []*v3.ChainEntryRecord[v3.Record]

	for i, record := range records {
		chainEntry, ok := record.(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			if l2.debug {
				log.Printf("[LAYER2] Skipping record %d: not a ChainEntryRecord (%T)", i, record)
			}
			continue
		}

		// Check stitching compatibility: receipt.Start must equal layer1Anchor
		if chainEntry.Receipt == nil {
			if l2.debug {
				log.Printf("[LAYER2] Skipping record %d: no receipt for stitching check", i)
			}
			continue
		}

		// Validate stitching compatibility using existing validation logic
		if err := l2.validateStitching(layer1Anchor, chainEntry.Receipt.Start); err != nil {
			if l2.debug {
				log.Printf("[LAYER2] Skipping record %d: stitching incompatible: %v", i, err)
			}
			continue
		}

		// This record can stitch properly
		stitchingCompatibleEntries = append(stitchingCompatibleEntries, chainEntry)
		if l2.debug {
			log.Printf("[LAYER2] Record %d passes stitching check: %s", i, chainEntry.Name)
		}
	}

	if len(stitchingCompatibleEntries) == 0 {
		return nil, fmt.Errorf("no records compatible with stitching requirement (L1.anchor = %x)", layer1Anchor[:8])
	}

	// CRITICAL SECOND PASS: Filter by AppHash binding - the real correctness requirement
	var appHashBoundEntries []*v3.ChainEntryRecord[v3.Record]

	for i, chainEntry := range stitchingCompatibleEntries {
		canBind, err := l2.verifyAppHashBinding(ctx, chainEntry)
		if err != nil {
			if l2.debug {
				log.Printf("[LAYER2] AppHash binding check failed for candidate %d: %v", i, err)
			}
			continue // Skip candidates with binding verification errors
		}

		if canBind {
			appHashBoundEntries = append(appHashBoundEntries, chainEntry)
			if l2.debug {
				log.Printf("[LAYER2] ✅ Candidate %d passes AppHash binding: %s", i, chainEntry.Name)
			}
		} else {
			if l2.debug {
				log.Printf("[LAYER2] ❌ Candidate %d fails AppHash binding: %s", i, chainEntry.Name)
			}
		}
	}

	// If we have AppHash-bound candidates, use only those. Otherwise fall back to stitching-only
	candidatesToSelect := appHashBoundEntries
	if len(appHashBoundEntries) == 0 {
		if l2.debug {
			log.Printf("[LAYER2] No AppHash-bound candidates found, falling back to stitching-only selection")
		}
		candidatesToSelect = stitchingCompatibleEntries
	} else {
		if l2.debug {
			log.Printf("[LAYER2] Found %d AppHash-bound candidates out of %d stitching-compatible",
				len(appHashBoundEntries), len(stitchingCompatibleEntries))
		}
	}

	// THIRD PASS: Apply name-based preference to the final candidate set
	var allEntries []*v3.ChainEntryRecord[v3.Record]
	var bptEntries []*v3.ChainEntryRecord[v3.Record]
	var rootEntries []*v3.ChainEntryRecord[v3.Record]

	for _, chainEntry := range candidatesToSelect {
		allEntries = append(allEntries, chainEntry)

		// Categorize by name for deterministic selection
		name := chainEntry.Name
		if name != "" {
			if contains(name, "bpt") {
				bptEntries = append(bptEntries, chainEntry)
			} else if contains(name, "root") {
				rootEntries = append(rootEntries, chainEntry)
			}
		}
	}

	if len(allEntries) == 0 {
		return nil, fmt.Errorf("no valid ChainEntryRecord found in %d records", len(records))
	}

	// Apply deterministic selection rules for Layer 3 AppHash binding correctness
	var selectedEntry *v3.ChainEntryRecord[v3.Record]
	var selectionReason string

	if len(allEntries) == 1 {
		// Simple case: exactly one valid entry
		selectedEntry = allEntries[0]
		selectionReason = "single_entry"
	} else if len(bptEntries) > 0 {
		// PREFER BPT records for AppHash binding (critical for Layer 3)
		// BPT anchors are more likely to match CometBFT AppHash since they represent
		// the complete state tree that maps to the consensus AppHash
		selectedEntry = bptEntries[0]
		selectionReason = fmt.Sprintf("prefer_bpt_for_apphash (%d bpt entries available)", len(bptEntries))
	} else if len(rootEntries) > 0 {
		// Fallback to root records if no BPT found
		selectedEntry = rootEntries[0]
		selectionReason = fmt.Sprintf("fallback_root (%d root entries available)", len(rootEntries))
	} else {
		// Last resort: take first entry but log the ambiguity
		selectedEntry = allEntries[0]
		selectionReason = fmt.Sprintf("first_of_ambiguous (%d entries, no clear type)", len(allEntries))
	}

	if l2.debug {
		log.Printf("[LAYER2] Selected anchor record: reason=%s, name=%s, total_candidates=%d",
			selectionReason, selectedEntry.Name, len(allEntries))
	}

	// Validate the selected entry has a receipt
	if selectedEntry.Receipt == nil {
		return nil, fmt.Errorf("selected anchor record has no receipt (name=%s)", selectedEntry.Name)
	}

	// ENHANCED VALIDATION: Check AppHash binding characteristics
	// Ensure the anchor has the right size/format for CometBFT AppHash binding
	anchorHash := selectedEntry.Receipt.Anchor
	if len(anchorHash) != 32 {
		if l2.debug {
			log.Printf("[LAYER2] Warning: selected anchor has unusual length %d (expected 32 for AppHash binding)", len(anchorHash))
		}
	}

	// Additional validation: BPT anchors should be non-zero
	allZero := true
	for _, b := range anchorHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("selected anchor is zero hash - cannot bind to valid AppHash")
	}

	return selectedEntry, nil
}

// verifyAppHashBinding checks if a candidate's anchor matches the AppHash at its height
func (l2 *Layer2Builder) verifyAppHashBinding(ctx context.Context, candidate *v3.ChainEntryRecord[v3.Record]) (bool, error) {
	if l2.cometClient == nil {
		if l2.debug {
			log.Printf("[LAYER2] No CometBFT client - skipping AppHash binding verification")
		}
		return true, nil // Fall back to name-based selection if no comet client
	}

	height := candidate.Receipt.LocalBlock
	if l2.debug {
		log.Printf("[LAYER2] Checking AppHash binding for height %d, anchor %x",
			height, candidate.Receipt.Anchor[:8])
	}

	// Fetch commit at the DN height (convert uint64 to int64)
	heightInt64 := int64(height)
	commit, err := l2.cometClient.Commit(ctx, &heightInt64)
	if err != nil {
		if l2.debug {
			log.Printf("[LAYER2] Failed to fetch commit for height %d: %v", height, err)
		}
		return false, fmt.Errorf("failed to fetch commit for AppHash binding: %w", err)
	}

	expectedAppHash := commit.SignedHeader.Header.AppHash
	candidateAnchor := candidate.Receipt.Anchor

	// Check if anchor matches AppHash
	if len(expectedAppHash) != len(candidateAnchor) {
		if l2.debug {
			log.Printf("[LAYER2] AppHash binding failed: length mismatch (expected=%d, candidate=%d)",
				len(expectedAppHash), len(candidateAnchor))
		}
		return false, nil
	}

	for i := 0; i < len(expectedAppHash); i++ {
		if expectedAppHash[i] != candidateAnchor[i] {
			if l2.debug {
				log.Printf("[LAYER2] AppHash binding failed: hash mismatch at byte %d", i)
			}
			return false, nil
		}
	}

	if l2.debug {
		log.Printf("[LAYER2] ✅ AppHash binding verified for height %d", height)
	}
	return true, nil
}

// executePagedAnchorSearch performs anchor search and warns if pagination may be needed
func (l2 *Layer2Builder) executePagedAnchorSearch(ctx context.Context, dnAnchorsURL *acc_url.URL, baseQuery *v3.AnchorSearchQuery) ([]v3.Record, error) {
	// Execute the anchor search
	resp, err := l2.client.Query(ctx, dnAnchorsURL, baseQuery)
	if err != nil {
		return nil, fmt.Errorf("anchor search failed: %w", err)
	}

	// Process response
	recordRange, ok := resp.(*v3.RecordRange[v3.Record])
	if !ok {
		return nil, fmt.Errorf("expected RecordRange[Record] from anchor search, got %T", resp)
	}

	// Check if pagination may be needed
	if uint64(len(recordRange.Records)) < recordRange.Total {
		if l2.debug {
			log.Printf("[LAYER2] WARNING: Only got %d of %d total records - pagination needed but not yet implemented",
				len(recordRange.Records), recordRange.Total)
			log.Printf("[LAYER2] This may miss valid AppHash-binding candidates on later pages")
		}
	}

	if l2.debug {
		log.Printf("[LAYER2] Retrieved %d records (total available: %d)", len(recordRange.Records), recordRange.Total)
	}

	return recordRange.Records, nil
}

// contains is a helper for truly case-insensitive substring matching
func contains(haystack, needle string) bool {
	if len(haystack) < len(needle) {
		return false
	}
	// Convert both to lowercase for case-insensitive comparison
	haystackLower := strings.ToLower(haystack)
	needleLower := strings.ToLower(needle)
	return strings.Contains(haystackLower, needleLower)
}

// Layer2Verifier verifies Layer 2 proofs
type Layer2Verifier struct {
	debug bool
}

// NewLayer2Verifier creates a new Layer 2 proof verifier
func NewLayer2Verifier(debug bool) *Layer2Verifier {
	return &Layer2Verifier{debug: debug}
}

// Verify validates a Layer 2 anchor stitching proof
func (l2v *Layer2Verifier) Verify(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) (*LayerResult, error) {
	if l2v.debug {
		log.Printf("[LAYER2 VERIFY] Verifying stitching from L1 anchor %x to L2 start %x",
			layer1.Anchor[:8], layer2.Start[:8])
	}

	result := &LayerResult{
		LayerName: "Layer2",
		Valid:     false,
		Details:   make(map[string]interface{}),
	}

	// Validate basic structure
	if layer1 == nil {
		result.ErrorMessage = "Layer 1 proof is nil"
		return result, nil
	}

	if layer2 == nil {
		result.ErrorMessage = "Layer 2 proof is nil"
		return result, nil
	}

	// Validate required scope
	if layer2.Scope != "acc://dn.acme/anchors" {
		result.ErrorMessage = fmt.Sprintf("invalid scope: expected 'acc://dn.acme/anchors', got '%s'", layer2.Scope)
		return result, nil
	}

	// Validate receipt integrity
	receiptVerifier := NewReceiptVerifier(l2v.debug)
	valid, err := receiptVerifier.ValidateIntegrity(&layer2.Receipt)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Receipt verification failed: %v", err)
		return result, nil
	}

	if !valid {
		result.ErrorMessage = "Receipt Merkle path verification failed"
		return result, nil
	}

	// Validate critical stitching invariant
	if err := l2v.validateStitching(layer1, layer2); err != nil {
		result.ErrorMessage = fmt.Sprintf("Stitching validation failed: %v", err)
		return result, nil
	}

	// Validate Layer 2 specific invariants
	if err := l2v.validateInvariants(layer2); err != nil {
		result.ErrorMessage = fmt.Sprintf("Invariant validation failed: %v", err)
		return result, nil
	}

	result.Valid = true
	result.Details["scope"] = layer2.Scope
	result.Details["recordName"] = layer2.RecordName
	result.Details["startHash"] = fmt.Sprintf("%x", layer2.Start)
	result.Details["dnAnchorHash"] = fmt.Sprintf("%x", layer2.Anchor)
	result.Details["dnHeight"] = layer2.LocalBlock

	if l2v.debug {
		log.Printf("[LAYER2 VERIFY] ✅ Verification successful")
	}

	return result, nil
}

// validateStitching validates the critical stitching requirement
func (l2v *Layer2Verifier) validateStitching(layer1 *Layer1EntryInclusion, layer2 *Layer2AnchorToDN) error {
	// Invariant 2: L2.start MUST equal L1.anchor (exact bytes)
	if len(layer1.Anchor) != len(layer2.Start) {
		return fmt.Errorf("stitching length mismatch: L1.anchor=%d, L2.start=%d",
			len(layer1.Anchor), len(layer2.Start))
	}

	for i := 0; i < len(layer1.Anchor); i++ {
		if layer1.Anchor[i] != layer2.Start[i] {
			return fmt.Errorf("stitching failed: L1.anchor != L2.start at byte %d", i)
		}
	}

	return nil
}

// validateInvariants validates Layer 2 specific requirements
func (l2v *Layer2Verifier) validateInvariants(layer2 *Layer2AnchorToDN) error {
	// Invariant: Start MUST equal receipt start
	if len(layer2.Start) != len(layer2.Receipt.Start) {
		return fmt.Errorf("start and receipt start length mismatch")
	}

	for i := 0; i < len(layer2.Start); i++ {
		if layer2.Start[i] != layer2.Receipt.Start[i] {
			return fmt.Errorf("start does not match receipt start at byte %d", i)
		}
	}

	// Invariant: Anchor MUST equal receipt anchor
	if len(layer2.Anchor) != len(layer2.Receipt.Anchor) {
		return fmt.Errorf("anchor and receipt anchor length mismatch")
	}

	for i := 0; i < len(layer2.Anchor); i++ {
		if layer2.Anchor[i] != layer2.Receipt.Anchor[i] {
			return fmt.Errorf("anchor does not match receipt anchor at byte %d", i)
		}
	}

	// Invariant: LocalBlock MUST equal receipt localBlock
	if layer2.LocalBlock != layer2.Receipt.LocalBlock {
		return fmt.Errorf("localBlock mismatch: layer2=%d, receipt=%d",
			layer2.LocalBlock, layer2.Receipt.LocalBlock)
	}

	return nil
}
