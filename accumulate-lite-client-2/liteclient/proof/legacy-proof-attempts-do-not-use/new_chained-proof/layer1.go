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

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// safeHex returns a safe hex representation of a byte slice, preventing panic on nil/short slices
func safeHex(data []byte, maxLen int) string {
	if data == nil {
		return "nil"
	}
	if len(data) == 0 {
		return "empty"
	}
	if len(data) <= maxLen {
		return fmt.Sprintf("%x", data)
	}
	return fmt.Sprintf("%x", data[:maxLen])
}

// Layer1Builder constructs Layer 1 proofs: Entry Inclusion → Partition Anchor
//
// Layer 1 proves that an entry hash is included in a partition root at a specific height.
// CRITICAL: Layer 1 MUST start from recordType:"chainEntry" receipts, NOT account receipts.
type Layer1Builder struct {
	client *jsonrpc.Client
	debug  bool
}

// NewLayer1Builder creates a new Layer 1 proof builder
func NewLayer1Builder(client *jsonrpc.Client, debug bool) *Layer1Builder {
	return &Layer1Builder{
		client: client,
		debug:  debug,
	}
}

// BuildFromChainEntry constructs Layer 1 proof from a specific chain entry
//
// This method follows the canonical construction algorithm from the spec:
// 1. Query the specific chain entry with includeReceipt=true
// 2. Extract the entry hash as the leaf
// 3. Validate the receipt structure
// 4. Return Layer1EntryInclusion proof object
func (l1 *Layer1Builder) BuildFromChainEntry(ctx context.Context, scope, chainName string, chainIndex uint64) (*Layer1EntryInclusion, error) {
	if l1.debug {
		log.Printf("[LAYER1] Building proof for scope=%s, chain=%s, index=%d", scope, chainName, chainIndex)
	}

	// Parse scope URL
	scopeURL, err := acc_url.Parse(scope)
	if err != nil {
		return nil, fmt.Errorf("invalid scope URL %s: %w", scope, err)
	}

	// Create chain query with receipt inclusion
	query := &v3.ChainQuery{
		Name:  chainName,
		Index: &chainIndex,
		IncludeReceipt: &v3.ReceiptOptions{
			ForAny: true,
		},
	}

	if l1.debug {
		log.Printf("[LAYER1] Querying chain entry: %s/%s[%d]", scope, chainName, chainIndex)
	}

	// Execute the query
	resp, err := l1.client.Query(ctx, scopeURL, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query chain entry: %w", err)
	}

	// Process response - must be ChainEntryRecord per v3 API
	chainEntry, ok := resp.(*v3.ChainEntryRecord[v3.Record])
	if !ok {
		return nil, fmt.Errorf("expected ChainEntryRecord[Record], got %T", resp)
	}

	// Extract chain entry hash - this is the leaf we're proving
	// Convert [32]byte to []byte for compatibility
	entryHash := chainEntry.Entry[:]
	if len(entryHash) == 0 {
		return nil, fmt.Errorf("chain entry contains no entry hash")
	}

	// Validate receipt presence
	receipt := chainEntry.Receipt
	if receipt == nil {
		return nil, fmt.Errorf("chain entry missing required receipt")
	}

	// Convert v3.Receipt to our MerkleReceipt format
	merkleReceipt := MerkleReceipt{
		Start:      receipt.Start,
		Anchor:     receipt.Anchor,
		LocalBlock: receipt.LocalBlock, // CRITICAL: Use receipt.LocalBlock per CERTEN spec
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

	// Validate critical Layer 1 invariants per spec
	if err := l1.validateLayer1Invariants(entryHash, &merkleReceipt); err != nil {
		return nil, fmt.Errorf("Layer 1 invariant validation failed: %w", err)
	}

	// CRITICAL: Determine exact partition via block query per spec section 3.2
	sourcePartition, err := l1.resolveSourcePartition(ctx, scope, merkleReceipt.LocalBlock)
	if err != nil {
		return nil, fmt.Errorf("partition resolution failed: %w", err)
	}

	if l1.debug {
		log.Printf("[LAYER1] Successfully built proof - Leaf: %s, Anchor: %s, SourcePartition: %s",
			safeHex(entryHash, 8), safeHex(merkleReceipt.Anchor, 8), sourcePartition)
	}

	return &Layer1EntryInclusion{
		Scope:           scope,
		ChainName:       chainName,
		ChainIndex:      chainIndex,
		Leaf:            entryHash,
		Receipt:         merkleReceipt,
		Anchor:          merkleReceipt.Anchor,
		LocalBlock:      merkleReceipt.LocalBlock,
		SourcePartition: sourcePartition,
	}, nil
}

// validateLayer1Invariants enforces the critical Layer 1 requirements from the spec
func (l1 *Layer1Builder) validateLayer1Invariants(entryHash []byte, receipt *MerkleReceipt) error {
	// Invariant: L1.Leaf MUST equal the returned chainEntry.entry
	if len(entryHash) == 0 {
		return fmt.Errorf("entry hash cannot be empty")
	}

	// Invariant: L1.Receipt.start MUST equal L1.Leaf (byte-for-byte)
	if len(receipt.Start) != len(entryHash) {
		return fmt.Errorf("receipt start length mismatch: receipt=%d, entry=%d",
			len(receipt.Start), len(entryHash))
	}

	for i := 0; i < len(entryHash); i++ {
		if receipt.Start[i] != entryHash[i] {
			return fmt.Errorf("receipt start does not match entry hash at byte %d", i)
		}
	}

	// Invariant: L1.Anchor MUST equal L1.Receipt.anchor
	if len(receipt.Anchor) == 0 {
		return fmt.Errorf("receipt anchor cannot be empty")
	}

	return nil
}

// resolveSourcePartition implements normative partition resolution per spec section 3.2
// MUST query the block record to extract the authoritative source partition URL
func (l1 *Layer1Builder) resolveSourcePartition(ctx context.Context, scope string, localBlock uint64) (string, error) {
	if l1.debug {
		log.Printf("[LAYER1] Resolving source partition for scope=%s, block=%d", scope, localBlock)
	}

	// Parse scope URL for block query
	scopeURL, err := acc_url.Parse(scope)
	if err != nil {
		return "", fmt.Errorf("invalid scope URL %s: %w", scope, err)
	}

	// Create block query per spec section 3.2
	query := &v3.BlockQuery{
		Minor: &localBlock,
	}

	// Execute block query to get source partition
	resp, err := l1.client.Query(ctx, scopeURL, query)
	if err != nil {
		return "", fmt.Errorf("block query failed for partition resolution: %w", err)
	}

	// Process block record response
	blockRecord, ok := resp.(*v3.MinorBlockRecord)
	if !ok {
		return "", fmt.Errorf("expected MinorBlockRecord for partition resolution, got %T", resp)
	}

	// Extract source partition from block record
	if blockRecord.Source == nil {
		return "", fmt.Errorf("block record missing source field - cannot determine partition")
	}

	sourcePartition := blockRecord.Source.String()
	if sourcePartition == "" {
		return "", fmt.Errorf("block record source partition is empty")
	}

	if l1.debug {
		log.Printf("[LAYER1] Resolved source partition: %s", sourcePartition)
	}

	// Validate partition format (basic sanity check)
	if !l1.validatePartitionFormat(sourcePartition) {
		return "", fmt.Errorf("invalid partition format: %s", sourcePartition)
	}

	return sourcePartition, nil
}

// validatePartitionFormat validates that the partition follows expected format
func (l1 *Layer1Builder) validatePartitionFormat(partition string) bool {
	// Expected formats per spec:
	// - acc://bvn-BVN1.acme (for BVN partitions)
	// - acc://dn.acme (for DN partition)
	return partition == "acc://dn.acme" ||
		strings.Contains(partition, "acc://bvn-") ||
		strings.Contains(partition, "acc://dn")
}

// Layer1Verifier verifies Layer 1 proofs
type Layer1Verifier struct {
	debug bool
}

// NewLayer1Verifier creates a new Layer 1 proof verifier
func NewLayer1Verifier(debug bool) *Layer1Verifier {
	return &Layer1Verifier{debug: debug}
}

// Verify validates a Layer 1 entry inclusion proof
func (l1v *Layer1Verifier) Verify(layer1 *Layer1EntryInclusion) (*LayerResult, error) {
	result := &LayerResult{
		LayerName: "Layer1",
		Valid:     false,
		Details:   make(map[string]interface{}),
	}

	// Validate basic structure
	if layer1 == nil {
		result.ErrorMessage = "Layer 1 proof is nil"
		return result, nil
	}

	if l1v.debug {
		log.Printf("[LAYER1 VERIFY] Verifying proof for leaf %s", safeHex(layer1.Leaf, 8))
	}

	if len(layer1.Leaf) == 0 {
		result.ErrorMessage = "Layer 1 leaf hash is empty"
		return result, nil
	}

	if len(layer1.Anchor) == 0 {
		result.ErrorMessage = "Layer 1 anchor is empty"
		return result, nil
	}

	// Validate receipt integrity using Merkle path verification
	receiptVerifier := NewReceiptVerifier(l1v.debug)
	valid, err := receiptVerifier.ValidateIntegrity(&layer1.Receipt)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Receipt verification failed: %v", err)
		return result, nil
	}

	if !valid {
		result.ErrorMessage = "Receipt Merkle path verification failed"
		return result, nil
	}

	// Validate Layer 1 specific invariants
	if err := l1v.validateInvariants(layer1); err != nil {
		result.ErrorMessage = fmt.Sprintf("Invariant validation failed: %v", err)
		return result, nil
	}

	result.Valid = true
	result.Details["sourcePartition"] = layer1.SourcePartition
	result.Details["leafHash"] = fmt.Sprintf("%x", layer1.Leaf)
	result.Details["anchorHash"] = fmt.Sprintf("%x", layer1.Anchor)
	result.Details["localBlock"] = layer1.LocalBlock

	if l1v.debug {
		log.Printf("[LAYER1 VERIFY] ✅ Verification successful")
	}

	return result, nil
}

// validateInvariants validates Layer 1 specific requirements
func (l1v *Layer1Verifier) validateInvariants(layer1 *Layer1EntryInclusion) error {
	// Invariant: Leaf MUST equal receipt start
	if len(layer1.Leaf) != len(layer1.Receipt.Start) {
		return fmt.Errorf("leaf and receipt start length mismatch")
	}

	for i := 0; i < len(layer1.Leaf); i++ {
		if layer1.Leaf[i] != layer1.Receipt.Start[i] {
			return fmt.Errorf("leaf does not match receipt start at byte %d", i)
		}
	}

	// Invariant: Anchor MUST equal receipt anchor
	if len(layer1.Anchor) != len(layer1.Receipt.Anchor) {
		return fmt.Errorf("anchor and receipt anchor length mismatch")
	}

	for i := 0; i < len(layer1.Anchor); i++ {
		if layer1.Anchor[i] != layer1.Receipt.Anchor[i] {
			return fmt.Errorf("anchor does not match receipt anchor at byte %d", i)
		}
	}

	// Invariant: LocalBlock MUST equal receipt localBlock
	if layer1.LocalBlock != layer1.Receipt.LocalBlock {
		return fmt.Errorf("localBlock mismatch: layer1=%d, receipt=%d",
			layer1.LocalBlock, layer1.Receipt.LocalBlock)
	}

	// Invariant: SourcePartition MUST be present per spec section 5.2
	if layer1.SourcePartition == "" {
		return fmt.Errorf("sourcePartition cannot be empty - required by spec section 5.2")
	}

	return nil
}
