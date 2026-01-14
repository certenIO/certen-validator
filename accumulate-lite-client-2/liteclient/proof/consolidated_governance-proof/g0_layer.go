// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"strings"
)

// CERTEN Governance Proof - G0 Layer (Inclusion and Finality Only)
// This file implements G0-level governance proofs as defined in CERTEN spec
// G0 proves only that a specific chain entry was committed to Accumulate state and finalized by consensus

// =============================================================================
// G0 Proof Layer
// =============================================================================

// G0Layer implements G0 governance proofs (Inclusion and Finality Only)
type G0Layer struct {
	client          RPCClientInterface
	artifactManager *ArtifactManager
	queryBuilder    QueryBuilder
}

// NewG0Layer creates a new G0 proof layer
func NewG0Layer(client RPCClientInterface, artifactManager *ArtifactManager) *G0Layer {
	return &G0Layer{
		client:          client,
		artifactManager: artifactManager,
		queryBuilder:    QueryBuilder{},
	}
}

// ProveG0 generates G0 proof for inclusion and finality
// Direct translation of Python generate_g0_proof
func (g0 *G0Layer) ProveG0(ctx context.Context, request G0Request) (*G0Result, error) {
	fmt.Printf("[G0] Starting G0 proof generation\n")
	fmt.Printf("[G0] Account: %s\n", request.Account)
	fmt.Printf("[G0] TxHash: %s\n", request.TxHash)
	fmt.Printf("[G0] Chain: %s\n", request.Chain)

	// Step 1: Prove execution inclusion and derive execution witness
	execMBI, execWitness, execEntry, receipt, err := g0.proveExecutionInclusion(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("execution inclusion proof failed: %v", err)
	}

	// Step 2: Bind expanded execution message to receipt leaf
	expandedMessageID, txData, err := g0.bindExpandedExecutionMessage(ctx, request, execEntry)
	if err != nil {
		return nil, fmt.Errorf("expanded execution binding failed: %v", err)
	}

	// Step 3: Extract key identifiers and metadata
	txID, canonicalTxHash, scope, principal, err := g0.extractExecutionMetadata(txData, request)
	if err != nil {
		return nil, fmt.Errorf("metadata extraction failed: %v", err)
	}

	// Step 4: Build G0 result
	result := &G0Result{
		EntryHashExec:     execEntry,
		TXID:              txID,
		TxHash:            canonicalTxHash,
		ExecMBI:           execMBI,
		ExecWitness:       execWitness,
		Scope:             scope,
		Chain:             request.Chain,
		ExpandedMessageID: expandedMessageID,
		Principal:         principal,
		Receipt:           receipt,
		G0ProofComplete:   true,
	}

	fmt.Printf("[G0] G0 proof complete:\n")
	fmt.Printf("[G0]   TXID: %s\n", txID[:16])
	fmt.Printf("[G0]   TX_HASH: %s\n", canonicalTxHash[:16])
	fmt.Printf("[G0]   EXEC_MBI: %d\n", execMBI)
	fmt.Printf("[G0]   Principal: %s\n", principal)

	return result, nil
}

// proveExecutionInclusion proves execution inclusion and derives execution witness
// Implements CERTEN Section 5.1 Execution Inclusion
func (g0 *G0Layer) proveExecutionInclusion(ctx context.Context, request G0Request) (int64, string, string, ReceiptData, error) {
	fmt.Printf("[G0] [INCLUSION] Proving execution inclusion for %s\n", SafeTruncate(request.TxHash, 16))

	// Build execution inclusion query (CERTEN Appendix A.1)
	query := g0.queryBuilder.BuildExecutionInclusionQuery(request.TxHash, request.Chain)
	fmt.Printf("[G0] [DEBUG] Execution inclusion query: %+v\n", query)

	// Execute query and save artifact
	response, err := g0.artifactManager.SaveRPCArtifact(
		ctx,
		fmt.Sprintf("execution_inclusion_%s_%s", request.Chain, SafeTruncate(request.TxHash, 16)),
		g0.client,
		request.Account,
		query,
	)
	if err != nil {
		return 0, "", "", ReceiptData{}, fmt.Errorf("execution inclusion query failed: %v", err)
	}

	// Extract chain entry and receipt
	chainEntry, receipt, err := g0.extractChainEntryAndReceipt(response)
	if err != nil {
		return 0, "", "", ReceiptData{}, fmt.Errorf("failed to extract chain entry and receipt: %v", err)
	}

	// Validate execution inclusion constraints (CERTEN Section 5.1)
	if err := g0.validateExecutionInclusion(chainEntry, receipt, request.TxHash); err != nil {
		return 0, "", "", ReceiptData{}, fmt.Errorf("execution inclusion validation failed: %v", err)
	}

	// Derive execution witness (CERTEN Section 5.1)
	execMBI := receipt.LocalBlock
	execWitness := receipt.Anchor

	fmt.Printf("[G0] [INCLUSION] [OK] EXEC_MBI=%d, EXEC_WITNESS=%s\n", execMBI, execWitness[:16])

	return execMBI, execWitness, chainEntry, receipt, nil
}

// bindExpandedExecutionMessage binds expanded execution message to receipt leaf
// Implements CERTEN Section 5.2 Expanded Execution Binding
func (g0 *G0Layer) bindExpandedExecutionMessage(ctx context.Context, request G0Request, execEntry string) (string, map[string]interface{}, error) {
	fmt.Printf("[G0] [BINDING] Binding expanded execution message for %s\n", execEntry[:16])

	// Build expanded execution query (with expand=true)
	query := g0.queryBuilder.BuildExecutionInclusionQuery(request.TxHash, request.Chain)
	query["expand"] = true

	// Execute query and save artifact
	response, err := g0.artifactManager.SaveRPCArtifact(
		ctx,
		fmt.Sprintf("expanded_execution_%s_%s", request.Chain, SafeTruncate(request.TxHash, 16)),
		g0.client,
		request.Account,
		query,
	)
	if err != nil {
		return "", nil, fmt.Errorf("expanded execution query failed: %v", err)
	}

	// Extract expanded message data
	txData, messageID, err := g0.extractExpandedMessage(response)
	if err != nil {
		return "", nil, fmt.Errorf("failed to extract expanded message: %v", err)
	}

	// Validate message ID binding (CERTEN Section 5.2) - aligned with Python response format
	// Extract principal name without acc:// prefix for scope part
	uu := URLUtils{}
	principalName := strings.TrimPrefix(uu.NormalizeURL(request.Account), "acc://")
	expectedMessageID := fmt.Sprintf("acc://%s@%s", execEntry, principalName)
	if messageID != expectedMessageID {
		return "", nil, ValidationError{
			Msg: fmt.Sprintf("Message ID binding failed: got %s, expected %s", messageID, expectedMessageID),
		}
	}

	fmt.Printf("[G0] [BINDING] [OK] Message ID: %s\n", messageID)

	return messageID, txData, nil
}

// extractExecutionMetadata extracts key identifiers and metadata from transaction data
func (g0 *G0Layer) extractExecutionMetadata(txData map[string]interface{}, request G0Request) (string, string, string, string, error) {
	// Extract TXID (same as entry hash for transaction-chain entries)
	txID := request.TxHash

	// Extract canonical TX_HASH
	canonicalTxHash := request.TxHash
	if request.CanonicalTxHash != nil && *request.CanonicalTxHash != "" {
		canonicalTxHash = *request.CanonicalTxHash
	}

	// Validate TX_HASH format
	hv := HexValidator{}
	normalizedTxHash, err := hv.RequireHex32(canonicalTxHash, "canonical TX_HASH")
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid canonical TX_HASH: %v", err)
	}

	// Extract scope from account
	scope := request.Account

	// Extract principal from scope
	principal, err := g0.extractPrincipal(scope)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to extract principal: %v", err)
	}

	fmt.Printf("[G0] [METADATA] TXID=%s, TX_HASH=%s\n", txID[:16], normalizedTxHash[:16])
	fmt.Printf("[G0] [METADATA] Scope=%s, Principal=%s\n", scope, principal)

	return txID, normalizedTxHash, scope, principal, nil
}

// extractChainEntryAndReceipt extracts chain entry and receipt from RPC response
func (g0 *G0Layer) extractChainEntryAndReceipt(response map[string]interface{}) (string, ReceiptData, error) {
	pu := ProofUtilities{}

	// Extract result object (JSON-RPC 2.0 standard format - aligned with Python)
	data := pu.CaseInsensitiveGet(response, "result")
	if data == nil {
		// Fallback to "data" for compatibility
		data = pu.CaseInsensitiveGet(response, "data")
		if data == nil {
			return "", ReceiptData{}, ValidationError{Msg: "Response missing result{} or data{}"}
		}
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return "", ReceiptData{}, ValidationError{Msg: "Data is not an object"}
	}

	// Extract chain entry - the result itself IS the chain entry (aligned with Python)
	chainEntryMap := dataMap

	// Verify this is actually a chain entry
	recordType := pu.CaseInsensitiveGet(chainEntryMap, "recordType")
	if recordType != "chainEntry" {
		return "", ReceiptData{}, ValidationError{Msg: fmt.Sprintf("Expected chainEntry, got recordType: %v", recordType)}
	}

	entry := pu.CaseInsensitiveGet(chainEntryMap, "entry")
	entryStr, ok := entry.(string)
	if !ok || entryStr == "" {
		return "", ReceiptData{}, ValidationError{Msg: "ChainEntry missing entry hash"}
	}

	// Extract receipt
	receiptObj := pu.CaseInsensitiveGet(dataMap, "receipt")
	if receiptObj == nil {
		return "", ReceiptData{}, ValidationError{Msg: "Response missing receipt{}"}
	}

	receiptMap, ok := receiptObj.(map[string]interface{})
	if !ok {
		return "", ReceiptData{}, ValidationError{Msg: "Receipt is not an object"}
	}

	receipt, err := g0.parseReceiptData(receiptMap)
	if err != nil {
		return "", ReceiptData{}, fmt.Errorf("failed to parse receipt: %v", err)
	}

	return entryStr, receipt, nil
}

// parseReceiptData parses receipt data from receipt object
func (g0 *G0Layer) parseReceiptData(receiptMap map[string]interface{}) (ReceiptData, error) {
	pu := ProofUtilities{}
	var receipt ReceiptData

	// Extract start
	if start := pu.CaseInsensitiveGet(receiptMap, "start"); start != nil {
		if startStr, ok := start.(string); ok {
			receipt.Start = startStr
		}
	}

	// Extract anchor
	if anchor := pu.CaseInsensitiveGet(receiptMap, "anchor"); anchor != nil {
		if anchorStr, ok := anchor.(string); ok {
			receipt.Anchor = anchorStr
		}
	}

	// Extract localBlock
	localBlock := pu.CaseInsensitiveGet(receiptMap, "localBlock")
	if localBlock == nil {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing localBlock"}
	}

	switch lb := localBlock.(type) {
	case float64:
		receipt.LocalBlock = int64(lb)
	case int:
		receipt.LocalBlock = int64(lb)
	case int64:
		receipt.LocalBlock = lb
	default:
		return ReceiptData{}, ValidationError{Msg: "Invalid localBlock type in receipt"}
	}

	// Validate localBlock > 0
	if receipt.LocalBlock <= 0 {
		return ReceiptData{}, ValidationError{Msg: fmt.Sprintf("Invalid localBlock: %d", receipt.LocalBlock)}
	}

	// Extract optional fields
	if majorBlock := pu.CaseInsensitiveGet(receiptMap, "majorBlock"); majorBlock != nil {
		switch mb := majorBlock.(type) {
		case float64:
			mbInt := int64(mb)
			receipt.MajorBlock = &mbInt
		case int:
			mbInt := int64(mb)
			receipt.MajorBlock = &mbInt
		case int64:
			receipt.MajorBlock = &mb
		}
	}

	if end := pu.CaseInsensitiveGet(receiptMap, "end"); end != nil {
		if endStr, ok := end.(string); ok && endStr != "" {
			receipt.End = &endStr
		}
	}

	return receipt, nil
}

// validateExecutionInclusion validates execution inclusion constraints
// Implements CERTEN Section 5.1 requirements
func (g0 *G0Layer) validateExecutionInclusion(chainEntry string, receipt ReceiptData, txHash string) error {
	hv := HexValidator{}

	// Normalize entry hash and transaction hash for comparison
	normalizedEntry, err := hv.RequireHex32(chainEntry, "chainEntry.entry")
	if err != nil {
		return fmt.Errorf("invalid chainEntry.entry: %v", err)
	}

	normalizedTxHash, err := hv.RequireHex32(txHash, "transaction hash")
	if err != nil {
		return fmt.Errorf("invalid transaction hash: %v", err)
	}

	normalizedReceiptStart, err := hv.RequireHex32(receipt.Start, "receipt.start")
	if err != nil {
		return fmt.Errorf("invalid receipt.start: %v", err)
	}

	// CERTEN Section 5.1: receipt.start == chainEntry.entry == ENTRY_HASH_exec
	if normalizedReceiptStart != normalizedEntry {
		return ValidationError{
			Msg: fmt.Sprintf("Receipt start mismatch: %s != %s", normalizedReceiptStart[:16], normalizedEntry[:16]),
		}
	}

	// CERTEN Section 5.1: ENTRY_HASH_exec == TXID for execution entry
	if normalizedEntry != normalizedTxHash {
		return ValidationError{
			Msg: fmt.Sprintf("Entry hash mismatch: %s != %s", normalizedEntry[:16], normalizedTxHash[:16]),
		}
	}

	// CERTEN Section 5.1: receipt.localBlock parses as integer > 0
	if receipt.LocalBlock <= 0 {
		return ValidationError{
			Msg: fmt.Sprintf("Invalid receipt localBlock: %d", receipt.LocalBlock),
		}
	}

	return nil
}

// extractExpandedMessage extracts expanded message data and message ID
func (g0 *G0Layer) extractExpandedMessage(response map[string]interface{}) (map[string]interface{}, string, error) {
	pu := ProofUtilities{}

	// Extract result object (JSON-RPC 2.0 standard format - aligned with Python)
	data := pu.CaseInsensitiveGet(response, "result")
	if data == nil {
		// Fallback to "data" for compatibility
		data = pu.CaseInsensitiveGet(response, "data")
		if data == nil {
			return nil, "", ValidationError{Msg: "Response missing result{} or data{}"}
		}
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, "", ValidationError{Msg: "Data is not an object"}
	}

	// Extract message object - it's in value.message path (aligned with Python)
	value := pu.CaseInsensitiveGet(dataMap, "value")
	if value == nil {
		return nil, "", ValidationError{Msg: "Response missing value{} for chain entry"}
	}

	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, "", ValidationError{Msg: "Value is not an object"}
	}

	msg := pu.CaseInsensitiveGet(valueMap, "message")
	if msg == nil {
		return nil, "", ValidationError{Msg: "Response missing value.message{} (expand=true required)"}
	}

	msgMap, ok := msg.(map[string]interface{})
	if !ok {
		return nil, "", ValidationError{Msg: "Message is not an object"}
	}

	// Extract message ID - it's at value.id level (aligned with Python response structure)
	messageID := pu.CaseInsensitiveGet(valueMap, "id")
	messageIDStr, ok := messageID.(string)
	if !ok || messageIDStr == "" {
		return nil, "", ValidationError{Msg: "Value missing id field for message ID"}
	}

	return msgMap, messageIDStr, nil
}

// extractPrincipal extracts principal from scope URL
func (g0 *G0Layer) extractPrincipal(scope string) (string, error) {
	uu := URLUtils{}
	normalizedScope := uu.NormalizeURL(scope)

	// Extract principal from acc://principal format or acc://principal/path
	if !strings.HasPrefix(normalizedScope, "acc://") {
		return "", ValidationError{Msg: fmt.Sprintf("Invalid scope format: %s", scope)}
	}

	// Remove acc:// prefix
	path := strings.TrimPrefix(normalizedScope, "acc://")

	// Extract principal (everything before first slash, or entire string if no slash)
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", ValidationError{Msg: fmt.Sprintf("Cannot extract principal from scope: %s", scope)}
	}

	return parts[0], nil
}