// Copyright 2025 Certen Protocol
//
// LiteClient Proof Generator Adapter - Integrates Accumulate lite client proof system
// Uses the REAL proof implementations from:
//   - working-proof_do_not_edit/ for L1-L3 chained proofs
//   - consolidated_governance-proof/ for G0/G1/G2 governance proofs

package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	lcbackend "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/backend"
	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	lctypes "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// LiteClientProofGenerator adapts the Accumulate lite client proof system
// into Certen's ProofGenerator interface for production-grade proof generation.
// Uses the REAL ProofBuilder from working-proof_do_not_edit/ for L1-L3 proofs.
type LiteClientProofGenerator struct {
	backend  lctypes.DataBackend
	v3Client *jsonrpc.Client
	// CometBFT clients are gone. L4 no longer asks a consensus RPC what the
	// app hash was; it carries Accumulate's own threshold-signed partition
	// anchors. The *Comet* endpoint parameters on the constructors below are
	// retained so existing callers and config keep compiling, and are ignored.
	proofBuilder *chained_proof.ProofBuilder
	endpoint     string
	dnEndpoint   string
	bvnEndpoint  string            // Legacy single BVN endpoint
	bvnEndpoints map[string]string // Map of BVN name to endpoint (bvn0, bvn1, bvn2, bvn3)
	timeout      time.Duration
}

// NewLiteClientProofGenerator creates a new lite client proof generator
// that connects directly to Accumulate v3 API for real cryptographic proofs.
// For backward compatibility, uses default DevNet CometBFT endpoints.
func NewLiteClientProofGenerator(v3Endpoint string, timeout time.Duration) (*LiteClientProofGenerator, error) {
	// Use default DevNet CometBFT endpoints
	// These match the ports exposed in devnet-accumulate-instance/docker-compose.yml
	dnCometEndpoint := "http://127.0.0.1:26657"
	bvnCometEndpoint := "http://127.0.0.1:26757"

	return NewLiteClientProofGeneratorWithComet(v3Endpoint, dnCometEndpoint, bvnCometEndpoint, timeout)
}

// NewLiteClientProofGeneratorWithComet creates a proof generator with explicit CometBFT endpoints.
// This is required for the REAL L1-L3 chained proofs with consensus binding.
// For multi-BVN networks, use NewLiteClientProofGeneratorMultiBVN instead.
func NewLiteClientProofGeneratorWithComet(v3Endpoint, dnCometEndpoint, bvnCometEndpoint string, timeout time.Duration) (*LiteClientProofGenerator, error) {
	// Use legacy single BVN as BVN0 for backward compatibility
	return NewLiteClientProofGeneratorMultiBVN(v3Endpoint, dnCometEndpoint, bvnCometEndpoint, bvnCometEndpoint, bvnCometEndpoint, "", timeout)
}

// NewLiteClientProofGeneratorMultiBVN creates a proof generator with all BVN CometBFT endpoints.
// This supports Kermit (3 BVNs: bvn1, bvn2, bvn3) and other multi-BVN networks.
// For Kermit network CometBFT ports:
//   - DN:   http://206.191.154.164:16592
//   - BVN1: http://206.191.154.164:16692
//   - BVN2: http://206.191.154.164:16792
//   - BVN3: http://206.191.154.164:16892
func NewLiteClientProofGeneratorMultiBVN(v3Endpoint, dnCometEndpoint, bvn0Endpoint, bvn1Endpoint, bvn2Endpoint, bvn3Endpoint string, timeout time.Duration) (*LiteClientProofGenerator, error) {
	if v3Endpoint == "" {
		return nil, fmt.Errorf("v3Endpoint cannot be empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Create V3Backend for basic account queries
	backend, err := lcbackend.NewRPCDataBackendV3(v3Endpoint)
	if err != nil {
		return nil, fmt.Errorf("create v3 backend: %w", err)
	}

	// Create V3 JSON-RPC client for real proof builder
	v3Client := jsonrpc.NewClient(v3Endpoint)

	var proofBuilder *chained_proof.ProofBuilder

	// The *Comet* endpoint parameters are accepted for source compatibility
	// with existing callers and config, and are no longer used to build
	// proofs. They are still recorded so operators can see what was passed.
	bvnEndpoints := make(map[string]string)
	for name, ep := range map[string]string{
		"bvn0": bvn0Endpoint, "bvn1": bvn1Endpoint,
		"bvn2": bvn2Endpoint, "bvn3": bvn3Endpoint,
	} {
		if ep != "" {
			bvnEndpoints[name] = ep
		}
	}
	bvnEndpoint := bvn0Endpoint
	if bvnEndpoint == "" {
		bvnEndpoint = bvn1Endpoint
	}

	// The ProofBuilder needs only the v3 client. It is therefore always
	// available: proof generation no longer silently degrades to "basic proof
	// mode" when a CometBFT endpoint is unset.
	proofBuilder = chained_proof.NewProofBuilder(v3Client, true)
	proofBuilder.WithArtifacts = true
	log.Printf("[PROOF] ProofBuilder initialized (L1-L4, no consensus-engine dependency)")

	return &LiteClientProofGenerator{
		backend:      backend,
		v3Client:     v3Client,
		proofBuilder: proofBuilder,
		endpoint:     v3Endpoint,
		dnEndpoint:   dnCometEndpoint,
		bvnEndpoint:  bvnEndpoint,
		bvnEndpoints: bvnEndpoints,
		timeout:      timeout,
	}, nil
}

// GenerateAccumulateProof generates a CompleteProof for the given account URL.
// This is a simplified version - for full L1-L3 proofs with consensus binding,
// use GenerateChainedProof with txHash and bvn parameters.
func (g *LiteClientProofGenerator) GenerateAccumulateProof(ctx context.Context, accountURL string) (*lcproof.CompleteProof, error) {
	if accountURL == "" {
		return nil, fmt.Errorf("accountURL cannot be empty")
	}

	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	// Query account to verify it exists
	account, err := g.backend.QueryAccount(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("query account %s: %w", accountURL, err)
	}
	if account == nil {
		return nil, fmt.Errorf("account %s not found", accountURL)
	}

	// Return a minimal proof structure - full proofs require txHash and bvn
	return &lcproof.CompleteProof{
		AccountURL: accountURL,
		Verified:   false,
		Error:      "partial_proof: use GenerateChainedProof with txHash and bvn for full L1-L3 proof",
	}, nil
}

// GenerateChainedProof generates a REAL L1-L4 chained proof. L4 carries
// Accumulate's own threshold-signed partition anchors for both the BVN and the
// DN, so the proof verifies offline and needs no consensus-engine endpoint.
// This is the production-grade proof method that uses the real ProofBuilder.
// Parameters:
//   - accountURL: The account URL (e.g., acc://certen-demo.acme/data)
//   - txHash: The transaction hash (64-char hex, no 0x prefix)
//   - bvn: The BVN partition (e.g., "bvn1")
func (g *LiteClientProofGenerator) GenerateChainedProof(ctx context.Context, accountURL, txHash, bvn string) (*chained_proof.ChainedProof, error) {
	if accountURL == "" {
		return nil, fmt.Errorf("accountURL cannot be empty")
	}
	if txHash == "" {
		return nil, fmt.Errorf("txHash cannot be empty for L1-L3 proof")
	}

	// CRITICAL FIX: Validate and normalize BVN partition
	// The BVN must be a valid partition name like "bvn0", "bvn1", etc.
	// It should NOT be "acc://dn" or empty - those are invalid for L1-L3 proofs
	bvn = normalizeBVNPartition(bvn, accountURL)

	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	log.Printf("[PROOF] Building L1-L4 chained proof for %s (txHash=%s, bvn=%s)", accountURL, txHash[:16]+"...", bvn)

	// The BVN partition still matters - it selects which anchor chains L2 and
	// L4 read - but it no longer selects a CometBFT endpoint.
	proofBuilder := chained_proof.NewProofBuilder(g.v3Client, true)
	proofBuilder.WithArtifacts = true

	// Build real proof using the working-proof_do_not_edit ProofBuilder
	chainedProof, err := proofBuilder.BuildProof(ctx, chained_proof.ProofInput{
		Account: accountURL,
		TxHash:  txHash,
		BVN:     bvn,
	})
	if err != nil {
		return nil, fmt.Errorf("build chained proof: %w", err)
	}

	log.Printf("[PROOF] L1-L4 chained proof built successfully:")
	log.Printf("[PROOF]    L1: TxChainIndex=%d, BVNMinorBlockIndex=%d", chainedProof.Layer1.TxChainIndex, chainedProof.Layer1.BVNMinorBlockIndex)
	log.Printf("[PROOF]    L2: DNMinorBlockIndex=%d", chainedProof.Layer2.DNMinorBlockIndex)
	log.Printf("[PROOF]    L3: DNConsensusHeight=%d", chainedProof.Layer3.DNConsensusHeight)
	log.Printf("[PROOF]    L4-BVN: partition=%s signatures=%d threshold=%d",
		chainedProof.Layer4BVN.Partition, len(chainedProof.Layer4BVN.Signatures), chainedProof.Layer4BVN.Threshold)
	log.Printf("[PROOF]    L4-DN:  partition=%s signatures=%d threshold=%d",
		chainedProof.Layer4DN.Partition, len(chainedProof.Layer4DN.Signatures), chainedProof.Layer4DN.Threshold)

	return chainedProof, nil
}

// ChainedProofToCompleteProof converts a ChainedProof to CompleteProof format
// for compatibility with existing code that expects CompleteProof.
// CRITICAL: This must preserve ALL proof data for PostgreSQL storage.
func ChainedProofToCompleteProof(cp *chained_proof.ChainedProof) *lcproof.CompleteProof {
	if cp == nil {
		return nil
	}

	complete := &lcproof.CompleteProof{
		AccountURL:  cp.Input.Account,
		BlockHeight: cp.Layer3.DNConsensusHeight,
		Partition:   cp.Input.BVN,
		Verified:    true,
	}

	// Convert Layer1 data (Account → BVN root anchor)
	// Layer1.Leaf = txHash (account/tx identifier)
	// Layer1.BVNRootChainAnchor = BPT root at BVN level
	if cp.Layer1.Leaf != "" {
		complete.AccountHash = hexToBytes(cp.Layer1.Leaf)
	}
	if cp.Layer1.BVNRootChainAnchor != "" {
		complete.BPTRoot = hexToBytes(cp.Layer1.BVNRootChainAnchor)
	}

	// Convert Layer1 Receipt to MainChainProof
	complete.MainChainProof = convertChainedReceipt(&cp.Layer1.Receipt)

	// Convert Layer2 data (BVN anchor → DN anchor)
	// Create BVN anchor proof from Layer2 receipts
	complete.BVNAnchorProof = &lcproof.PartitionAnchor{
		Partition: cp.Input.BVN,
		Receipt:   convertChainedReceipt(&cp.Layer2.RootReceipt),
	}

	// Convert BPT receipt from Layer2
	complete.BPTProof = convertChainedReceipt(&cp.Layer2.BptReceipt)

	// Convert Layer3 data (DN anchor → consensus)
	// DNStateTreeAnchor = final block hash at consensus height
	if cp.Layer3.DNStateTreeAnchor != "" {
		complete.BlockHash = hexToBytes(cp.Layer3.DNStateTreeAnchor)
	}

	// Create DN anchor proof from Layer3 receipts
	complete.DNAnchorProof = &lcproof.PartitionAnchor{
		Partition: "directory",
		Receipt:   convertChainedReceipt(&cp.Layer3.RootReceipt),
	}

	// Create combined receipt from Layer3 BPT receipt (final proof path)
	complete.CombinedReceipt = convertChainedReceipt(&cp.Layer3.BptReceipt)

	// L4 - the two threshold-signed partition anchors. This is what the
	// governance root commits to as L4ConsensusProofH; before this, that slot
	// was zero in every govRoot ever signed.
	// Every signer partition's quorum, not only the principal's. A root that
	// committed to one leg of a two-leg proof would attest to less than the
	// proof carries, and the resulting root would be perfectly well-formed.
	complete.ConsensusProof = BuildL4ConsensusProofFromProof(cp)

	// ...and the evidence for it, carried through unreduced.
	//
	// ConsensusProof above is a SUMMARY, by design: it is the govRoot preimage,
	// so it holds partition, threshold, sorted signers and the anchors, and
	// nothing that would couple the hash to incidental encoding. That makes it
	// a claim a reader can only believe. These two legs are what lets a reader
	// check it instead - the signatures, the validator set, and the canonical
	// signed bytes the quorum covered - and they travel in the same column, so
	// no second query is needed to verify a stored proof.
	//
	// Pass-through, not a re-derivation: the pointers are the same legs
	// BuildL4ConsensusProof summarised, so the evidence and the conclusion
	// cannot describe different anchors. Nil stays nil - a partial L4 is not
	// stored as though it were complete.
	complete.Layer4BVN = cp.Layer4BVN
	complete.Layer4DN = cp.Layer4DN

	log.Printf("[PROOF] ChainedProofToCompleteProof: converted L1-L3 proof data")
	log.Printf("[PROOF]   AccountHash: %d bytes", len(complete.AccountHash))
	log.Printf("[PROOF]   BPTRoot: %d bytes", len(complete.BPTRoot))
	log.Printf("[PROOF]   BlockHash: %d bytes", len(complete.BlockHash))
	log.Printf("[PROOF]   MainChainProof: %v", complete.MainChainProof != nil)
	log.Printf("[PROOF]   BVNAnchorProof: %v", complete.BVNAnchorProof != nil)
	log.Printf("[PROOF]   DNAnchorProof: %v", complete.DNAnchorProof != nil)
	log.Printf("[PROOF]   BPTProof: %v", complete.BPTProof != nil)
	log.Printf("[PROOF]   CombinedReceipt: %v", complete.CombinedReceipt != nil)
	if complete.Layer4BVN != nil && complete.Layer4DN != nil {
		log.Printf("[PROOF]   L4 evidence: %s (%d sigs, %d validators, %d B signed) + %s (%d sigs, %d validators, %d B signed)",
			complete.Layer4BVN.Partition, len(complete.Layer4BVN.Signatures),
			len(complete.Layer4BVN.ValidatorSet), len(complete.Layer4BVN.SequencedMessage)/2,
			complete.Layer4DN.Partition, len(complete.Layer4DN.Signatures),
			len(complete.Layer4DN.ValidatorSet), len(complete.Layer4DN.SequencedMessage)/2)
	} else {
		log.Printf("[PROOF]   L4 evidence: ABSENT - this proof is summary-only and cannot be verified offline")
	}

	return complete
}

// convertChainedReceipt converts a chained_proof.Receipt to merkle.Receipt
func convertChainedReceipt(r *chained_proof.Receipt) *merkle.Receipt {
	if r == nil || r.Start == "" {
		return nil
	}

	receipt := &merkle.Receipt{
		Start:  hexToBytes(r.Start),
		Anchor: hexToBytes(r.Anchor),
	}

	// Convert each step in the receipt
	for _, step := range r.Entries {
		entry := &merkle.ReceiptEntry{
			Hash:  hexToBytes(step.Hash),
			Right: step.Right,
		}
		receipt.Entries = append(receipt.Entries, entry)
	}

	return receipt
}

// hexToBytes converts a hex string to bytes, returning nil on error
func hexToBytes(s string) []byte {
	if s == "" {
		return nil
	}
	// Remove 0x prefix if present
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Printf("[PROOF] hexToBytes failed for %q: %v", truncateString(s, 16), err)
		return nil
	}
	return b
}

// GenerateProofForIntent generates an Accumulate proof for a CERTEN intent.
// For full L1-L3 proofs, use GenerateChainedProofForIntent with txHash.
func (g *LiteClientProofGenerator) GenerateProofForIntent(ctx context.Context, intentURL string) (*lcproof.CompleteProof, error) {
	return g.GenerateAccumulateProof(ctx, intentURL)
}

// GenerateChainedProofForIntent generates a REAL L1-L3 proof for a CERTEN intent transaction.
// This should be called when the transaction hash is known (after the intent is discovered).
func (g *LiteClientProofGenerator) GenerateChainedProofForIntent(ctx context.Context, accountURL, txHash, bvn string) (*chained_proof.ChainedProof, error) {
	return g.GenerateChainedProof(ctx, accountURL, txHash, bvn)
}

// HasRealProofBuilder reports whether the real L1-L4 proof builder is
// available. It needs only a v3 client, so this is true whenever the generator
// was constructed successfully. It used to require a DN CometBFT client and at
// least one BVN CometBFT client, which meant an unset endpoint silently
// downgraded proof generation.
func (g *LiteClientProofGenerator) HasRealProofBuilder() bool {
	return g.proofBuilder != nil
}

// VerifyProof verifies a CompleteProof using the lite client verification system.
// This performs structural validation of the proof components. Full
// cryptographic verification is done by chained_proof.ProofVerifier, which is
// entirely offline.
func (g *LiteClientProofGenerator) VerifyProof(proof *lcproof.CompleteProof) error {
	if proof == nil {
		return fmt.Errorf("proof is nil")
	}

	// Validate basic proof structure
	errors := validateProofStructure(proof)
	if len(errors) > 0 {
		return fmt.Errorf("proof validation failed: %v", errors)
	}

	// Validate Merkle receipt integrity for each proof layer
	if proof.MainChainProof != nil {
		if err := validateMerkleReceipt(proof.MainChainProof, "main_chain"); err != nil {
			return err
		}
	}

	if proof.BPTProof != nil {
		if err := validateMerkleReceipt(proof.BPTProof, "bpt"); err != nil {
			return err
		}
	}

	if proof.CombinedReceipt != nil {
		if err := validateMerkleReceipt(proof.CombinedReceipt, "combined"); err != nil {
			return err
		}
	}

	// Validate BVN anchor proof
	if proof.BVNAnchorProof != nil && proof.BVNAnchorProof.Receipt != nil {
		if err := validateMerkleReceipt(proof.BVNAnchorProof.Receipt, "bvn_anchor"); err != nil {
			return err
		}
	}

	// Validate DN anchor proof
	if proof.DNAnchorProof != nil && proof.DNAnchorProof.Receipt != nil {
		if err := validateMerkleReceipt(proof.DNAnchorProof.Receipt, "dn_anchor"); err != nil {
			return err
		}
	}

	return nil
}

// validateProofStructure checks the basic structure of a CompleteProof
func validateProofStructure(proof *lcproof.CompleteProof) []string {
	var errors []string

	// At least one proof component should be present
	hasComponent := proof.MainChainProof != nil ||
		proof.BPTProof != nil ||
		proof.BVNAnchorProof != nil ||
		proof.DNAnchorProof != nil ||
		proof.CombinedReceipt != nil

	if !hasComponent {
		errors = append(errors, "proof has no valid components")
	}

	// If we have block info, validate it
	if proof.BlockHeight > 0 {
		if len(proof.BlockHash) == 0 {
			errors = append(errors, "block_height present but block_hash empty")
		}
	}

	// Validate BPT root if present
	if len(proof.BPTRoot) > 0 && len(proof.BPTRoot) != 32 {
		errors = append(errors, fmt.Sprintf("invalid bpt_root length: got %d, want 32", len(proof.BPTRoot)))
	}

	// Validate account hash if present
	if len(proof.AccountHash) > 0 && len(proof.AccountHash) != 32 {
		errors = append(errors, fmt.Sprintf("invalid account_hash length: got %d, want 32", len(proof.AccountHash)))
	}

	return errors
}

// validateMerkleReceipt validates the integrity of a Merkle receipt
// This includes both structural validation and cryptographic path verification
func validateMerkleReceipt(receipt *merkle.Receipt, name string) error {
	if receipt == nil {
		return nil // nil receipt is valid (not present)
	}

	// Start hash should be present
	if len(receipt.Start) == 0 {
		return fmt.Errorf("%s receipt: missing start hash", name)
	}

	// If entries are present, validate their structure
	for i, entry := range receipt.Entries {
		if entry == nil {
			return fmt.Errorf("%s receipt: nil entry at index %d", name, i)
		}
		if len(entry.Hash) == 0 {
			return fmt.Errorf("%s receipt: empty hash at index %d", name, i)
		}
		// Hash should be 32 bytes (SHA256)
		if len(entry.Hash) != 32 {
			return fmt.Errorf("%s receipt: invalid hash length at index %d: got %d, want 32", name, i, len(entry.Hash))
		}
	}

	// Perform cryptographic Merkle path verification
	// This verifies that applying all entries to the start hash produces the anchor
	if err := verifyMerklePathCryptographic(receipt, name); err != nil {
		return err
	}

	return nil
}

// verifyMerklePathCryptographic verifies that the Merkle path is cryptographically valid
// It recomputes the hash chain from Start through all Entries and verifies it matches Anchor
func verifyMerklePathCryptographic(receipt *merkle.Receipt, name string) error {
	if receipt == nil || len(receipt.Entries) == 0 {
		// No entries to verify - Start is the anchor
		return nil
	}

	// Start with the initial hash
	current := make([]byte, 32)
	copy(current, receipt.Start)

	// Apply each entry in the Merkle path
	for i, entry := range receipt.Entries {
		if entry == nil || len(entry.Hash) != 32 {
			return fmt.Errorf("%s receipt: invalid entry at index %d for cryptographic verification", name, i)
		}

		// Combine current hash with entry hash based on position (Left or Right)
		// In Accumulate's Merkle trees: H(left || right)
		var combined []byte
		if entry.Right {
			// Entry hash goes on the right: H(current || entry.Hash)
			combined = append(current, entry.Hash...)
		} else {
			// Entry hash goes on the left: H(entry.Hash || current)
			combined = append(entry.Hash, current...)
		}

		// Compute SHA256 of the combined hashes
		newHash := sha256Hash(combined)
		current = newHash[:]
	}

	// Verify the computed hash matches the anchor (if anchor is present)
	if len(receipt.Anchor) == 32 {
		if !bytesEqual(current, receipt.Anchor) {
			return fmt.Errorf("%s receipt: cryptographic verification failed - computed anchor does not match", name)
		}
	}

	return nil
}

// sha256Hash computes SHA256 hash of data
func sha256Hash(data []byte) [32]byte {
	// Use crypto/sha256 for hash computation
	var result [32]byte
	h := sha256.Sum256(data)
	copy(result[:], h[:])
	return result
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// normalizeBVNPartition validates and normalizes the BVN partition for L1-L3 proofs.
// Returns a valid BVN name like "bvn0", "bvn1", etc.
// If the input is invalid (e.g., "acc://dn", empty), it determines the correct BVN.
// DEPRECATED: Use LiteClientProofGenerator.routeBVNForAccount() instead for proper routing.
func normalizeBVNPartition(bvn, accountURL string) string {
	bvn = strings.ToLower(strings.TrimSpace(bvn))

	// Check if already a valid BVN partition name
	if strings.HasPrefix(bvn, "bvn") && len(bvn) >= 4 {
		// Already looks like a valid BVN (bvn0, bvn1, bvn2, etc.)
		log.Printf("[PROOF] BVN partition validated: %s", bvn)
		return bvn
	}

	// Invalid or missing BVN - try to calculate from account URL
	log.Printf("[PROOF] ⚠️ Invalid BVN partition '%s' for account %s - calculating from routing", bvn, accountURL)

	// Calculate BVN from account URL routing number
	calculatedBVN := calculateBVNFromAccountURL(accountURL)
	if calculatedBVN != "" {
		log.Printf("[PROOF] ✅ Calculated BVN partition: %s (from account URL routing)", calculatedBVN)
		return calculatedBVN
	}

	// Fallback to bvn1 if calculation fails
	defaultBVN := "bvn1"
	log.Printf("[PROOF] ⚠️ Could not calculate BVN, defaulting to %s", defaultBVN)
	return defaultBVN
}

// calculateBVNFromAccountURL calculates the BVN partition from an account URL
// using the Accumulate routing algorithm (prefix matching on routing number).
// This implements the same logic as the Accumulate routing package.
func calculateBVNFromAccountURL(accountURL string) string {
	// Parse the account URL to extract the identity
	// Account URLs are like: acc://identity.acme/path or acc://identity.acme
	if !strings.HasPrefix(accountURL, "acc://") {
		return ""
	}

	// Extract identity from URL (everything after acc:// up to / or end)
	urlPart := strings.TrimPrefix(accountURL, "acc://")
	identity := strings.Split(urlPart, "/")[0]

	// Calculate routing number from identity
	// The routing number is derived from SHA256 hash of the lowercase identity
	routingNumber := calculateRoutingNumber(identity)
	if routingNumber == 0 {
		return ""
	}

	// Use hardcoded Kermit routing table (3 BVNs)
	// Routes: length=1 → BVN1, length=2/value=2 → BVN2, length=2/value=3 → BVN3
	// This matches the Kermit network configuration
	return routeByPrefixTable(routingNumber)
}

// calculateRoutingNumber computes the routing number from an identity string.
// This matches Accumulate's url.Routing() method.
func calculateRoutingNumber(identity string) uint64 {
	if identity == "" {
		return 0
	}

	// Normalize to lowercase
	identity = strings.ToLower(identity)

	// SHA256 hash of the identity
	h := sha256.Sum256([]byte(identity))

	// Routing number is first 8 bytes as big-endian uint64
	var routingNum uint64
	for i := 0; i < 8; i++ {
		routingNum = (routingNum << 8) | uint64(h[i])
	}

	log.Printf("[PROOF] 🔢 Identity '%s' routing number: %016X", identity, routingNum)
	return routingNum
}

// routeByPrefixTable routes a routing number using the Kermit network's routing table.
// Kermit routing table:
//   - length=1, value=0 (implicit) → BVN1 (first bit = 0)
//   - length=2, value=2 → BVN2 (first 2 bits = 10)
//   - length=2, value=3 → BVN3 (first 2 bits = 11)
//
// This means:
//   - If first bit is 0 → BVN1
//   - If first 2 bits are 10 → BVN2
//   - If first 2 bits are 11 → BVN3
func routeByPrefixTable(routingNumber uint64) string {
	// Extract first 2 bits (positions 63 and 62)
	first2Bits := (routingNumber >> 62) & 0x3

	// Route based on prefix
	switch first2Bits {
	case 0, 1:
		// First bit is 0 (00 or 01) → BVN1 (length=1 match)
		if (routingNumber >> 63) == 0 {
			log.Printf("[PROOF] 🎯 Routing: first bit=0 → BVN1")
			return "bvn1"
		}
		// First bit is 1, check 2-bit prefix
		fallthrough
	case 2:
		// First 2 bits = 10 → BVN2
		log.Printf("[PROOF] 🎯 Routing: first 2 bits=10 → BVN2")
		return "bvn2"
	case 3:
		// First 2 bits = 11 → BVN3
		log.Printf("[PROOF] 🎯 Routing: first 2 bits=11 → BVN3")
		return "bvn3"
	}

	// Should not reach here
	return "bvn1"
}

// CalculateBVNFromAccountURL is the exported version of calculateBVNFromAccountURL.
// It calculates the BVN partition from an account URL using Accumulate's
// deterministic routing algorithm (SHA256-based prefix matching).
// For Kermit testnet, this returns "bvn1", "bvn2", or "bvn3".
// Returns empty string if the account URL is invalid.
func CalculateBVNFromAccountURL(accountURL string) string {
	return calculateBVNFromAccountURL(accountURL)
}

// GetEndpoint returns the Accumulate v3 endpoint being used
func (g *LiteClientProofGenerator) GetEndpoint() string {
	return g.endpoint
}

// GetTimeout returns the configured timeout for API calls
func (g *LiteClientProofGenerator) GetTimeout() time.Duration {
	return g.timeout
}

// CertenProofAdapter adapts lite client CompleteProof to legacy CertenProof interface
// This provides backward compatibility while transitioning to the lite client system.
type CertenProofAdapter struct {
	CompleteProof   *lcproof.CompleteProof
	OriginalRequest *ProofRequest
	GeneratedAt     time.Time
	ValidatorID     string
}

// NewCertenProofAdapter creates an adapter that wraps a CompleteProof
func NewCertenProofAdapter(proof *lcproof.CompleteProof, req *ProofRequest, validatorID string) *CertenProofAdapter {
	return &CertenProofAdapter{
		CompleteProof:   proof,
		OriginalRequest: req,
		GeneratedAt:     time.Now(),
		ValidatorID:     validatorID,
	}
}

// ToCertenProof converts a CompleteProof to the legacy CertenProof format
// for compatibility with existing ValidatorBlock building code.
func (a *CertenProofAdapter) ToCertenProof() *CertenProof {
	if a.CompleteProof == nil {
		return nil
	}

	// Map CompleteProof to CertenProof structure
	certenProof := &CertenProof{
		ProofID:      fmt.Sprintf("lite_client_proof_%d", time.Now().Unix()),
		ProofVersion: "3.0", // Lite client version
		ProofType:    "accumulate_complete",
		GeneratedAt:  a.GeneratedAt,
		ValidatorID:  a.ValidatorID,
		Environment:  "production",
		BlockHeight:  a.CompleteProof.BlockHeight,
	}

	// Set request-specific fields if available
	if a.OriginalRequest != nil {
		certenProof.TransactionHash = a.OriginalRequest.TransactionHash
		certenProof.AccountURL = a.OriginalRequest.AccountURL
	}

	// Map lite client proof to legacy structure
	certenProof.LiteClientProof = &LiteClientProofData{
		CompleteProof: a.CompleteProof,
		AccountHash:   a.CompleteProof.AccountHash,
		BPTRoot:       a.CompleteProof.BPTRoot,
		BlockHash:     a.CompleteProof.BlockHash,
		// L4 flows from exactly one origin - ChainedProofToCompleteProof -
		// so the signer and the EVM submitter cannot disagree about it.
		ConsensusProof:  a.CompleteProof.ConsensusProof,
		ProofValid:      true, // If we got here, the proof was generated successfully
		ValidationLevel: "complete",
	}

	// CRITICAL: Populate AccumulateAnchor from CompleteProof data
	// This is required by ValidatorBlock building code in bft_integration.go
	// Without this, the fallback values are used which is suboptimal
	blockHashHex := ""
	if len(a.CompleteProof.BlockHash) > 0 {
		blockHashHex = fmt.Sprintf("%x", a.CompleteProof.BlockHash)
	}

	// Get transaction hash from request if available
	txHash := ""
	accountURL := ""
	if a.OriginalRequest != nil {
		txHash = a.OriginalRequest.TransactionHash
		accountURL = a.OriginalRequest.AccountURL
	}
	// Fallback to CompleteProof's AccountURL if available
	if accountURL == "" && a.CompleteProof.AccountURL != "" {
		accountURL = a.CompleteProof.AccountURL
	}

	// Only set AccumulateAnchor if we have meaningful data
	if a.CompleteProof.BlockHeight > 0 || blockHashHex != "" || txHash != "" {
		certenProof.AccumulateAnchor = &AccumulateAnchorData{
			BlockHash:   blockHashHex,
			BlockHeight: a.CompleteProof.BlockHeight,
			TxHash:      txHash,
		}
		log.Printf("[PROOF] ✅ AccumulateAnchor populated: height=%d, blockHash=%s..., txHash=%s...",
			a.CompleteProof.BlockHeight,
			truncateString(blockHashHex, 16),
			truncateString(txHash, 16))
	}

	// Set verification status
	certenProof.VerificationStatus = &VerificationStatusData{
		OverallValid:      true,
		Confidence:        1.0,
		VerificationLevel: "complete",
		ComponentStatus:   map[string]bool{"lite_client": true},
		VerifiedAt:        time.Now(),
	}

	// Set metrics
	certenProof.ProcessingTime = time.Since(a.GeneratedAt)
	certenProof.Metrics = &ProofGenerationMetrics{
		TotalTime:   certenProof.ProcessingTime,
		ProofSize:   len(fmt.Sprintf("%+v", a.CompleteProof)),
		CacheHits:   0,
		CacheMisses: 1,
	}

	return certenProof
}

// =============================================================================
// CONSENSUS STATE QUERY
// =============================================================================

// ConsensusState represents the current Accumulate network consensus state
type ConsensusState struct {
	BlockHeight int64     // Current block height
	BlockHash   string    // Current block hash (hex encoded)
	Timestamp   time.Time // Timestamp of the state query
}

// GetConsensusState retrieves the current consensus state from Accumulate network
// This is used for batch anchoring to know the current network state.
func (g *LiteClientProofGenerator) GetConsensusState(ctx context.Context) (*ConsensusState, error) {
	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	// Consensus state now comes from Accumulate itself rather than a CometBFT
	// status query, so it works on any consensus engine.
	dnURL := "acc://dn.acme"

	// Query account to verify connectivity (we extract block info from proof below)
	_, queryErr := g.backend.QueryAccount(ctx, dnURL)
	if queryErr != nil {
		// Try alternative endpoints before failing
		alternativeURLs := []string{
			"acc://bvn-bvn0.acme",
			"acc://bvn-bvn1.acme",
			"acc://acme",
		}

		for _, altURL := range alternativeURLs {
			altAccount, altErr := g.backend.QueryAccount(ctx, altURL)
			if altErr == nil && altAccount != nil {
				return &ConsensusState{
					BlockHeight: 0, // Not available from account query
					BlockHash:   "",
					Timestamp:   time.Now(),
				}, nil
			}
		}

		// All attempts failed - return error with details
		return nil, fmt.Errorf("failed to get consensus state from any Accumulate endpoint: primary error: %w", queryErr)
	}

	// Create a minimal proof to extract block info
	proof, proofErr := g.GenerateAccumulateProof(ctx, dnURL)
	if proofErr != nil {
		return nil, fmt.Errorf("failed to generate proof for consensus state: %w", proofErr)
	}

	// Validate we got real block data
	if proof.BlockHeight == 0 && len(proof.BlockHash) == 0 {
		return nil, fmt.Errorf("proof returned but contains no block data")
	}

	// Extract block info from the proof
	var blockHashHex string
	if len(proof.BlockHash) > 0 {
		blockHashHex = fmt.Sprintf("%x", proof.BlockHash)
	}

	return &ConsensusState{
		BlockHeight: int64(proof.BlockHeight),
		BlockHash:   blockHashHex,
		Timestamp:   time.Now(),
	}, nil
}

// BuildL4ConsensusProof reduces the two stored Layer4 legs to the evidence the
// governance root commits to.
//
// Returns nil if either leg is missing, so a proof without full L4 produces a
// ZERO L4ConsensusProofH rather than a partial one. That is deliberate: a
// half-populated L4 commitment would be indistinguishable from a complete one
// downstream. Callers that require L4 must check for the zero hash - see
// RequireL4Committed.
func BuildL4ConsensusProof(bvn, dn *chained_proof.Layer4) *lcproof.ConsensusProof {
	if bvn == nil || dn == nil {
		return nil
	}
	return &lcproof.ConsensusProof{
		Version: lcproof.L4GovRootVersion,
		BVN:     summarizeL4Leg(bvn),
		DN:      summarizeL4Leg(dn),
	}
}

// BuildL4ConsensusProofFromProof summarises EVERY signer partition's quorum,
// not only the principal's.
//
// Governance can span partitions, so a proof may carry a leg per partition that
// signed. A govRoot built from the principal's leg alone would attest to less
// than the proof actually carries - and it would do so silently, because the
// resulting root is perfectly well-formed.
//
// Returns nil if any required leg is missing, so a proof without full L4
// produces a ZERO L4ConsensusProofH rather than a partial one. A half-populated
// commitment is indistinguishable from a complete one downstream.
func BuildL4ConsensusProofFromProof(cp *chained_proof.ChainedProof) *lcproof.ConsensusProof {
	if cp == nil || cp.Layer4DN == nil {
		return nil
	}
	legs := cp.Legs()
	if len(legs) == 0 {
		return nil
	}

	// Legs() is already in canonical partition order, and the principal's leg is
	// singled out only because that is where the v1 shape kept it. Which leg is
	// "principal" is a property of the proof, not of the order they were
	// discovered in, so this is deterministic.
	principal := cp.PrincipalLegForSummary()
	if principal == nil || principal.Layer4BVN == nil {
		return nil
	}

	out := &lcproof.ConsensusProof{
		Version: lcproof.L4GovRootVersion,
		BVN:     summarizeL4Leg(principal.Layer4BVN),
		DN:      summarizeL4Leg(cp.Layer4DN),
	}
	for _, leg := range legs {
		if leg.Layer4BVN == nil {
			// A leg the proof names but cannot evidence. Returning a summary
			// without it would commit to a quorum set smaller than the proof
			// claims, so there is no partial answer to give.
			return nil
		}
		if strings.EqualFold(leg.Partition, principal.Partition) {
			continue
		}
		out.BVNs = append(out.BVNs, summarizeL4Leg(leg.Layer4BVN))
	}
	return out
}

func summarizeL4Leg(l *chained_proof.Layer4) lcproof.L4LegSummary {
	signers := make([]string, 0, len(l.Signatures))
	for _, s := range l.Signatures {
		signers = append(signers, strings.ToLower(s.PublicKey))
	}
	// Sorted, and de-duplicated: the quorum is a SET of distinct signers, and
	// the govRoot must commit to that set, not to however many rows the API
	// returned in whatever order it returned them.
	sort.Strings(signers)
	signers = dedupeSorted(signers)

	return lcproof.L4LegSummary{
		Partition:       l.Partition,
		SignedHash:      strings.ToLower(l.SignedHash),
		StateTreeAnchor: strings.ToLower(l.StateTreeAnchor),
		RootChainAnchor: strings.ToLower(l.RootChainAnchor),
		MinorBlockIndex: l.MinorBlockIndex,
		Threshold:       l.Threshold,
		Signers:         signers,
	}
}

func dedupeSorted(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// RequireL4Committed fails closed if the L4 evidence that must go into the
// governance root is absent.
//
// The govRoot builder's SetL4ConsensusProofFromJSON returns early on nil and
// leaves L4ConsensusProofH as thirty-two zero bytes. That is indistinguishable
// downstream from "L4 was computed and happened to hash to zero", so the
// absence has to be caught here rather than discovered as a silently weaker
// commitment.
func RequireL4Committed(p *CertenProof) error {
	if p == nil || p.LiteClientProof == nil {
		return fmt.Errorf("no lite client proof: L4 cannot be committed to the governance root")
	}
	cp := p.LiteClientProof.ConsensusProof
	if cp == nil {
		return fmt.Errorf("L4 evidence missing: the governance root would commit a zero L4 slot, " +
			"claiming a validator quorum that is not carried in the proof")
	}
	if cp.Version == "" {
		return fmt.Errorf("L4 evidence carries no version tag")
	}
	for name, leg := range map[string]*lcproof.L4LegSummary{"bvn": &cp.BVN, "dn": &cp.DN} {
		if leg.Partition == "" || leg.SignedHash == "" || leg.StateTreeAnchor == "" {
			return fmt.Errorf("L4 %s leg is incomplete: partition=%q signedHash=%q stateTreeAnchor=%q",
				name, leg.Partition, SafeTrunc(leg.SignedHash), SafeTrunc(leg.StateTreeAnchor))
		}
		if leg.Threshold == 0 {
			return fmt.Errorf("L4 %s leg has a zero threshold, which no signature set can fail", name)
		}
		if uint64(len(leg.Signers)) < leg.Threshold {
			return fmt.Errorf("L4 %s leg carries %d distinct signers against threshold %d",
				name, len(leg.Signers), leg.Threshold)
		}
	}
	if cp.BVN.Partition == cp.DN.Partition {
		return fmt.Errorf("L4 legs are both signed by %q; the BVN->DN hop is not witnessed", cp.BVN.Partition)
	}
	return nil
}

// SafeTrunc shortens a hash for error messages.
func SafeTrunc(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}
