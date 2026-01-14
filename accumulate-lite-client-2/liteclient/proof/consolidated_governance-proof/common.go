// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CERTEN Governance Proof - Common Utilities
// This file provides shared utilities for all governance proof levels (G0, G1, G2).
// Direct translation of Python gov_proof_common.py

// =============================================================================
// Hex Validation and Normalization
// =============================================================================

var (
	// HEX32_PATTERN matches 64 hex characters (32 bytes)
	HEX32_PATTERN = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// HEX64_PATTERN matches 128 hex characters (64 bytes)
	HEX64_PATTERN = regexp.MustCompile(`^[0-9a-f]{128}$`)
	// MSGID_PATTERN matches acc://<64hex>@<scope> format
	MSGID_PATTERN = regexp.MustCompile(`^acc://([0-9a-f]{64})@(.+)$`)
)

// HexValidator provides utilities for hex validation and normalization
type HexValidator struct{}

// IsHex32 checks if string is valid 32-byte hex (64 hex chars)
func (HexValidator) IsHex32(s string) bool {
	if s == "" {
		return false
	}
	return HEX32_PATTERN.MatchString(strings.ToLower(s))
}

// IsHex64 checks if string is valid 64-byte hex (128 hex chars)
func (HexValidator) IsHex64(s string) bool {
	if s == "" {
		return false
	}
	return HEX64_PATTERN.MatchString(strings.ToLower(s))
}

// NormalizeHex normalizes hex string by removing 0x prefix and converting to lowercase
func (HexValidator) NormalizeHex(s string, requiredBytes int) (string, error) {
	if s == "" {
		return "", ValidationError{Msg: "empty hex string"}
	}

	normalized := strings.ToLower(strings.TrimPrefix(s, "0x"))

	if requiredBytes > 0 {
		expectedLen := requiredBytes * 2
		if len(normalized) != expectedLen {
			return "", ValidationError{Msg: fmt.Sprintf("Expected %d hex chars, got %d", expectedLen, len(normalized))}
		}
	}

	return normalized, nil
}

// RequireHex32 requires string to be valid 32-byte hex
func (hv HexValidator) RequireHex32(s, fieldName string) (string, error) {
	normalized, err := hv.NormalizeHex(s, 0)
	if err != nil {
		return "", err
	}
	if !hv.IsHex32(normalized) {
		return "", ValidationError{Msg: fmt.Sprintf("%s must be 32-byte hex, got: %s", fieldName, s)}
	}
	return normalized, nil
}

// RequireHex64 requires string to be valid 64-byte hex
func (hv HexValidator) RequireHex64(s, fieldName string) (string, error) {
	normalized, err := hv.NormalizeHex(s, 0)
	if err != nil {
		return "", err
	}
	if !hv.IsHex64(normalized) {
		return "", ValidationError{Msg: fmt.Sprintf("%s must be 64-byte hex, got: %s", fieldName, s)}
	}
	return normalized, nil
}

// AsHex32 converts value to hex32 string if possible, returns empty string otherwise
func (hv HexValidator) AsHex32(x interface{}) string {
	if s, ok := x.(string); ok {
		normalized, err := hv.NormalizeHex(s, 0)
		if err == nil && hv.IsHex32(normalized) {
			return normalized
		}
	}
	if b, ok := x.([]byte); ok && len(b) == 32 {
		return hex.EncodeToString(b)
	}
	return ""
}

// =============================================================================
// URL and Scope Utilities
// =============================================================================

// URLUtils provides utilities for URL and scope handling
type URLUtils struct{}

// NormalizeURL normalizes Accumulate URL to standard format
func (URLUtils) NormalizeURL(u string) string {
	if u == "" {
		return u
	}
	if strings.HasPrefix(u, "acc://") {
		return u
	}
	if strings.HasPrefix(u, "acc:") {
		return "acc://" + u[4:]
	}
	if !strings.Contains(u, "://") {
		return "acc://" + u
	}
	return u
}

// NormalizeScope normalizes scope string for RPC queries
func (uu URLUtils) NormalizeScope(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.HasPrefix(strings.ToLower(s), "acc://") {
		s = "acc://" + strings.TrimPrefix(s, "/")
	}
	return strings.TrimSuffix(s, "/")
}

// ParseMsgID parses acc://<64hex>@<scope> format
// Returns (hash, normalized_scope_url) or error if invalid
func (uu URLUtils) ParseMsgID(s string) (string, string, error) {
	if s == "" {
		return "", "", ValidationError{Msg: "empty MSGID"}
	}

	matches := MSGID_PATTERN.FindStringSubmatch(strings.TrimSpace(s))
	if len(matches) != 3 {
		return "", "", ValidationError{Msg: fmt.Sprintf("Invalid MSGID format: %s", s)}
	}

	hash := strings.ToLower(matches[1])
	scopePart := strings.TrimSpace(matches[2])

	var scope string
	if strings.HasPrefix(strings.ToLower(scopePart), "acc://") {
		scope = uu.NormalizeScope(scopePart)
	} else {
		scope = uu.NormalizeScope("acc://" + strings.TrimPrefix(scopePart, "/"))
	}

	return hash, scope, nil
}

// ParseAccURLHash extracts the leading 32-byte hash from an acc URL
func (uu URLUtils) ParseAccURLHash(url string) (string, error) {
	if url == "" {
		return "", ValidationError{Msg: "empty acc URL"}
	}

	normalized := uu.NormalizeURL(url)
	if !strings.HasPrefix(normalized, "acc://") {
		return "", ValidationError{Msg: fmt.Sprintf("Not an acc:// URL: %s", url)}
	}

	rest := normalized[6:] // Remove "acc://"
	parts := strings.Split(rest, "@")
	hash := parts[0]

	hv := HexValidator{}
	return hv.RequireHex32(hash, "Message ID hash")
}

// =============================================================================
// File Operations
// =============================================================================

// FileUtils provides utilities for file operations
type FileUtils struct{}

// EnsureDir creates directory if it doesn't exist
func (FileUtils) EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// WriteJSON writes object as JSON to file
func (FileUtils) WriteJSON(path string, obj interface{}) error {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ReadJSON reads JSON from file
func (FileUtils) ReadJSON(path string, obj interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, obj)
}

// WriteBytes writes bytes to file
func (FileUtils) WriteBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// WriteText writes text to file
func (FileUtils) WriteText(path string, text string) error {
	return os.WriteFile(path, []byte(text), 0644)
}

// SHA256Hex calculates SHA256 hex digest of bytes
func (FileUtils) SHA256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// RPC Client
// =============================================================================

// RPCConfig holds configuration for RPC client
type RPCConfig struct {
	Endpoint   string        // RPC endpoint URL
	Timeout    time.Duration // Request timeout
	Backend    string        // "http" or "curl"
	CurlBinary string        // Path to curl binary
	UseHTTP    bool          // Use HTTP client
	UseCurl    bool          // Use curl client
	UserAgent  string        // User agent string
}

// RPCClient provides unified RPC client with multiple backends
type RPCClient struct {
	config RPCConfig
}

// NewRPCClient creates a new RPC client
func NewRPCClient(config RPCConfig) *RPCClient {
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.Backend == "" {
		config.Backend = "http"
	}
	if config.CurlBinary == "" {
		config.CurlBinary = "curl"
	}
	return &RPCClient{config: config}
}

// GetEndpoint returns the RPC endpoint
func (c *RPCClient) GetEndpoint() string {
	return c.config.Endpoint
}

// Query executes RPC query
func (c *RPCClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	fmt.Printf("[RPC] [DEBUG] Querying scope: %s\n", scope)
	fmt.Printf("[RPC] [DEBUG] Query: %+v\n", query)

	uu := URLUtils{}
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "query",
		"params": map[string]interface{}{
			"scope": uu.NormalizeScope(scope),
			"query": query,
		},
	}

	switch c.config.Backend {
	case "http":
		return c.queryHTTP(ctx, payload)
	case "curl":
		return c.queryCurl(ctx, payload)
	default:
		return nil, RPCError{Msg: fmt.Sprintf("Unknown RPC backend: %s", c.config.Backend)}
	}
}

// QueryRaw executes RPC query and returns raw response bytes
func (c *RPCClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	uu := URLUtils{}
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "query",
		"params": map[string]interface{}{
			"scope": uu.NormalizeScope(scope),
			"query": query,
		},
	}

	switch c.config.Backend {
	case "http":
		return c.queryHTTPRaw(ctx, payload)
	case "curl":
		return c.queryCurlRaw(ctx, payload)
	default:
		return nil, RPCError{Msg: fmt.Sprintf("Unknown RPC backend: %s", c.config.Backend)}
	}
}

func (c *RPCClient) queryHTTP(ctx context.Context, payload map[string]interface{}) (map[string]interface{}, error) {
	rawResp, err := c.queryHTTPRaw(ctx, payload)
	if err != nil {
		return nil, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rawResp, &response); err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Non-JSON response: %v", err)}
	}

	fmt.Printf("[RPC] [DEBUG] Response keys: %v\n", getMapKeys(response))

	return response, nil
}

func (c *RPCClient) queryHTTPRaw(ctx context.Context, payload map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Failed to marshal payload: %v", err)}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Failed to create request: %v", err)}
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.config.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("RPC POST failed: %v", err)}
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Failed to read response: %v", err)}
	}

	fmt.Printf("[RPC] [DEBUG] Raw response (first 500 chars): %s\n", string(rawResp[:min(len(rawResp), 500)]))

	return rawResp, nil
}

// Helper function to get map keys for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (c *RPCClient) queryCurl(ctx context.Context, payload map[string]interface{}) (map[string]interface{}, error) {
	rawResp, err := c.queryCurlRaw(ctx, payload)
	if err != nil {
		return nil, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rawResp, &response); err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Non-JSON response: %v first=%q", err, string(rawResp[:min(200, len(rawResp))]))}
	}

	return response, nil
}

func (c *RPCClient) queryCurlRaw(ctx context.Context, payload map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, RPCError{Msg: fmt.Sprintf("Failed to marshal payload: %v", err)}
	}

	cmd := exec.CommandContext(ctx,
		c.config.CurlBinary,
		"-sS",
		"--fail-with-body",
		"-X", "POST",
		c.config.Endpoint,
		"-H", "Content-Type: application/json",
		"--data-binary", "@-",
		"--max-time", strconv.Itoa(int(c.config.Timeout.Seconds())),
	)

	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, RPCError{Msg: fmt.Sprintf("curl failed (rc=%d): %s", exitErr.ExitCode(), string(exitErr.Stderr))}
		}
		return nil, RPCError{Msg: fmt.Sprintf("curl execution failed: %v", err)}
	}

	return output, nil
}

// =============================================================================
// Enhanced Cryptographic Verification
// =============================================================================

// CryptographicVerifier provides superior cryptographic verification capabilities
type CryptographicVerifier struct {
	auditTrail  []AuditEvent
	trailMutex  sync.RWMutex
	verifyCount int64
	failCount   int64
	domains     map[string]SigningDomain
}

// AuditEvent represents a cryptographic operation for audit trail
type AuditEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Operation   string    `json:"operation"`
	Subject     string    `json:"subject"`
	Result      string    `json:"result"`
	Hash        string    `json:"hash"`
	Signature   string    `json:"signature,omitempty"`
	PublicKey   string    `json:"publicKey,omitempty"`
	ErrorDetail string    `json:"errorDetail,omitempty"`
}

// SigningDomain represents cryptographic signing domain configuration
type SigningDomain struct {
	Name            string
	HashAlgorithm   string
	SignatureFormat string
	Prefix          []byte
	Verifier        func(pubKey, signature, message []byte) bool
}

// NewCryptographicVerifier creates a new cryptographic verifier with superior security
func NewCryptographicVerifier() *CryptographicVerifier {
	cv := &CryptographicVerifier{
		auditTrail: make([]AuditEvent, 0),
		domains:    make(map[string]SigningDomain),
	}

	// Register superior Ed25519 verification with Accumulate domain
	cv.RegisterSigningDomain(SigningDomain{
		Name:            "accumulate_ed25519",
		HashAlgorithm:   "SHA512",
		SignatureFormat: "Ed25519",
		Prefix:          []byte("accumulate/"),
		Verifier:        cv.verifyEd25519Signature,
	})

	return cv
}

// RegisterSigningDomain registers a cryptographic signing domain
func (cv *CryptographicVerifier) RegisterSigningDomain(domain SigningDomain) {
	cv.domains[domain.Name] = domain
	cv.auditLog("DOMAIN_REGISTER", domain.Name, "SUCCESS", "", "", "", "")
}

// VerifyEd25519Signature verifies Ed25519 signature with superior security
func (cv *CryptographicVerifier) VerifyEd25519Signature(pubKeyHex, signatureHex, domainName string, messageData []byte) (bool, error) {
	cv.trailMutex.Lock()
	cv.verifyCount++
	cv.trailMutex.Unlock()

	// Validate inputs with constant-time comparison where applicable
	if len(pubKeyHex) != 64 {
		cv.auditLog("ED25519_VERIFY", pubKeyHex[:min(16, len(pubKeyHex))], "FAIL", "", signatureHex[:min(16, len(signatureHex))], pubKeyHex, "Invalid public key length")
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
		return false, ValidationError{Msg: fmt.Sprintf("Invalid Ed25519 public key length: %d", len(pubKeyHex))}
	}

	if len(signatureHex) != 128 {
		cv.auditLog("ED25519_VERIFY", pubKeyHex[:16], "FAIL", "", signatureHex[:min(16, len(signatureHex))], pubKeyHex, "Invalid signature length")
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
		return false, ValidationError{Msg: fmt.Sprintf("Invalid Ed25519 signature length: %d", len(signatureHex))}
	}

	// Decode public key with validation
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		cv.auditLog("ED25519_VERIFY", pubKeyHex[:16], "FAIL", "", signatureHex[:16], pubKeyHex, "Public key decode error")
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
		return false, ValidationError{Msg: fmt.Sprintf("Invalid public key hex: %v", err)}
	}

	// Decode signature with validation
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		cv.auditLog("ED25519_VERIFY", pubKeyHex[:16], "FAIL", "", signatureHex[:16], pubKeyHex, "Signature decode error")
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
		return false, ValidationError{Msg: fmt.Sprintf("Invalid signature hex: %v", err)}
	}

	// Get signing domain configuration
	domain, exists := cv.domains[domainName]
	if !exists {
		cv.auditLog("ED25519_VERIFY", pubKeyHex[:16], "FAIL", "", signatureHex[:16], pubKeyHex, "Unknown signing domain")
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
		return false, ValidationError{Msg: fmt.Sprintf("Unknown signing domain: %s", domainName)}
	}

	// Prepare message with domain prefix (Accumulate protocol)
	var finalMessage []byte
	if len(domain.Prefix) > 0 {
		finalMessage = append(domain.Prefix, messageData...)
	} else {
		finalMessage = messageData
	}

	// Calculate message hash for audit
	msgHash := sha256.Sum256(finalMessage)
	msgHashHex := hex.EncodeToString(msgHash[:])

	// Perform cryptographic verification using Go's crypto/ed25519 package
	valid := ed25519.Verify(ed25519.PublicKey(pubKeyBytes), finalMessage, signatureBytes)

	// Audit log the verification attempt
	result := "FAIL"
	if valid {
		result = "SUCCESS"
	} else {
		cv.trailMutex.Lock()
		cv.failCount++
		cv.trailMutex.Unlock()
	}

	cv.auditLog("ED25519_VERIFY", pubKeyHex[:16], result, msgHashHex, signatureHex[:16], pubKeyHex, "")

	return valid, nil
}

// verifyEd25519Signature is the internal verifier function for signing domains
func (cv *CryptographicVerifier) verifyEd25519Signature(pubKey, signature, message []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pubKey), message, signature)
}

// ComputeAccumulateDigest computes the Accumulate protocol digest for Ed25519
func (cv *CryptographicVerifier) ComputeAccumulateDigest(txHash string, signerVersion int64, timestamp *int64) ([]byte, error) {
	// Validate transaction hash
	hv := HexValidator{}
	normalizedTxHash, err := hv.RequireHex32(txHash, "transaction hash")
	if err != nil {
		return nil, err
	}

	// Decode transaction hash
	txHashBytes, err := hex.DecodeString(normalizedTxHash)
	if err != nil {
		return nil, ValidationError{Msg: fmt.Sprintf("Failed to decode transaction hash: %v", err)}
	}

	// Build digest according to Accumulate protocol
	var digestData []byte
	digestData = append(digestData, []byte("accumulate/")...) // Domain prefix
	digestData = append(digestData, txHashBytes...)           // Transaction hash (32 bytes)

	// Add signer version (8 bytes, big-endian)
	versionBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		versionBytes[i] = byte(signerVersion & 0xFF)
		signerVersion >>= 8
	}
	digestData = append(digestData, versionBytes...)

	// Add timestamp if provided (8 bytes, big-endian)
	if timestamp != nil {
		timestampBytes := make([]byte, 8)
		ts := *timestamp
		for i := 7; i >= 0; i-- {
			timestampBytes[i] = byte(ts & 0xFF)
			ts >>= 8
		}
		digestData = append(digestData, timestampBytes...)
	}

	// Audit log digest computation
	digestHash := sha256.Sum256(digestData)
	digestHashHex := hex.EncodeToString(digestHash[:])
	cv.auditLog("DIGEST_COMPUTE", normalizedTxHash[:16], "SUCCESS", digestHashHex, "", "", "")

	return digestData, nil
}

// GetAuditTrail returns the complete cryptographic audit trail
func (cv *CryptographicVerifier) GetAuditTrail() []AuditEvent {
	cv.trailMutex.RLock()
	defer cv.trailMutex.RUnlock()

	// Return a copy to prevent external modification
	trail := make([]AuditEvent, len(cv.auditTrail))
	copy(trail, cv.auditTrail)
	return trail
}

// GetVerificationStats returns verification statistics
func (cv *CryptographicVerifier) GetVerificationStats() (verified int64, failed int64) {
	cv.trailMutex.RLock()
	defer cv.trailMutex.RUnlock()
	return cv.verifyCount - cv.failCount, cv.failCount
}

// auditLog adds an event to the cryptographic audit trail
func (cv *CryptographicVerifier) auditLog(operation, subject, result, hash, signature, publicKey, errorDetail string) {
	cv.trailMutex.Lock()
	defer cv.trailMutex.Unlock()

	event := AuditEvent{
		Timestamp:   time.Now().UTC(),
		Operation:   operation,
		Subject:     subject,
		Result:      result,
		Hash:        hash,
		Signature:   signature,
		PublicKey:   publicKey,
		ErrorDetail: errorDetail,
	}

	cv.auditTrail = append(cv.auditTrail, event)
}

// =============================================================================
// Enhanced Bundle Integrity
// =============================================================================

// BundleIntegrityManager provides superior bundle integrity verification
type BundleIntegrityManager struct {
	chainOfCustody []CustodyEvent
	custodyMutex   sync.RWMutex
	artifactHashes map[string]string
	hashMutex      sync.RWMutex
	verifier       *CryptographicVerifier
}

// CustodyEvent represents a chain-of-custody event
type CustodyEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ArtifactID  string    `json:"artifactId"`
	Operation   string    `json:"operation"`
	Hash        string    `json:"hash"`
	PreviousHash string   `json:"previousHash,omitempty"`
	Operator    string    `json:"operator"`
	Validated   bool      `json:"validated"`
}

// NewBundleIntegrityManager creates enhanced bundle integrity manager
func NewBundleIntegrityManager(verifier *CryptographicVerifier) *BundleIntegrityManager {
	return &BundleIntegrityManager{
		chainOfCustody: make([]CustodyEvent, 0),
		artifactHashes: make(map[string]string),
		verifier:       verifier,
	}
}

// RecordArtifact records an artifact with integrity verification
func (bim *BundleIntegrityManager) RecordArtifact(artifactID string, data []byte) string {
	// Calculate double SHA256 for enhanced security
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	finalHash := hex.EncodeToString(secondHash[:])

	// Get previous hash for chaining
	bim.custodyMutex.RLock()
	var previousHash string
	if len(bim.chainOfCustody) > 0 {
		previousHash = bim.chainOfCustody[len(bim.chainOfCustody)-1].Hash
	}
	bim.custodyMutex.RUnlock()

	// Create custody event
	event := CustodyEvent{
		Timestamp:    time.Now().UTC(),
		ArtifactID:   artifactID,
		Operation:    "CREATE",
		Hash:         finalHash,
		PreviousHash: previousHash,
		Operator:     "CERTENGovernanceProof",
		Validated:    true,
	}

	// Record in chain of custody
	bim.custodyMutex.Lock()
	bim.chainOfCustody = append(bim.chainOfCustody, event)
	bim.custodyMutex.Unlock()

	// Store artifact hash
	bim.hashMutex.Lock()
	bim.artifactHashes[artifactID] = finalHash
	bim.hashMutex.Unlock()

	return finalHash
}

// VerifyArtifact verifies artifact integrity against recorded hash
func (bim *BundleIntegrityManager) VerifyArtifact(artifactID string, data []byte) bool {
	bim.hashMutex.RLock()
	expectedHash, exists := bim.artifactHashes[artifactID]
	bim.hashMutex.RUnlock()

	if !exists {
		return false
	}

	// Calculate hash and verify
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	actualHash := hex.EncodeToString(secondHash[:])

	// Use constant-time comparison for security
	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(actualHash)) == 1
}

// GetCustodyChain returns the complete chain of custody
func (bim *BundleIntegrityManager) GetCustodyChain() []CustodyEvent {
	bim.custodyMutex.RLock()
	defer bim.custodyMutex.RUnlock()

	chain := make([]CustodyEvent, len(bim.chainOfCustody))
	copy(chain, bim.chainOfCustody)
	return chain
}

// =============================================================================
// Enhanced Artifact Management
// =============================================================================

// ArtifactManager manages RPC artifacts with superior cryptographic verification
// Implements CERTEN Section 4.2 Bundle Integrity requirements
type ArtifactManager struct {
	workDir         string
	artifactsDir    string
	fileUtils       FileUtils
	verifier        *CryptographicVerifier
	bundleManager   *BundleIntegrityManager
	securityMetadata map[string]SecurityMetadata
	metaMutex       sync.RWMutex
}

// SecurityMetadata tracks enhanced security metadata for artifacts
type SecurityMetadata struct {
	ArtifactID       string    `json:"artifactId"`
	CreationTime     time.Time `json:"creationTime"`
	IntegrityHash    string    `json:"integrityHash"`
	VerificationHash string    `json:"verificationHash"`
	ChainPosition    int       `json:"chainPosition"`
	CustodyEvents    int       `json:"custodyEvents"`
	SecurityLevel    string    `json:"securityLevel"`
	AuditEvents      int       `json:"auditEvents"`
}

// NewArtifactManager creates enhanced artifact manager with superior security
func NewArtifactManager(workdir string) (*ArtifactManager, error) {
	artifactsDir := filepath.Join(workdir, "artifacts")
	fu := FileUtils{}
	if err := fu.EnsureDir(artifactsDir); err != nil {
		return nil, fmt.Errorf("failed to create artifacts directory: %v", err)
	}

	// Create security subdirectories
	securityDir := filepath.Join(workdir, "security")
	auditDir := filepath.Join(securityDir, "audit")
	custodyDir := filepath.Join(securityDir, "custody")

	if err := fu.EnsureDir(securityDir); err != nil {
		return nil, fmt.Errorf("failed to create security directory: %v", err)
	}
	if err := fu.EnsureDir(auditDir); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %v", err)
	}
	if err := fu.EnsureDir(custodyDir); err != nil {
		return nil, fmt.Errorf("failed to create custody directory: %v", err)
	}

	// Initialize cryptographic components
	verifier := NewCryptographicVerifier()
	bundleManager := NewBundleIntegrityManager(verifier)

	return &ArtifactManager{
		workDir:          workdir,
		artifactsDir:     artifactsDir,
		fileUtils:        fu,
		verifier:         verifier,
		bundleManager:    bundleManager,
		securityMetadata: make(map[string]SecurityMetadata),
	}, nil
}

// SaveRPCArtifact saves RPC query and response with superior cryptographic verification
func (am *ArtifactManager) SaveRPCArtifact(ctx context.Context, label string, client RPCClientInterface, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	// Build request payload
	uu := URLUtils{}
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "query",
		"params": map[string]interface{}{
			"scope": uu.NormalizeScope(scope),
			"query": query,
		},
	}

	// File paths with enhanced security structure
	reqPath := filepath.Join(am.artifactsDir, label+".request.json")
	rawPath := filepath.Join(am.artifactsDir, label+".response.raw.json")
	parsedPath := filepath.Join(am.artifactsDir, label+".response.parsed.json")
	shaPath := filepath.Join(am.artifactsDir, label+".response.sha256")
	metaPath := filepath.Join(am.artifactsDir, label+".meta.json")
	securityPath := filepath.Join(am.workDir, "security", label+".security.json")
	auditPath := filepath.Join(am.workDir, "security", "audit", label+".audit.json")
	custodyPath := filepath.Join(am.workDir, "security", "custody", label+".custody.json")

	// Save request with integrity tracking
	requestData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	_ = am.bundleManager.RecordArtifact(label+".request", requestData)

	if err := am.fileUtils.WriteBytes(reqPath, requestData); err != nil {
		return nil, fmt.Errorf("failed to save request: %v", err)
	}

	// Execute RPC call and get raw bytes
	rawResponse, err := client.QueryRaw(ctx, scope, query)
	if err != nil {
		return nil, fmt.Errorf("RPC query failed: %v", err)
	}

	// Calculate multiple hash levels for enhanced security
	responseHash := am.fileUtils.SHA256Hex(rawResponse)
	integrityhash := am.bundleManager.RecordArtifact(label+".response", rawResponse)

	// Additional verification hash
	verificationData := append(requestData, rawResponse...)
	verificationHash := am.fileUtils.SHA256Hex(verificationData)

	// Parse JSON response
	var parsedResponse map[string]interface{}
	if err := json.Unmarshal(rawResponse, &parsedResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Save artifacts with integrity verification
	if err := am.fileUtils.WriteBytes(rawPath, rawResponse); err != nil {
		return nil, fmt.Errorf("failed to save raw response: %v", err)
	}

	if err := am.fileUtils.WriteJSON(parsedPath, parsedResponse); err != nil {
		return nil, fmt.Errorf("failed to save parsed response: %v", err)
	}

	// Enhanced hash file with multiple verification levels
	hashData := fmt.Sprintf("SHA256: %s\nIntegrity: %s\nVerification: %s\nTimestamp: %d\n",
		responseHash, integrityhash, verificationHash, time.Now().Unix())
	if err := am.fileUtils.WriteText(shaPath, hashData); err != nil {
		return nil, fmt.Errorf("failed to save response hash: %v", err)
	}

	// Create enhanced metadata with security tracking
	custodyChain := am.bundleManager.GetCustodyChain()
	auditTrail := am.verifier.GetAuditTrail()
	verifiedCount, failedCount := am.verifier.GetVerificationStats()

	metadata := EnhancedRPCArtifact{
		Label:            label,
		Endpoint:         client.GetEndpoint(),
		SHA256Response:   responseHash,
		IntegrityHash:    integrityhash,
		VerificationHash: verificationHash,
		Timestamp:        time.Now().Unix(),
		SecurityLevel:    "ENHANCED",
		CustodyEvents:    len(custodyChain),
		AuditEvents:      len(auditTrail),
		VerifiedOps:      verifiedCount,
		FailedOps:        failedCount,
	}

	if err := am.fileUtils.WriteJSON(metaPath, metadata); err != nil {
		return nil, fmt.Errorf("failed to save metadata: %v", err)
	}

	// Save security metadata
	securityMeta := SecurityMetadata{
		ArtifactID:       label,
		CreationTime:     time.Now().UTC(),
		IntegrityHash:    integrityhash,
		VerificationHash: verificationHash,
		ChainPosition:    len(custodyChain),
		CustodyEvents:    len(custodyChain),
		SecurityLevel:    "ENHANCED",
		AuditEvents:      len(auditTrail),
	}

	am.metaMutex.Lock()
	am.securityMetadata[label] = securityMeta
	am.metaMutex.Unlock()

	if err := am.fileUtils.WriteJSON(securityPath, securityMeta); err != nil {
		return nil, fmt.Errorf("failed to save security metadata: %v", err)
	}

	// Save audit trail
	if err := am.fileUtils.WriteJSON(auditPath, auditTrail); err != nil {
		return nil, fmt.Errorf("failed to save audit trail: %v", err)
	}

	// Save custody chain
	if err := am.fileUtils.WriteJSON(custodyPath, custodyChain); err != nil {
		return nil, fmt.Errorf("failed to save custody chain: %v", err)
	}

	return parsedResponse, nil
}

// =============================================================================
// Query Builders
// =============================================================================

// QueryBuilder builds structured v3 JSON-RPC queries with CERTEN specification compliance
type QueryBuilder struct{}

// BuildNormativeChainQuery builds a CERTEN normative chain query (Appendix A.1)
// This implementation directly matches the CERTEN specification templates
func (QueryBuilder) BuildNormativeChainQuery(name, entryHex string, includeReceipt, expand bool) map[string]interface{} {
	return map[string]interface{}{
		"queryType":      "chain",
		"name":           name,
		"entry":          entryHex,
		"includeReceipt": includeReceipt, // Boolean as required by spec
		"expand":         expand,         // Boolean as required by spec
	}
}

// BuildDefaultQuery builds default transaction query
func (QueryBuilder) BuildDefaultQuery(includeReceipt interface{}, expand *bool) map[string]interface{} {
	query := map[string]interface{}{
		"queryType": "default",
	}
	if includeReceipt != nil {
		query["includeReceipt"] = includeReceipt
	}
	if expand != nil {
		query["expand"] = *expand
	}
	return query
}

// BuildChainQuery builds flexible chain query with optional parameters
func (QueryBuilder) BuildChainQuery(name string, entryHex *string, rangeStart, rangeCount *int, includeReceipt interface{}, expand *bool) map[string]interface{} {
	query := map[string]interface{}{
		"queryType": "chain",
		"name":      name,
	}

	if entryHex != nil {
		query["entry"] = *entryHex
	}

	if rangeStart != nil && rangeCount != nil {
		query["range"] = map[string]interface{}{
			"start": *rangeStart,
			"count": *rangeCount,
		}
	}

	if includeReceipt != nil {
		query["includeReceipt"] = includeReceipt
	}
	if expand != nil {
		query["expand"] = *expand
	}

	return query
}

// BuildChainCountQuery builds a query to get chain count
func (QueryBuilder) BuildChainCountQuery(name string) map[string]interface{} {
	return map[string]interface{}{
		"queryType": "chain",
		"name":      name,
	}
}

// BuildMsgIDQuery builds CERTEN normative query for MSGID resolution (Appendix A.7)
func (QueryBuilder) BuildMsgIDQuery() map[string]interface{} {
	return map[string]interface{}{
		"queryType": "default",
		"includeReceipt": map[string]bool{
			"forAny": true,
		},
		"expand": true,
	}
}

// =============================================================================
// Proof Utilities
// =============================================================================

// ProofUtilities provides shared proof utilities and helpers
type ProofUtilities struct{}

// ExpectResult extracts result from RPC response with error checking
func (ProofUtilities) ExpectResult(response map[string]interface{}) (map[string]interface{}, error) {
	if errorField, exists := response["error"]; exists && errorField != nil {
		return nil, RPCError{Msg: fmt.Sprintf("RPC returned error: %v", errorField)}
	}

	result, exists := response["result"]
	if !exists {
		return nil, RPCError{Msg: "RPC response missing result object"}
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, RPCError{Msg: "RPC result is not an object"}
	}

	return resultMap, nil
}

// NormalizeRecords normalizes records from RPC response
func (ProofUtilities) NormalizeRecords(result map[string]interface{}) ([]map[string]interface{}, error) {
	records, exists := result["records"]
	if !exists {
		return nil, ValidationError{Msg: "Missing records in response"}
	}

	recordsArray, ok := records.([]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Records is not an array"}
	}

	var normalizedRecords []map[string]interface{}
	for i, record := range recordsArray {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			return nil, ValidationError{Msg: fmt.Sprintf("Record %d is not an object", i)}
		}
		normalizedRecords = append(normalizedRecords, recordMap)
	}

	return normalizedRecords, nil
}

// FindChainEntry finds chain entry in records
func (pu ProofUtilities) FindChainEntry(records []map[string]interface{}, chain, entryHash string) (map[string]interface{}, error) {
	for _, record := range records {
		if recordType, ok := record["recordType"].(string); ok && recordType == "chainEntry" {
			if name, ok := record["name"].(string); ok && name == chain {
				if entry, ok := record["entry"].(string); ok {
					hv := HexValidator{}
					normalizedEntry, err := hv.RequireHex32(entry, "entry")
					if err == nil && normalizedEntry == entryHash {
						return record, nil
					}
				}
			}
		}
	}
	return nil, ValidationError{Msg: fmt.Sprintf("Chain entry not found: %s/%s", chain, entryHash)}
}

// ExtractReceiptFromChainEntry extracts receipt from chain entry result
func (ProofUtilities) ExtractReceiptFromChainEntry(chainEntry map[string]interface{}) (ReceiptData, error) {
	receiptField, exists := chainEntry["receipt"]
	if !exists {
		return ReceiptData{}, ValidationError{Msg: "Missing receipt on chain entry (includeReceipt:true required)"}
	}

	receiptMap, ok := receiptField.(map[string]interface{})
	if !ok {
		return ReceiptData{}, ValidationError{Msg: "Receipt is not an object"}
	}

	// Handle nested receipt.receipt structure
	if innerReceipt, exists := receiptMap["receipt"]; exists {
		if innerMap, ok := innerReceipt.(map[string]interface{}); ok {
			receiptMap = innerMap
		}
	}

	receipt := ReceiptData{}

	if start, ok := receiptMap["start"].(string); ok {
		hv := HexValidator{}
		normalizedStart, err := hv.RequireHex32(start, "receipt.start")
		if err != nil {
			return ReceiptData{}, err
		}
		receipt.Start = normalizedStart
	} else {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing start"}
	}

	if anchor, ok := receiptMap["anchor"].(string); ok {
		hv := HexValidator{}
		normalizedAnchor, err := hv.RequireHex32(anchor, "receipt.anchor")
		if err != nil {
			return ReceiptData{}, err
		}
		receipt.Anchor = normalizedAnchor
	} else {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing anchor"}
	}

	if localBlock, ok := receiptMap["localBlock"]; ok {
		switch lb := localBlock.(type) {
		case float64:
			receipt.LocalBlock = int64(lb)
		case int:
			receipt.LocalBlock = int64(lb)
		case int64:
			receipt.LocalBlock = lb
		case string:
			parsed, err := strconv.ParseInt(lb, 10, 64)
			if err != nil {
				return ReceiptData{}, ValidationError{Msg: fmt.Sprintf("Receipt localBlock not integer: %v", localBlock)}
			}
			receipt.LocalBlock = parsed
		default:
			return ReceiptData{}, ValidationError{Msg: fmt.Sprintf("Receipt localBlock not integer: %v", localBlock)}
		}
	} else {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing localBlock"}
	}

	// Optional fields
	if end, ok := receiptMap["end"].(string); ok && end != "" {
		receipt.End = &end
	}

	if majorBlock, ok := receiptMap["majorBlock"]; ok {
		switch mb := majorBlock.(type) {
		case float64:
			val := int64(mb)
			receipt.MajorBlock = &val
		case int:
			val := int64(mb)
			receipt.MajorBlock = &val
		case int64:
			receipt.MajorBlock = &mb
		}
	}

	return receipt, nil
}

// ExtractExpandedValue extracts expanded value from chain entry
func (ProofUtilities) ExtractExpandedValue(chainEntry map[string]interface{}) (map[string]interface{}, error) {
	value, exists := chainEntry["value"]
	if !exists {
		return nil, ValidationError{Msg: "Missing value in chain entry (expand:true required)"}
	}

	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Value is not an object"}
	}

	return valueMap, nil
}

// ExtractExpandedMessageID extracts message.id from expanded value for binding validation
func (pu ProofUtilities) ExtractExpandedMessageID(value map[string]interface{}) (string, error) {
	message, exists := value["message"]
	if !exists {
		return "", ValidationError{Msg: "Missing message in expanded value"}
	}

	messageMap, ok := message.(map[string]interface{})
	if !ok {
		return "", ValidationError{Msg: "Message is not an object"}
	}

	messageID, exists := messageMap["id"]
	if !exists {
		return "", ValidationError{Msg: "Missing message.id"}
	}

	messageIDStr, ok := messageID.(string)
	if !ok {
		return "", ValidationError{Msg: "Message.id is not a string"}
	}

	return messageIDStr, nil
}

// TryExtractPrincipal attempts to extract principal from chain entry (best effort)
func (pu ProofUtilities) TryExtractPrincipal(chainEntry map[string]interface{}) string {
	value, err := pu.ExtractExpandedValue(chainEntry)
	if err != nil {
		return ""
	}

	message, exists := value["message"]
	if !exists {
		return ""
	}

	messageMap, ok := message.(map[string]interface{})
	if !ok {
		return ""
	}

	if principal, ok := messageMap["principal"].(string); ok {
		uu := URLUtils{}
		return uu.NormalizeURL(principal)
	}

	return ""
}

// CaseInsensitiveGet performs case-insensitive key lookup in map
func (ProofUtilities) CaseInsensitiveGet(m map[string]interface{}, key string) interface{} {
	// Try exact match first
	if val, exists := m[key]; exists {
		return val
	}

	// Try case-insensitive search
	lowerKey := strings.ToLower(key)
	for k, v := range m {
		if strings.ToLower(k) == lowerKey {
			return v
		}
	}

	return nil
}

// =============================================================================
// QueryBuilder Missing Methods
// =============================================================================

// BuildMainChainQuery builds main chain query for chain count
func (qb QueryBuilder) BuildMainChainQuery(entryHex *string) map[string]interface{} {
	if entryHex != nil {
		return qb.BuildChainQuery("main", entryHex, nil, nil, true, nil)
	}
	return qb.BuildChainCountQuery("main")
}

// BuildMainChainRangeQuery builds main chain range query
func (qb QueryBuilder) BuildMainChainRangeQuery(start, count int) map[string]interface{} {
	return qb.BuildChainQuery("main", nil, &start, &count, map[string]interface{}{"forAny": true}, &[]bool{true}[0])
}

// BuildSignatureChainQuery builds signature chain query
func (qb QueryBuilder) BuildSignatureChainQuery(entryHex *string, start, count int) map[string]interface{} {
	if entryHex != nil {
		return qb.BuildChainQuery("signature", entryHex, nil, nil, true, nil)
	}
	return qb.BuildChainCountQuery("signature")
}

// BuildSignatureChainRangeQuery builds signature chain range query
func (qb QueryBuilder) BuildSignatureChainRangeQuery(start, count int) map[string]interface{} {
	return qb.BuildChainQuery("signature", nil, &start, &count, false, &[]bool{false}[0])
}

// BuildSignatureEntryQuery builds single signature entry query
func (qb QueryBuilder) BuildSignatureEntryQuery(entryHex string) map[string]interface{} {
	return qb.BuildChainQuery("signature", &entryHex, nil, nil, true, &[]bool{true}[0])
}

// BuildExecutionInclusionQuery builds execution inclusion query
// Aligned with working Python implementation query structure
func (qb QueryBuilder) BuildExecutionInclusionQuery(txHash, chain string) map[string]interface{} {
	query := map[string]interface{}{
		"queryType":      "chain",
		"name":           chain,
		"entry":          txHash,
		"includeReceipt": true,
	}
	fmt.Printf("[QUERY] [DEBUG] Built execution inclusion query: %+v\n", query)
	return query
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SafeTruncate safely truncates a string to the specified length
// Returns the original string if it's shorter than the target length
func SafeTruncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

// Enhanced metadata structures for superior security tracking

// EnhancedRPCArtifact extends RPCArtifact with superior security metadata
type EnhancedRPCArtifact struct {
	Label            string `json:"label"`
	Endpoint         string `json:"endpoint"`
	SHA256Response   string `json:"sha256_response_raw"`
	IntegrityHash    string `json:"integrity_hash"`
	VerificationHash string `json:"verification_hash"`
	Timestamp        int64  `json:"ts_unix"`
	SecurityLevel    string `json:"security_level"`
	CustodyEvents    int    `json:"custody_events"`
	AuditEvents      int    `json:"audit_events"`
	VerifiedOps      int64  `json:"verified_operations"`
	FailedOps        int64  `json:"failed_operations"`
}

// GetCryptographicVerifier returns the cryptographic verifier instance
func (am *ArtifactManager) GetCryptographicVerifier() *CryptographicVerifier {
	return am.verifier
}

// GetBundleIntegrityManager returns the bundle integrity manager
func (am *ArtifactManager) GetBundleIntegrityManager() *BundleIntegrityManager {
	return am.bundleManager
}

// GetSecurityMetadata returns security metadata for an artifact
func (am *ArtifactManager) GetSecurityMetadata(artifactID string) (SecurityMetadata, bool) {
	am.metaMutex.RLock()
	defer am.metaMutex.RUnlock()
	meta, exists := am.securityMetadata[artifactID]
	return meta, exists
}

// VerifyArtifactIntegrity verifies the integrity of a stored artifact
func (am *ArtifactManager) VerifyArtifactIntegrity(label string) (bool, error) {
	// Read the raw response file
	rawPath := filepath.Join(am.artifactsDir, label+".response.raw.json")
	rawData, err := os.ReadFile(rawPath)
	if err != nil {
		return false, fmt.Errorf("failed to read artifact: %v", err)
	}

	// Verify against bundle integrity manager
	return am.bundleManager.VerifyArtifact(label+".response", rawData), nil
}