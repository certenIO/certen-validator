// Copyright 2025 Certen Protocol
//
// GovernanceProofAdapter - Adapter for generating real G0/G1/G2 governance proofs
//
// This adapter interfaces with the consolidated_governance-proof system to generate
// real governance proofs with cryptographic verification per CERTEN spec v3-governance-kpsw-exec-4.0
//
// Proof Levels:
// - G0: Inclusion and Finality Only
// - G1: Governance Correctness (Authority Validated)
// - G2: Governance + Outcome Binding

package proof

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GovernanceProofGenerator interface for governance proof generation
type GovernanceProofGenerator interface {
	// GenerateG0 generates G0 proof (Inclusion and Finality)
	GenerateG0(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error)
	// GenerateG1 generates G1 proof (Governance Correctness)
	GenerateG1(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error)
	// GenerateG2 generates G2 proof (Governance + Outcome Binding)
	GenerateG2(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error)
	// GenerateAtLevel generates governance proof at specified level
	GenerateAtLevel(ctx context.Context, level GovernanceLevel, req *GovernanceRequest) (*GovernanceProof, error)
}

// GovernanceRequest contains parameters for governance proof generation
type GovernanceRequest struct {
	// Required fields
	AccountURL      string `json:"account_url"`      // Principal account URL (acc://...)
	TransactionHash string `json:"transaction_hash"` // Transaction hash (64-char hex)

	// G1+ fields (required for G1 and G2)
	KeyPage string `json:"key_page,omitempty"` // Key page URL (acc://...)

	// Optional fields
	Chain         string `json:"chain,omitempty"`          // Chain name (default: "main")
	V3Endpoint    string `json:"v3_endpoint,omitempty"`    // V3 RPC endpoint
	WorkDir       string `json:"work_dir,omitempty"`       // Working directory for artifacts
	SigningDomain string `json:"signing_domain,omitempty"` // Signing domain
}

// CLIGovernanceProofGenerator implements governance proof generation via CLI subprocess
type CLIGovernanceProofGenerator struct {
	govProofPath string        // Path to govproof CLI binary
	txhashPath   string        // Path to txhash CLI binary (for G2 payload verification)
	v3Endpoint   string        // Default V3 endpoint
	workDir      string        // Base working directory
	timeout      time.Duration // Command timeout
	logger       *log.Logger
}

// NewCLIGovernanceProofGenerator creates a new CLI-based governance proof generator
func NewCLIGovernanceProofGenerator(govProofPath, v3Endpoint, workDir string, timeout time.Duration) (*CLIGovernanceProofGenerator, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &CLIGovernanceProofGenerator{
		govProofPath: govProofPath,
		v3Endpoint:   v3Endpoint,
		workDir:      workDir,
		timeout:      timeout,
		logger:       log.Default(),
	}, nil
}

// SetTxHashPath sets the path to the txhash tool for G2 payload verification
func (g *CLIGovernanceProofGenerator) SetTxHashPath(path string) {
	g.txhashPath = path
}

// SetLogger sets a custom logger
func (g *CLIGovernanceProofGenerator) SetLogger(logger *log.Logger) {
	g.logger = logger
}

// GenerateG0 generates G0 governance proof
func (g *CLIGovernanceProofGenerator) GenerateG0(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	return g.GenerateAtLevel(ctx, GovLevelG0, req)
}

// GenerateG1 generates G1 governance proof
func (g *CLIGovernanceProofGenerator) GenerateG1(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	if req.KeyPage == "" {
		return nil, fmt.Errorf("G1 proof requires KeyPage")
	}
	return g.GenerateAtLevel(ctx, GovLevelG1, req)
}

// GenerateG2 generates G2 governance proof
func (g *CLIGovernanceProofGenerator) GenerateG2(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	if req.KeyPage == "" {
		return nil, fmt.Errorf("G2 proof requires KeyPage")
	}
	return g.GenerateAtLevel(ctx, GovLevelG2, req)
}

// GenerateAtLevel generates governance proof at specified level using CLI
func (g *CLIGovernanceProofGenerator) GenerateAtLevel(ctx context.Context, level GovernanceLevel, req *GovernanceRequest) (*GovernanceProof, error) {
	if g.govProofPath == "" {
		// Return stub proof if CLI not configured
		g.logger.Printf("[GOV-PROOF] CLI not configured, returning stub proof for level %s", level)
		return g.createStubProof(level, req), nil
	}

	// Build command arguments
	args := g.buildCLIArgs(level, req)

	g.logger.Printf("[GOV-PROOF] Executing: %s %s", g.govProofPath, strings.Join(args, " "))

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, g.govProofPath, args...)

	// Capture output
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			g.logger.Printf("[GOV-PROOF] CLI failed: %s", string(exitErr.Stderr))
			return nil, fmt.Errorf("governance proof CLI failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("governance proof CLI error: %w", err)
	}

	// Parse JSON output
	return g.parseOutput(level, output)
}

// buildCLIArgs builds CLI arguments for governance proof generation
func (g *CLIGovernanceProofGenerator) buildCLIArgs(level GovernanceLevel, req *GovernanceRequest) []string {
	args := []string{
		"--level", string(level),
		"--json",
		"--quiet",
	}

	// V3 endpoint - ensure it has /v3 suffix
	endpoint := req.V3Endpoint
	if endpoint == "" {
		endpoint = g.v3Endpoint
	}
	if endpoint != "" {
		// Ensure endpoint ends with /v3
		if !strings.HasSuffix(endpoint, "/v3") {
			endpoint = strings.TrimSuffix(endpoint, "/") + "/v3"
		}
		args = append(args, "--endpoint", endpoint)
	}

	// Key page (required for G1+)
	if req.KeyPage != "" {
		args = append(args, "--keypage", req.KeyPage)
	}

	// Working directory
	workDir := req.WorkDir
	if workDir == "" && g.workDir != "" {
		workDir = filepath.Join(g.workDir, fmt.Sprintf("gov_%s_%d", level, time.Now().Unix()))
	}
	if workDir != "" {
		args = append(args, "--workdir", workDir)
	}

	// Signing domain
	if req.SigningDomain != "" {
		args = append(args, "--signing-domain", req.SigningDomain)
	}

	// TxHash tool path for G2 payload verification
	if level == GovLevelG2 && g.txhashPath != "" {
		args = append(args, "--txhash", g.txhashPath)
	}

	// Positional arguments: account chain txhash
	chain := req.Chain
	if chain == "" {
		chain = "main"
	}
	args = append(args, req.AccountURL, chain, req.TransactionHash)

	return args
}

// extractJSON extracts JSON content from CLI output, skipping log lines
// The CLI may output log lines like "[G0] Starting..." before the JSON
func extractJSON(output []byte) []byte {
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// JSON objects start with '{', arrays with '['
		// Skip empty lines and log lines like "[G0]", "[RPC]", etc.
		if len(trimmed) > 0 && trimmed[0] == '{' {
			return []byte(trimmed)
		}
	}
	// If no JSON object found, try to find last line with content
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if len(trimmed) > 0 && trimmed[0] == '{' {
			return []byte(trimmed)
		}
	}
	return output // Return original if no JSON found
}

// parseOutput parses CLI JSON output into GovernanceProof
func (g *CLIGovernanceProofGenerator) parseOutput(level GovernanceLevel, output []byte) (*GovernanceProof, error) {
	govProof := &GovernanceProof{
		Level:       level,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
	}

	// Extract JSON from output (CLI may print log lines before JSON)
	jsonData := extractJSON(output)

	switch level {
	case GovLevelG0:
		var result G0Result
		if err := json.Unmarshal(jsonData, &result); err != nil {
			return nil, fmt.Errorf("parse G0 result: %w", err)
		}
		govProof.G0 = &result
	case GovLevelG1:
		var result G1Result
		if err := json.Unmarshal(jsonData, &result); err != nil {
			return nil, fmt.Errorf("parse G1 result: %w", err)
		}
		govProof.G1 = &result
	case GovLevelG2:
		var result G2Result
		if err := json.Unmarshal(jsonData, &result); err != nil {
			return nil, fmt.Errorf("parse G2 result: %w", err)
		}
		govProof.G2 = &result
	default:
		return nil, fmt.Errorf("unknown governance level: %s", level)
	}

	return govProof, nil
}

// createStubProof creates a stub proof when CLI is not available
func (g *CLIGovernanceProofGenerator) createStubProof(level GovernanceLevel, req *GovernanceRequest) *GovernanceProof {
	govProof := &GovernanceProof{
		Level:       level,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
	}

	switch level {
	case GovLevelG0:
		govProof.G0 = &G0Result{
			TxHash:          req.TransactionHash,
			Scope:           req.AccountURL,
			Chain:           "main",
			Principal:       req.AccountURL,
			G0ProofComplete: false, // Stub - not verified
		}
	case GovLevelG1:
		govProof.G1 = &G1Result{
			G0Result: G0Result{
				TxHash:          req.TransactionHash,
				Scope:           req.AccountURL,
				Chain:           "main",
				Principal:       req.AccountURL,
				G0ProofComplete: false,
			},
			G1ProofComplete: false, // Stub - not verified
		}
	case GovLevelG2:
		govProof.G2 = &G2Result{
			G1Result: G1Result{
				G0Result: G0Result{
					TxHash:          req.TransactionHash,
					Scope:           req.AccountURL,
					Chain:           "main",
					Principal:       req.AccountURL,
					G0ProofComplete: false,
				},
				G1ProofComplete: false,
			},
			G2ProofComplete: false, // Stub - not verified
		}
	}

	return govProof
}

// =============================================================================
// In-Process Governance Proof Generator (for when library is available)
// =============================================================================

// InProcessGovernanceGenerator generates governance proofs in-process
// This can be used when the governance proof library is properly packaged
type InProcessGovernanceGenerator struct {
	v3Endpoint string
	workDir    string
	timeout    time.Duration
	logger     *log.Logger
}

// NewInProcessGovernanceGenerator creates a new in-process governance generator
func NewInProcessGovernanceGenerator(v3Endpoint, workDir string, timeout time.Duration) *InProcessGovernanceGenerator {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return &InProcessGovernanceGenerator{
		v3Endpoint: v3Endpoint,
		workDir:    workDir,
		timeout:    timeout,
		logger:     log.Default(),
	}
}

// GenerateG0 generates G0 proof in-process
// TODO: Implement when consolidated_governance-proof is refactored to library
func (g *InProcessGovernanceGenerator) GenerateG0(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	g.logger.Printf("[GOV-PROOF-INPROC] G0 proof generation not yet implemented in-process")

	// Return stub for now
	return &GovernanceProof{
		Level:       GovLevelG0,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
		G0: &G0Result{
			TxHash:          req.TransactionHash,
			Scope:           req.AccountURL,
			Chain:           "main",
			Principal:       req.AccountURL,
			G0ProofComplete: false,
		},
	}, nil
}

// GenerateG1 generates G1 proof in-process
func (g *InProcessGovernanceGenerator) GenerateG1(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	g.logger.Printf("[GOV-PROOF-INPROC] G1 proof generation not yet implemented in-process")
	return g.GenerateG0(ctx, req) // Fallback
}

// GenerateG2 generates G2 proof in-process
func (g *InProcessGovernanceGenerator) GenerateG2(ctx context.Context, req *GovernanceRequest) (*GovernanceProof, error) {
	g.logger.Printf("[GOV-PROOF-INPROC] G2 proof generation not yet implemented in-process")
	return g.GenerateG0(ctx, req) // Fallback
}

// GenerateAtLevel generates governance proof at specified level
func (g *InProcessGovernanceGenerator) GenerateAtLevel(ctx context.Context, level GovernanceLevel, req *GovernanceRequest) (*GovernanceProof, error) {
	switch level {
	case GovLevelG0:
		return g.GenerateG0(ctx, req)
	case GovLevelG1:
		return g.GenerateG1(ctx, req)
	case GovLevelG2:
		return g.GenerateG2(ctx, req)
	default:
		return nil, fmt.Errorf("unknown governance level: %s", level)
	}
}
