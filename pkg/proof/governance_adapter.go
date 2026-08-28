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
		return nil, fmt.Errorf("governance proof CLI not configured (govProofPath is empty)")
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
		// A context expiry KILLS the child, and a killed process returns an *exec.ExitError
		// whose Stderr is EMPTY — so this used to log exactly "governance proof CLI failed:"
		// with nothing after the colon. That is what a too-short PARENT deadline looked like
		// in production: G2 was killed on every value-moving intent, governance settled at
		// G1, and HIGH-004 then refused the intent — while the CLI ran fine by hand. Name the
		// cause instead of emitting an empty reason.
		if cmdCtx.Err() != nil {
			g.logger.Printf("[GOV-PROOF] %s CLI killed by context (%v); own budget %v — "+
				"if this is well under %v the caller's deadline is the real limit",
				level, cmdCtx.Err(), g.timeout, g.timeout)
			return nil, fmt.Errorf(
				"governance proof CLI for %s killed by context expiry (%v); own budget %v — "+
					"the caller's deadline likely does not cover G0+G1+G2 round trips",
				level, cmdCtx.Err(), g.timeout)
		}

		if exitErr, ok := err.(*exec.ExitError); ok {
			// This CLI reports most failures on stdout, not stderr, so fall back to stdout
			// rather than returning an error with no text in it.
			detail := strings.TrimSpace(string(exitErr.Stderr))
			if detail == "" {
				detail = strings.TrimSpace(string(output))
				if len(detail) > 800 {
					detail = "..." + detail[len(detail)-800:]
				}
			}
			if detail == "" {
				detail = fmt.Sprintf("exit status %d with no output on stdout or stderr", exitErr.ExitCode())
			}
			g.logger.Printf("[GOV-PROOF] %s CLI failed: %s", level, detail)
			return nil, fmt.Errorf("governance proof CLI for %s failed: %s", level, detail)
		}
		return nil, fmt.Errorf("governance proof CLI for %s error: %w", level, err)
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

	// Give the CLI our budget rather than letting it use its own 30s default.
	//
	// The CLI applies --timeout to the WHOLE proof operation, not per request, and G1 makes
	// many sequential v3 round trips (~1-3s each against the Kermit endpoint). At the 30s
	// default it ran out mid-flight, and its failure mode is silent: signatureSet extraction
	// returns a context error, the "direct extraction" fallback is an unimplemented stub that
	// returns EMPTY, and the run then reports "Threshold not satisfied: 0/1" — an
	// infrastructure timeout wearing the costume of a governance rejection.
	//
	// Leave a small margin under our own deadline so the CLI reaches its internal timeout and
	// reports a real reason, instead of being SIGKILLed by exec.CommandContext with empty
	// stderr and no explanation at all.
	cliBudget := int((g.timeout - 5*time.Second).Seconds())
	if cliBudget < 30 {
		cliBudget = 30
	}
	args = append(args, "--timeout", fmt.Sprintf("%d", cliBudget))

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

	// STAGE 2 — keep the merkle path the hashed structs are not allowed to hold.
	//
	// The CLI already emits receipt.entries (ExtractReceiptFromChainEntry
	// captures it), and the unmarshal above drops it on the floor: GovReceiptData
	// has no Entries field and MUST NOT gain one, because it sits inside the
	// G0/G1/G2 canonical hash. So the raw JSON is read a SECOND time, for that
	// one field, into a type no hash can reach.
	//
	// A side read on purpose: the hashed structs are parsed exactly as before and
	// nothing in this pass can influence what they contain.
	// PHASE 8 ITEM 2 - the timing basis, kept the same way and for the same
	// reason. The CLI emits a top-level "timingBasis" array; the unmarshal above
	// drops it because G1Result has no such field and MUST NOT gain one, since
	// it sits inside the govRoot preimage. A second side read keeps it in a type
	// no hash can reach.
	//
	// G0 is skipped: a G0 result records that the transaction executed and
	// evaluates no signatures, so it has no timing claim to qualify.
	if level != GovLevelG0 {
		if tb := TimingBasisFromRaw(string(level), jsonData); len(tb) > 0 {
			govProof.TimingBasis = append(govProof.TimingBasis, tb...)
			if weak := WeakenedTimingBasis(tb); len(weak) > 0 {
				g.logger.Printf("[GOV-PROOF] %s timing basis: %d of %d counted signature(s) are "+
					"CROSS-PARTITION - their ordering rests on execution inclusion, not on a local "+
					"block comparison (first: %s on %s vs principal on %s)",
					level, len(weak), len(tb), truncHex(weak[0].MessageHash),
					weak[0].SignerPartition, weak[0].PrincipalPartition)
			} else {
				g.logger.Printf("[GOV-PROOF] %s timing basis: all %d counted signature(s) locally "+
					"ordered against execMBI on one partition", level, len(tb))
			}
		} else {
			// Not loud like the receipt case: a govproof build predating this
			// evidence produces exactly this, and the absence is recorded rather
			// than filled in. It must not read as "all locally ordered".
			g.logger.Printf("[GOV-PROOF] %s carries NO timing basis - which signatures rest on "+
				"execution inclusion is NOT recorded for this proof", level)
		}
	}

	if ev := GovReceiptEvidenceFromRaw(string(level), jsonData); ev != nil {
		govProof.Receipts = append(govProof.Receipts, *ev)
		g.logger.Printf("[GOV-PROOF] %s receipt evidence captured: %d merkle step(s), anchor=%s",
			level, len(ev.Entries), truncHex(ev.Anchor))
	} else {
		// Loud, because this is the difference between a proof that can be
		// recomputed from storage and one that can only be read. A govproof build
		// predating receipt.entries produces exactly this.
		g.logger.Printf("[GOV-PROOF] %s carries NO receipt merkle path — this level will be stored "+
			"summary-only and cannot be recomputed from storage", level)
	}

	return govProof, nil
}
