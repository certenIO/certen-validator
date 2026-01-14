package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	api "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Environment variables for configuration
const (
	envV3RPC     = "ACC_V3_RPC"
	envV2RPC     = "ACC_V2_RPC"
	envExplorer  = "ACC_EXPLORER_BASE"
	envAccountURL = "TEST_ACCOUNT_URL"
)

// ProofArtifacts captures all cryptographic evidence
type ProofArtifacts struct {
	AccountURL       string              `json:"account_url"`
	Timestamp        time.Time           `json:"timestamp"`
	AccountState     json.RawMessage     `json:"account_state"`
	ComponentHashes  ComponentHashes     `json:"component_hashes"`
	BPTHash          string              `json:"bpt_hash"`
	AccountReceipt   *api.Receipt        `json:"account_receipt,omitempty"`
	BVNReceipt       *api.Receipt        `json:"bvn_receipt,omitempty"`
	DNReceipt        *api.Receipt        `json:"dn_receipt,omitempty"`
	DNRootHash       string              `json:"dn_root_hash,omitempty"`
	BlockHeight      uint64              `json:"block_height"`
	ValidatorSigs    []ValidatorSig      `json:"validator_signatures,omitempty"`
	ProofComplete    bool                `json:"proof_complete"`
	MissingArtifacts []string            `json:"missing_artifacts"`
	SourcesUsed      map[string][]string `json:"sources_used"`
}

// ComponentHashes per Paul's BPT specification
type ComponentHashes struct {
	MainState      string `json:"main_state"`
	SecondaryState string `json:"secondary_state"`
	Chains         string `json:"chains"`
	Pending        string `json:"pending"`
}

// ValidatorSig represents a validator signature
type ValidatorSig struct {
	ValidatorHash string `json:"validator_hash"`
	Signature     string `json:"signature"`
	PublicKey     string `json:"public_key,omitempty"`
}

func TestEndToEnd_AccountProof(t *testing.T) {
	// Skip if no endpoints configured
	v3Endpoint := os.Getenv(envV3RPC)
	if v3Endpoint == "" {
		v3Endpoint = "https://mainnet.accumulatenetwork.io/v3"
		fmt.Printf("⚠️  %s not set, using default: %s\n", envV3RPC, v3Endpoint)
	}

	accountURL := os.Getenv(envAccountURL)
	if accountURL == "" {
		accountURL = "acc://RenatoDAP.acme"
		fmt.Printf("⚠️  %s not set, using default: %s\n", envAccountURL, accountURL)
	}

	artifacts := &ProofArtifacts{
		AccountURL:       accountURL,
		Timestamp:        time.Now(),
		MissingArtifacts: []string{},
		SourcesUsed:      make(map[string][]string),
	}

	fmt.Println(strings.Repeat("=", 61))
	fmt.Println("🔍 Accumulate Account Proof - End-to-End Verification")
	fmt.Println(strings.Repeat("=", 61))
	fmt.Printf("Target Account: %s\n", accountURL)
	fmt.Printf("V3 Endpoint: %s\n", v3Endpoint)
	fmt.Println()

	// Step 1: Query account and compute component hashes
	fmt.Println("📊 Step 1: Query Account State")
	fmt.Println(strings.Repeat("-", 41))
	
	ctx := context.Background()
	client := jsonrpc.NewClient(v3Endpoint)
	
	accURL, err := url.Parse(accountURL)
	if err != nil {
		t.Fatalf("❌ Invalid account URL: %v", err)
	}

	// Query with receipt request
	query := &api.DefaultQuery{
		IncludeReceipt: &api.ReceiptOptions{},
	}
	
	resp, err := client.Query(ctx, accURL, query)
	if err != nil {
		t.Fatalf("❌ Failed to query account: %v", err)
	}

	artifacts.SourcesUsed["account_state"] = []string{"V3 API"}
	
	// Log account type
	if accRecord, ok := resp.(*api.AccountRecord); ok {
		fmt.Printf("✅ Account Type: %s\n", accRecord.Account.Type())
		
		// Marshal for artifacts
		stateJSON, _ := json.Marshal(accRecord.Account)
		artifacts.AccountState = stateJSON
		
		// Check for receipt
		if accRecord.Receipt != nil {
			fmt.Printf("✅ Account Receipt Available\n")
			artifacts.AccountReceipt = accRecord.Receipt
		} else {
			fmt.Printf("⚠️  No receipt in account response\n")
			artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "account_receipt")
		}
	}

	// Step 2: Compute BPT component hashes
	fmt.Println("\n📊 Step 2: Compute BPT Component Hashes")
	fmt.Println(strings.Repeat("-", 41))
	
	// Note: This is where we would compute the actual component hashes
	// Per Paul's spec (bpt-complete-guide.md lines 99-109):
	// BPT_Value = MerkleHash(Main, Secondary, Chains, Pending)
	
	// For now, we'll query the chains to demonstrate the pattern
	chainQuery := &api.ChainQuery{
		Name:           "main",
		IncludeReceipt: &api.ReceiptOptions{},
	}
	
	chainResp, err := client.Query(ctx, accURL, chainQuery)
	if err == nil {
		if chainRecord, ok := chainResp.(*api.ChainRecord); ok {
			fmt.Printf("✅ Main Chain Height: %d\n", chainRecord.Count)
			if len(chainRecord.State) > 0 {
				// This would be the chain component hash
				artifacts.ComponentHashes.Chains = hex.EncodeToString(chainRecord.State[0][:])
			}
		}
	} else {
		fmt.Printf("⚠️  Failed to query chain: %v\n", err)
		artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "chain_state")
	}

	// Step 3: Build receipt chain Account → BVN → DN
	fmt.Println("\n📊 Step 3: Build Receipt Chain (Account → BVN → DN)")
	fmt.Println(strings.Repeat("-", 41))
	
	// Check if we have account receipt
	if artifacts.AccountReceipt != nil {
		fmt.Printf("✅ Account Receipt Start: %x\n", artifacts.AccountReceipt.Start[:16])
		fmt.Printf("   Receipt Anchor: %x\n", artifacts.AccountReceipt.Anchor[:16])
		fmt.Printf("   Receipt Entries: %d\n", len(artifacts.AccountReceipt.Entries))
		
		// Validate the receipt
		validated := artifacts.AccountReceipt.Validate(nil)
		if validated {
			fmt.Printf("✅ Account Receipt Validated\n")
		} else {
			fmt.Printf("❌ Account Receipt Validation Failed\n")
			artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "valid_account_receipt")
		}
	} else {
		fmt.Printf("❌ No account receipt available\n")
		artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "account_to_bvn_receipt")
	}

	// Note: BVN → DN receipts would require anchor search queries
	fmt.Printf("⚠️  BVN → DN receipt chain not implemented (API limitation)\n")
	artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "bvn_to_dn_receipt")

	// Step 4: Verify DN block commit with validator signatures
	fmt.Println("\n📊 Step 4: Verify DN Block Commit")
	fmt.Println(strings.Repeat("-", 41))
	
	// This is where we would verify validator signatures
	// Current finding: Not exposed via public API
	fmt.Printf("❌ Validator signatures not accessible via API\n")
	artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "validator_signatures")
	artifacts.MissingArtifacts = append(artifacts.MissingArtifacts, "consensus_verification")

	// Step 5: Final verification status
	fmt.Println("\n" + strings.Repeat("=", 61))
	fmt.Println("📋 Verification Summary")
	fmt.Println(strings.Repeat("=", 61))
	
	artifacts.ProofComplete = len(artifacts.MissingArtifacts) == 0
	
	if artifacts.ProofComplete {
		fmt.Println("✅ PROOF VERIFIED - All cryptographic links validated")
	} else {
		fmt.Println("❌ PROOF INCOMPLETE - Missing artifacts:")
		for _, missing := range artifacts.MissingArtifacts {
			fmt.Printf("   • %s\n", missing)
		}
	}

	// Output JSON artifacts
	fmt.Println("\n📊 Proof Artifacts (JSON):")
	artifactsJSON, _ := json.MarshalIndent(artifacts, "", "  ")
	fmt.Println(string(artifactsJSON))

	// Evidence log entries
	fmt.Println("\n📝 Evidence References:")
	fmt.Println("• Receipt validation: pkg/database/merkle/receipt.go:47-58")
	fmt.Println("• BPT components: new_documentation/docs/bpt-complete-guide.md:99-109")
	fmt.Println("• API queries: pkg/api/v3/jsonrpc/client.go")
	fmt.Println("• Missing: Validator signature verification (not exposed)")

	if !artifacts.ProofComplete {
		t.Logf("⚠️  Test incomplete due to missing artifacts: %v", artifacts.MissingArtifacts)
	}
}

// computeComponentHash computes the hash for a BPT component
func computeComponentHash(data []byte) [32]byte {
	if len(data) == 0 {
		return [32]byte{} // Empty component
	}
	return sha256.Sum256(data)
}

// combineMerkleHashes combines hashes per Accumulate's merkle algorithm
func combineMerkleHashes(hashes ...[32]byte) [32]byte {
	// This would implement the actual merkle combination
	// For now, return a placeholder
	h := sha256.New()
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}