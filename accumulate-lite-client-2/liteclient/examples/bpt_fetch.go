package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	v2api "gitlab.com/accumulatenetwork/accumulate/pkg/client/api/v2"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

func main() {
	var (
		partition = flag.String("partition", "bvn-cyclops", "Partition name (e.g., bvn-cyclops, dn)")
		height    = flag.String("height", "latest", "Block height (latest or number)")
		apiVer    = flag.String("api", "v3", "API version (v2 or v3)")
		server    = flag.String("server", "https://mainnet.accumulatenetwork.io", "Accumulate server URL")
	)
	flag.Parse()

	fmt.Printf("╔══════════════════════════════════════════╗\n")
	fmt.Printf("║         BPT STATE ROOT FETCHER           ║\n")
	fmt.Printf("╚══════════════════════════════════════════╝\n\n")

	fmt.Printf("Partition: %s\n", *partition)
	fmt.Printf("Height: %s\n", *height)
	fmt.Printf("API: %s\n", *apiVer)
	fmt.Printf("Server: %s\n\n", *server)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch *apiVer {
	case "v2":
		if err := fetchWithV2(ctx, *server, *partition, *height); err != nil {
			log.Fatalf("V2 fetch failed: %v", err)
		}
	case "v3":
		if err := fetchWithV3(ctx, *server, *partition, *height); err != nil {
			log.Fatalf("V3 fetch failed: %v", err)
		}
	default:
		log.Fatalf("Unsupported API version: %s (use v2 or v3)", *apiVer)
	}
}

// fetchWithV2 demonstrates V2 API capabilities and limitations for BPT access
func fetchWithV2(ctx context.Context, server, partition, height string) error {
	fmt.Printf("=== V2 API BPT ANALYSIS ===\n\n")

	client, err := v2api.New(server)
	if err != nil {
		return fmt.Errorf("failed to create v2 client: %w", err)
	}

	// Construct partition URL
	partitionURL := fmt.Sprintf("acc://%s.acme", partition)
	accUrl, err := acc_url.Parse(partitionURL)
	if err != nil {
		return fmt.Errorf("invalid partition URL %s: %w", partitionURL, err)
	}

	fmt.Printf("1. Querying partition ledger: %s\n", partitionURL)

	// Query the partition's main account
	resp, err := client.Query(ctx, &v2api.GeneralQuery{
		UrlQuery: v2api.UrlQuery{Url: accUrl},
	})
	if err != nil {
		return fmt.Errorf("failed to query partition: %w", err)
	}

	// Parse response
	respMap, ok := resp.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected response type: %T", resp)
	}

	// Extract account data
	data, ok := respMap["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no account data in response")
	}

	accountType, _ := data["type"].(string)
	fmt.Printf("   Account Type: %s\n", accountType)

	// Look for main chain information
	if mainChain, ok := respMap["mainChain"].(map[string]interface{}); ok {
		if roots, ok := mainChain["roots"].([]interface{}); ok && len(roots) > 0 {
			fmt.Printf("   Main Chain Roots Found: %d\n", len(roots))
			for i, root := range roots {
				if rootStr, ok := root.(string); ok {
					fmt.Printf("     [%d]: %s\n", i, rootStr)
				}
			}
		} else {
			fmt.Printf("   Main Chain Roots: None found\n")
		}
	}

	fmt.Printf("\n❌ V2 API LIMITATION: No direct BPT/StateRoot access\n")
	fmt.Printf("   - Can query partition accounts and main chains\n")
	fmt.Printf("   - Cannot access StateTreeAnchor (BPT root) directly\n")
	fmt.Printf("   - Would need to query system ledger chains for BPT data\n\n")

	// Try to access system ledger
	fmt.Printf("2. Attempting to query partition ledger system account...\n")
	ledgerURL := fmt.Sprintf("acc://%s.acme/ledger", partition)
	ledgerAccUrl, _ := acc_url.Parse(ledgerURL)

	ledgerResp, err := client.Query(ctx, &v2api.GeneralQuery{
		UrlQuery: v2api.UrlQuery{Url: ledgerAccUrl},
	})
	if err != nil {
		fmt.Printf("   ❌ System ledger not accessible: %v\n\n", err)
	} else {
		fmt.Printf("   ✅ System ledger accessible\n")
		if ledgerMap, ok := ledgerResp.(map[string]interface{}); ok {
			if ledgerData, ok := ledgerMap["data"].(map[string]interface{}); ok {
				ledgerType, _ := ledgerData["type"].(string)
				fmt.Printf("   Ledger Type: %s\n", ledgerType)
				// This would contain the root chain with BPT hashes, but structure is complex
				fmt.Printf("   ⚠️ Root chain parsing requires protocol knowledge\n\n")
			}
		}
	}

	return nil
}

// fetchWithV3 demonstrates V3 API capabilities for BPT access
func fetchWithV3(ctx context.Context, server, partition, height string) error {
	fmt.Printf("=== V3 API BPT ANALYSIS ===\n\n")

	client := jsonrpc.NewClient(server + "/v3")

	// Construct partition URL
	partitionURL := fmt.Sprintf("acc://%s.acme", partition)
	accUrl, err := acc_url.Parse(partitionURL)
	if err != nil {
		return fmt.Errorf("invalid partition URL %s: %w", partitionURL, err)
	}

	fmt.Printf("1. Querying partition for current state: %s\n", partitionURL)

	// Query with default query to get LastBlock info
	resp, err := client.Query(ctx, accUrl, &v3.DefaultQuery{})
	if err != nil {
		return fmt.Errorf("failed to query partition: %w", err)
	}

	// Parse the response to find BPT root
	switch r := resp.(type) {
	case *v3.AccountRecord:
		fmt.Printf("   Account Record Found\n")
		if r.Account != nil {
			fmt.Printf("   Account URL: %s\n", r.Account.GetUrl())
		}

		// Check for directory information in the response
		if r.Directory != nil {
			fmt.Printf("   Directory information found\n")
		}

		// Look for directory information
		if r.Directory != nil {
			fmt.Printf("   Directory Records Found\n")
		}

		// Look for state root in account data
		fmt.Printf("\n2. Searching for BPT Root (StateRoot)...\n")

		// Try to access the state root - this might be in different places
		// depending on the account type and response structure
		fmt.Printf("   ⚠️  StateRoot location varies by account type\n")
		fmt.Printf("   📋 Response type: %T\n", r)

		// For system accounts, we might need to query chains
		if partition != "dn" && partition != "Directory" {
			return tryQueryBVNStateRoot(ctx, client, accUrl)
		}

	default:
		fmt.Printf("   Unexpected response type: %T\n", resp)
		return fmt.Errorf("unexpected response type: %T", resp)
	}

	return nil
}

// tryQueryBVNStateRoot attempts various methods to get the BVN state root
func tryQueryBVNStateRoot(ctx context.Context, client *jsonrpc.Client, partitionUrl *acc_url.URL) error {
	fmt.Printf("\n3. Attempting BVN StateRoot extraction methods...\n")

	// Method 1: Try querying the system ledger directly
	fmt.Printf("   Method 1: Query partition system ledger\n")
	ledgerUrl := partitionUrl.JoinPath("ledger")

	ledgerResp, err := client.Query(ctx, ledgerUrl, &v3.DefaultQuery{})
	if err != nil {
		fmt.Printf("   ❌ System ledger query failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ System ledger accessible\n")
		fmt.Printf("   📋 Ledger response type: %T\n", ledgerResp)

		// Try to find the root chain or state information
		switch lr := ledgerResp.(type) {
		case *v3.AccountRecord:
			fmt.Printf("   🔍 Ledger Account: %s\n", lr.Account.GetUrl())
			// The ledger should have chains like #minor-root
			// But we need chain query to access the actual root data
		}
	}

	// Method 2: Try chain query for the root chain
	fmt.Printf("\n   Method 2: Query partition root chain\n")
	rootResp, err := client.Query(ctx, partitionUrl, &v3.ChainQuery{
		Name:           "minor-root", // System root chain name
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		fmt.Printf("   ❌ Root chain query failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ Root chain accessible\n")
		fmt.Printf("   📋 Root chain response type: %T\n", rootResp)

		// This should contain PartitionAnchor entries with StateTreeAnchor
		switch cr := rootResp.(type) {
		case *v3.ChainEntryRecord[v3.Record]:
			if cr.Value != nil {
				fmt.Printf("   🎯 Chain entry found\n")
				// Try to extract StateTreeAnchor from the entry
				// This would require parsing the PartitionAnchor transaction
				if analyzeChainEntry(cr) {
					return nil // Success!
				}
			}
		case *v3.RecordRange[v3.Record]:
			if len(cr.Records) > 0 {
				fmt.Printf("   🎯 Chain entries found: %d\n", len(cr.Records))
				// Analyze the latest entry for StateTreeAnchor
				for i, record := range cr.Records {
					fmt.Printf("     Entry %d: %T\n", i, record)
					if entry, ok := record.(*v3.ChainEntryRecord[v3.Record]); ok {
						if analyzeChainEntry(entry) {
							return nil // Success!
						}
					}
				}
			}
		}
	}

	fmt.Printf("\n❌ CURRENT V3 API GAPS:\n")
	fmt.Printf("   - No direct StateRoot query endpoint\n")
	fmt.Printf("   - Complex navigation through system chains required\n")
	fmt.Printf("   - StateTreeAnchor parsing needs protocol knowledge\n")
	fmt.Printf("   - Missing: query.partitionStateRoot(height) endpoint\n\n")

	fmt.Printf("✅ WHAT WORKS:\n")
	fmt.Printf("   - Anchor search can find where BPT roots are anchored\n")
	fmt.Printf("   - Chain queries can access system chains\n")
	fmt.Printf("   - Receipt generation works for anchor chains\n\n")

	return fmt.Errorf("StateRoot extraction requires additional V3 API endpoints")
}

// analyzeChainEntry tries to extract BPT root from a chain entry
func analyzeChainEntry(entry *v3.ChainEntryRecord[v3.Record]) bool {
	if entry.Value == nil {
		return false
	}

	// The Value should contain a transaction, likely PartitionAnchor
	// which has StateTreeAnchor field, but we need to parse the transaction
	fmt.Printf("       Chain entry value type: %T\n", entry.Value)

	// For now, just show that we found the entry
	// Full parsing would require transaction decoding
	fmt.Printf("       ⚠️  Transaction parsing required to extract StateTreeAnchor\n")

	return false
}

// Example usage and test cases
func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
