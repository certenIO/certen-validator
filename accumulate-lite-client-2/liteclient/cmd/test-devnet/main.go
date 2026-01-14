package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production"
)

func main() {
	var (
		endpoint   = flag.String("endpoint", "http://localhost:8080", "Devnet API endpoint base URL")
		accountURL = flag.String("account", "acc://test1.acme", "Account URL to test")
		checkOnly  = flag.Bool("check", false, "Only check observer status")
		output     = flag.String("output", "", "Save proof result to JSON file")
		timeout    = flag.Duration("timeout", 30*time.Second, "Request timeout")
	)
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║        DEVNET CRYPTOGRAPHIC PROOF TEST              ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("\nEndpoint: %s\n", *endpoint)
	fmt.Printf("Account:  %s\n", *accountURL)
	fmt.Println("\n" + repeatStr("─", 58))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Create devnet proof client
	client := production.NewDevnetProof(*endpoint)

	// Check observer status first
	observerEnabled, err := client.TestObserverStatus(ctx)
	if err != nil {
		log.Printf("Failed to check observer status: %v", err)
	}

	if *checkOnly {
		os.Exit(0)
	}

	fmt.Println("\n" + repeatStr("─", 58))

	// Generate full proof
	result, err := client.GenerateFullProof(ctx, *accountURL)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}

	// Display summary
	fmt.Println("\n" + repeatStr("═", 58))
	fmt.Println("                    PROOF SUMMARY")
	fmt.Println(repeatStr("═", 58))
	
	fmt.Printf("\n%-20s %s\n", "Observer Enabled:", formatBool(observerEnabled))
	fmt.Printf("%-20s %s\n", "Proof Complete:", formatBool(result.Complete))
	
	fmt.Println("\nSteps Completed:")
	fmt.Printf("  Step 1 (BPT Hash):    %s\n", formatStep(result.Step1BPTHash != ""))
	fmt.Printf("  Step 2 (BPT Lookup):  %s\n", formatStep(result.Step2BPTLookup != nil && result.Step2BPTLookup.Found))
	fmt.Printf("  Step 3 (BVN Receipt): %s\n", formatStep(result.Step3BVNReceipt != nil))
	fmt.Printf("  Step 4 (DN Anchor):   %s\n", formatStep(result.Step4DNAnchor != nil))
	fmt.Printf("  Step 5 (Consensus):   %s\n", formatStep(result.Step5Consensus != nil && result.Step5Consensus.Threshold))

	if len(result.Errors) > 0 {
		fmt.Println("\n⚠️  Issues Encountered:")
		for _, err := range result.Errors {
			fmt.Printf("  • %s\n", err)
		}
	}

	// Save to file if requested
	if *output != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal result: %v", err)
		} else if err := os.WriteFile(*output, data, 0644); err != nil {
			log.Printf("Failed to write output file: %v", err)
		} else {
			fmt.Printf("\n💾 Proof saved to: %s\n", *output)
		}
	}

	// Provide next steps based on results
	fmt.Println("\n" + repeatStr("─", 58))
	fmt.Println("NEXT STEPS:")
	
	if !observerEnabled {
		fmt.Println("1. Enable observer in your Accumulate API config:")
		fmt.Println("   - Set EnableObserver: true in API configuration")
		fmt.Println("   - Restart devnet")
		fmt.Println("2. Re-run this test")
	} else if !result.Complete {
		fmt.Println("1. Check which API endpoints are missing")
		fmt.Println("2. Implement missing endpoints in Accumulate repo:")
		if result.Step2BPTLookup == nil {
			fmt.Println("   - QueryDirectory for BPT lookups")
		}
		if result.Step4DNAnchor == nil {
			fmt.Println("   - Anchor chain access endpoints")
		}
		if result.Step5Consensus == nil {
			fmt.Println("   - Validator consensus endpoints")
		}
	} else {
		fmt.Println("✅ Full cryptographic proof successful!")
		fmt.Println("   The devnet API modifications are working correctly.")
	}
	
	fmt.Println(repeatStr("═", 58))
}

func formatBool(b bool) string {
	if b {
		return "✅ Yes"
	}
	return "❌ No"
}

func formatStep(completed bool) string {
	if completed {
		return "✅ Complete"
	}
	return "❌ Incomplete"
}

func repeatStr(s string, n int) string {
	return strings.Repeat(s, n)
}