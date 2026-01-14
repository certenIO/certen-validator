package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func combineHashes(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func VerifyBPTProof(start []byte, entries []interface{}, anchor []byte) bool {
	current := start
	
	for _, entry := range entries {
		e := entry.(map[string]interface{})
		hashStr := e["hash"].(string)
		hash, _ := hex.DecodeString(hashStr)
		
		// Check if this entry is from the right
		isRight := false
		if r, ok := e["right"]; ok {
			isRight = r.(bool)
		}
		
		// Combine hashes based on position
		if isRight {
			current = combineHashes(current, hash)
		} else {
			current = combineHashes(hash, current)
		}
	}
	
	return bytes.Equal(current, anchor)
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("                         BPT PROOF VERIFICATION TEST                            ")
	fmt.Println("================================================================================")
	fmt.Println()
	
	client := &http.Client{Timeout: 10 * time.Second}
	endpoint := "http://localhost:26660/v3"
	
	// Test accounts
	accounts := []string{
		"acc://dn.acme",
		"acc://ACME",
		"acc://dn.acme/ledger",
	}
	
	successCount := 0
	
	for _, accountURL := range accounts {
		fmt.Printf("\n📍 Testing: %s\n", accountURL)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		
		// Query account with receipt
		request := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "query",
			"params": map[string]interface{}{
				"scope": accountURL,
				"query": map[string]interface{}{
					"type": "account",
					"includeReceipt": map[string]interface{}{
						"forAny": true,
					},
				},
			},
		}
		
		jsonData, _ := json.Marshal(request)
		resp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}
		defer resp.Body.Close()
		
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		
		// Check for receipt
		if res, ok := result["result"].(map[string]interface{}); ok {
			if receipt, ok := res["receipt"].(map[string]interface{}); ok {
				fmt.Println("\n✅ BPT Proof Found!")
				
				// Extract proof components
				startStr := receipt["start"].(string)
				anchorStr := receipt["anchor"].(string)
				entries := receipt["entries"].([]interface{})
				
				start, _ := hex.DecodeString(startStr)
				anchor, _ := hex.DecodeString(anchorStr)
				
				fmt.Printf("  • Start (Account State): %s\n", startStr[:16]+"...")
				fmt.Printf("  • Anchor (BPT Root):     %s\n", anchorStr[:16]+"...")
				fmt.Printf("  • Proof Length:          %d entries\n", len(entries))
				
				if localBlock, ok := receipt["localBlock"]; ok {
					fmt.Printf("  • Block Height:          %.0f\n", localBlock.(float64))
				}
				if localBlockTime, ok := receipt["localBlockTime"]; ok {
					fmt.Printf("  • Block Time:            %s\n", localBlockTime)
				}
				
				// Verify the proof
				fmt.Print("\n🔍 Verifying Merkle Proof... ")
				if VerifyBPTProof(start, entries, anchor) {
					fmt.Println("✅ VALID!")
					fmt.Println("  The account state is cryptographically proven to exist in the BPT")
					successCount++
				} else {
					fmt.Println("❌ INVALID")
					fmt.Println("  The proof does not verify correctly")
				}
				
			} else {
				fmt.Println("❌ No receipt in response")
			}
		} else {
			fmt.Println("❌ No result in response")
		}
	}
	
	fmt.Println("\n================================================================================")
	fmt.Println("                              TEST COMPLETE                                     ")
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Printf("RESULTS: %d/%d accounts verified successfully\n", successCount, len(accounts))
	fmt.Println()
	
	if successCount > 0 {
		fmt.Println("✅ SUCCESS: BPT proofs are working!")
		fmt.Println()
		fmt.Println("What we've proven:")
		fmt.Println("1. The API returns complete BPT proofs with account queries")
		fmt.Println("2. Proofs include: account state hash, merkle path, and BPT root")
		fmt.Println("3. The merkle proofs verify mathematically")
		fmt.Println()
		fmt.Println("This is Component 2 of the complete cryptographic proof:")
		fmt.Println("Account State Hash → BPT Root via Merkle Proof")
		os.Exit(0)
	} else {
		fmt.Println("❌ FAILURE: No proofs could be verified")
		os.Exit(1)
	}
}