// Copyright 2025 Certen Protocol
//
// txhash - Compute Accumulate transaction hash from JSON
//
// This tool computes the canonical transaction hash from a transaction's JSON
// representation. It uses Accumulate's official protocol package to ensure
// the hash computation matches the blockchain exactly.
//
// Usage:
//   echo '{"header": {...}, "body": {...}}' | ./txhash
//
// Output:
//   hash=<64-char-hex>

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func main() {
	// Read JSON from stdin
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		os.Exit(1)
	}

	// Try to parse as full message wrapper first (from API response)
	var wrapper struct {
		Message struct {
			Transaction *protocol.Transaction `json:"transaction"`
		} `json:"message"`
		Transaction *protocol.Transaction `json:"transaction"`
	}

	if err := json.Unmarshal(input, &wrapper); err == nil {
		// Check if we got transaction from message.transaction path
		if wrapper.Message.Transaction != nil {
			hash := wrapper.Message.Transaction.GetHash()
			fmt.Printf("hash=%s\n", hex.EncodeToString(hash))
			return
		}
		// Check if we got transaction from direct transaction path
		if wrapper.Transaction != nil {
			hash := wrapper.Transaction.GetHash()
			fmt.Printf("hash=%s\n", hex.EncodeToString(hash))
			return
		}
	}

	// Try to parse as direct Transaction object
	var tx protocol.Transaction
	if err := json.Unmarshal(input, &tx); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing transaction JSON: %v\n", err)
		fmt.Fprintf(os.Stderr, "input was: %s\n", string(input[:min(len(input), 200)]))
		os.Exit(1)
	}

	// Validate that we have required fields
	if tx.Header.Principal == nil {
		fmt.Fprintf(os.Stderr, "error: transaction header missing principal\n")
		os.Exit(1)
	}
	if tx.Body == nil {
		fmt.Fprintf(os.Stderr, "error: transaction missing body\n")
		os.Exit(1)
	}

	// Compute hash
	hash := tx.GetHash()

	// Output in expected format
	fmt.Printf("hash=%s\n", hex.EncodeToString(hash))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
