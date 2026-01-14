// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifier

import (
	"time"
)

// HeightOrTime specifies when to verify account state
type HeightOrTime struct {
	Height uint64
	Time   time.Time
	Mode   string // "latest"|"height"|"time"
}

// Hop represents a single verification step in the proof chain
type Hop struct {
	Name    string            // e.g., "TxReceipt", "AccountMainChain", "BVNAnchor", "DNAnchor"
	Inputs  map[string][]byte // Input hashes
	Outputs map[string][]byte // Output hashes after verification
	Ok      bool              // Verification passed
	Err     string            // Error message if failed
}

// Report contains the complete verification result
type Report struct {
	AccountURL string       // Account being verified
	At         HeightOrTime // When the verification was performed
	Strategy   string       // Strategy used (e.g., "receipt-chaining")
	Hops       []Hop        // All verification steps
	Verified   bool         // Overall verification result
}

// ReceiptData wraps receipt with metadata
type ReceiptData struct {
	Receipt   []byte // Serialized receipt
	Start     []byte // Starting hash
	Anchor    []byte // Anchor hash
	ChainName string // Chain this came from
	Index     uint64 // Entry index
}
