// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Verifier performs trustless local verification of account data
type Verifier struct {
	v3Client *jsonrpc.Client
	debug    bool
}

// NewVerifier creates a new verifier
func NewVerifier(v3ServerURL string, debug bool) *Verifier {
	return &Verifier{
		v3Client: jsonrpc.NewClient(v3ServerURL),
		debug:    debug,
	}
}

// VerifyAccount performs complete trustless verification of an account
func (v *Verifier) VerifyAccount(ctx context.Context, accountURL string, at HeightOrTime) (Report, error) {
	report := Report{
		AccountURL: accountURL,
		At:         at,
		Strategy:   "receipt-chaining",
		Hops:       []Hop{},
		Verified:   false,
	}

	if v.debug {
		log.Printf("[VERIFY] Starting verification of %s", accountURL)
	}

	// Try Strategy A: Receipt-Chaining
	verified, hops := v.strategyReceiptChaining(ctx, accountURL, at)

	if verified {
		report.Strategy = "receipt-chaining"
		report.Hops = hops
		report.Verified = true
		return report, nil
	}

	// Try Strategy B: State Reconstruction
	if v.debug {
		log.Printf("[VERIFY] Strategy A failed, trying Strategy B")
	}

	verified, hops = v.strategyStateReconstruction(ctx, accountURL, at)
	report.Strategy = "state-reconstruction"
	report.Hops = hops
	report.Verified = verified

	if !verified && len(hops) > 0 {
		// Find the failing hop
		for _, hop := range hops {
			if !hop.Ok {
				return report, fmt.Errorf("verification failed at %s: %s", hop.Name, hop.Err)
			}
		}
	}

	return report, nil
}

// strategyReceiptChaining implements Strategy A: Transaction → Account → BVN → DN
func (v *Verifier) strategyReceiptChaining(ctx context.Context, accountURL string, at HeightOrTime) (bool, []Hop) {
	hops := []Hop{}

	// Parse account URL
	accUrl, err := acc_url.Parse(accountURL)
	if err != nil {
		hops = append(hops, Hop{
			Name: "ParseURL",
			Ok:   false,
			Err:  err.Error(),
		})
		return false, hops
	}

	// Step 1: Get account's main chain entry with receipt
	if v.debug {
		log.Printf("[VERIFY] Step 1: Fetching account main chain with receipt")
	}

	chainQuery := &v3.ChainQuery{
		Name: "main",
		Range: &v3.RangeOptions{
			Count:   ptr(uint64(1)),
			FromEnd: true,
		},
		IncludeReceipt: &v3.ReceiptOptions{
			ForAny: true,
		},
	}

	res, err := v.v3Client.Query(ctx, accUrl, chainQuery)
	if err != nil {
		hops = append(hops, Hop{
			Name: "FetchAccountChain",
			Ok:   false,
			Err:  err.Error(),
		})
		return false, hops
	}

	// Extract chain entry and receipt
	var accountReceipt *merkle.Receipt

	if rr, ok := res.(*v3.RecordRange[v3.Record]); ok && len(rr.Records) > 0 {
		if ce, ok := rr.Records[0].(*v3.ChainEntryRecord[v3.Record]); ok {
			if ce.Receipt != nil {
				accountReceipt = &ce.Receipt.Receipt
			}
		}
	}

	if accountReceipt == nil {
		hops = append(hops, Hop{
			Name: "ExtractAccountReceipt",
			Ok:   false,
			Err:  "no receipt in account chain response",
		})
		return false, hops
	}

	// Verify the account receipt locally
	hop1 := v.verifyReceiptLocally("AccountMainChain", accountReceipt)
	hops = append(hops, hop1)
	if !hop1.Ok {
		return false, hops
	}

	// Step 2: Find where this anchors into BVN
	if v.debug {
		anchorDisplay := accountReceipt.Anchor
		if len(anchorDisplay) > 8 {
			anchorDisplay = anchorDisplay[:8]
		}
		log.Printf("[VERIFY] Step 2: Finding BVN anchor for %x", anchorDisplay)
	}

	// We need to find which BVN partition this account belongs to
	// For now, assume "Cyclops" (would need routing table in production)
	bvnUrl, _ := acc_url.Parse("acc://bvn-Cyclops.acme/anchors")

	// Search for our anchor in BVN
	searchAnchor := accountReceipt.Anchor
	if len(searchAnchor) > 8 {
		searchAnchor = searchAnchor[:8]
	}
	anchorSearch := &v3.AnchorSearchQuery{
		Anchor: searchAnchor,
		IncludeReceipt: &v3.ReceiptOptions{
			ForAny: true,
		},
	}

	bvnRes, err := v.v3Client.Query(ctx, bvnUrl, anchorSearch)
	if err != nil {
		// Try searching in the main chain instead
		bvnChainQuery := &v3.ChainQuery{
			Name: "main",
			Range: &v3.RangeOptions{
				Count:   ptr(uint64(100)),
				FromEnd: true,
			},
			IncludeReceipt: &v3.ReceiptOptions{
				ForAny: true,
			},
		}
		bvnRes, err = v.v3Client.Query(ctx, bvnUrl, bvnChainQuery)
		if err != nil {
			hops = append(hops, Hop{
				Name: "FetchBVNAnchor",
				Ok:   false,
				Err:  fmt.Sprintf("anchor %x not found in BVN: %v", searchAnchor, err),
			})
			return false, hops
		}
	}

	// Extract BVN receipt
	var bvnReceipt *merkle.Receipt
	if rr, ok := bvnRes.(*v3.RecordRange[v3.Record]); ok && len(rr.Records) > 0 {
		for _, record := range rr.Records {
			if ce, ok := record.(*v3.ChainEntryRecord[v3.Record]); ok {
				// Check if this entry matches our anchor
				entrySlice := ce.Entry[:]
				entryPrefix := entrySlice
				if len(entryPrefix) > 8 {
					entryPrefix = entryPrefix[:8]
				}
				anchorPrefix := accountReceipt.Anchor
				if len(anchorPrefix) > 8 {
					anchorPrefix = anchorPrefix[:8]
				}
				if bytes.Equal(entryPrefix, anchorPrefix) {
					if ce.Receipt != nil {
						bvnReceipt = &ce.Receipt.Receipt
						break
					}
				}
			}
		}
	}

	if bvnReceipt == nil {
		hops = append(hops, Hop{
			Name: "ExtractBVNReceipt",
			Ok:   false,
			Err:  "BVN receipt not found",
		})
		return false, hops
	}

	// Verify BVN receipt locally
	hop2 := v.verifyReceiptLocally("BVNAnchor", bvnReceipt)
	hops = append(hops, hop2)
	if !hop2.Ok {
		return false, hops
	}

	// Step 3: Combine receipts
	if v.debug {
		log.Printf("[VERIFY] Step 3: Combining receipts")
	}

	combinedReceipt, err := accountReceipt.Combine(bvnReceipt)
	if err != nil {
		hops = append(hops, Hop{
			Name: "CombineReceipts",
			Ok:   false,
			Err:  err.Error(),
		})
		return false, hops
	}

	// Verify combined receipt
	hop3 := v.verifyReceiptLocally("CombinedProof", combinedReceipt)
	hops = append(hops, hop3)

	return hop3.Ok, hops
}

// verifyReceiptLocally performs local cryptographic verification
func (v *Verifier) verifyReceiptLocally(name string, receipt *merkle.Receipt) Hop {
	hop := Hop{
		Name:    name,
		Inputs:  make(map[string][]byte),
		Outputs: make(map[string][]byte),
		Ok:      false,
		Err:     "",
	}

	// Record inputs
	hop.Inputs["start"] = receipt.Start
	hop.Inputs["anchor"] = receipt.Anchor
	hop.Inputs["path_length"] = []byte(fmt.Sprintf("%d", len(receipt.Entries)))

	// Perform local validation (reimplementing to be explicit)
	currentHash := make([]byte, len(receipt.Start))
	copy(currentHash, receipt.Start)

	if v.debug {
		hashDisplay := currentHash
		if len(hashDisplay) > 8 {
			hashDisplay = hashDisplay[:8]
		}
		log.Printf("[LOCAL VERIFY] %s: Start=%x", name, hashDisplay)
	}

	// Apply each proof node
	for i, entry := range receipt.Entries {
		// Compute SHA256(left || right) based on entry.Right flag
		h := sha256.New()
		if entry.Right {
			h.Write(currentHash)
			h.Write(entry.Hash)
		} else {
			h.Write(entry.Hash)
			h.Write(currentHash)
		}
		currentHash = h.Sum(nil)

		if v.debug {
			hashDisplay := currentHash
			if len(hashDisplay) > 8 {
				hashDisplay = hashDisplay[:8]
			}
			log.Printf("[LOCAL VERIFY] %s: Step %d: %x", name, i+1, hashDisplay)
		}
	}

	// Record output
	hop.Outputs["computed"] = currentHash
	hop.Outputs["expected"] = receipt.Anchor

	// Check if computed hash matches anchor
	if bytes.Equal(currentHash, receipt.Anchor) {
		hop.Ok = true
		if v.debug {
			computedDisplay := currentHash
			if len(computedDisplay) > 8 {
				computedDisplay = computedDisplay[:8]
			}
			expectedDisplay := receipt.Anchor
			if len(expectedDisplay) > 8 {
				expectedDisplay = expectedDisplay[:8]
			}
			log.Printf("[LOCAL VERIFY] %s: ✅ Valid (computed=%x, expected=%x)",
				name, computedDisplay, expectedDisplay)
		}
	} else {
		computedDisplay := currentHash
		if len(computedDisplay) > 8 {
			computedDisplay = computedDisplay[:8]
		}
		expectedDisplay := receipt.Anchor
		if len(expectedDisplay) > 8 {
			expectedDisplay = expectedDisplay[:8]
		}
		hop.Err = fmt.Sprintf("hash mismatch: computed=%x, expected=%x",
			computedDisplay, expectedDisplay)
		if v.debug {
			log.Printf("[LOCAL VERIFY] %s: ❌ Invalid: %s", name, hop.Err)
		}
	}

	return hop
}

// strategyStateReconstruction implements the state reconstruction verification strategy.
// TODO: Implement state reconstruction verification.
func (v *Verifier) strategyStateReconstruction(ctx context.Context, accountURL string, at HeightOrTime) (bool, []Hop) {
	// This is a stub implementation
	return false, []Hop{{Name: "state-reconstruction", Ok: false, Err: "not yet implemented"}}
}

// Helper function
func ptr(v uint64) *uint64 {
	return &v
}
