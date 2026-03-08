// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ProofExtractor extracts proof components from API responses
type ProofExtractor struct {
	client *Client
}

// NewProofExtractor creates a new proof extractor
func NewProofExtractor(client *Client) *ProofExtractor {
	return &ProofExtractor{client: client}
}

// ExtractBPTRoot extracts the BPT root from an account proof
func (pe *ProofExtractor) ExtractBPTRoot(receipt *api.Receipt) (string, error) {
	if receipt == nil || receipt.Anchor == nil {
		return "", fmt.Errorf("no anchor in receipt")
	}

	// The Anchor field contains the merkle root hash directly
	return hex.EncodeToString(receipt.Anchor), nil
}

// ExtractBlockInfo extracts block information from a receipt
func (pe *ProofExtractor) ExtractBlockInfo(receipt *api.Receipt) (*BlockInfo, error) {
	if receipt == nil {
		return nil, fmt.Errorf("no receipt")
	}

	return &BlockInfo{
		Index: receipt.LocalBlock,
		Time:  uint64(receipt.LocalBlockTime.Unix()),
	}, nil
}

// BlockInfo contains extracted block information
type BlockInfo struct {
	Index uint64 `json:"index"`
	Time  uint64 `json:"time"`
}

// ValidateAccountURL validates and normalizes an account URL
func ValidateAccountURL(accountStr string) (*url.URL, error) {
	// Clean up the URL string
	accountStr = strings.TrimSpace(accountStr)

	// Handle different URL formats
	if !strings.HasPrefix(accountStr, "acc://") {
		accountStr = "acc://" + accountStr
	}

	// Ensure .acme suffix for identity accounts
	if !strings.Contains(accountStr, "/") && !strings.HasSuffix(accountStr, ".acme") {
		accountStr = accountStr + ".acme"
	}

	// Parse the URL
	accountURL, err := url.Parse(accountStr)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	return accountURL, nil
}

// IsWellKnownAccount checks if an account is well-known (always exists)
func IsWellKnownAccount(accountURL *url.URL) bool {
	wellKnown := []string{
		"acc://dn.acme",
		"acc://dn",
		"acc://bvn0.acme",
		"acc://bvn1.acme",
		"acc://bvn2.acme",
	}

	urlStr := accountURL.String()
	for _, known := range wellKnown {
		if urlStr == known {
			return true
		}
	}

	return false
}

// GetAccountType returns the type of an account
func GetAccountType(account protocol.Account) string {
	switch account.(type) {
	case *protocol.LiteIdentity:
		return "LiteIdentity"
	case *protocol.ADI:
		return "ADI"
	case *protocol.TokenAccount:
		return "TokenAccount"
	case *protocol.DataAccount:
		return "DataAccount"
	case *protocol.KeyBook:
		return "KeyBook"
	case *protocol.KeyPage:
		return "KeyPage"
	default:
		return "Unknown"
	}
}

// CheckAPIFeatures checks which proof-related features the API supports
func CheckAPIFeatures(ctx context.Context, client *Client) (*APIFeatures, error) {
	features := &APIFeatures{}

	// Check if receipts are supported
	testURL := protocol.DnUrl()
	resp, err := client.QueryAccount(ctx, testURL, true)
	if err == nil && resp.Receipt != nil {
		features.Receipts = true
		if resp.Receipt.Anchor != nil {
			features.MerkleProofs = true
		}
		if resp.Receipt.LocalBlock > 0 {
			features.BlockInfo = true
		}
	}

	// Check network status
	_, err = client.GetNetworkStatus(ctx)
	if err == nil {
		features.NetworkStatus = true
		// Validator info not available in current API
		features.ValidatorInfo = false
	}

	return features, nil
}

// APIFeatures describes which proof features are available
type APIFeatures struct {
	Receipts      bool `json:"receipts"`
	MerkleProofs  bool `json:"merkleProofs"`
	BlockInfo     bool `json:"blockInfo"`
	NetworkStatus bool `json:"networkStatus"`
	ValidatorInfo bool `json:"validatorInfo"`
	ConsensusData bool `json:"consensusData"` // Future feature
}
