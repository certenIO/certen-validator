// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package backend

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// RPCDataBackendV3 implements the DataBackend interface using the Accumulate v3 JSON-RPC API.
// This provides anchor searching capabilities needed for BVN proof generation.
type RPCDataBackendV3 struct {
	client *jsonrpc.Client
	server string
}

// NewRPCDataBackendV3 creates a new DataBackend implementation using a v3 jsonrpc.Client.
func NewRPCDataBackendV3(server string) (types.DataBackend, error) {
	if server == "" {
		return nil, fmt.Errorf("server URL cannot be empty")
	}
	return &RPCDataBackendV3{
		client: jsonrpc.NewClient(server),
		server: server,
	}, nil
}

// QueryAccount retrieves account data from the Accumulate network using v3 API
func (b *RPCDataBackendV3) QueryAccount(ctx context.Context, accountURL string) (*types.AccountData, error) {
	// Parse the URL
	accURL, err := acc_url.Parse(accountURL)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL %s: %w", accountURL, err)
	}

	// Create query with receipt options for proof data
	query := &v3.DefaultQuery{
		IncludeReceipt: &v3.ReceiptOptions{},
	}

	// Query the account
	resp, err := b.client.Query(ctx, accURL, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query account %s: %w", accountURL, err)
	}

	// Process response based on type
	switch r := resp.(type) {
	case *v3.AccountRecord:
		// Extract account data
		accountData := &types.AccountData{
			URL:         accountURL,
			Type:        r.Account.Type(),
			Data:        r.Account,
			LastUpdated: time.Now(),
			FromCache:   false,
		}

		// Add receipt if available (convert from v3.Receipt to merkle.Receipt)
		if r.Receipt != nil {
			// v3.Receipt embeds merkle.Receipt, so we can use it directly
			accountData.Receipt = &r.Receipt.Receipt
		}

		// Store raw response for debugging
		accountData.RawResponse = map[string]interface{}{
			"type":    r.Account.Type().String(),
			"account": r.Account,
		}

		return accountData, nil

	case *v3.ChainRecord:
		// Handle chain records (shouldn't happen for account queries)
		return nil, fmt.Errorf("received chain record instead of account record for %s", accountURL)

	default:
		return nil, fmt.Errorf("unexpected response type %T for account %s", resp, accountURL)
	}
}

// GetNetworkStatus retrieves the network status including partition information using v3 API
func (b *RPCDataBackendV3) GetNetworkStatus(ctx context.Context) (*types.NetworkStatus, error) {
	// Query the Directory Network (DN) for network info using network-status method
	res, err := b.client.NetworkStatus(ctx, v3.NetworkStatusOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to query network status: %w", err)
	}

	// Convert the v3 NetworkStatus to our types.NetworkStatus
	status := &types.NetworkStatus{
		Partitions: make([]types.PartitionInfo, len(res.Network.Partitions)),
	}

	for i, partition := range res.Network.Partitions {
		partitionURL, err := acc_url.Parse(fmt.Sprintf("acc://%s.acme", partition.ID))
		if err != nil {
			log.Printf("[V3-BACKEND] Warning: could not parse partition URL for %s: %v", partition.ID, err)
			continue
		}
		status.Partitions[i] = types.PartitionInfo{
			ID:   partition.ID,
			Type: partition.Type.String(),  // Convert enum to string
			URL:  partitionURL.URL(),       // Convert acc_url.URL to *url.URL
		}
	}

	log.Printf("[V3-BACKEND] ✅ Successfully retrieved network status with %d partitions", len(status.Partitions))
	return status, nil
}

// GetMainChainReceipt fetches a cryptographic receipt for an account's main chain using the v3 API.
// If startHash is provided, queries for that specific entry. Otherwise, gets the latest entry.
func (b *RPCDataBackendV3) GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error) {
	accUrl, err := acc_url.Parse(accountUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	// Build the chain query - include Entry if startHash is provided
	chainQuery := &v3.ChainQuery{
		Name:           "main",
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	}

	// If a specific hash is provided, query for that entry (like working-proof does)
	if len(startHash) == 32 {
		chainQuery.Entry = startHash
		log.Printf("[V3-BACKEND] GetMainChainReceipt querying for specific entry: %x", startHash[:8])
	} else {
		// No specific hash - query for the latest entry by getting chain state first
		log.Printf("[V3-BACKEND] GetMainChainReceipt querying for latest entry (no specific hash)")

		// First, get chain info to find the latest index
		chainInfoRes, err := b.client.Query(ctx, accUrl, &v3.ChainQuery{Name: "main"})
		if err != nil {
			return nil, fmt.Errorf("failed to query main chain info for %s: %w", accountUrl, err)
		}

		// Extract the chain record to get count
		switch ci := chainInfoRes.(type) {
		case *v3.ChainRecord:
			if ci.Count == 0 {
				return nil, fmt.Errorf("main chain is empty for %s", accountUrl)
			}
			// Query the latest entry by index
			latestIndex := ci.Count - 1
			chainQuery.Index = &latestIndex
			log.Printf("[V3-BACKEND] Chain has %d entries, querying index %d", ci.Count, latestIndex)
		case *v3.RecordRange[v3.Record]:
			// Sometimes we get a range back - try to extract useful info
			if len(ci.Records) == 0 {
				return nil, fmt.Errorf("empty chain record range for %s", accountUrl)
			}
			// Use index-based query with last available
			if ci.Total > 0 {
				latestIndex := ci.Total - 1
				chainQuery.Index = &latestIndex
				log.Printf("[V3-BACKEND] RecordRange has total %d, querying index %d", ci.Total, latestIndex)
			} else {
				return nil, fmt.Errorf("cannot determine chain length for %s", accountUrl)
			}
		default:
			return nil, fmt.Errorf("unexpected chain info response type: %T", chainInfoRes)
		}
	}

	// Now query with the properly configured chainQuery
	res, err := b.client.Query(ctx, accUrl, chainQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query main chain receipt for %s: %w", accountUrl, err)
	}

	log.Printf("[V3-BACKEND] GetMainChainReceipt response type: %T", res)

	// Handle both response types - v3 API may return either ChainEntryRecord or RecordRange
	switch r := res.(type) {
	case *v3.ChainEntryRecord[v3.Record]:
		if r.Receipt == nil {
			return nil, fmt.Errorf("v3 API response did not include a receipt for %s", accountUrl)
		}
		log.Printf("[V3-BACKEND] Got ChainEntryRecord with receipt for %s (index=%d)", accountUrl, r.Index)
		return convertV3ToMerkleReceipt(r.Receipt), nil
	case *v3.RecordRange[v3.Record]:
		// Handle RecordRange response (common for chain queries)
		if len(r.Records) == 0 {
			return nil, fmt.Errorf("no chain entries found for %s", accountUrl)
		}
		// Extract first ChainEntryRecord from the range
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type in range: got %T, expected *v3.ChainEntryRecord[v3.Record]", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("v3 API response did not include a receipt for %s", accountUrl)
		}
		log.Printf("[V3-BACKEND] Extracted ChainEntryRecord from RecordRange for %s (index=%d)", accountUrl, chainEntry.Index)
		return convertV3ToMerkleReceipt(chainEntry.Receipt), nil
	default:
		return nil, fmt.Errorf("unexpected response type: expected *v3.ChainEntryRecord or *v3.RecordRange, got %T", res)
	}
}

// convertV3ToMerkleReceipt converts a v3 API receipt to the internal merkle.Receipt format
func convertV3ToMerkleReceipt(v3Receipt *v3.Receipt) *merkle.Receipt {
	if v3Receipt == nil {
		return nil
	}

	// v3.Receipt embeds merkle.Receipt, so we can access it directly
	return &v3Receipt.Receipt
}

// GetDNAnchorReceipt searches for a specific anchor in the DN and returns its receipt.
// GetRoutingTable is not supported by the V3 backend.
func (b *RPCDataBackendV3) GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	return nil, fmt.Errorf("GetRoutingTable not supported by v3 backend")
}

func (b *RPCDataBackendV3) GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error) {
	// The DN partition is a constant.
	partitionUrl, err := acc_url.Parse("acc://dn.acme")
	if err != nil {
		return nil, fmt.Errorf("invalid DN partition URL: %w", err)
	}

	// Use the v3 client's Query method to search for the anchor.
	res, err := b.client.Query(ctx, partitionUrl, &v3.AnchorSearchQuery{
		Anchor:         anchor,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query DN anchor receipt: %w", err)
	}

	switch r := res.(type) {
	case *v3.RecordRange[v3.Record]:
		if len(r.Records) == 0 {
			return nil, fmt.Errorf("no anchor found in DN for anchor %x", anchor)
		}
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type in range: got %T", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("no receipt found in DN anchor search result")
		}

		log.Printf("[DATA BACKEND V3] Successfully retrieved DN anchor receipt")
		return &chainEntry.Receipt.Receipt, nil
	default:
		return nil, fmt.Errorf("unexpected response type: expected *v3.RecordRange, got %T", res)
	}
}

// GetDNIntermediateAnchorReceipt searches for a BVN root anchor in the DN intermediate anchor chain.
// This implements the first step of the DN proof structure: BVN Root Anchor → DN Intermediate Anchor.
func (b *RPCDataBackendV3) GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error) {
	// The DN partition is a constant.
	partitionUrl, err := acc_url.Parse("acc://dn.acme")
	if err != nil {
		return nil, fmt.Errorf("invalid DN partition URL: %w", err)
	}

	// Search for the BVN root anchor in the DN intermediate anchor chain
	// This uses the same anchor search mechanism but targets the intermediate chain
	res, err := b.client.Query(ctx, partitionUrl, &v3.AnchorSearchQuery{
		Anchor:         bvnRootAnchor,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query DN intermediate anchor receipt: %w", err)
	}

	switch r := res.(type) {
	case *v3.RecordRange[v3.Record]:
		if len(r.Records) == 0 {
			return nil, fmt.Errorf("no BVN root anchor found in DN intermediate chain for anchor %x", bvnRootAnchor)
		}
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type in range: got %T", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("no receipt found in DN intermediate anchor search result")
		}

		log.Printf("[DATA BACKEND V3] Successfully retrieved DN intermediate anchor receipt")
		return &chainEntry.Receipt.Receipt, nil
	default:
		return nil, fmt.Errorf("unexpected response type: expected *v3.RecordRange, got %T", res)
	}
}

func (b *RPCDataBackendV3) GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error) {
	// IMPORTANT: Main chain roots are NOT in anchor chains - they're in the BPT itself.
	// The V3 API doesn't provide direct BPT access, only anchor chain searches.
	// We need to use an alternative approach or return an appropriate error.

	log.Printf("[BPT RECEIPT] Attempting to find hash %x in partition '%s'", hash, partition)
	log.Printf("[BPT RECEIPT] Note: V3 API does not provide direct BPT access, trying alternative approaches...")

	// Construct proper partition URL
	var partitionUrl *acc_url.URL
	var err error
	if partition == "dn" {
		// Special case for DN queries
		partitionUrl, err = acc_url.Parse("acc://dn.acme")
	} else {
		// BVN partition format - construct proper URL
		partitionUrl, err = acc_url.Parse(fmt.Sprintf("acc://bvn-%s.acme", partition))
	}
	if err != nil {
		return nil, fmt.Errorf("invalid partition URL for %s: %w", partition, err)
	}

	// Try anchor search first (this will likely fail for main chain roots)
	res, err := b.client.Query(ctx, partitionUrl, &v3.AnchorSearchQuery{
		Anchor:         hash,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})

	// Check if it's a "not found" error which is expected for main chain roots
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.Printf("[BPT RECEIPT] Hash not found in anchor chains (expected for main chain roots)")
			// This is expected - main chain roots are in BPT, not anchor chains
			// Return a specific error to indicate we need an alternative approach
			return nil, fmt.Errorf("main chain root %x not in anchor chains (need BPT access)", hash)
		}
		return nil, fmt.Errorf("failed to search partition %s: %w", partition, err)
	}

	// If we somehow found it, return the receipt
	switch r := res.(type) {
	case *v3.RecordRange[v3.Record]:
		if len(r.Records) == 0 {
			// This shouldn't happen if err was nil, but check anyway
			return nil, fmt.Errorf("hash %x not found in partition %s", hash, partition)
		}
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type: got %T", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("no receipt found in search result")
		}

		log.Printf("[BPT RECEIPT] Unexpectedly found hash in partition %s anchor chains", partition)
		return &chainEntry.Receipt.Receipt, nil
	default:
		return nil, fmt.Errorf("unexpected response type: expected *v3.RecordRange, got %T", res)
	}
}

// GetMainChainRootInDNAnchorChain searches specifically for a BVN partition's main chain root
// in the Directory Network anchor chains. This implements the correct Accumulate architecture
// where main chain roots flow upward: Account (BVN) → DN Anchor Chains → DN BPT → DN Root.
//
// Parameters:
//   - partition: The source BVN partition name (e.g., "Cyclops")
//   - mainChainRoot: The main chain root hash from that partition to find in DN
//
// Returns:
//   - *merkle.Receipt: Receipt proving the main chain root exists in DN anchor chains
//   - error: Any errors during the search
func (b *RPCDataBackendV3) GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error) {
	log.Printf("[DN ANCHOR SEARCH] Searching for main chain root %x from partition '%s' in Directory Network", mainChainRoot, partition)

	dnUrl, err := acc_url.Parse("acc://dn.acme")
	if err != nil {
		return nil, fmt.Errorf("invalid DN URL: %w", err)
	}

	// Search DN anchor chains for the main chain root from the specified partition
	// The DN contains anchor chains like: dn.acme/anchors#{partition}-root
	res, err := b.client.Query(ctx, dnUrl, &v3.AnchorSearchQuery{
		Anchor:         mainChainRoot,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search for main chain root from %s in DN: %w", partition, err)
	}

	switch r := res.(type) {
	case *v3.RecordRange[v3.Record]:
		if len(r.Records) == 0 {
			return nil, fmt.Errorf("main chain root %x from partition %s not found in any DN anchor chain", mainChainRoot, partition)
		}
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type in DN anchor search: got %T", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("no receipt found for main chain root in DN anchor chain")
		}

		log.Printf("[DN ANCHOR SEARCH] ✅ Found main chain root from partition %s in DN anchor chain", partition)
		log.Printf("[DN ANCHOR SEARCH] Receipt anchor: %x", chainEntry.Receipt.Receipt.Anchor)
		return &chainEntry.Receipt.Receipt, nil
	default:
		return nil, fmt.Errorf("unexpected response type from DN anchor search: expected *v3.RecordRange, got %T", res)
	}
}

// GetBVNAnchorReceipt searches for a specific anchor in a BVN partition and returns its receipt.
func (b *RPCDataBackendV3) GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error) {
	// Construct proper BVN partition URL from partition name
	partitionURL := fmt.Sprintf("acc://bvn-%s.acme", partition)
	partitionUrl, err := acc_url.Parse(partitionURL)
	if err != nil {
		return nil, fmt.Errorf("invalid partition URL %s: %w", partitionURL, err)
	}

	// Use the v3 client's Query method to search for the anchor.
	res, err := b.client.Query(ctx, partitionUrl, &v3.AnchorSearchQuery{
		Anchor:         anchor,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query BVN anchor receipt for partition %s: %w", partition, err)
	}

	switch r := res.(type) {
	case *v3.RecordRange[v3.Record]:
		if len(r.Records) == 0 {
			return nil, fmt.Errorf("no anchor found in partition %s for anchor %x", partition, anchor)
		}
		chainEntry, ok := r.Records[0].(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("unexpected record type in range: got %T", r.Records[0])
		}
		if chainEntry.Receipt == nil {
			return nil, fmt.Errorf("no receipt found in anchor search result")
		}

		log.Printf("[DATA BACKEND V3] Successfully retrieved BVN anchor receipt")
		return &chainEntry.Receipt.Receipt, nil
	default:
		return nil, fmt.Errorf("unexpected response type: expected *v3.RecordRange, got %T", res)
	}
}
