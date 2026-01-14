// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package liteclient implements the DataBackend interface for account data retrieval.
//
// DESIGN PATTERN: Single Responsibility Principle
// DataBackend is focused solely on retrieving account data from the Accumulate network.
// It does NOT handle cryptographic proof generation, which is the responsibility of ProofBackend.
//
// RESPONSIBILITIES:
// - Query account data from network APIs
// - Retrieve network status and partition information
// - Transform raw API responses into AccountData structures
// - Handle network errors and retries
//
// NON-RESPONSIBILITIES (handled by ProofBackend):
// - Cryptographic proof generation
// - Merkle receipt construction
// - Trust path validation
// - Receipt combination and validation

package backend

// TODO: MIGRATE TO API V3-ONLY ARCHITECTURE
// ===========================================================================
// FUTURE REFACTORING: Eliminate dual V2/V3 API support
//
// CURRENT ISSUE:
// - This file implements V2 API backend + BackendPair hybrid approach
// - LiteClient uses BOTH V2 (basic operations) and V3 (advanced proofs)
// - Increases complexity, maintenance burden, and dependency conflicts
//
// MIGRATION PLAN:
// 1. Implement missing operations in v3_client.go:
//    - Fix GetRoutingTable() (currently returns error in V3)
//    - Ensure V3 QueryAccount() fully compatible with all account types
//    - Test V3 GetNetworkStatus() parity with V2 version
//
// 2. Update LiteClient core (liteclient.go):
//    - Remove dataBackendV2 field, keep only dataBackendV3
//    - Remove BackendPair dependency, use single V3 backend
//    - Update all account handlers to use V3 data structures
//    - Remove v2api imports and dependencies
//
// 3. Configuration integration:
//    - Use centralized config.yml V3 endpoints exclusively
//    - Remove all hardcoded V2 endpoint references
//    - Implement network mode switching (devnet/testnet/mainnet)
//
// BENEFITS:
// - Unified API surface (V3-only)
// - Reduced complexity and dependencies
// - Better alignment with centralized configuration
// - Future-proof architecture
//
// RISK ASSESSMENT: Medium-High
// - V2 QueryAccount heavily used in account processing
// - V2 GetNetworkStatus used for partition discovery
// - Need thorough testing of V3 compatibility
//
// ESTIMATED EFFORT: 2-3 days
// ===========================================================================

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	v2api "gitlab.com/accumulatenetwork/accumulate/pkg/client/api/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// RPCDataBackend implements DataBackend using the Accumulate v2 RPC API.
// This implementation handles the specifics of the v2 API protocol while conforming
// to the DataBackend interface contract.
//
// DESIGN PRINCIPLES:
// - Single Responsibility: Only handles data retrieval
// - Defensive Programming: Validates all inputs and handles errors explicitly
// - Protocol Compliance: Uses canonical Accumulate API patterns
type RPCDataBackend struct {
	client *v2api.Client
	server string
}

// NewRPCDataBackend creates a new DataBackend implementation using v2api.Client.
// Returns an error if the client is nil, following the fail-fast principle.
//
// Parameters:
//   - server: The Accumulate server URL for logging and debugging
//   - client: The v2api.Client instance for making API calls
//
// Returns:
//   - DataBackend: The configured data backend implementation
//   - error: Any initialization errors
func NewRPCDataBackend(server string, client *v2api.Client) (types.DataBackend, error) {
	if client == nil {
		return nil, fmt.Errorf("v2api client cannot be nil")
	}
	if server == "" {
		return nil, fmt.Errorf("server URL cannot be empty")
	}

	return &RPCDataBackend{
		client: client,
		server: server,
	}, nil
}

// QueryAccount implements DataBackend.QueryAccount for v2 API.
// This method demonstrates the Single Responsibility Principle by focusing solely
// on data retrieval and transformation, delegating validation to the caller.
//
// The method performs the following steps:
// 1. Parse and validate the account URL
// 2. Query the account data using the v2 API
// 3. Transform the response into AccountData structure
// 4. Extract metadata (height, type) from the response
// 5. Return structured account data for further processing
func (b *RPCDataBackend) QueryAccount(ctx context.Context, accountUrl string) (*types.AccountData, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	accUrl, err := acc_url.Parse(accountUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	log.Printf("Querying account: %s from server: %s", accUrl, b.server)

	queryParams := &v2api.UrlQuery{Url: accUrl}
	params := &v2api.GeneralQuery{UrlQuery: *queryParams}
	response, err := b.client.Query(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query account %s: %w", accUrl, err)
	}

	respMap, ok := response.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: want map[string]interface{}, got %T", response)
	}

	ad := &types.AccountData{
		RawResponse: respMap,
	}

	rawData, ok := respMap["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("response is missing 'data' field or it is not a map")
	}

	// Extract type
	typeStr, ok := rawData["type"].(string)
	if !ok {
		return nil, fmt.Errorf("account data is missing 'type' field")
	}
	accountType, ok := protocol.AccountTypeByName(typeStr)
	if !ok {
		return nil, fmt.Errorf("unknown account type %q", typeStr)
	}
	ad.Type = accountType

	// Extract URL
	if urlStr, ok := rawData["url"].(string); ok {
		ad.URL = urlStr
	} else {
		return nil, fmt.Errorf("account data is missing 'url' field")
	}

	if mainChain, ok := respMap["mainChain"].(map[string]interface{}); ok {
		if roots, ok := mainChain["roots"].([]interface{}); ok {
			for _, r := range roots {
				if s, ok := r.(string); ok {
					hash, err := hex.DecodeString(s)
					if err == nil {
						ad.MainChainRoots = append(ad.MainChainRoots, hash)
					}
				}
			}
		}
	}

	// Convert the map to JSON
	jsonBytes, err := json.Marshal(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal raw account data: %w", err)
	}

	// Deserialize into concrete type
	var account protocol.Account
	switch accountType {
	case protocol.AccountTypeTokenAccount:
		var acc protocol.TokenAccount
		if err := json.Unmarshal(jsonBytes, &acc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TokenAccount: %w", err)
		}
		account = &acc

	case protocol.AccountTypeKeyBook:
		var acc protocol.KeyBook
		if err := json.Unmarshal(jsonBytes, &acc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal KeyBook: %w", err)
		}
		account = &acc

	case protocol.AccountTypeKeyPage:
		var acc protocol.KeyPage
		if err := json.Unmarshal(jsonBytes, &acc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal KeyPage: %w", err)
		}
		account = &acc

	case protocol.AccountTypeIdentity:
		var acc protocol.ADI
		if err := json.Unmarshal(jsonBytes, &acc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ADI: %w", err)
		}
		account = &acc

	case protocol.AccountTypeAnchorLedger:
		var acc protocol.AnchorLedger
		if err := json.Unmarshal(jsonBytes, &acc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal AnchorLedger: %w", err)
		}
		account = &acc

	default:
		return nil, fmt.Errorf("unsupported account type: %s", typeStr)
	}

	ad.Data = account

	log.Printf("[DATA BACKEND] Successfully retrieved account data for %s (type: %s)", ad.URL, ad.Type)

	return ad, nil
}

// GetNetworkStatus implements DataBackend.GetNetworkStatus.
// It queries the live network's /network endpoint to get real partition data.
// GetRoutingTable implements DataBackend.GetRoutingTable for the v2 API.
func (b *RPCDataBackend) GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	desc, err := b.client.Describe(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to describe network: %w", err)
	}
	return desc.Values.Routing, nil
}

func (b *RPCDataBackend) GetNetworkStatus(ctx context.Context) (*types.NetworkStatus, error) {
	log.Printf("[DATA BACKEND] Getting real network status from %s/v2", b.server)

	// Use the standard HTTP client to make a request to the /network endpoint.
	req, err := http.NewRequestWithContext(ctx, "POST", b.server+"/v2", strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"network-status","params":{}}`))
	if err != nil {
		return nil, fmt.Errorf("failed to create network status request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute network status request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network status request failed with status code: %d", resp.StatusCode)
	}

	// A minimal struct to capture the network status response.
	var networkStatusResponse struct {
		Result struct {
			Network struct {
				Partitions []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"partitions"`
			} `json:"network"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&networkStatusResponse); err != nil {
		return nil, fmt.Errorf("failed to decode network status response: %w", err)
	}

	// Convert the API response to our local NetworkStatus struct
	status := &types.NetworkStatus{
		Partitions: make([]types.PartitionInfo, len(networkStatusResponse.Result.Network.Partitions)),
	}

	for i, p := range networkStatusResponse.Result.Network.Partitions {
		partitionUrl, err := url.Parse(fmt.Sprintf("acc://%s.acme", p.ID))
		if err != nil {
			log.Printf("[DATA BACKEND] Warning: could not parse partition URL for %s: %v", p.ID, err)
			continue
		}
		status.Partitions[i] = types.PartitionInfo{
			ID:   p.ID,
			Type: p.Type,
			URL:  partitionUrl,
		}
	}

	log.Printf("[DATA BACKEND] ✅ Successfully retrieved network status with %d partitions", len(status.Partitions))
	return status, nil
}

// extractHeightFromResponse attempts to extract block height from the raw API response.
// This is a best-effort operation that handles various response formats.
//
// Parameters:
//   - rawResponse: The unmarshaled API response as a map
//
// Returns:
//   - int64: The extracted height, or 0 if extraction fails
func (b *RPCDataBackend) extractHeightFromResponse(rawResponse map[string]interface{}) int64 {
	// Try multiple possible locations for height information
	heightFields := []string{"height", "blockHeight", "chainHeight", "lastBlockHeight"}

	for _, field := range heightFields {
		if heightValue, exists := rawResponse[field]; exists {
			switch h := heightValue.(type) {
			case float64:
				return int64(h)
			case int64:
				return h
			case int:
				return int64(h)
			case string:
				// Try to parse string as integer
				var heightInt int64
				if _, err := fmt.Sscanf(h, "%d", &heightInt); err == nil {
					return heightInt
				}
			}
		}
	}

	// Try to extract from nested structures
	if chains, exists := rawResponse["chains"]; exists {
		if chainsArray, ok := chains.([]interface{}); ok {
			for _, chain := range chainsArray {
				if chainMap, ok := chain.(map[string]interface{}); ok {
					if height, exists := chainMap["height"]; exists {
						if heightFloat, ok := height.(float64); ok {
							return int64(heightFloat)
						}
					}
				}
			}
		}
	}

	// Fallback: return 0 if height cannot be extracted
	log.Printf("[DATA BACKEND] Warning: could not extract height from response")
	return 0
}

// GetMainChainReceipt implements DataBackend.GetMainChainReceipt for v2 API.
// It queries the account with the option to include the main chain receipt starting from a specific hash.
func (b *RPCDataBackend) GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error) {
	accUrl, err := acc_url.Parse(accountUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	// To get a receipt for a specific entry, we query a transaction URL.
	txidUrl := accUrl.WithTxID(*(*[32]byte)(startHash))

	params := &v2api.GeneralQuery{
		UrlQuery: v2api.UrlQuery{Url: txidUrl.AsUrl()},
	}

	// The Query method returns a response that includes the receipt.
	// We must type-assert the response to get the receipt.
	res, err := b.client.Query(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query main chain receipt for %s: %w", accountUrl, err)
	}

	qcr, ok := res.(*v2api.ChainQueryResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: want *v2api.ChainQueryResponse, got %T", res)
	}

	// The receipt from the API is of type pkg/types/merkle.Receipt, but we need to return
	// pkg/database/merkle.Receipt. We must convert it by copying the fields.
	receipt := &merkle.Receipt{
		Start:   qcr.Receipt.Proof.Start,
		Entries: qcr.Receipt.Proof.Entries,
		Anchor:  qcr.Receipt.Proof.Anchor,
	}
	return receipt, nil
}

// GetBVNAnchorReceipt queries the specified BVN partition for a receipt proving the inclusion of a main chain anchor.
// This is a critical step in the trust path, linking the main chain to the BVN.
//
// PROOF FLOW:
// 1. Construct a v2api.GeneralQuery with the main chain anchor and partition URL.
// 2. Set Prove: true to request a cryptographic receipt.
// 3. Execute the query against the network.
// 4. Type-assert the response to *v2api.ChainQueryResponse.
// 5. Extract and return the Merkle receipt from the response.
// GetBVNAnchorReceipt is a placeholder implementation for the v2 backend.
// Anchor searches require the v3 API, which is implemented in RPCDataBackendV3.
func (b *RPCDataBackend) GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("GetBVNAnchorReceipt not implemented for v2 backend, use v3")
}

// GetDNAnchorReceipt is a placeholder implementation.
func (b *RPCDataBackend) GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error) {
	// V2 client does not directly support DN anchor receipts.
	// This method should be implemented in a V3-specific backend.
	return nil, fmt.Errorf("GetDNAnchorReceipt not supported by V2 backend")
}

// GetDNIntermediateAnchorReceipt is a placeholder implementation for the V2 backend.
func (b *RPCDataBackend) GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error) {
	// V2 client does not directly support DN intermediate anchor receipts.
	// This method should be implemented in a V3-specific backend.
	return nil, fmt.Errorf("GetDNIntermediateAnchorReceipt not supported by V2 backend")
}

// GetBPTReceipt is a placeholder implementation for the V2 backend.
// The actual implementation should exist in a V3-specific backend.
func (b *RPCDataBackend) GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("GetBPTReceipt not supported by V2 backend")
}

// GetMainChainRootInDNAnchorChain is a placeholder implementation for the V2 backend.
func (b *RPCDataBackend) GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error) {
	return nil, fmt.Errorf("GetMainChainRootInDNAnchorChain not supported by V2 backend")
}

// BackendPair provides access to both V2 and V3 backends, allowing components
// to use the appropriate one for a given feature.
//
// DESIGN PATTERN: Wrapper/Facade
// This struct acts as a facade over the two backend implementations, providing
// a single point of access without merging their interfaces.
// BackendPair implements DataBackend by delegating to the appropriate backend.
type BackendPair struct {
	V2 types.DataBackend
	V3 types.DataBackend
}

// NewBackendPair creates a new backend pair, ensuring neither backend is nil.
func NewBackendPair(v2, v3 types.DataBackend) (*BackendPair, error) {
	if v2 == nil {
		return nil, fmt.Errorf("v2 backend cannot be nil")
	}
	if v3 == nil {
		return nil, fmt.Errorf("v3 backend cannot be nil")
	}
	return &BackendPair{V2: v2, V3: v3}, nil
}

// Implement DataBackend interface by delegating to appropriate backend

// QueryAccount delegates to V2 backend (primary for account queries)
func (bp *BackendPair) QueryAccount(ctx context.Context, url string) (*types.AccountData, error) {
	return bp.V2.QueryAccount(ctx, url)
}

// GetNetworkStatus delegates to V2 backend
func (bp *BackendPair) GetNetworkStatus(ctx context.Context) (*types.NetworkStatus, error) {
	return bp.V2.GetNetworkStatus(ctx)
}

// GetRoutingTable delegates to V2 backend
func (bp *BackendPair) GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	return bp.V2.GetRoutingTable(ctx)
}

// GetMainChainReceipt tries V3 first, falls back to V2
func (bp *BackendPair) GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error) {
	// Try V3 first for better receipt support
	receipt, err := bp.V3.GetMainChainReceipt(ctx, accountUrl, startHash)
	if err == nil {
		return receipt, nil
	}
	log.Printf("[BACKEND PAIR] V3 GetMainChainReceipt failed, trying V2: %v", err)
	return bp.V2.GetMainChainReceipt(ctx, accountUrl, startHash)
}

// GetBVNAnchorReceipt delegates to V3 backend (V2 doesn't support this)
func (bp *BackendPair) GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error) {
	return bp.V3.GetBVNAnchorReceipt(ctx, partition, anchor)
}

// GetDNAnchorReceipt delegates to V3 backend (V2 doesn't support this)
func (bp *BackendPair) GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error) {
	return bp.V3.GetDNAnchorReceipt(ctx, anchor)
}

// GetDNIntermediateAnchorReceipt delegates to V3 backend
func (bp *BackendPair) GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error) {
	return bp.V3.GetDNIntermediateAnchorReceipt(ctx, bvnRootAnchor)
}

// GetBPTReceipt delegates to V3 backend (V2 doesn't support BPT queries)
func (bp *BackendPair) GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error) {
	return bp.V3.GetBPTReceipt(ctx, partition, hash)
}

// GetMainChainRootInDNAnchorChain delegates to V3 backend
func (bp *BackendPair) GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error) {
	return bp.V3.GetMainChainRootInDNAnchorChain(ctx, partition, mainChainRoot)
}
