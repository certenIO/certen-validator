package execution

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// TronClient handles TRON blockchain interactions using TRON's HTTP API.
// TRON's /jsonrpc endpoint does NOT support eth_getTransactionCount or
// eth_sendRawTransaction, so we must use the native HTTP API for writes.
type TronClient struct {
	httpEndpoint string
	privateKey   *ecdsa.PrivateKey
	ownerAddress string // TRON hex format: 41 + 20 bytes (no 0x prefix)
	httpClient   *http.Client
	contractABI  abi.ABI
}

// NewTronClient creates a TRON client from an HTTP endpoint and private key.
// The endpoint should be the base URL (e.g., https://api.shasta.trongrid.io).
// Any /jsonrpc suffix is stripped automatically.
func NewTronClient(httpEndpoint string, privateKeyHex string) (*TronClient, error) {
	// Strip /jsonrpc suffix — we use the HTTP API
	httpEndpoint = strings.TrimSuffix(httpEndpoint, "/jsonrpc")
	httpEndpoint = strings.TrimSuffix(httpEndpoint, "/")

	if strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = privateKeyHex[2:]
	}
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Derive TRON address: 41 + last 20 bytes of keccak256(uncompressed pubkey)
	ethAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
	tronAddr := "41" + hex.EncodeToString(ethAddr.Bytes())

	// Parse contract ABI for encoding function calls
	parsedABI, err := abi.JSON(strings.NewReader(contracts.CertenAnchorV4ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse anchor ABI: %w", err)
	}

	return &TronClient{
		httpEndpoint: httpEndpoint,
		privateKey:   privateKey,
		ownerAddress: tronAddr,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		contractABI:  parsedABI,
	}, nil
}

// GetOwnerAddressHex returns the TRON address in 41-prefixed hex format.
func (tc *TronClient) GetOwnerAddressHex() string {
	return tc.ownerAddress
}

// GetEthAddress returns the 0x-prefixed Ethereum-compatible address.
func (tc *TronClient) GetEthAddress() string {
	return "0x" + tc.ownerAddress[2:]
}

// CreateAnchor calls createAnchor on the anchor contract via TRON HTTP API.
func (tc *TronClient) CreateAnchor(
	ctx context.Context,
	contractAddress string,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	accumulateBlockHeight *big.Int,
	feeLimit int64,
) (string, error) {
	log.Printf("📡 [TRON] Creating anchor via HTTP API...")
	log.Printf("   Contract: %s", contractAddress)
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])

	// ABI-encode the parameters
	calldata, err := tc.contractABI.Pack("createAnchor",
		bundleId, adiURLHash, operationCommitment,
		crossChainCommitment, governanceRoot, accumulateBlockHeight,
	)
	if err != nil {
		return "", fmt.Errorf("ABI encoding failed: %w", err)
	}

	// calldata = 4-byte selector + params. TRON wants just the params portion.
	paramHex := hex.EncodeToString(calldata[4:])

	txResult, err := tc.triggerSmartContract(ctx, contractAddress,
		"createAnchor(bytes32,bytes32,bytes32,bytes32,bytes32,uint256)",
		paramHex, feeLimit)
	if err != nil {
		return "", fmt.Errorf("triggerSmartContract failed: %w", err)
	}

	txID, err := tc.signAndBroadcast(ctx, txResult)
	if err != nil {
		return "", fmt.Errorf("sign/broadcast failed: %w", err)
	}

	log.Printf("✅ [TRON] Anchor created: txID=%s", txID)
	return txID, nil
}

// ExecuteComprehensiveProof calls executeComprehensiveProof on the anchor contract.
func (tc *TronClient) ExecuteComprehensiveProof(
	ctx context.Context,
	contractAddress string,
	anchorId [32]byte,
	proof contracts.CertenAnchorV4CertenProof,
	feeLimit int64,
) (string, error) {
	log.Printf("📡 [TRON] Submitting comprehensive proof via HTTP API...")

	// ABI-encode using go-ethereum's abi package (handles nested structs)
	calldata, err := tc.contractABI.Pack("executeComprehensiveProof", anchorId, proof)
	if err != nil {
		return "", fmt.Errorf("ABI encoding failed: %w", err)
	}

	paramHex := hex.EncodeToString(calldata[4:])

	txResult, err := tc.triggerSmartContract(ctx, contractAddress,
		// Must match exact Solidity signature for TRON's ABI parsing
		"executeComprehensiveProof(bytes32,(bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes))",
		paramHex, feeLimit)
	if err != nil {
		return "", fmt.Errorf("triggerSmartContract failed: %w", err)
	}

	txID, err := tc.signAndBroadcast(ctx, txResult)
	if err != nil {
		return "", fmt.Errorf("sign/broadcast failed: %w", err)
	}

	log.Printf("✅ [TRON] Comprehensive proof submitted: txID=%s", txID)
	return txID, nil
}

// ExecuteWithGovernance calls executeWithGovernance on the anchor contract.
func (tc *TronClient) ExecuteWithGovernance(
	ctx context.Context,
	contractAddress string,
	anchorId [32]byte,
	target string,
	value *big.Int,
	data []byte,
	feeLimit int64,
) (string, error) {
	log.Printf("📡 [TRON] Executing governance via HTTP API...")

	// Convert target to TRON 41-prefix hex
	targetHex := target
	if strings.HasPrefix(target, "0x") || strings.HasPrefix(target, "0X") {
		targetHex = "41" + target[2:]
	}
	_ = targetHex // used for logging

	// ABI-encode using go-ethereum (target as Ethereum address for ABI encoding)
	targetAddr := toEthAddress(target)
	calldata, err := tc.contractABI.Pack("executeWithGovernance", anchorId, targetAddr, value, data)
	if err != nil {
		return "", fmt.Errorf("ABI encoding failed: %w", err)
	}

	paramHex := hex.EncodeToString(calldata[4:])

	txResult, err := tc.triggerSmartContract(ctx, contractAddress,
		"executeWithGovernance(bytes32,address,uint256,bytes)",
		paramHex, feeLimit)
	if err != nil {
		return "", fmt.Errorf("triggerSmartContract failed: %w", err)
	}

	txID, err := tc.signAndBroadcast(ctx, txResult)
	if err != nil {
		return "", fmt.Errorf("sign/broadcast failed: %w", err)
	}

	log.Printf("✅ [TRON] Governance executed: txID=%s", txID)
	return txID, nil
}

// WaitForConfirmation polls for transaction confirmation.
func (tc *TronClient) WaitForConfirmation(ctx context.Context, txID string, timeout time.Duration) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info, err := tc.getTransactionInfo(ctx, txID)
		if err != nil {
			log.Printf("⚠️ [TRON] Polling tx info: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		// If blockNumber is present, transaction is confirmed
		if _, ok := info["blockNumber"]; ok {
			receipt := info["receipt"]
			if receiptMap, ok := receipt.(map[string]interface{}); ok {
				result := receiptMap["result"]
				log.Printf("   TRON receipt: result=%v", result)
				if result == "OUT_OF_ENERGY" {
					return info, fmt.Errorf("transaction OUT_OF_ENERGY")
				}
			}
			return info, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return nil, fmt.Errorf("transaction %s not confirmed after %v", txID, timeout)
}

// triggerSmartContract builds an unsigned transaction via TRON's HTTP API.
func (tc *TronClient) triggerSmartContract(
	ctx context.Context,
	contractAddress string,
	functionSelector string,
	parameter string,
	feeLimit int64,
) (map[string]interface{}, error) {
	// Convert 0x address to TRON 41-prefix format
	tronContract := contractAddress
	if strings.HasPrefix(contractAddress, "0x") || strings.HasPrefix(contractAddress, "0X") {
		tronContract = "41" + contractAddress[2:]
	}

	payload := map[string]interface{}{
		"owner_address":     tc.ownerAddress,
		"contract_address":  tronContract,
		"function_selector": functionSelector,
		"parameter":         parameter,
		"fee_limit":         feeLimit,
		"call_value":        0,
		"visible":           false,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		tc.httpEndpoint+"/wallet/triggersmartcontract", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Check for API-level error
	if resultField, ok := result["result"].(map[string]interface{}); ok {
		if success, ok := resultField["result"].(bool); ok && !success {
			msg := ""
			if msgBytes, ok := resultField["message"].(string); ok {
				decoded, _ := hex.DecodeString(msgBytes)
				if len(decoded) > 0 {
					msg = string(decoded)
				} else {
					msg = msgBytes
				}
			}
			return nil, fmt.Errorf("triggerSmartContract failed: %s", msg)
		}
	}

	return result, nil
}

// signAndBroadcast signs a transaction and broadcasts it to the network.
func (tc *TronClient) signAndBroadcast(ctx context.Context, txResult map[string]interface{}) (string, error) {
	tx, ok := txResult["transaction"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no transaction in API result")
	}

	txID, ok := tx["txID"].(string)
	if !ok {
		return "", fmt.Errorf("no txID in transaction")
	}

	// Sign: txID is the SHA256 hash of raw_data (already computed by TRON API)
	txIDBytes, err := hex.DecodeString(txID)
	if err != nil {
		return "", fmt.Errorf("invalid txID hex: %w", err)
	}

	sig, err := crypto.Sign(txIDBytes, tc.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Add signature to transaction
	tx["signature"] = []string{hex.EncodeToString(sig)}

	// Broadcast
	body, _ := json.Marshal(tx)
	req, err := http.NewRequestWithContext(ctx, "POST",
		tc.httpEndpoint+"/wallet/broadcasttransaction", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("broadcast failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading broadcast response: %w", err)
	}

	var broadcastResult map[string]interface{}
	if err := json.Unmarshal(respBody, &broadcastResult); err != nil {
		return "", fmt.Errorf("parsing broadcast response: %w", err)
	}

	if success, ok := broadcastResult["result"].(bool); !ok || !success {
		msg := ""
		if msgField, ok := broadcastResult["message"].(string); ok {
			msg = msgField
		}
		return "", fmt.Errorf("broadcast rejected: %s (response: %s)", msg, string(respBody))
	}

	log.Printf("✅ [TRON] Transaction broadcast successful: %s", txID)
	return txID, nil
}

// getTransactionInfo retrieves transaction receipt/confirmation info.
func (tc *TronClient) getTransactionInfo(ctx context.Context, txID string) (map[string]interface{}, error) {
	payload := map[string]string{"value": txID}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST",
		tc.httpEndpoint+"/wallet/gettransactioninfobyid", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// toEthAddress converts a hex address string to a common.Address.
func toEthAddress(addr string) common.Address {
	cleaned := strings.TrimPrefix(addr, "0x")
	cleaned = strings.TrimPrefix(cleaned, "0X")
	// Strip TRON 41-prefix if present (21 bytes = 42 hex chars)
	if len(cleaned) == 42 && strings.HasPrefix(cleaned, "41") {
		cleaned = cleaned[2:]
	}
	return common.HexToAddress(cleaned)
}
