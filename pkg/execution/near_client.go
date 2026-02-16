package execution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

// =============================================================================
// NEAR CLIENT
// =============================================================================

// NearClient handles NEAR Protocol blockchain interactions using JSON-RPC.
// Mirrors TronClient pattern but uses Ed25519 signing and Borsh serialization.
type NearClient struct {
	rpcEndpoint     string
	signerAccountID string             // e.g. "certen-v1.testnet"
	privateKey      ed25519.PrivateKey // 64-byte Ed25519 key
	publicKey       ed25519.PublicKey  // 32-byte public key
	publicKeyBase58 string             // "ed25519:Base58..." for RPC queries
	httpClient      *http.Client
}

// NewNearClient creates a NEAR client from an RPC endpoint and Ed25519 key.
// Key format: "ed25519:Base58Encoded64ByteKeypair" (seed || public key).
func NewNearClient(rpcEndpoint, signerAccountID, nearPrivateKey string) (*NearClient, error) {
	rpcEndpoint = strings.TrimSuffix(rpcEndpoint, "/")

	// Parse the ed25519:base58... key format
	if !strings.HasPrefix(nearPrivateKey, "ed25519:") {
		return nil, fmt.Errorf("NEAR private key must start with 'ed25519:' prefix")
	}
	keyData, err := base58.Decode(nearPrivateKey[len("ed25519:"):])
	if err != nil {
		return nil, fmt.Errorf("failed to base58-decode NEAR private key: %w", err)
	}
	if len(keyData) != 64 {
		return nil, fmt.Errorf("NEAR private key must be 64 bytes (seed+pubkey), got %d", len(keyData))
	}

	// First 32 bytes = seed, last 32 bytes = public key
	seed := keyData[:32]
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Verify derived public key matches embedded public key
	if !bytes.Equal(pubKey, keyData[32:]) {
		return nil, fmt.Errorf("derived public key does not match embedded public key in NEAR key")
	}

	pubKeyBase58 := "ed25519:" + base58.Encode(pubKey)

	log.Printf("🔑 [NEAR] Client created: signer=%s pubKey=%s", signerAccountID, pubKeyBase58)

	return &NearClient{
		rpcEndpoint:     rpcEndpoint,
		signerAccountID: signerAccountID,
		privateKey:      privKey,
		publicKey:       pubKey,
		publicKeyBase58: pubKeyBase58,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSignerAccountID returns the signer's NEAR account ID.
func (nc *NearClient) GetSignerAccountID() string {
	return nc.signerAccountID
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor calls create_anchor on the NEAR anchor contract.
func (nc *NearClient) CreateAnchor(
	ctx context.Context,
	contractID string,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	blockHeight uint64,
	gas uint64,
) (string, error) {
	log.Printf("📡 [NEAR] Creating anchor on %s...", contractID)
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])

	args := map[string]interface{}{
		"bundle_id":              base64.StdEncoding.EncodeToString(bundleId[:]),
		"adi_url_hash":           base64.StdEncoding.EncodeToString(adiURLHash[:]),
		"operation_commitment":   base64.StdEncoding.EncodeToString(operationCommitment[:]),
		"cross_chain_commitment": base64.StdEncoding.EncodeToString(crossChainCommitment[:]),
		"governance_root":        base64.StdEncoding.EncodeToString(governanceRoot[:]),
		"accumulate_block_height": blockHeight,
	}

	txHash, err := nc.callContract(ctx, contractID, "create_anchor", args, gas, big.NewInt(0))
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [NEAR] Anchor created: txHash=%s", txHash)
	return txHash, nil
}

// =============================================================================
// STEP 2: EXECUTE COMPREHENSIVE PROOF
// =============================================================================

// NearCertenProofInput is the JSON structure for the NEAR anchor contract's
// execute_comprehensive_proof method. Maps to Rust CertenProofInput.
type NearCertenProofInput struct {
	TransactionHash string               `json:"transaction_hash"`
	MerkleRoot      string               `json:"merkle_root"`
	ProofHashes     []string             `json:"proof_hashes"`
	LeafHash        string               `json:"leaf_hash"`
	GovernanceProof NearGovernanceProof   `json:"governance_proof"`
	BlsProof        NearBLSProof          `json:"bls_proof"`
	Commitments     NearCommitmentsJSON   `json:"commitments"`
	Timestamp       uint64                `json:"timestamp"`
	ValidatorSigs   string                `json:"validator_signatures"`
}

// NearGovernanceProof is the governance section of the proof.
type NearGovernanceProof struct {
	KeyBookURL         string   `json:"key_book_url"`
	KeyBookRoot        string   `json:"key_book_root"`
	KeyPageProofs      []string `json:"key_page_proofs"`
	AuthorityAddress   string   `json:"authority_address"`
	AuthorityLevel     uint8    `json:"authority_level"`
	Nonce              uint64   `json:"nonce"`
	RequiredSignatures uint64   `json:"required_signatures"`
	ProvidedSignatures uint64   `json:"provided_signatures"`
	ThresholdMet       bool     `json:"threshold_met"`
}

// NearBLSProof is the BLS signature section of the proof.
type NearBLSProof struct {
	AggregateSignature string   `json:"aggregate_signature"`
	ValidatorAddresses []string `json:"validator_addresses"`
	VotingPowers       []uint64 `json:"voting_powers"`
	TotalVotingPower   uint64   `json:"total_voting_power"`
	SignedVotingPower  uint64   `json:"signed_voting_power"`
	ThresholdMet       bool     `json:"threshold_met"`
	MessageHash        string   `json:"message_hash"`
}

// NearCommitmentsJSON is the commitments section of the proof.
type NearCommitmentsJSON struct {
	OperationCommitment  string `json:"operation_commitment"`
	CrossChainCommitment string `json:"cross_chain_commitment"`
	GovernanceRoot       string `json:"governance_root"`
	SourceChain          string `json:"source_chain"`
	BlockHeight          uint64 `json:"block_height"`
	CommitmentHash       string `json:"commitment_hash"`
	AdiURL               string `json:"adi_url"`
	AuthorityURL         string `json:"authority_url"`
}

// ExecuteComprehensiveProof calls execute_comprehensive_proof on the anchor contract.
func (nc *NearClient) ExecuteComprehensiveProof(
	ctx context.Context,
	contractID string,
	anchorId [32]byte,
	proof NearCertenProofInput,
	gas uint64,
) (string, error) {
	log.Printf("📡 [NEAR] Submitting comprehensive proof on %s...", contractID)

	args := map[string]interface{}{
		"anchor_id": base64.StdEncoding.EncodeToString(anchorId[:]),
		"proof":     proof,
	}

	txHash, err := nc.callContract(ctx, contractID, "execute_comprehensive_proof", args, gas, big.NewInt(0))
	if err != nil {
		return "", fmt.Errorf("execute_comprehensive_proof failed: %w", err)
	}

	log.Printf("✅ [NEAR] Comprehensive proof submitted: txHash=%s", txHash)
	return txHash, nil
}

// =============================================================================
// STEP 3: EXECUTE GOVERNANCE PROOF DIRECT
// =============================================================================

// NearCallJSON maps to Rust's NearCall struct on the user account contract.
type NearCallJSON struct {
	Target   string `json:"target"`
	Method   string `json:"method"`
	Args     string `json:"args"`
	Deposit  string `json:"deposit"`
	GasTgas  uint64 `json:"gas_tgas"`
}

// NearADIGovernanceProofJSON maps to Rust's ADIGovernanceProof on the user account contract.
type NearADIGovernanceProofJSON struct {
	AdiURL              string                    `json:"adi_url"`
	AnchorID            string                    `json:"anchor_id"`
	MerkleProof         []string                  `json:"merkle_proof"`
	KeyBookProof        NearKeyBookProofJSON      `json:"key_book_proof"`
	RoleProof           NearRoleProofJSON         `json:"role_proof"`
	ThresholdProof      NearThresholdProofJSON    `json:"threshold_proof"`
	ValidatorSignatures string                    `json:"validator_signatures"`
	TimestampSec        uint64                    `json:"timestamp_sec"`
	ExpiresAtSec        uint64                    `json:"expires_at_sec"`
	Nonce               uint64                    `json:"nonce"`
	RequiredLevel       uint8                     `json:"required_level"`
}

// NearKeyBookProofJSON is the key book proof section.
type NearKeyBookProofJSON struct {
	KeyBookURL     string   `json:"key_book_url"`
	KeyBookRoot    string   `json:"key_book_root"`
	HierarchyDepth uint8    `json:"hierarchy_depth"`
	KeyPageProofs  []string `json:"key_page_proofs"`
	ValidFromSec   uint64   `json:"valid_from_sec"`
	ValidUntilSec  uint64   `json:"valid_until_sec"`
}

// NearRoleProofJSON is the role proof section.
type NearRoleProofJSON struct {
	Level        uint8  `json:"level"`
	Permissions  uint64 `json:"permissions"`
	RoleHash     string `json:"role_hash"`
	Signature    string `json:"signature"`
	AuthorizedBy string `json:"authorized_by"`
	GrantedAtSec uint64 `json:"granted_at_sec"`
}

// NearThresholdProofJSON is the threshold proof section.
type NearThresholdProofJSON struct {
	RequiredThreshold uint64   `json:"required_threshold"`
	Signatures        []string `json:"signatures"`
	Signers           []string `json:"signers"`
	VotingPowers      []uint64 `json:"voting_powers"`
	TotalVotingPower  uint64   `json:"total_voting_power"`
	MessageHash       string   `json:"message_hash"`
}

// ExecuteGovernanceProofDirect calls execute_governance_proof_direct on the user's
// NEAR account contract. This is Step 3 — the user's account verifies the
// governance proof and executes the proxied call.
func (nc *NearClient) ExecuteGovernanceProofDirect(
	ctx context.Context,
	userAccountID string,
	call NearCallJSON,
	proof NearADIGovernanceProofJSON,
	gas uint64,
) (string, error) {
	log.Printf("📡 [NEAR] Executing governance proof direct on user account %s...", userAccountID)
	log.Printf("   Target: %s", call.Target)
	log.Printf("   Deposit: %s yoctoNEAR", call.Deposit)

	args := map[string]interface{}{
		"call":  call,
		"proof": proof,
	}

	txHash, err := nc.callContract(ctx, userAccountID, "execute_governance_proof_direct", args, gas, big.NewInt(0))
	if err != nil {
		return "", fmt.Errorf("execute_governance_proof_direct failed: %w", err)
	}

	log.Printf("✅ [NEAR] Governance proof direct executed: txHash=%s", txHash)
	return txHash, nil
}

// =============================================================================
// READ OPERATIONS
// =============================================================================

// NearAnchorData holds anchor data read from the NEAR anchor contract.
type NearAnchorData struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	BlockHeight           uint64
	Timestamp             uint64
	Validator             string
	Valid                 bool
}

// GetAnchorData reads anchor data from the contract via a view call.
func (nc *NearClient) GetAnchorData(ctx context.Context, contractID string, anchorId [32]byte) (*NearAnchorData, error) {
	args := map[string]interface{}{
		"anchor_id": base64.StdEncoding.EncodeToString(anchorId[:]),
	}
	argsJSON, _ := json.Marshal(args)

	resultBytes, err := nc.callViewFunction(ctx, contractID, "get_anchor", argsJSON)
	if err != nil {
		return nil, fmt.Errorf("get_anchor view call failed: %w", err)
	}

	// Parse the JSON response from the contract
	var raw struct {
		BundleId             string `json:"bundle_id"`
		MerkleRoot           string `json:"merkle_root"`
		AdiURLHash           string `json:"adi_url_hash"`
		OperationCommitment  string `json:"operation_commitment"`
		CrossChainCommitment string `json:"cross_chain_commitment"`
		GovernanceRoot       string `json:"governance_root"`
		BlockHeight          uint64 `json:"accumulate_block_height"`
		Timestamp            uint64 `json:"timestamp"`
		Validator            string `json:"validator"`
		Valid                bool   `json:"valid"`
	}
	if err := json.Unmarshal(resultBytes, &raw); err != nil {
		return nil, fmt.Errorf("parsing anchor data: %w", err)
	}

	if !raw.Valid {
		return nil, fmt.Errorf("anchor not found or invalid on-chain")
	}

	anchor := &NearAnchorData{
		BlockHeight: raw.BlockHeight,
		Timestamp:   raw.Timestamp,
		Validator:   raw.Validator,
		Valid:       raw.Valid,
	}

	// Decode base64 fields
	decodeB64ToArray := func(s string, dst *[32]byte) {
		if data, err := base64.StdEncoding.DecodeString(s); err == nil && len(data) >= 32 {
			copy(dst[:], data[:32])
		}
	}
	decodeB64ToArray(raw.BundleId, &anchor.BundleId)
	decodeB64ToArray(raw.MerkleRoot, &anchor.MerkleRoot)
	decodeB64ToArray(raw.AdiURLHash, &anchor.AdiURLHash)
	decodeB64ToArray(raw.OperationCommitment, &anchor.OperationCommitment)
	decodeB64ToArray(raw.CrossChainCommitment, &anchor.CrossChainCommitment)
	decodeB64ToArray(raw.GovernanceRoot, &anchor.GovernanceRoot)

	log.Printf("✅ [NEAR] Anchor read-back verified: bundleId=0x%x opCommit=0x%x",
		anchor.BundleId[:8], anchor.OperationCommitment[:8])

	return anchor, nil
}

// CheckAccountExists checks if a NEAR account exists.
func (nc *NearClient) CheckAccountExists(ctx context.Context, accountID string) (bool, error) {
	params := map[string]interface{}{
		"request_type": "view_account",
		"finality":     "final",
		"account_id":   accountID,
	}

	_, err := nc.rpcCall(ctx, "query", params)
	if err != nil {
		// Account doesn't exist or RPC error
		if strings.Contains(err.Error(), "does not exist") ||
			strings.Contains(err.Error(), "UNKNOWN_ACCOUNT") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeployAccountViaFactory calls create_account on the NEAR account factory.
// deposit is in yoctoNEAR and is attached to the function call action.
func (nc *NearClient) DeployAccountViaFactory(
	ctx context.Context,
	factoryID string,
	owner string, // EVM hex address of derived owner
	ownerEth string, // same as owner for compatibility
	adiURL string,
	salt uint64,
	deposit *big.Int,
	gas uint64,
) (string, error) {
	log.Printf("📡 [NEAR] Deploying account via factory %s...", factoryID)
	log.Printf("   Owner: %s", owner)
	log.Printf("   ADI URL: %s", adiURL)
	log.Printf("   Salt: %d", salt)
	log.Printf("   Deposit: %s yoctoNEAR", deposit.String())

	args := map[string]interface{}{
		"owner":     owner,
		"owner_eth": ownerEth,
		"adi_url":   adiURL,
		"salt":      salt,
	}

	txHash, err := nc.callContract(ctx, factoryID, "create_account", args, gas, deposit)
	if err != nil {
		return "", fmt.Errorf("factory create_account failed: %w", err)
	}

	log.Printf("✅ [NEAR] Account deployment submitted: txHash=%s", txHash)
	return txHash, nil
}

// PredictAccountID calls get_account_id on the factory to get the deterministic account ID.
// Matches the API bridge which also calls get_account_id.
func (nc *NearClient) PredictAccountID(ctx context.Context, factoryID, owner, adiURL string, salt uint64) (string, error) {
	args := map[string]interface{}{
		"owner":   owner,
		"adi_url": adiURL,
		"salt":    salt,
	}
	argsJSON, _ := json.Marshal(args)

	resultBytes, err := nc.callViewFunction(ctx, factoryID, "get_account_id", argsJSON)
	if err != nil {
		return "", fmt.Errorf("get_account_id view call failed: %w", err)
	}

	// Result is a JSON string with the account ID
	var accountID string
	if err := json.Unmarshal(resultBytes, &accountID); err != nil {
		// Try as raw string
		accountID = strings.Trim(string(resultBytes), "\"")
	}

	if accountID == "" {
		return "", fmt.Errorf("factory returned empty account ID")
	}

	log.Printf("✅ [NEAR] Predicted account ID: %s", accountID)
	return accountID, nil
}

// =============================================================================
// TRANSACTION CONFIRMATION
// =============================================================================

// WaitForConfirmation polls for transaction confirmation.
func (nc *NearClient) WaitForConfirmation(ctx context.Context, txHash string, timeout time.Duration) (map[string]interface{}, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		params := map[string]interface{}{
			"tx_hash":           txHash,
			"sender_account_id": nc.signerAccountID,
			"wait_until":        "EXECUTED",
		}

		result, err := nc.rpcCall(ctx, "tx", params)
		if err != nil {
			// Try legacy format if object params fail
			result, err = nc.rpcCall(ctx, "tx", []interface{}{txHash, nc.signerAccountID})
		}
		if err != nil {
			log.Printf("⚠️ [NEAR] Polling tx status: %v", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		var info map[string]interface{}
		if err := json.Unmarshal(result, &info); err != nil {
			log.Printf("⚠️ [NEAR] Failed to parse tx result: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Check for status field
		if status, ok := info["status"].(map[string]interface{}); ok {
			if _, ok := status["SuccessValue"]; ok {
				log.Printf("✅ [NEAR] Transaction confirmed: %s", txHash)
				return info, nil
			}
			if _, ok := status["SuccessReceiptId"]; ok {
				log.Printf("✅ [NEAR] Transaction confirmed (receipt): %s", txHash)
				return info, nil
			}
			if failure, ok := status["Failure"]; ok {
				return info, fmt.Errorf("transaction failed: %v", failure)
			}
		}

		// Check transaction_outcome for the status
		if txOutcome, ok := info["transaction_outcome"].(map[string]interface{}); ok {
			if outcome, ok := txOutcome["outcome"].(map[string]interface{}); ok {
				if status, ok := outcome["status"].(map[string]interface{}); ok {
					if _, ok := status["SuccessReceiptId"]; ok {
						// Check receipts_outcome for final status
						if receipts, ok := info["receipts_outcome"].([]interface{}); ok && len(receipts) > 0 {
							log.Printf("✅ [NEAR] Transaction confirmed with %d receipts: %s", len(receipts), txHash)
							return info, nil
						}
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("transaction %s not confirmed after %v", txHash, timeout)
}

// =============================================================================
// PRIVATE: TRANSACTION BUILDING
// =============================================================================

// getNonceAndBlockHash fetches the current nonce and a recent block hash for the signer.
func (nc *NearClient) getNonceAndBlockHash(ctx context.Context) (uint64, [32]byte, error) {
	params := map[string]interface{}{
		"request_type": "view_access_key",
		"finality":     "final",
		"account_id":   nc.signerAccountID,
		"public_key":   nc.publicKeyBase58,
	}

	result, err := nc.rpcCall(ctx, "query", params)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("view_access_key query failed: %w", err)
	}

	var accessKey struct {
		Nonce     uint64 `json:"nonce"`
		BlockHash string `json:"block_hash"`
	}
	if err := json.Unmarshal(result, &accessKey); err != nil {
		return 0, [32]byte{}, fmt.Errorf("parsing access key response: %w", err)
	}

	blockHashBytes, err := base58.Decode(accessKey.BlockHash)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("decoding block hash: %w", err)
	}

	var blockHash [32]byte
	copy(blockHash[:], blockHashBytes)

	return accessKey.Nonce, blockHash, nil
}

// callContract builds, signs, and broadcasts a function call transaction.
// Returns the base58-encoded transaction hash.
func (nc *NearClient) callContract(
	ctx context.Context,
	receiverID string,
	methodName string,
	args interface{},
	gas uint64,
	deposit *big.Int,
) (string, error) {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("marshaling args: %w", err)
	}

	signedTxBase64, txHash, err := nc.buildAndSignTransaction(ctx, receiverID, methodName, argsJSON, gas, deposit)
	if err != nil {
		return "", fmt.Errorf("building transaction: %w", err)
	}

	result, err := nc.broadcastTx(ctx, signedTxBase64)
	if err != nil {
		return "", fmt.Errorf("broadcasting transaction: %w", err)
	}

	// Check for execution errors in the broadcast result
	if status, ok := result["status"].(map[string]interface{}); ok {
		if failure, ok := status["Failure"]; ok {
			return txHash, fmt.Errorf("transaction execution failed: %v", failure)
		}
	}

	return txHash, nil
}

// buildAndSignTransaction constructs a NEAR transaction with a FunctionCall action,
// signs it with Ed25519, and returns the base64-encoded signed transaction + tx hash.
func (nc *NearClient) buildAndSignTransaction(
	ctx context.Context,
	receiverID string,
	methodName string,
	argsJSON []byte,
	gas uint64,
	deposit *big.Int,
) (string, string, error) {
	nonce, blockHash, err := nc.getNonceAndBlockHash(ctx)
	if err != nil {
		return "", "", err
	}

	// Borsh-serialize the transaction
	var txBuf bytes.Buffer

	// signer_id: string
	borshWriteString(&txBuf, nc.signerAccountID)
	// public_key: enum(0=ED25519) + 32 bytes
	txBuf.WriteByte(0) // ED25519 key type
	txBuf.Write(nc.publicKey[:32])
	// nonce: u64
	borshWriteU64(&txBuf, nonce+1)
	// receiver_id: string
	borshWriteString(&txBuf, receiverID)
	// block_hash: [32]byte
	txBuf.Write(blockHash[:])
	// actions: Vec<Action> - we always have exactly 1 FunctionCall
	borshWriteU32(&txBuf, 1) // vector length

	// Action::FunctionCall (variant index 2)
	txBuf.WriteByte(2)
	borshWriteString(&txBuf, methodName)
	borshWriteBytes(&txBuf, argsJSON)
	borshWriteU64(&txBuf, gas)
	borshWriteU128(&txBuf, deposit)

	txBytes := txBuf.Bytes()

	// SHA-256 hash the serialized transaction
	hash := sha256.Sum256(txBytes)

	// Sign with Ed25519
	signature := ed25519.Sign(nc.privateKey, hash[:])

	// Borsh-serialize the SignedTransaction
	var signedBuf bytes.Buffer
	signedBuf.Write(txBytes) // transaction (already serialized)
	signedBuf.WriteByte(0)   // ED25519 signature type
	signedBuf.Write(signature[:64])

	signedTxBase64 := base64.StdEncoding.EncodeToString(signedBuf.Bytes())
	txHash := base58.Encode(hash[:])

	return signedTxBase64, txHash, nil
}

// broadcastTx sends a signed transaction via broadcast_tx_commit.
func (nc *NearClient) broadcastTx(ctx context.Context, signedTxBase64 string) (map[string]interface{}, error) {
	result, err := nc.rpcCall(ctx, "broadcast_tx_commit", []interface{}{signedTxBase64})
	if err != nil {
		return nil, fmt.Errorf("broadcast_tx_commit failed: %w", err)
	}

	var info map[string]interface{}
	if err := json.Unmarshal(result, &info); err != nil {
		return nil, fmt.Errorf("parsing broadcast result: %w", err)
	}

	return info, nil
}

// callViewFunction executes a read-only function call on a contract.
func (nc *NearClient) callViewFunction(ctx context.Context, contractID, method string, argsJSON []byte) ([]byte, error) {
	params := map[string]interface{}{
		"request_type": "call_function",
		"finality":     "final",
		"account_id":   contractID,
		"method_name":  method,
		"args_base64":  base64.StdEncoding.EncodeToString(argsJSON),
	}

	result, err := nc.rpcCall(ctx, "query", params)
	if err != nil {
		return nil, err
	}

	var viewResult struct {
		Result []byte `json:"result"`
		Logs   []string `json:"logs"`
	}
	if err := json.Unmarshal(result, &viewResult); err != nil {
		return nil, fmt.Errorf("parsing view result: %w", err)
	}

	return viewResult.Result, nil
}

// =============================================================================
// PRIVATE: JSON-RPC
// =============================================================================

// rpcCall makes a generic JSON-RPC call to the NEAR node.
func (nc *NearClient) rpcCall(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling RPC request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", nc.rpcEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := nc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading RPC response: %w", err)
	}

	var rpcResp struct {
		Result json.RawMessage        `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parsing RPC response: %w (body: %s)", err, string(respBody[:min(len(respBody), 200)]))
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s (data: %s)", rpcResp.Error.Code, rpcResp.Error.Message, string(rpcResp.Error.Data))
	}

	return rpcResp.Result, nil
}

// =============================================================================
// BORSH SERIALIZATION HELPERS
// =============================================================================

func borshWriteString(buf *bytes.Buffer, s string) {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(s)))
	buf.Write(lenBuf)
	buf.WriteString(s)
}

func borshWriteBytes(buf *bytes.Buffer, data []byte) {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
	buf.Write(lenBuf)
	buf.Write(data)
}

func borshWriteU32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
}

func borshWriteU64(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

func borshWriteU128(buf *bytes.Buffer, v *big.Int) {
	b := make([]byte, 16)
	if v != nil && v.Sign() > 0 {
		// Convert big-endian big.Int bytes to little-endian u128
		vBytes := v.Bytes()
		for i := 0; i < len(vBytes) && i < 16; i++ {
			b[i] = vBytes[len(vBytes)-1-i]
		}
	}
	buf.Write(b)
}

// =============================================================================
// NEAR-SPECIFIC DERIVATION HELPERS
// =============================================================================

// DeriveNearAccountOwnerBytes32 derives the full 32-byte keccak256 owner for NEAR.
// Returns the full hash as a 64-character hex string (no 0x prefix).
// This matches the API bridge's deriveOwnerBytes32() and is used as the NEAR
// implicit account ID format that the factory contract expects for `owner: AccountId`.
func DeriveNearAccountOwnerBytes32(adiURL string) string {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	return hex.EncodeToString(hash)
}

// DeriveNearAccountOwnerEth derives the EVM owner address from an ADI URL.
// Returns the checksummed EVM address (last 20 bytes of keccak256).
// Used for the `owner_eth` parameter of the factory contract.
func DeriveNearAccountOwnerEth(adiURL string) string {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	addr := common.BytesToAddress(hash[12:])
	return addr.Hex() // checksummed 0x... format
}

// DeriveNearAccountSalt derives the deterministic salt from an ADI URL.
// Truncated to 53 bits (% 2^53) for JSON number safety, matching the
// API bridge's deriveSafeSalt() which ensures the value fits in JS
// Number.MAX_SAFE_INTEGER. The NEAR contract expects salt: u64 via serde JSON.
func DeriveNearAccountSalt(adiURL string) uint64 {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	// Full 256-bit value as big.Int, then mod 2^53
	fullBig := new(big.Int).SetBytes(hash)
	mod53 := new(big.Int).Exp(big.NewInt(2), big.NewInt(53), nil)
	truncated := new(big.Int).Mod(fullBig, mod53)
	return truncated.Uint64()
}

// encodeBytes32AsBase64 converts a [32]byte to base64 string for NEAR JSON args.
func encodeBytes32AsBase64(data [32]byte) string {
	return base64.StdEncoding.EncodeToString(data[:])
}

// encodeBytesAsBase64 converts a byte slice to base64 string for NEAR JSON args.
func encodeBytesAsBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// encodeAddressAsHex converts a common.Address to hex string for NEAR JSON args.
func encodeAddressAsHex(addr common.Address) string {
	return "0x" + hex.EncodeToString(addr.Bytes())
}

