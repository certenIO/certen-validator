package execution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// =============================================================================
// APTOS CLIENT
// =============================================================================

// AptosClient handles Aptos blockchain interactions using the REST API.
// Uses Ed25519 signing, BCS serialization, and SHA3-256 hashing.
type AptosClient struct {
	rpcEndpoint    string
	privateKey     ed25519.PrivateKey // 64-byte Ed25519
	publicKey      ed25519.PublicKey  // 32-byte
	accountAddress string             // 0x + hex(SHA3-256(pubkey | 0x00))
	packageAddress string             // where all Move modules live
	httpClient     *http.Client

	// Sequence number tracking to avoid collisions on sequential transactions.
	seqNumMu   sync.Mutex
	lastSeqNum uint64
}

// Aptos constants
const (
	aptosTestnetChainID uint8  = 2
	aptosMaxGasAmount   uint64 = 500_000
	aptosGasUnitPrice   uint64 = 100
	aptosExpirationSecs uint64 = 600 // 10 minutes
)

// NewAptosClient creates an Aptos client from an RPC endpoint and Ed25519 private key.
// Key format: hex-encoded 32-byte seed (with or without 0x prefix).
func NewAptosClient(rpcEndpoint, privateKeyHex, packageAddress string) (*AptosClient, error) {
	rpcEndpoint = strings.TrimSuffix(rpcEndpoint, "/")
	rpcEndpoint = strings.TrimSuffix(rpcEndpoint, "/v1")

	// Strip common prefixes
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "ed25519-priv-")

	// Handle 64-byte keypair (seed+pubkey) — take first 32 bytes as seed
	seed, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to hex-decode Aptos private key: %w", err)
	}
	if len(seed) == 64 {
		seed = seed[:32]
	} else if len(seed) != 32 {
		return nil, fmt.Errorf("Aptos private key must be 32 or 64 bytes, got %d", len(seed))
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Derive account address: SHA3-256(pubkey | 0x00)
	hasher := sha3.New256()
	hasher.Write(pubKey)
	hasher.Write([]byte{0x00}) // single-key auth scheme
	addrBytes := hasher.Sum(nil)
	accountAddress := "0x" + hex.EncodeToString(addrBytes)

	log.Printf("🔑 [APTOS] Client created: account=%s package=%s", accountAddress, packageAddress)

	return &AptosClient{
		rpcEndpoint:    rpcEndpoint,
		privateKey:     privKey,
		publicKey:      pubKey,
		accountAddress: accountAddress,
		packageAddress: packageAddress,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetAccountAddress returns the derived account address.
func (ac *AptosClient) GetAccountAddress() string {
	return ac.accountAddress
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor calls create_anchor entry function on the anchor V5 module.
// V5: 9 args including executionCommitment (CRITICAL-001).
// Uses JSON submission via /encode_submission for reliable BCS encoding.
func (ac *AptosClient) CreateAnchor(
	ctx context.Context,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	blockHeight uint64,
) (string, error) {
	log.Printf("📡 [APTOS] Creating anchor (V6.1)...")
	log.Printf("   Account: %s", ac.accountAddress)
	log.Printf("   Package: %s", ac.packageAddress)
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])
	log.Printf("   ADI URL Hash: 0x%x", adiURLHash[:8])
	log.Printf("   Op Commitment: 0x%x", operationCommitment[:8])
	log.Printf("   CC Commitment: 0x%x", crossChainCommitment[:8])
	log.Printf("   Gov Root: 0x%x", governanceRoot[:8])
	log.Printf("   Exec Commitment: 0x%x", executionCommitment[:8])
	log.Printf("   Block Height: %d", blockHeight)

	seqNum, err := ac.getSequenceNumber(ctx)
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: getting sequence number: %w", err)
	}
	log.Printf("   Sequence Number: %d", seqNum)

	function := fmt.Sprintf("%s::certen_anchor_v6_1::create_anchor", ac.packageAddress)

	payload := map[string]interface{}{
		"type":           "entry_function_payload",
		"function":       function,
		"type_arguments": []string{},
		"arguments": []interface{}{
			ac.packageAddress,                         // anchor_owner: address (AnchorStateV5 lives at package address)
			bytes32ToU256String(bundleId),             // bundle_id: u256
			bytes32ToU256String(adiURLHash),           // adi_url_hash: u256
			bytes32ToU256String(operationCommitment),  // operation_commitment: u256
			bytes32ToU256String(crossChainCommitment), // cross_chain_commitment: u256
			bytes32ToU256String(governanceRoot),       // governance_root: u256
			bytes32ToU256String(executionCommitment),  // execution_commitment: u256 (CRITICAL-001)
			bytes32ToU256String(operationID),          // operation_id: u256 (V6.1)
			fmt.Sprintf("%d", blockHeight),            // accumulate_block_height: u64
		},
	}

	txn := map[string]interface{}{
		"sender":                    ac.accountAddress,
		"sequence_number":           fmt.Sprintf("%d", seqNum),
		"max_gas_amount":            fmt.Sprintf("%d", aptosMaxGasAmount),
		"gas_unit_price":            fmt.Sprintf("%d", aptosGasUnitPrice),
		"expiration_timestamp_secs": fmt.Sprintf("%d", time.Now().Unix()+int64(aptosExpirationSecs)),
		"payload":                   payload,
	}

	log.Printf("📡 [APTOS] Submitting create_anchor via JSON/encode_submission (seqNum=%d)", seqNum)

	txHash, err := ac.signAndSubmitJSON(ctx, txn)
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [APTOS] Anchor created: txHash=%s", txHash)
	return txHash, nil
}

// InitializeAnchorState calls initialize(owner, network) on the anchor V6.1 module.
// V6.1: network is a vector<u8> ("testnet"/"mainnet") from which the contract
// derives deployment_chain_id = keccak256("certen:chain:v1:aptos:" || network).
// Safe to call multiple times — returns nil if already initialized.
func (ac *AptosClient) InitializeAnchorState(ctx context.Context) error {
	log.Printf("📡 [APTOS] Initializing anchor state V6.1 for %s...", ac.accountAddress)

	seqNum, err := ac.getSequenceNumber(ctx)
	if err != nil {
		return fmt.Errorf("initialize: getting sequence number: %w", err)
	}

	function := fmt.Sprintf("%s::certen_anchor_v6_1::initialize", ac.packageAddress)

	payload := map[string]interface{}{
		"type":           "entry_function_payload",
		"function":       function,
		"type_arguments": []string{},
		"arguments":      []interface{}{"0x" + hex.EncodeToString([]byte("testnet"))}, // network: vector<u8> (V6.1)
	}

	txn := map[string]interface{}{
		"sender":                    ac.accountAddress,
		"sequence_number":           fmt.Sprintf("%d", seqNum),
		"max_gas_amount":            fmt.Sprintf("%d", aptosMaxGasAmount),
		"gas_unit_price":            fmt.Sprintf("%d", aptosGasUnitPrice),
		"expiration_timestamp_secs": fmt.Sprintf("%d", time.Now().Unix()+int64(aptosExpirationSecs)),
		"payload":                   payload,
	}

	txHash, err := ac.signAndSubmitJSON(ctx, txn)
	if err != nil {
		// Check if already initialized (E_ALREADY_INITIALIZED = 2)
		if strings.Contains(err.Error(), "ALREADY_INITIALIZED") ||
			strings.Contains(err.Error(), "0x2") ||
			strings.Contains(err.Error(), "Move abort") {
			log.Printf("✅ [APTOS] Anchor state already initialized")
			return nil
		}
		return fmt.Errorf("initialize failed: %w", err)
	}

	log.Printf("⏳ [APTOS] Waiting for initialize confirmation: %s", txHash)
	waitErr := ac.WaitForConfirmation(ctx, txHash, 30*time.Second)
	if waitErr != nil {
		// If the tx failed with ALREADY_INITIALIZED, that's fine
		if strings.Contains(waitErr.Error(), "ALREADY_INITIALIZED") ||
			strings.Contains(waitErr.Error(), "0x2") {
			log.Printf("✅ [APTOS] Anchor state already initialized (confirmed)")
			return nil
		}
		return fmt.Errorf("initialize confirmation failed: %w", waitErr)
	}

	log.Printf("✅ [APTOS] Anchor state initialized successfully")
	return nil
}

// =============================================================================
// STEP 2: EXECUTE COMPREHENSIVE PROOF
// =============================================================================

// AptosCertenProof holds the proof data for comprehensive proof verification.
// These fields map to the Move CertenProof struct constructors.
type AptosCertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte

	// GovernanceProofData fields
	GovKeyBookURL         string
	GovKeyBookRoot        [32]byte
	GovKeyPageProofs      [][32]byte
	GovAuthorityAddress   string // 0x+64hex address
	GovAuthorityLevel     uint8
	GovNonce              uint64
	GovRequiredSignatures uint64
	GovProvidedSignatures uint64

	// BLSProofData fields
	BLSProofBytes           []byte
	BLSMessageHash          []byte
	BLSPubkeyCommitment     []byte
	BLSSignedVotingPower    uint64
	BLSTotalVotingPower     uint64
	BLSThresholdNumerator   uint64
	BLSThresholdDenominator uint64
	BLSValidatorAddresses   []string // 0x+64hex addresses

	// CommitmentData fields
	CommitOperationCommitment  [32]byte
	CommitCrossChainCommitment [32]byte
	CommitGovernanceRoot       [32]byte
	CommitSourceChain          string
	CommitSourceBlockHeight    uint64
	CommitSourceTxHash         [32]byte
	CommitTargetChain          string
	CommitTargetAddress        string // 0x+64hex address

	ExpirationTimeSecs uint64
	Metadata           []byte
}

// submitComprehensiveProofBCS submits a comprehensive proof via the REST API JSON approach.
// Since execute_comprehensive_proof_strict is a `public fun` (not `entry`) that takes
// a CertenProof struct, we call the flat entry function variant which accepts all fields
// individually and constructs the struct internally.
func (ac *AptosClient) submitComprehensiveProofBCS(
	ctx context.Context,
	anchorId [32]byte,
	proof AptosCertenProof,
) (string, error) {
	log.Printf("📡 [APTOS] Step 2: Submitting comprehensive proof...")
	log.Printf("   Anchor ID: 0x%x", anchorId[:8])
	log.Printf("   Tx Hash: 0x%x", proof.TransactionHash[:8])
	log.Printf("   Merkle Root: 0x%x", proof.MerkleRoot[:8])
	log.Printf("   Proof Hashes: %d", len(proof.ProofHashes))
	log.Printf("   Gov Key Book: %s", proof.GovKeyBookURL)
	log.Printf("   Gov Authority: %s", proof.GovAuthorityAddress)
	log.Printf("   BLS Proof Bytes: %d bytes", len(proof.BLSProofBytes))
	log.Printf("   BLS Validators: %d", len(proof.BLSValidatorAddresses))
	log.Printf("   Target Chain: %s", proof.CommitTargetChain)
	log.Printf("   Target Address: %s", proof.CommitTargetAddress)

	seqNum, err := ac.getSequenceNumber(ctx)
	if err != nil {
		return "", err
	}
	log.Printf("   Sequence Number: %d", seqNum)

	// Build proof hashes vector
	proofHashesHex := make([]string, len(proof.ProofHashes))
	for i, h := range proof.ProofHashes {
		proofHashesHex[i] = bytes32ToU256String(h)
	}

	keyPageProofsHex := make([]string, len(proof.GovKeyPageProofs))
	for i, h := range proof.GovKeyPageProofs {
		keyPageProofsHex[i] = bytes32ToU256String(h)
	}

	blsValidators := proof.BLSValidatorAddresses
	if len(blsValidators) == 0 {
		blsValidators = []string{ac.accountAddress}
	}

	// Call the flat entry function variant that accepts all proof fields individually
	payload := map[string]interface{}{
		"type":           "entry_function_payload",
		"function":       fmt.Sprintf("%s::certen_anchor_v6_1::execute_comprehensive_proof_flat", ac.packageAddress),
		"type_arguments": []string{},
		"arguments": []interface{}{
			ac.packageAddress,                          // anchor_owner: address (AnchorState lives at package address)
			bytes32ToU256String(anchorId),              // anchor_id: u256
			bytes32ToU256String(proof.TransactionHash), // transaction_hash: u256
			bytes32ToU256String(proof.MerkleRoot),      // merkle_root: u256
			proofHashesHex,                             // proof_hashes: vector<u256>
			bytes32ToU256String(proof.LeafHash),        // leaf_hash: u256
			// GovernanceProofData fields
			"0x" + hex.EncodeToString([]byte(proof.GovKeyBookURL)), // gov_key_book_url: vector<u8>
			bytes32ToU256String(proof.GovKeyBookRoot),              // gov_key_book_root: u256
			keyPageProofsHex,                               // gov_key_page_proofs: vector<u256>
			proof.GovAuthorityAddress,                      // gov_authority_address: address
			uint8(proof.GovAuthorityLevel),                 // gov_authority_level: u8 (JSON number, not string)
			fmt.Sprintf("%d", proof.GovNonce),              // gov_nonce: u64
			fmt.Sprintf("%d", proof.GovRequiredSignatures), // gov_required_signatures: u64
			fmt.Sprintf("%d", proof.GovProvidedSignatures), // gov_provided_signatures: u64
			// BLSProofData fields
			"0x" + hex.EncodeToString(proof.BLSProofBytes),       // bls_proof_bytes: vector<u8>
			"0x" + hex.EncodeToString(proof.BLSMessageHash),      // bls_message_hash: vector<u8>
			"0x" + hex.EncodeToString(proof.BLSPubkeyCommitment), // bls_pubkey_commitment: vector<u8>
			fmt.Sprintf("%d", proof.BLSSignedVotingPower),        // bls_signed_voting_power: u64
			fmt.Sprintf("%d", proof.BLSTotalVotingPower),         // bls_total_voting_power: u64
			fmt.Sprintf("%d", proof.BLSThresholdNumerator),       // bls_threshold_numerator: u64
			fmt.Sprintf("%d", proof.BLSThresholdDenominator),     // bls_threshold_denominator: u64
			blsValidators, // bls_validator_addresses: vector<address>
			// CommitmentData fields
			bytes32ToU256String(proof.CommitOperationCommitment),       // commit_operation_commitment: u256
			bytes32ToU256String(proof.CommitCrossChainCommitment),      // commit_cross_chain_commitment: u256
			bytes32ToU256String(proof.CommitGovernanceRoot),            // commit_governance_root: u256
			"0x" + hex.EncodeToString([]byte(proof.CommitSourceChain)), // commit_source_chain: vector<u8>
			fmt.Sprintf("%d", proof.CommitSourceBlockHeight),           // commit_source_block_height: u64
			bytes32ToU256String(proof.CommitSourceTxHash),              // commit_source_tx_hash: u256
			"0x" + hex.EncodeToString([]byte(proof.CommitTargetChain)), // commit_target_chain: vector<u8>
			proof.CommitTargetAddress,                                  // commit_target_address: address
			// Top-level fields
			fmt.Sprintf("%d", proof.ExpirationTimeSecs), // expiration_time_secs: u64
			"0x" + hex.EncodeToString(proof.Metadata),   // metadata: vector<u8>
		},
	}

	txn := map[string]interface{}{
		"sender":                    ac.accountAddress,
		"sequence_number":           fmt.Sprintf("%d", seqNum),
		"max_gas_amount":            fmt.Sprintf("%d", aptosMaxGasAmount),
		"gas_unit_price":            fmt.Sprintf("%d", aptosGasUnitPrice),
		"expiration_timestamp_secs": fmt.Sprintf("%d", time.Now().Unix()+int64(aptosExpirationSecs)),
		"payload":                   payload,
	}

	return ac.signAndSubmitJSON(ctx, txn)
}

// =============================================================================
// STEP 3: EXECUTE GOVERNANCE PROOF DIRECT
// =============================================================================

// AptosADIGovernanceProof holds the governance proof for Step 3.
type AptosADIGovernanceProof struct {
	AdiURL        string
	AnchorID      [32]byte
	MerkleProof   [][32]byte
	Timestamp     uint64
	ExpiresAt     uint64
	Nonce         uint64
	RequiredLevel uint8

	// BLS fields (passed through for re-verification)
	BLSProofBytes           []byte
	BLSMessageHash          []byte
	BLSPubkeyCommitment     []byte
	BLSSignedVotingPower    uint64
	BLSTotalVotingPower     uint64
	BLSThresholdNumerator   uint64
	BLSThresholdDenominator uint64
	BLSValidatorAddresses   []string
}

// ExecuteGovernanceProofDirect calls execute_governance_proof_direct on the user's
// resource account. This is Step 3 — verifies governance proof and executes transfer.
func (ac *AptosClient) ExecuteGovernanceProofDirect(
	ctx context.Context,
	userAccountAddr string,
	recipientAddr string,
	amountOctas uint64,
	proof AptosADIGovernanceProof,
) (string, error) {
	log.Printf("📡 [APTOS] Executing governance proof direct on account %s...", userAccountAddr)
	log.Printf("   Target: %s", recipientAddr)
	log.Printf("   Amount: %d octas", amountOctas)

	// execute_governance_proof_direct(relayer, account_addr, operation_type, target, value_octas, operation_data, proof)
	// This is a public fun — we need to call it via script or a flat entry function wrapper.
	// For Aptos, the practical approach is to use the flat entry function variant if available,
	// or call via script payload.

	// Use the flat entry function approach via REST API JSON
	seqNum, err := ac.getSequenceNumber(ctx)
	if err != nil {
		return "", err
	}

	// Merkle proof as vector of hex-encoded 32-byte hashes
	merkleProofHex := make([]string, len(proof.MerkleProof))
	for i, h := range proof.MerkleProof {
		merkleProofHex[i] = "0x" + hex.EncodeToString(h[:])
	}

	blsValidators := proof.BLSValidatorAddresses
	if len(blsValidators) == 0 {
		blsValidators = []string{ac.accountAddress}
	}

	// OP_APT_TRANSFER = 0x00000001
	operationType := uint32(1)

	payload := map[string]interface{}{
		"type":           "entry_function_payload",
		"function":       fmt.Sprintf("%s::certen_account_v4::execute_governance_proof_direct_flat", ac.packageAddress),
		"type_arguments": []string{},
		"arguments": []interface{}{
			userAccountAddr,                // account_addr: address
			uint32(operationType),          // operation_type: u32 (JSON number, not string)
			recipientAddr,                  // target: address
			fmt.Sprintf("%d", amountOctas), // value_octas: u64
			"0x",                           // operation_data: vector<u8> (empty)
			// ADIGovernanceProof fields (flattened)
			"0x" + hex.EncodeToString([]byte(proof.AdiURL)), // adi_url: vector<u8>
			"0x" + hex.EncodeToString(proof.AnchorID[:]),    // anchor_id: vector<u8>
			merkleProofHex,                                       // merkle_proof: vector<vector<u8>>
			fmt.Sprintf("%d", proof.Timestamp),                   // timestamp_secs: u64
			fmt.Sprintf("%d", proof.ExpiresAt),                   // expires_at_secs: u64
			"0x" + hex.EncodeToString(proof.BLSProofBytes),       // bls_proof_bytes: vector<u8>
			"0x" + hex.EncodeToString(proof.BLSMessageHash),      // bls_message_hash: vector<u8>
			"0x" + hex.EncodeToString(proof.BLSPubkeyCommitment), // bls_pubkey_commitment: vector<u8>
			fmt.Sprintf("%d", proof.BLSSignedVotingPower),        // bls_signed_voting_power: u64
			fmt.Sprintf("%d", proof.BLSTotalVotingPower),         // bls_total_voting_power: u64
			fmt.Sprintf("%d", proof.BLSThresholdNumerator),       // bls_threshold_numerator: u64
			fmt.Sprintf("%d", proof.BLSThresholdDenominator),     // bls_threshold_denominator: u64
			blsValidators,                  // validator_addresses: vector<address>
			fmt.Sprintf("%d", proof.Nonce), // nonce: u64
			uint8(proof.RequiredLevel),     // required_level: u8 (JSON number, not string)
		},
	}

	txn := map[string]interface{}{
		"sender":                    ac.accountAddress,
		"sequence_number":           fmt.Sprintf("%d", seqNum),
		"max_gas_amount":            fmt.Sprintf("%d", aptosMaxGasAmount),
		"gas_unit_price":            fmt.Sprintf("%d", aptosGasUnitPrice),
		"expiration_timestamp_secs": fmt.Sprintf("%d", time.Now().Unix()+int64(aptosExpirationSecs)),
		"payload":                   payload,
	}

	txHash, err := ac.signAndSubmitJSON(ctx, txn)
	if err != nil {
		return "", fmt.Errorf("execute_governance_proof_direct failed: %w", err)
	}

	log.Printf("✅ [APTOS] Governance proof direct executed: txHash=%s", txHash)
	return txHash, nil
}

// =============================================================================
// ACCOUNT OPERATIONS
// =============================================================================

// DeployAccountViaFactory calls create_account on the factory module.
func (ac *AptosClient) DeployAccountViaFactory(
	ctx context.Context,
	owner string, // 0x+64hex address
	adiURL string,
	salt uint64,
) (string, error) {
	log.Printf("📡 [APTOS] Deploying account via factory...")
	log.Printf("   Owner: %s", owner)
	log.Printf("   ADI URL: %s", adiURL)
	log.Printf("   Salt: %d", salt)

	// create_account(caller, factory_addr, owner, adi_url: vector<u8>, salt: u64)
	function := fmt.Sprintf("%s::certen_account_factory_v3::create_account", ac.packageAddress)

	args := [][]byte{
		bcsAddress(ac.packageAddress), // factory_addr: address
		bcsAddress(owner),             // owner: address
		bcsVectorU8([]byte(adiURL)),   // adi_url: vector<u8>
		bcsU64(salt),                  // salt: u64
	}

	txHash, err := ac.submitEntryFunction(ctx, function, nil, args, aptosMaxGasAmount)
	if err != nil {
		return "", fmt.Errorf("factory create_account failed: %w", err)
	}

	log.Printf("✅ [APTOS] Account deployment submitted: txHash=%s", txHash)
	return txHash, nil
}

// PredictAccountAddress computes the factory-deployed resource account address locally.
// Replicates the Move logic: seed = BCS(owner) + adi_url + BCS(salt) + BCS(anchor_contract)
// address = SHA3-256(deployer_address + seed + 0xFF)
func (ac *AptosClient) PredictAccountAddress(
	ctx context.Context,
	owner string,
	adiURL string,
	salt uint64,
) (string, error) {
	// Fetch FactoryStateV2 to get deployer_address and anchor_contract
	resourceType := fmt.Sprintf("%s::certen_account_factory_v3::FactoryStateV2", ac.packageAddress)
	url := fmt.Sprintf("%s/v1/accounts/%s/resource/%s", ac.rpcEndpoint, ac.packageAddress, resourceType)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching FactoryState: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("FactoryState fetch failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var resource struct {
		Data struct {
			DeployerAddress string `json:"deployer_address"`
			AnchorContract  string `json:"anchor_contract"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resource); err != nil {
		return "", fmt.Errorf("parsing FactoryState: %w", err)
	}

	deployerAddr := strings.TrimPrefix(resource.Data.DeployerAddress, "0x")
	anchorContract := strings.TrimPrefix(resource.Data.AnchorContract, "0x")
	ownerClean := strings.TrimPrefix(owner, "0x")

	// Pad to 64 hex chars (32 bytes)
	for len(deployerAddr) < 64 {
		deployerAddr = "0" + deployerAddr
	}
	for len(anchorContract) < 64 {
		anchorContract = "0" + anchorContract
	}
	for len(ownerClean) < 64 {
		ownerClean = "0" + ownerClean
	}

	deployerBytes, err := hex.DecodeString(deployerAddr)
	if err != nil {
		return "", fmt.Errorf("decoding deployer address: %w", err)
	}
	ownerBytes, err := hex.DecodeString(ownerClean)
	if err != nil {
		return "", fmt.Errorf("decoding owner: %w", err)
	}
	anchorBytes, err := hex.DecodeString(anchorContract)
	if err != nil {
		return "", fmt.Errorf("decoding anchor contract: %w", err)
	}

	// Build seed: BCS(owner) + adi_url_raw + BCS(salt) + BCS(anchor_contract)
	// BCS for address = 32 bytes as-is; BCS for u64 = 8 bytes little-endian
	seed := make([]byte, 0, 32+len(adiURL)+8+32)
	seed = append(seed, ownerBytes...)
	seed = append(seed, []byte(adiURL)...)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)
	seed = append(seed, saltBytes...)
	seed = append(seed, anchorBytes...)

	// create_resource_address: SHA3-256(deployer + seed + 0xFF)
	hasher := sha3.New256()
	hasher.Write(deployerBytes)
	hasher.Write(seed)
	hasher.Write([]byte{0xFF})
	addrBytes := hasher.Sum(nil)

	addr := "0x" + hex.EncodeToString(addrBytes)
	log.Printf("✅ [APTOS] Predicted account address: %s (deployer=%s)", addr, resource.Data.DeployerAddress)
	return addr, nil
}

// CheckAccountExists checks if a certen abstract account is initialized on-chain.
// It checks for the AccountState resource, not just account existence (resource accounts
// can exist without being initialized by the factory).
func (ac *AptosClient) CheckAccountExists(ctx context.Context, addr string) (bool, error) {
	resourceType := fmt.Sprintf("%s::certen_account_v4::AccountStateV3", ac.packageAddress)
	url := fmt.Sprintf("%s/v1/accounts/%s/resource/%s", ac.rpcEndpoint, addr, resourceType)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("account check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("account check failed (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	return true, nil
}

// GetAPTBalance returns the address's APT balance in octas via the migration-aware
// 0x1::coin::balance view (handles both CoinStore and the fungible-asset primary
// store). Used to cryptographically confirm the Step-3 transfer credited the
// recipient — note execute_apt_transfer returns false (no abort) on insufficient
// balance, so a "successful" tx alone does NOT prove the funds moved; the recipient
// balance delta does.
func (ac *AptosClient) GetAPTBalance(ctx context.Context, addr string) (uint64, error) {
	res, err := ac.callViewFunction(ctx, "0x1::coin::balance", []string{"0x1::aptos_coin::AptosCoin"}, []interface{}{addr})
	if err != nil {
		return 0, err
	}
	var arr []string
	if err := json.Unmarshal(res, &arr); err != nil || len(arr) == 0 {
		return 0, fmt.Errorf("parse APT balance: %w", err)
	}
	bal, err := strconv.ParseUint(strings.TrimSpace(arr[0]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("APT balance %q not numeric: %w", arr[0], err)
	}
	return bal, nil
}

// ConfirmRecipientCredited cryptographically confirms the Step-3 transfer credited
// the recipient by polling its APT balance until it rises at least minDelta octas
// above the pre-transfer baseline. This is the on-chain proof the funds actually
// moved (the governance tx can succeed without transferring when the account's
// balance is insufficient).
func (ac *AptosClient) ConfirmRecipientCredited(ctx context.Context, recipientAddr string, baseline uint64, minDelta uint64, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		bal, err := ac.GetAPTBalance(ctx, recipientAddr)
		if err == nil && bal >= baseline+minDelta {
			return bal, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return 0, fmt.Errorf("recipient %s APT balance did not rise by >= %d octas above %d within %v", recipientAddr, minDelta, baseline, timeout)
}

// =============================================================================
// READ OPERATIONS
// =============================================================================

// AptosAnchorData holds anchor data read from the Aptos contract.
type AptosAnchorData struct {
	BundleId             [32]byte
	MerkleRoot           [32]byte
	AdiURLHash           [32]byte
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	BlockHeight          uint64
	Timestamp            uint64
	Validator            string
	ProofExecuted        bool
	Invalidated          bool
}

// GetAnchorData reads anchor data via the get_anchor view function.
func (ac *AptosClient) GetAnchorData(ctx context.Context, bundleId [32]byte) (*AptosAnchorData, error) {
	function := fmt.Sprintf("%s::certen_anchor_v6_1::get_anchor_v5", ac.packageAddress)

	result, err := ac.callViewFunction(ctx, function, nil, []interface{}{
		ac.packageAddress,             // anchor_owner: address (AnchorState lives at package address)
		bytes32ToU256String(bundleId), // bundle_id: u256
	})
	if err != nil {
		return nil, fmt.Errorf("get_anchor view call failed: %w", err)
	}

	// Parse the Option<Anchor> result.
	// Aptos serializes Option<T> as {"vec": [<value>]} for Some or {"vec": []} for None.
	var resultArr []interface{}
	if err := json.Unmarshal(result, &resultArr); err != nil {
		return nil, fmt.Errorf("parsing view result: %w", err)
	}

	if len(resultArr) == 0 {
		return nil, fmt.Errorf("anchor not found")
	}

	// Unwrap the Option: resultArr[0] = {"vec": [<anchor_data>]}
	optionMap, ok := resultArr[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected anchor format: %T", resultArr[0])
	}

	vecArr, ok := optionMap["vec"].([]interface{})
	if !ok || len(vecArr) == 0 {
		return nil, fmt.Errorf("anchor not found (Option::None)")
	}

	anchorMap, ok := vecArr[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected anchor data format: %T", vecArr[0])
	}

	anchor := &AptosAnchorData{}

	// Parse fields from the anchor map
	if v, ok := anchorMap["bundle_id"].(string); ok {
		u256ToBytes32(v, &anchor.BundleId)
	}
	if v, ok := anchorMap["merkle_root"].(string); ok {
		u256ToBytes32(v, &anchor.MerkleRoot)
	}
	if v, ok := anchorMap["adi_url_hash"].(string); ok {
		u256ToBytes32(v, &anchor.AdiURLHash)
	}
	if v, ok := anchorMap["operation_commitment"].(string); ok {
		u256ToBytes32(v, &anchor.OperationCommitment)
	}
	if v, ok := anchorMap["cross_chain_commitment"].(string); ok {
		u256ToBytes32(v, &anchor.CrossChainCommitment)
	}
	if v, ok := anchorMap["governance_root"].(string); ok {
		u256ToBytes32(v, &anchor.GovernanceRoot)
	}
	if v, ok := anchorMap["accumulate_block_height"].(string); ok {
		fmt.Sscanf(v, "%d", &anchor.BlockHeight)
	}
	if v, ok := anchorMap["timestamp_secs"].(string); ok {
		fmt.Sscanf(v, "%d", &anchor.Timestamp)
	}
	if v, ok := anchorMap["validator"].(string); ok {
		anchor.Validator = v
	}
	if v, ok := anchorMap["proof_executed"].(bool); ok {
		anchor.ProofExecuted = v
	}
	if v, ok := anchorMap["valid"].(bool); ok {
		anchor.Invalidated = !v
	}

	log.Printf("✅ [APTOS] Anchor read-back: bundleId=0x%x proofExecuted=%v",
		anchor.BundleId[:8], anchor.ProofExecuted)

	return anchor, nil
}

// =============================================================================
// TRANSACTION CONFIRMATION
// =============================================================================

// WaitForConfirmation polls for transaction confirmation.
func (ac *AptosClient) WaitForConfirmation(ctx context.Context, txHash string, timeout time.Duration) error {
	log.Printf("⏳ [APTOS] Waiting for confirmation: %s (timeout=%v)", txHash, timeout)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		url := fmt.Sprintf("%s/v1/transactions/by_hash/%s", ac.rpcEndpoint, txHash)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}

		resp, err := ac.httpClient.Do(req)
		if err != nil {
			log.Printf("⚠️ [APTOS] Polling tx status: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 404 {
			// Transaction not yet indexed
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		var txInfo map[string]interface{}
		if err := json.Unmarshal(body, &txInfo); err != nil {
			log.Printf("⚠️ [APTOS] Failed to parse tx result: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Check for success
		if success, ok := txInfo["success"].(bool); ok {
			if success {
				log.Printf("✅ [APTOS] Transaction confirmed: %s", txHash)
				return nil
			}
			// Transaction failed
			vmStatus := txInfo["vm_status"]
			return fmt.Errorf("transaction failed: %v", vmStatus)
		}

		// Not yet finalized
		if txType, ok := txInfo["type"].(string); ok && txType == "pending_transaction" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return fmt.Errorf("transaction %s not confirmed after %v", txHash, timeout)
}

// =============================================================================
// PRIVATE: TRANSACTION BUILDING & SUBMISSION
// =============================================================================

// getSequenceNumber fetches the current sequence number for the account.
func (ac *AptosClient) getSequenceNumber(ctx context.Context) (uint64, error) {
	ac.seqNumMu.Lock()
	defer ac.seqNumMu.Unlock()

	url := fmt.Sprintf("%s/v1/accounts/%s", ac.rpcEndpoint, ac.accountAddress)
	log.Printf("📡 [APTOS] GET %s", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("account info request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading account info: %w", err)
	}

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("account info failed (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var accountInfo struct {
		SequenceNumber string `json:"sequence_number"`
	}
	if err := json.Unmarshal(body, &accountInfo); err != nil {
		return 0, fmt.Errorf("parsing account info: %w", err)
	}

	var seqNum uint64
	fmt.Sscanf(accountInfo.SequenceNumber, "%d", &seqNum)

	// Use the higher of RPC sequence number or locally tracked number.
	// lastSeqNum tracks the NEXT expected seqNum after our last submission.
	// Only override if we've submitted beyond what the RPC knows about.
	if ac.lastSeqNum > seqNum {
		seqNum = ac.lastSeqNum
	}
	ac.lastSeqNum = seqNum + 1

	return seqNum, nil
}

// submitEntryFunction builds, signs, and submits an entry function transaction via BCS.
func (ac *AptosClient) submitEntryFunction(
	ctx context.Context,
	function string, // e.g. "0xpkg::module::function"
	typeArgs []string,
	args [][]byte, // BCS-encoded arguments
	maxGas uint64,
) (string, error) {
	seqNum, err := ac.getSequenceNumber(ctx)
	if err != nil {
		return "", fmt.Errorf("getting sequence number: %w", err)
	}

	expiration := uint64(time.Now().Unix()) + aptosExpirationSecs

	log.Printf("📡 [APTOS] TX seqNum=%d function=%s", seqNum, function)

	// Build BCS-encoded RawTransaction
	rawTxBytes := ac.bcsEncodeRawTransaction(seqNum, maxGas, aptosGasUnitPrice, expiration, function, typeArgs, args)

	// Signing message = SHA3-256("APTOS::RawTransaction") || rawTxBytes
	// Ed25519 signs this concatenation directly (no extra hash).
	prefixHasher := sha3.New256()
	prefixHasher.Write([]byte("APTOS::RawTransaction"))
	prefix := prefixHasher.Sum(nil)

	var signingMsg bytes.Buffer
	signingMsg.Write(prefix)
	signingMsg.Write(rawTxBytes)

	// Sign with Ed25519
	signature := ed25519.Sign(ac.privateKey, signingMsg.Bytes())

	// Submit via REST API using BCS-encoded signed transaction
	// Build SignedTransaction: RawTransaction + Authenticator
	var signedBuf bytes.Buffer
	signedBuf.Write(rawTxBytes)
	// Authenticator: Ed25519 = variant 0
	signedBuf.WriteByte(0) // AccountAuthenticator::Ed25519
	// Ed25519PublicKey: BCS bytes with ULEB128 length prefix
	bcsWriteULEB128(&signedBuf, 32)
	signedBuf.Write(ac.publicKey[:32])
	// Ed25519Signature: BCS bytes with ULEB128 length prefix
	bcsWriteULEB128(&signedBuf, 64)
	signedBuf.Write(signature[:64])

	return ac.submitBCSTransaction(ctx, signedBuf.Bytes())
}

// bcsEncodeRawTransaction encodes a RawTransaction in BCS format.
func (ac *AptosClient) bcsEncodeRawTransaction(
	seqNum, maxGas, gasUnitPrice, expiration uint64,
	function string,
	typeArgs []string,
	args [][]byte,
) []byte {
	var buf bytes.Buffer

	// sender: address (32 bytes)
	senderBytes, _ := hex.DecodeString(strings.TrimPrefix(ac.accountAddress, "0x"))
	if len(senderBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(senderBytes):], senderBytes)
		senderBytes = padded
	}
	buf.Write(senderBytes)

	// sequence_number: u64
	bcsWriteU64LE(&buf, seqNum)

	// payload: TransactionPayload::EntryFunction (variant 2)
	bcsWriteULEB128(&buf, 2)

	// EntryFunction:
	// module: ModuleId { address, name }
	// Parse "0xaddr::module::function" into parts
	parts := strings.SplitN(function, "::", 3)
	if len(parts) != 3 {
		log.Printf("⚠️ [APTOS] Invalid function format: %s", function)
		return buf.Bytes()
	}

	moduleAddr := parts[0]
	moduleName := parts[1]
	funcName := parts[2]

	// module.address (32 bytes)
	addrBytes, _ := hex.DecodeString(strings.TrimPrefix(moduleAddr, "0x"))
	if len(addrBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(addrBytes):], addrBytes)
		addrBytes = padded
	}
	buf.Write(addrBytes)

	// module.name: Identifier (ULEB128 length + bytes)
	bcsWriteString(&buf, moduleName)

	// function.name: Identifier
	bcsWriteString(&buf, funcName)

	// type_arguments: Vec<TypeTag>
	if typeArgs == nil {
		bcsWriteULEB128(&buf, 0)
	} else {
		bcsWriteULEB128(&buf, uint64(len(typeArgs)))
		// TypeTag encoding would go here for each type arg
	}

	// arguments: Vec<Vec<u8>> (each arg is already BCS-encoded)
	bcsWriteULEB128(&buf, uint64(len(args)))
	for _, arg := range args {
		bcsWriteULEB128(&buf, uint64(len(arg)))
		buf.Write(arg)
	}

	// max_gas_amount: u64
	bcsWriteU64LE(&buf, maxGas)

	// gas_unit_price: u64
	bcsWriteU64LE(&buf, gasUnitPrice)

	// expiration_timestamp_secs: u64
	bcsWriteU64LE(&buf, expiration)

	// chain_id: u8
	buf.WriteByte(aptosTestnetChainID)

	return buf.Bytes()
}

// submitBCSTransaction submits a BCS-encoded signed transaction to the Aptos REST API.
func (ac *AptosClient) submitBCSTransaction(ctx context.Context, signedTxBytes []byte) (string, error) {
	url := fmt.Sprintf("%s/v1/transactions", ac.rpcEndpoint)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(signedTxBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x.aptos.signed_transaction+bcs")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("submit transaction request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading submit response: %w", err)
	}

	if resp.StatusCode != 202 && resp.StatusCode != 200 {
		return "", fmt.Errorf("submit transaction failed (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 500)]))
	}

	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing submit result: %w", err)
	}

	return result.Hash, nil
}

// signAndSubmitJSON signs and submits a JSON-encoded transaction via the REST API.
// Uses the /transactions/encode_submission + sign + /transactions flow.
// This is the most reliable approach since Aptos handles BCS encoding internally.
func (ac *AptosClient) signAndSubmitJSON(ctx context.Context, txn map[string]interface{}) (string, error) {
	// Step 1: Encode for signing
	encodeURL := fmt.Sprintf("%s/v1/transactions/encode_submission", ac.rpcEndpoint)

	txnJSON, err := json.Marshal(txn)
	if err != nil {
		return "", fmt.Errorf("marshaling transaction: %w", err)
	}

	log.Printf("📡 [APTOS-JSON] Step 1/3: POST %s", encodeURL)
	log.Printf("   Request body (%d bytes): %s", len(txnJSON), string(txnJSON[:min(len(txnJSON), 500)]))

	req, err := http.NewRequestWithContext(ctx, "POST", encodeURL, bytes.NewReader(txnJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("encode_submission request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading encode response: %w", err)
	}

	log.Printf("   encode_submission response (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 200)]))

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("encode_submission failed (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 500)]))
	}

	// Response is a hex-encoded byte string to sign
	var encodedHex string
	if err := json.Unmarshal(body, &encodedHex); err != nil {
		return "", fmt.Errorf("parsing encoded submission: %w", err)
	}

	msgBytes, err := hex.DecodeString(strings.TrimPrefix(encodedHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decoding encoded submission: %w", err)
	}

	log.Printf("📡 [APTOS-JSON] Step 2/3: Signing %d bytes with Ed25519 (pubkey=0x%s...)", len(msgBytes), hex.EncodeToString(ac.publicKey[:8]))

	// Step 2: Sign with Ed25519
	signature := ed25519.Sign(ac.privateKey, msgBytes)

	log.Printf("   Signature: 0x%s...", hex.EncodeToString(signature[:16]))

	// Step 3: Submit with signature
	txn["signature"] = map[string]interface{}{
		"type":       "ed25519_signature",
		"public_key": "0x" + hex.EncodeToString(ac.publicKey),
		"signature":  "0x" + hex.EncodeToString(signature),
	}

	submitURL := fmt.Sprintf("%s/v1/transactions", ac.rpcEndpoint)

	submitJSON, err := json.Marshal(txn)
	if err != nil {
		return "", fmt.Errorf("marshaling signed transaction: %w", err)
	}

	log.Printf("📡 [APTOS-JSON] Step 3/3: POST %s (%d bytes)", submitURL, len(submitJSON))

	req2, err := http.NewRequestWithContext(ctx, "POST", submitURL, bytes.NewReader(submitJSON))
	if err != nil {
		return "", err
	}
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := ac.httpClient.Do(req2)
	if err != nil {
		return "", fmt.Errorf("submit transaction request failed: %w", err)
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return "", fmt.Errorf("reading submit response: %w", err)
	}

	log.Printf("   submit response (HTTP %d): %s", resp2.StatusCode, string(body2[:min(len(body2), 300)]))

	if resp2.StatusCode != 202 && resp2.StatusCode != 200 {
		return "", fmt.Errorf("submit transaction failed (HTTP %d): %s", resp2.StatusCode, string(body2[:min(len(body2), 500)]))
	}

	var result struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(body2, &result); err != nil {
		return "", fmt.Errorf("parsing submit result: %w", err)
	}

	return result.Hash, nil
}

// callViewFunction executes a read-only view function via the REST API.
func (ac *AptosClient) callViewFunction(
	ctx context.Context,
	function string,
	typeArgs []string,
	args []interface{},
) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/v1/view", ac.rpcEndpoint)

	if typeArgs == nil {
		typeArgs = []string{}
	}

	payload := map[string]interface{}{
		"function":       function,
		"type_arguments": typeArgs,
		"arguments":      args,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling view request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payloadJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("view function request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading view response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("view function failed (HTTP %d): %s", resp.StatusCode, string(body[:min(len(body), 500)]))
	}

	return body, nil
}

// =============================================================================
// BCS SERIALIZATION HELPERS
// =============================================================================

// bcsWriteULEB128 writes a ULEB128-encoded unsigned integer.
func bcsWriteULEB128(buf *bytes.Buffer, v uint64) {
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if v == 0 {
			break
		}
	}
}

// bcsWriteU64LE writes a little-endian u64.
func bcsWriteU64LE(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

// bcsWriteString writes a BCS string (ULEB128 length + UTF-8 bytes).
func bcsWriteString(buf *bytes.Buffer, s string) {
	bcsWriteULEB128(buf, uint64(len(s)))
	buf.WriteString(s)
}

// bcsAddress encodes an address (32 bytes) from hex string.
func bcsAddress(addr string) []byte {
	addr = strings.TrimPrefix(addr, "0x")
	b, _ := hex.DecodeString(addr)
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return padded
	}
	return b[:32]
}

// bcsU64 encodes a u64 as 8 little-endian bytes.
func bcsU64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// bcsU256FromBytes32 converts a [32]byte (big-endian) to BCS u256 (32 little-endian bytes).
func bcsU256FromBytes32(data [32]byte) []byte {
	// BCS u256 is 32 bytes in little-endian order
	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = data[31-i]
	}
	return result
}

// bcsVectorU8 encodes a vector<u8> (ULEB128 length + raw bytes).
func bcsVectorU8(data []byte) []byte {
	var buf bytes.Buffer
	bcsWriteULEB128(&buf, uint64(len(data)))
	buf.Write(data)
	return buf.Bytes()
}

// =============================================================================
// CONVERSION HELPERS
// =============================================================================

// bytes32ToU256String converts a [32]byte to a decimal u256 string for Aptos REST API.
func bytes32ToU256String(data [32]byte) string {
	n := new(big.Int).SetBytes(data[:])
	return n.String()
}

// u256ToBytes32 converts a decimal u256 string to [32]byte big-endian.
func u256ToBytes32(s string, dst *[32]byte) {
	n := new(big.Int)
	n.SetString(s, 10)
	b := n.Bytes()
	if len(b) > 32 {
		b = b[:32]
	}
	// Right-align in 32-byte array
	copy(dst[32-len(b):], b)
}

// =============================================================================
// APTOS-SPECIFIC DERIVATION HELPERS
// =============================================================================

// DeriveAptosAccountOwnerBytes32 derives the full 32-byte keccak256 owner for Aptos.
// Returns "0x" + full 64-char hex string.
// Matches the API bridge's deriveOwnerBytes32(): keccak256(adiUrl) as hex without 0x.
func DeriveAptosAccountOwnerBytes32(adiURL string) string {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	return "0x" + hex.EncodeToString(hash)
}

// DeriveAptosAccountSalt derives the deterministic u64 salt from an ADI URL.
// Matches the API bridge's deriveSaltU64(): keccak256(adiUrl) % 2^64.
func DeriveAptosAccountSalt(adiURL string) uint64 {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	fullBig := new(big.Int).SetBytes(hash)
	mod64 := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
	truncated := new(big.Int).Mod(fullBig, mod64)
	return truncated.Uint64()
}

// aptosAuthorityLevelForOctas returns the authority level based on octas amount.
// Matches the Move contract's value-based thresholds:
// < 100 APT (10^10 octas) = OPERATOR(1)
// < 1000 APT (10^11 octas) = MANAGER(2)
// < 10000 APT (10^12 octas) = ADMIN(3)
// >= 10000 APT = ROOT(4)
func aptosAuthorityLevelForOctas(octas uint64) uint8 {
	const (
		rootThreshold    = 10_000_00000000 // 10,000 APT (10^12 octas)
		adminThreshold   = 1_000_00000000  // 1,000 APT
		managerThreshold = 100_00000000    // 100 APT
	)

	if octas >= rootThreshold {
		return 4 // ROOT
	} else if octas >= adminThreshold {
		return 3 // ADMIN
	} else if octas >= managerThreshold {
		return 2 // MANAGER
	}
	return 1 // OPERATOR
}

// computeAptosExecutionCommitment computes the CRITICAL-001 execution commitment for Aptos.
// Matches Move: keccak256(chain_id_u8 || target_bcs_32bytes || value_u64_le || data_hash_32bytes)
func computeAptosExecutionCommitment(chainID uint8, target string, valueOctas uint64, dataHash [32]byte) [32]byte {
	var buf []byte

	// chain_id as single byte
	buf = append(buf, chainID)

	// target as 32 bytes (BCS address format, left-padded)
	targetClean := strings.TrimPrefix(target, "0x")
	for len(targetClean) < 64 {
		targetClean = "0" + targetClean
	}
	targetBytes, _ := hex.DecodeString(targetClean)
	buf = append(buf, targetBytes...)

	// value as u64 little-endian (BCS encoding)
	valBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(valBytes, valueOctas)
	buf = append(buf, valBytes...)

	// data_hash as 32 bytes
	buf = append(buf, dataHash[:]...)

	hash := ethcrypto.Keccak256(buf)
	var out [32]byte
	copy(out[:], hash)
	return out
}
