package execution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

// =============================================================================
// SUI CLIENT
// =============================================================================

// SuiClient handles Sui blockchain interactions using JSON-RPC 2.0.
// Uses Ed25519 signing with BLAKE2b-256 hashing and Programmable Transaction Blocks (PTBs).
type SuiClient struct {
	rpcEndpoint       string
	privateKey        ed25519.PrivateKey // 64-byte Ed25519
	publicKey         ed25519.PublicKey  // 32-byte
	senderAddress     string             // 0x + hex(BLAKE2b-256(0x00 || pubkey))
	packageAddress    string             // where all modules live
	anchorStateObject string             // shared object ID for AnchorState
	factoryObject     string             // shared object ID for Factory
	httpClient        *http.Client

	// Cache for shared object initial versions (fetched once)
	anchorStateVersion uint64
	factoryVersion     uint64
	versionsLoaded     bool
}

// SUI constants
const (
	suiGasBudget       uint64 = 50_000_000 // 50M MIST = 0.05 SUI
	suiClockObjectID          = "0x0000000000000000000000000000000000000000000000000000000000000006"
	suiClockVersion    uint64 = 1
)

// NewSuiClient creates a SUI client from an RPC endpoint and Bech32m-encoded private key.
// Key format: "suiprivkey1q..." — Bech32m decode → strip flag byte (0x00) → 32-byte Ed25519 seed.
func NewSuiClient(rpcEndpoint, privateKeyBech32, packageAddress, anchorStateObject, factoryObject string) (*SuiClient, error) {
	rpcEndpoint = strings.TrimSuffix(rpcEndpoint, "/")

	// Decode Bech32m private key
	seed, err := decodeSuiPrivateKey(privateKeyBech32)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SUI private key: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Derive SUI address: BLAKE2b-256(0x00 || ed25519_pubkey)
	// Flag byte 0x00 = Ed25519 signature scheme
	hasher, _ := blake2b.New256(nil)
	hasher.Write([]byte{0x00})
	hasher.Write(pubKey)
	addrBytes := hasher.Sum(nil)
	senderAddress := "0x" + hex.EncodeToString(addrBytes)

	log.Printf("🔑 [SUI] Client created: address=%s package=%s", senderAddress, packageAddress)

	return &SuiClient{
		rpcEndpoint:       rpcEndpoint,
		privateKey:        privKey,
		publicKey:         pubKey,
		senderAddress:     senderAddress,
		packageAddress:    packageAddress,
		anchorStateObject: anchorStateObject,
		factoryObject:     factoryObject,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetSenderAddress returns the derived sender address.
func (sc *SuiClient) GetSenderAddress() string {
	return sc.senderAddress
}

// =============================================================================
// BECH32M KEY DECODING
// =============================================================================

// decodeSuiPrivateKey decodes a suiprivkey1q... Bech32m-encoded key to a 32-byte Ed25519 seed.
func decodeSuiPrivateKey(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, "suiprivkey1") {
		return nil, fmt.Errorf("SUI private key must start with 'suiprivkey1'")
	}

	// Bech32m decode
	_, data5bit, err := bech32mDecode(encoded)
	if err != nil {
		return nil, fmt.Errorf("bech32m decode failed: %w", err)
	}

	// Convert 5-bit to 8-bit
	data8bit, err := convertBits(data5bit, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("bit conversion failed: %w", err)
	}

	if len(data8bit) < 33 {
		return nil, fmt.Errorf("decoded key too short: %d bytes (need 33: 1 flag + 32 seed)", len(data8bit))
	}

	// First byte is the key scheme flag (0x00 = Ed25519)
	if data8bit[0] != 0x00 {
		return nil, fmt.Errorf("unsupported key scheme: 0x%02x (expected 0x00 for Ed25519)", data8bit[0])
	}

	return data8bit[1:33], nil
}

// Bech32m character set
const bech32mCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32mDecode decodes a Bech32m-encoded string.
func bech32mDecode(bech string) (string, []byte, error) {
	bech = strings.ToLower(bech)

	pos := strings.LastIndex(bech, "1")
	if pos < 1 {
		return "", nil, fmt.Errorf("missing separator '1'")
	}

	hrp := bech[:pos]
	dataStr := bech[pos+1:]

	if len(dataStr) < 6 {
		return "", nil, fmt.Errorf("data part too short")
	}

	// Decode characters to values
	values := make([]byte, len(dataStr))
	for i, c := range dataStr {
		idx := strings.IndexRune(bech32mCharset, c)
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid character '%c' at position %d", c, i)
		}
		values[i] = byte(idx)
	}

	// Verify checksum (Bech32m uses constant 0x2bc830a3)
	if !bech32mVerifyChecksum(hrp, values) {
		return "", nil, fmt.Errorf("checksum verification failed")
	}

	// Strip checksum (last 6 values)
	return hrp, values[:len(values)-6], nil
}

// bech32mPolymod computes the Bech32m polynomial modular checksum.
func bech32mPolymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}[i]
			}
		}
	}
	return chk
}

// bech32mHRPExpand expands the HRP for checksum computation.
func bech32mHRPExpand(hrp string) []byte {
	result := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, byte(c>>5))
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, byte(c&31))
	}
	return result
}

// bech32mVerifyChecksum verifies a Bech32/Bech32m checksum.
// SUI private keys use standard Bech32 encoding (constant 1), not Bech32m (0x2bc830a3).
func bech32mVerifyChecksum(hrp string, data []byte) bool {
	expanded := bech32mHRPExpand(hrp)
	values := append(expanded, data...)
	polymod := bech32mPolymod(values)
	return polymod == 1 || polymod == 0x2bc830a3
}

// convertBits converts between bit groups (e.g., 5-bit to 8-bit).
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	var result []byte
	maxv := uint32((1 << toBits) - 1)

	for _, d := range data {
		acc = (acc << fromBits) | uint32(d)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else {
		if bits >= fromBits {
			return nil, fmt.Errorf("illegal zero padding")
		}
		if (acc<<(toBits-bits))&maxv != 0 {
			return nil, fmt.Errorf("non-zero padding")
		}
	}

	return result, nil
}

// =============================================================================
// JSON-RPC HELPERS
// =============================================================================

// rpcCall makes a JSON-RPC 2.0 call to the SUI node.
func (sc *SuiClient) rpcCall(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling RPC request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", sc.rpcEndpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading RPC response: %w", err)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("parsing RPC response: %w (body: %s)", err, string(body[:min(len(body), 500)]))
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// getObject fetches an object by ID via sui_getObject.
func (sc *SuiClient) getObject(ctx context.Context, objectID string) (json.RawMessage, error) {
	return sc.rpcCall(ctx, "sui_getObject", []interface{}{
		objectID,
		map[string]interface{}{
			"showType":    true,
			"showContent": true,
			"showOwner":   true,
		},
	})
}

// getSharedObjectVersion fetches the initial_shared_version for a shared object.
func (sc *SuiClient) getSharedObjectVersion(ctx context.Context, objectID string) (uint64, error) {
	result, err := sc.getObject(ctx, objectID)
	if err != nil {
		return 0, err
	}

	var obj struct {
		Data struct {
			Owner struct {
				Shared struct {
					InitialSharedVersion uint64 `json:"initial_shared_version"`
				} `json:"Shared"`
			} `json:"owner"`
		} `json:"data"`
	}
	if err := json.Unmarshal(result, &obj); err != nil {
		return 0, fmt.Errorf("parsing object: %w", err)
	}

	version := obj.Data.Owner.Shared.InitialSharedVersion
	if version == 0 {
		return 0, fmt.Errorf("object %s is not a shared object or version not found", objectID)
	}

	return version, nil
}

// ensureSharedVersions fetches and caches shared object versions.
func (sc *SuiClient) ensureSharedVersions(ctx context.Context) error {
	if sc.versionsLoaded {
		return nil
	}

	var err error
	sc.anchorStateVersion, err = sc.getSharedObjectVersion(ctx, sc.anchorStateObject)
	if err != nil {
		return fmt.Errorf("fetching AnchorState version: %w", err)
	}
	log.Printf("   AnchorState initial_shared_version: %d", sc.anchorStateVersion)

	if sc.factoryObject != "" {
		sc.factoryVersion, err = sc.getSharedObjectVersion(ctx, sc.factoryObject)
		if err != nil {
			log.Printf("⚠️ [SUI] Failed to fetch Factory version (non-fatal): %v", err)
		} else {
			log.Printf("   Factory initial_shared_version: %d", sc.factoryVersion)
		}
	}

	sc.versionsLoaded = true
	return nil
}

// getGasCoins fetches gas coins for the sender address.
func (sc *SuiClient) getGasCoins(ctx context.Context) ([]suiCoinRef, error) {
	result, err := sc.rpcCall(ctx, "suix_getCoins", []interface{}{
		sc.senderAddress,
		"0x2::sui::SUI",
		nil, // cursor
		5,   // limit
	})
	if err != nil {
		return nil, fmt.Errorf("getting gas coins: %w", err)
	}

	var resp struct {
		Data []struct {
			CoinObjectId string `json:"coinObjectId"`
			Version      string `json:"version"`
			Digest       string `json:"digest"`
			Balance      string `json:"balance"`
		} `json:"data"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("parsing coins: %w", err)
	}

	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("no SUI coins found for %s", sc.senderAddress)
	}

	coins := make([]suiCoinRef, len(resp.Data))
	for i, c := range resp.Data {
		coins[i] = suiCoinRef{
			ObjectID: c.CoinObjectId,
			Version:  parseUint64(c.Version),
			Digest:   c.Digest,
		}
	}

	return coins, nil
}

type suiCoinRef struct {
	ObjectID string
	Version  uint64
	Digest   string
}

// =============================================================================
// TRANSACTION BUILDING & SUBMISSION
// =============================================================================

// buildAndExecuteMoveCall builds a MoveCall via unsafe_moveCall, signs, and submits it.
func (sc *SuiClient) buildAndExecuteMoveCall(
	ctx context.Context,
	module string,
	function string,
	typeArgs []string,
	sharedInputs []suiSharedInput,
	args []interface{},
	gasBudget uint64,
) (string, error) {
	if err := sc.ensureSharedVersions(ctx); err != nil {
		return "", fmt.Errorf("loading shared versions: %w", err)
	}

	txBytes, err := sc.buildMoveCallTxBytes(ctx, module, function, typeArgs, sharedInputs, args, gasBudget)
	if err != nil {
		return "", fmt.Errorf("building move call tx: %w", err)
	}

	return sc.signAndSubmit(ctx, txBytes)
}

type suiSharedInput struct {
	ObjectID             string
	InitialSharedVersion uint64
	Mutable              bool
}

// =============================================================================
// SuiJSON ENCODING HELPERS (for unsafe_moveCall argument format)
// =============================================================================

// suiJsonVecU8 encodes []byte as a JSON array of integers for SuiJSON vector<u8>.
// SuiJSON treats strings as UTF-8 bytes (NOT base64), so we must use integer arrays
// for arbitrary binary data.
func suiJsonVecU8(data []byte) []int {
	result := make([]int, len(data))
	for i, b := range data {
		result[i] = int(b)
	}
	return result
}

// suiJsonVecVecU8From32 encodes [][32]byte as an array of integer arrays for SuiJSON vector<vector<u8>>.
func suiJsonVecVecU8From32(items [][32]byte) [][]int {
	result := make([][]int, len(items))
	for i, item := range items {
		result[i] = suiJsonVecU8(item[:])
	}
	return result
}

// suiJsonVecVecU8 encodes [][]byte as an array of integer arrays for SuiJSON vector<vector<u8>>.
func suiJsonVecVecU8(items [][]byte) [][]int {
	result := make([][]int, len(items))
	for i, item := range items {
		result[i] = suiJsonVecU8(item)
	}
	return result
}

// suiJsonU64 encodes a uint64 as a string number for SuiJSON u64.
func suiJsonU64(v uint64) string {
	return fmt.Sprintf("%d", v)
}

// suiJsonU8 encodes a uint8 as an integer for SuiJSON u8.
func suiJsonU8(v uint8) int {
	return int(v)
}

// suiJsonAddress normalizes a SUI address to "0x" + 64 hex chars.
func suiJsonAddress(addr string) string {
	addr = strings.TrimPrefix(addr, "0x")
	if len(addr) < 64 {
		addr = strings.Repeat("0", 64-len(addr)) + addr
	}
	return "0x" + addr
}

// suiJsonVecAddress encodes []string addresses for SuiJSON vector<address>.
func suiJsonVecAddress(addrs []string) []string {
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = suiJsonAddress(addr)
	}
	return result
}

// suiJsonVecU64 encodes []uint64 as an array of string numbers for SuiJSON vector<u64>.
func suiJsonVecU64(values []uint64) []string {
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = fmt.Sprintf("%d", v)
	}
	return result
}

// buildMoveCallTxBytes uses unsafe_moveCall to construct transaction bytes.
// The RPC server resolves Move types from the function signature and handles BCS
// serialization internally; callers pass SuiJSON-formatted args.
func (sc *SuiClient) buildMoveCallTxBytes(
	ctx context.Context,
	module string,
	function string,
	typeArgs []string,
	sharedInputs []suiSharedInput,
	args []interface{},
	gasBudget uint64,
) ([]byte, error) {
	if typeArgs == nil {
		typeArgs = []string{}
	}

	// Prepend shared object IDs to the argument list
	suiArgs := make([]interface{}, 0, len(sharedInputs)+len(args))
	for _, shared := range sharedInputs {
		suiArgs = append(suiArgs, shared.ObjectID)
	}
	suiArgs = append(suiArgs, args...)

	result, err := sc.rpcCall(ctx, "unsafe_moveCall", []interface{}{
		sc.senderAddress,            // signer
		sc.packageAddress,           // package
		module,                      // module
		function,                    // function
		typeArgs,                    // type_arguments
		suiArgs,                     // arguments (SuiJSON format)
		nil,                         // gas (auto-select)
		fmt.Sprintf("%d", gasBudget), // gas_budget
	})
	if err != nil {
		return nil, fmt.Errorf("unsafe_moveCall failed: %w", err)
	}

	var txResult struct {
		TxBytes string `json:"txBytes"`
	}
	if err := json.Unmarshal(result, &txResult); err != nil {
		return nil, fmt.Errorf("parsing moveCall result: %w", err)
	}

	txBytes, err := base64.StdEncoding.DecodeString(txResult.TxBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tx bytes: %w", err)
	}

	return txBytes, nil
}

// signAndSubmit signs transaction bytes and submits to the network.
// SUI signing: Ed25519Sign(BLAKE2b-256(intent_prefix || tx_data_bcs))
// intent_prefix = [0, 0, 0] (TransactionData, version 0, SUI)
func (sc *SuiClient) signAndSubmit(ctx context.Context, txBytes []byte) (string, error) {
	// Build intent message: [0, 0, 0] || tx_data_bcs
	intentMsg := make([]byte, 3+len(txBytes))
	intentMsg[0] = 0 // IntentScope::TransactionData
	intentMsg[1] = 0 // IntentVersion::V0
	intentMsg[2] = 0 // AppId::Sui
	copy(intentMsg[3:], txBytes)

	// Hash with BLAKE2b-256
	hasher, _ := blake2b.New256(nil)
	hasher.Write(intentMsg)
	digest := hasher.Sum(nil)

	// Sign with Ed25519
	signature := ed25519.Sign(sc.privateKey, digest)

	// Build the serialized signature: flag(1) || signature(64) || pubkey(32)
	serializedSig := make([]byte, 1+64+32)
	serializedSig[0] = 0x00 // Ed25519 scheme flag
	copy(serializedSig[1:65], signature)
	copy(serializedSig[65:97], sc.publicKey)

	sigB64 := base64.StdEncoding.EncodeToString(serializedSig)
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	log.Printf("📡 [SUI] Submitting tx (%d bytes, sig=%d bytes)", len(txBytes), len(serializedSig))

	// Submit via sui_executeTransactionBlock
	result, err := sc.rpcCall(ctx, "sui_executeTransactionBlock", []interface{}{
		txB64,
		[]string{sigB64},
		map[string]interface{}{
			"showEffects": true,
			"showEvents":  true,
		},
		"WaitForLocalExecution",
	})
	if err != nil {
		return "", fmt.Errorf("execute transaction failed: %w", err)
	}

	// Parse digest from result
	var execResult struct {
		Digest  string `json:"digest"`
		Effects struct {
			Status struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"status"`
		} `json:"effects"`
	}
	if err := json.Unmarshal(result, &execResult); err != nil {
		return "", fmt.Errorf("parsing execute result: %w", err)
	}

	if execResult.Effects.Status.Status == "failure" {
		return execResult.Digest, fmt.Errorf("transaction failed: %s", execResult.Effects.Status.Error)
	}

	log.Printf("✅ [SUI] Transaction submitted: digest=%s status=%s",
		execResult.Digest, execResult.Effects.Status.Status)

	return execResult.Digest, nil
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor calls create_anchor on the certen_anchor_v3 module.
func (sc *SuiClient) CreateAnchor(
	ctx context.Context,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	blockHeight uint64,
) (string, error) {
	log.Printf("📡 [SUI] Step 1: Creating anchor...")
	log.Printf("   Account: %s", sc.senderAddress)
	log.Printf("   Package: %s", sc.packageAddress)
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])
	log.Printf("   Block Height: %d", blockHeight)

	// Shared object inputs: AnchorState (mutable), Clock (immutable)
	sharedInputs := []suiSharedInput{
		{ObjectID: sc.anchorStateObject, InitialSharedVersion: sc.anchorStateVersion, Mutable: true},
		{ObjectID: suiClockObjectID, InitialSharedVersion: suiClockVersion, Mutable: false},
	}

	// Pure arguments in SuiJSON format:
	// bundle_id, adi_url_hash, op_commit, cc_commit, gov_root: vector<u8> → base64
	// block_height: u64 → string number
	args := []interface{}{
		suiJsonVecU8(bundleId[:]),
		suiJsonVecU8(adiURLHash[:]),
		suiJsonVecU8(operationCommitment[:]),
		suiJsonVecU8(crossChainCommitment[:]),
		suiJsonVecU8(governanceRoot[:]),
		suiJsonU64(blockHeight),
	}

	digest, err := sc.buildAndExecuteMoveCall(ctx,
		"certen_anchor_v3", "create_anchor",
		nil, sharedInputs, args, suiGasBudget,
	)
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [SUI] Anchor created: digest=%s", digest)
	return digest, nil
}

// =============================================================================
// STEP 2: EXECUTE COMPREHENSIVE PROOF
// =============================================================================

// SuiCertenProof holds the proof data for comprehensive proof verification on SUI.
type SuiCertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte

	GovKeyBookURL         string
	GovKeyBookRoot        [32]byte
	GovKeyPageProofs      [][32]byte
	GovAuthorityAddress   string // 0x+64hex SUI address
	GovAuthorityLevel     uint8
	GovNonce              uint64
	GovRequiredSignatures uint64
	GovProvidedSignatures uint64

	BLSProofBytes        []byte
	BLSValidatorAddresses []string // 0x+64hex SUI addresses
	BLSVotingPowers      []uint64
	BLSTotalVotingPower  uint64
	BLSSignedVotingPower uint64
	BLSMessageHash       [32]byte
	BLSPubkeyCommitment  []byte

	CommitOperationCommitment  [32]byte
	CommitCrossChainCommitment [32]byte
	CommitGovernanceRoot       [32]byte
	CommitSourceChain          string
	CommitSourceBlockHeight    uint64
	CommitSourceTxHash         [32]byte
	CommitTargetChain          string
	CommitTargetAddress        string // 0x+64hex SUI address

	ExpirationTimeMs uint64
	Metadata         []byte
}

// ExecuteComprehensiveProof calls execute_comprehensive_proof on the anchor module.
func (sc *SuiClient) ExecuteComprehensiveProof(
	ctx context.Context,
	anchorId [32]byte,
	proof SuiCertenProof,
) (string, error) {
	log.Printf("📡 [SUI] Step 2: Submitting comprehensive proof...")
	log.Printf("   Anchor ID: 0x%x", anchorId[:8])
	log.Printf("   Tx Hash: 0x%x", proof.TransactionHash[:8])
	log.Printf("   Proof Hashes: %d", len(proof.ProofHashes))

	sharedInputs := []suiSharedInput{
		{ObjectID: sc.anchorStateObject, InitialSharedVersion: sc.anchorStateVersion, Mutable: true},
		{ObjectID: suiClockObjectID, InitialSharedVersion: suiClockVersion, Mutable: false},
	}

	// Default BLS validator addresses and voting powers
	blsValidatorAddrs := proof.BLSValidatorAddresses
	if len(blsValidatorAddrs) == 0 {
		blsValidatorAddrs = []string{sc.senderAddress}
	}
	blsVotingPowers := proof.BLSVotingPowers
	if len(blsVotingPowers) == 0 {
		blsVotingPowers = []uint64{100}
	}

	// Arguments in SuiJSON format
	args := []interface{}{
		suiJsonVecU8(anchorId[:]),                              // anchor_id_bytes: vector<u8>
		suiJsonVecU8(proof.TransactionHash[:]),                 // transaction_hash_bytes: vector<u8>
		suiJsonVecU8(proof.MerkleRoot[:]),                      // merkle_root_bytes: vector<u8>
		suiJsonVecVecU8From32(proof.ProofHashes),               // proof_hashes_bytes: vector<vector<u8>>
		suiJsonVecU8(proof.LeafHash[:]),                        // leaf_hash_bytes: vector<u8>
		proof.GovKeyBookURL,                                    // gov_key_book_url: String
		suiJsonVecU8(proof.GovKeyBookRoot[:]),                  // gov_key_book_root_bytes: vector<u8>
		suiJsonVecVecU8From32(proof.GovKeyPageProofs),          // gov_key_page_proofs_bytes: vector<vector<u8>>
		suiJsonAddress(proof.GovAuthorityAddress),              // gov_authority_address: address
		suiJsonU8(proof.GovAuthorityLevel),                     // gov_authority_level: u8
		suiJsonU64(proof.GovNonce),                             // gov_nonce: u64
		suiJsonU64(proof.GovRequiredSignatures),                // gov_required_signatures: u64
		suiJsonU64(proof.GovProvidedSignatures),                // gov_provided_signatures: u64
		suiJsonVecU8(proof.BLSProofBytes),                     // bls_proof_points_bytes: vector<u8>
		suiJsonVecAddress(blsValidatorAddrs),                   // bls_validator_addresses: vector<address>
		suiJsonVecU64(blsVotingPowers),                         // bls_voting_powers: vector<u64>
		suiJsonU64(proof.BLSTotalVotingPower),                  // bls_total_voting_power: u64
		suiJsonU64(proof.BLSSignedVotingPower),                 // bls_signed_voting_power: u64
		suiJsonVecU8(proof.BLSMessageHash[:]),                  // bls_message_hash_bytes: vector<u8>
		suiJsonVecU8(proof.BLSPubkeyCommitment),               // bls_pubkey_commitment: vector<u8>
		suiJsonVecU8(proof.CommitOperationCommitment[:]),       // commit_operation_bytes: vector<u8>
		suiJsonVecU8(proof.CommitCrossChainCommitment[:]),      // commit_cross_chain_bytes: vector<u8>
		suiJsonVecU8(proof.CommitGovernanceRoot[:]),            // commit_governance_bytes: vector<u8>
		proof.CommitSourceChain,                                // commit_source_chain: String
		suiJsonU64(proof.CommitSourceBlockHeight),              // commit_source_block_height: u64
		suiJsonVecU8(proof.CommitSourceTxHash[:]),              // commit_source_tx_hash_bytes: vector<u8>
		proof.CommitTargetChain,                                // commit_target_chain: String
		suiJsonAddress(proof.CommitTargetAddress),              // commit_target_address: address
		suiJsonU64(proof.ExpirationTimeMs),                     // expiration_time_ms: u64
		suiJsonVecU8(proof.Metadata),                          // metadata: vector<u8>
	}

	digest, err := sc.buildAndExecuteMoveCall(ctx,
		"certen_anchor_v3", "execute_comprehensive_proof",
		nil, sharedInputs, args, suiGasBudget,
	)
	if err != nil {
		return "", fmt.Errorf("execute_comprehensive_proof failed: %w", err)
	}

	log.Printf("✅ [SUI] Comprehensive proof executed: digest=%s", digest)
	return digest, nil
}

// =============================================================================
// STEP 3: WITHDRAW SUI DIRECT
// =============================================================================

// SuiADIGovernanceProof holds the governance proof for Step 3.
type SuiADIGovernanceProof struct {
	AdiURL        string
	AnchorID      [32]byte
	MerklePath    [][32]byte

	// Key Book Proof
	KBUrl        string
	KBRoot       [32]byte
	KBDepth      uint64
	KBValidFrom  uint64
	KBValidUntil uint64

	// Role proof
	RoleLevel        uint8
	RoleHash         [32]byte
	RoleAuthorizedBy string // 0x+64hex
	RoleGrantedAt    uint64
	RoleSignature    []byte

	// Threshold proof
	ThreshRequired    uint64
	ThreshActual      uint64
	ThreshSignatures  [][]byte
	ThreshSigners     []string // 0x+64hex
	ThreshVotingPowers []uint64
	ThreshTotalPower  uint64
	ThreshMessageHash [32]byte

	Timestamp          uint64
	ExpiresAt          uint64
	ValidatorSignatures []byte
	Nonce              uint64
	RequiredLevel      uint8
	OperationHash      [32]byte
}

// WithdrawSuiDirect calls withdraw_sui_direct on the user's CertenAccountV2.
func (sc *SuiClient) WithdrawSuiDirect(
	ctx context.Context,
	accountObjectId string,
	accountObjectVersion uint64,
	recipientAddr string,
	amountMist uint64,
	proof SuiADIGovernanceProof,
) (string, error) {
	log.Printf("📡 [SUI] Step 3: Withdrawing SUI direct...")
	log.Printf("   Account: %s", accountObjectId)
	log.Printf("   Recipient: %s", recipientAddr)
	log.Printf("   Amount: %d MIST", amountMist)

	// Shared object inputs: account (mutable), AnchorState (immutable), Clock (immutable)
	sharedInputs := []suiSharedInput{
		{ObjectID: accountObjectId, InitialSharedVersion: accountObjectVersion, Mutable: true},
		{ObjectID: sc.anchorStateObject, InitialSharedVersion: sc.anchorStateVersion, Mutable: false},
		{ObjectID: suiClockObjectID, InitialSharedVersion: suiClockVersion, Mutable: false},
	}

	// Arguments in SuiJSON format
	args := []interface{}{
		suiJsonAddress(recipientAddr),                          // recipient: address
		suiJsonU64(amountMist),                                 // amount: u64
		proof.AdiURL,                                           // proof_adi_url: String
		suiJsonVecU8(proof.AnchorID[:]),                        // proof_anchor_id: vector<u8>
		suiJsonVecVecU8From32(proof.MerklePath),                // proof_merkle_path: vector<vector<u8>>
		proof.KBUrl,                                            // kb_url: String
		suiJsonVecU8(proof.KBRoot[:]),                          // kb_root: vector<u8>
		suiJsonU64(proof.KBDepth),                              // kb_depth: u64
		suiJsonU64(proof.KBValidFrom),                          // kb_valid_from: u64
		suiJsonU64(proof.KBValidUntil),                         // kb_valid_until: u64
		suiJsonU8(proof.RoleLevel),                             // role_level: u8
		suiJsonVecU8(proof.RoleHash[:]),                        // role_hash: vector<u8>
		suiJsonAddress(proof.RoleAuthorizedBy),                 // role_authorized_by: address
		suiJsonU64(proof.RoleGrantedAt),                        // role_granted_at: u64
		suiJsonVecU8(proof.RoleSignature),                      // role_signature: vector<u8>
		suiJsonU64(proof.ThreshRequired),                       // thresh_required: u64
		suiJsonU64(proof.ThreshActual),                         // thresh_actual: u64
		suiJsonVecVecU8(proof.ThreshSignatures),                // thresh_signatures: vector<vector<u8>>
		suiJsonVecAddress(proof.ThreshSigners),                 // thresh_signers: vector<address>
		suiJsonVecU64(proof.ThreshVotingPowers),                // thresh_voting_powers: vector<u64>
		suiJsonU64(proof.ThreshTotalPower),                     // thresh_total_power: u64
		suiJsonVecU8(proof.ThreshMessageHash[:]),               // thresh_message_hash: vector<u8>
		suiJsonU64(proof.Timestamp),                            // proof_timestamp: u64
		suiJsonU64(proof.ExpiresAt),                            // proof_expires_at: u64
		suiJsonVecU8(proof.ValidatorSignatures),                // validator_signatures: vector<u8>
		suiJsonU64(proof.Nonce),                                // proof_nonce: u64
		suiJsonU8(proof.RequiredLevel),                         // required_level: u8
		suiJsonVecU8(proof.OperationHash[:]),                   // operation_hash: vector<u8>
	}

	digest, err := sc.buildAndExecuteMoveCall(ctx,
		"certen_account_v2", "withdraw_sui_direct",
		nil, sharedInputs, args, suiGasBudget,
	)
	if err != nil {
		return "", fmt.Errorf("withdraw_sui_direct failed: %w", err)
	}

	log.Printf("✅ [SUI] Withdraw executed: digest=%s", digest)
	return digest, nil
}

// =============================================================================
// ACCOUNT OPERATIONS
// =============================================================================

// DeployAccountViaFactory calls create_account on the certen_account_factory module.
func (sc *SuiClient) DeployAccountViaFactory(
	ctx context.Context,
	owner string,
	adiURL string,
	salt uint64,
) (string, error) {
	log.Printf("📡 [SUI] Deploying account via factory...")
	log.Printf("   Owner: %s", owner)
	log.Printf("   ADI URL: %s", adiURL)
	log.Printf("   Salt: %d", salt)

	if sc.factoryObject == "" {
		return "", fmt.Errorf("factory object not configured")
	}

	// Factory takes: Factory (shared, mutable), Clock (shared, immutable), owner, adi_url, salt, payment (Coin<SUI>)
	// The payment coin is handled differently — we need to split a gas coin.
	// Use unsafe_moveCall which handles coin splitting automatically.

	// For factory deployment, we need a payment coin.
	// Use unsafe_moveCall which lets us pass a coin object ID directly.
	// The factory will consume the coin.
	gasCoins, err := sc.getGasCoins(ctx)
	if err != nil {
		return "", fmt.Errorf("getting gas coins for factory: %w", err)
	}
	if len(gasCoins) < 2 {
		return "", fmt.Errorf("need at least 2 coin objects (one for gas, one for payment), have %d", len(gasCoins))
	}

	// Use the second coin as payment
	paymentCoinID := gasCoins[1].ObjectID

	// Build arguments for unsafe_moveCall (mix of objects and pure values)
	suiArgs := make([]interface{}, 0)
	suiArgs = append(suiArgs, sc.factoryObject)   // factory object
	suiArgs = append(suiArgs, suiClockObjectID)    // clock object
	suiArgs = append(suiArgs, owner)               // owner address (pure)
	suiArgs = append(suiArgs, adiURL)              // adi_url string (pure)
	suiArgs = append(suiArgs, fmt.Sprintf("%d", salt)) // salt (pure)
	suiArgs = append(suiArgs, paymentCoinID)       // payment coin object

	result, err := sc.rpcCall(ctx, "unsafe_moveCall", []interface{}{
		sc.senderAddress,
		sc.packageAddress,
		"certen_account_factory",
		"create_account",
		[]string{},
		suiArgs,
		nil,
		fmt.Sprintf("%d", suiGasBudget),
	})
	if err != nil {
		return "", fmt.Errorf("factory create_account failed: %w", err)
	}

	var txResult struct {
		TxBytes string `json:"txBytes"`
	}
	if err := json.Unmarshal(result, &txResult); err != nil {
		return "", fmt.Errorf("parsing factory result: %w", err)
	}

	txBytes, err := base64.StdEncoding.DecodeString(txResult.TxBytes)
	if err != nil {
		return "", fmt.Errorf("decoding factory tx bytes: %w", err)
	}

	digest, err := sc.signAndSubmit(ctx, txBytes)
	if err != nil {
		return "", fmt.Errorf("factory deployment failed: %w", err)
	}

	log.Printf("✅ [SUI] Account deployment submitted: digest=%s", digest)
	return digest, nil
}

// CheckAccountExists checks if a CertenAccountV2 shared object exists at the given object ID.
func (sc *SuiClient) CheckAccountExists(ctx context.Context, objectId string) (bool, uint64, error) {
	result, err := sc.getObject(ctx, objectId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "deleted") ||
			strings.Contains(err.Error(), "notExists") {
			return false, 0, nil
		}
		return false, 0, err
	}

	// Parse the object to check if it has the right type
	var obj struct {
		Data struct {
			ObjectId string `json:"objectId"`
			Type     string `json:"type"`
			Owner    struct {
				Shared struct {
					InitialSharedVersion uint64 `json:"initial_shared_version"`
				} `json:"Shared"`
			} `json:"owner"`
		} `json:"data"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(result, &obj); err != nil {
		return false, 0, fmt.Errorf("parsing object: %w", err)
	}

	if obj.Error != nil {
		return false, 0, nil
	}

	// Check if it's a CertenAccountV2
	if strings.Contains(obj.Data.Type, "certen_account_v2::CertenAccountV2") {
		return true, obj.Data.Owner.Shared.InitialSharedVersion, nil
	}

	return false, 0, nil
}

// GetAccountObject looks up a user's CertenAccountV2 object by querying owned objects.
// In SUI, the "from" address from the intent is the account object ID itself.
func (sc *SuiClient) GetAccountObject(ctx context.Context, accountObjectId string) (bool, uint64, error) {
	return sc.CheckAccountExists(ctx, accountObjectId)
}

// =============================================================================
// READ OPERATIONS
// =============================================================================

// SuiAnchorData holds anchor data read from the SUI contract.
type SuiAnchorData struct {
	BundleId             [32]byte
	MerkleRoot           [32]byte
	AdiURLHash           [32]byte
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	BlockHeight          uint64
	Timestamp            uint64
	ProofExecuted        bool
}

// GetAnchorData reads anchor data via devInspect calling get_anchor_data view function.
func (sc *SuiClient) GetAnchorData(ctx context.Context, bundleId [32]byte) (*SuiAnchorData, error) {
	log.Printf("📡 [SUI] Reading anchor data for bundle 0x%x...", bundleId[:8])

	// Build a transaction via unsafe_moveCall, then run it through devInspect
	args := []interface{}{
		sc.anchorStateObject,
		suiJsonVecU8(bundleId[:]),
	}

	txResult, err := sc.rpcCall(ctx, "unsafe_moveCall", []interface{}{
		sc.senderAddress,
		sc.packageAddress,
		"certen_anchor_v3",
		"get_anchor_data",
		[]string{},
		args,
		nil,
		fmt.Sprintf("%d", suiGasBudget),
	})
	if err != nil {
		log.Printf("⚠️ [SUI] DevInspect build failed: %v, using empty anchor data", err)
		return &SuiAnchorData{BundleId: bundleId}, nil
	}

	var moveCallResult struct {
		TxBytes string `json:"txBytes"`
	}
	if err := json.Unmarshal(txResult, &moveCallResult); err != nil {
		log.Printf("⚠️ [SUI] DevInspect parse failed: %v, using empty anchor data", err)
		return &SuiAnchorData{BundleId: bundleId}, nil
	}

	result, err := sc.rpcCall(ctx, "sui_devInspectTransactionBlock", []interface{}{
		sc.senderAddress,
		moveCallResult.TxBytes,
		nil, // epoch
		nil, // additional_args
	})
	if err != nil {
		log.Printf("⚠️ [SUI] DevInspect failed: %v, using empty anchor data", err)
		return &SuiAnchorData{BundleId: bundleId}, nil
	}

	// Check execution status
	var inspectResult struct {
		Effects struct {
			Status struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"status"`
		} `json:"effects"`
	}
	if err := json.Unmarshal(result, &inspectResult); err == nil {
		if inspectResult.Effects.Status.Status == "failure" {
			log.Printf("⚠️ [SUI] DevInspect execution failed: %s", inspectResult.Effects.Status.Error)
		}
	}

	// For now, return minimal data — the key fields are populated by the proof builder
	return &SuiAnchorData{BundleId: bundleId}, nil
}

// =============================================================================
// TRANSACTION CONFIRMATION
// =============================================================================

// WaitForConfirmation polls for transaction confirmation.
func (sc *SuiClient) WaitForConfirmation(ctx context.Context, txDigest string, timeout time.Duration) error {
	log.Printf("⏳ [SUI] Waiting for confirmation: %s (timeout=%v)", txDigest, timeout)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, err := sc.rpcCall(ctx, "sui_getTransactionBlock", []interface{}{
			txDigest,
			map[string]interface{}{
				"showEffects": true,
			},
		})
		if err != nil {
			log.Printf("⚠️ [SUI] Polling tx status: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		var txInfo struct {
			Digest  string `json:"digest"`
			Effects struct {
				Status struct {
					Status string `json:"status"`
					Error  string `json:"error"`
				} `json:"status"`
			} `json:"effects"`
		}
		if err := json.Unmarshal(result, &txInfo); err != nil {
			log.Printf("⚠️ [SUI] Failed to parse tx result: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		switch txInfo.Effects.Status.Status {
		case "success":
			log.Printf("✅ [SUI] Transaction confirmed: %s", txDigest)
			return nil
		case "failure":
			return fmt.Errorf("transaction failed: %s", txInfo.Effects.Status.Error)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return fmt.Errorf("transaction %s not confirmed after %v", txDigest, timeout)
}

// =============================================================================
// SUI-SPECIFIC DERIVATION HELPERS
// =============================================================================

// DeriveSuiAccountOwnerBytes32 derives the full 32-byte keccak256 owner for SUI.
// Returns "0x" + full 64-char hex string (padded to 32 bytes).
// Matches the API bridge's deriveOwnerBytes32(): keccak256(adiUrl) as hex.
func DeriveSuiAccountOwnerBytes32(adiURL string) string {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	return "0x" + hex.EncodeToString(hash)
}

// DeriveSuiAccountSalt derives the deterministic u64 salt from an ADI URL.
// Matches the API bridge's deriveSaltU64(): keccak256(adiUrl) % 2^64.
func DeriveSuiAccountSalt(adiURL string) uint64 {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	fullBig := new(big.Int).SetBytes(hash)
	mod64 := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
	truncated := new(big.Int).Mod(fullBig, mod64)
	return truncated.Uint64()
}

// suiAuthorityLevelForMist returns the authority level based on MIST amount.
// Matches the Move contract's value-based thresholds:
// < 100 SUI (10^11 MIST) = OPERATOR(1)
// < 1000 SUI (10^12 MIST) = MANAGER(2)
// < 10000 SUI (10^13 MIST) = ADMIN(3)
// >= 10000 SUI = ROOT(4)
func suiAuthorityLevelForMist(mist uint64) uint8 {
	const (
		rootThreshold    = 10_000_000_000_000 // 10,000 SUI (10^13 MIST)
		adminThreshold   = 1_000_000_000_000  // 1,000 SUI
		managerThreshold = 100_000_000_000    // 100 SUI
	)

	if mist >= rootThreshold {
		return 4 // ROOT
	} else if mist >= adminThreshold {
		return 3 // ADMIN
	} else if mist >= managerThreshold {
		return 2 // MANAGER
	}
	return 1 // OPERATOR
}

// =============================================================================
// UTILITY HELPERS
// =============================================================================

// parseUint64 parses a string to uint64 (SUI returns numbers as strings in JSON).
func parseUint64(s string) uint64 {
	n := new(big.Int)
	n.SetString(s, 10)
	return n.Uint64()
}
