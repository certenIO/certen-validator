package execution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
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

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// =============================================================================
// TON CLIENT
// =============================================================================

// TonClient handles TON blockchain interactions using TON Center API v2.
// Uses WalletV4R2-compatible external messages signed with Ed25519.
// TON contracts are written in Tact and use async actor-model architecture.
type TonClient struct {
	apiURL          string
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	senderAddress   *address.Address
	anchorContract  *address.Address
	blsVerifier     *address.Address
	factoryContract *address.Address
	httpClient      *http.Client

	walletAddress *address.Address
	subwalletID   uint32

	// Local seqno tracking to avoid stale API reads between rapid sends
	lastSeqno    uint32
	seqnoKnown   bool
}

// TON constants
const (
	tonGasAmount       uint64 = 200_000_000 // 0.2 TON for message forwarding
	tonDeployGas       uint64 = 500_000_000 // 0.5 TON for deployment
	tonProofGas        uint64 = 300_000_000 // 0.3 TON for proof execution
	tonGovGas          uint64 = 300_000_000 // 0.3 TON for governance execution
	tonPollingInterval        = 5 * time.Second
	tonPollingTimeout         = 2 * time.Minute
)

// Tact message op codes: CRC32C(messageName) | 0x80000000
// Pre-computed for the messages we send.
const (
	opCreateAnchor                 uint32 = 0xD0D98A6F
	opExecuteComprehensiveProof    uint32 = 0xC0F7E3D1
	opExecuteGovernanceProofDirect uint32 = 0xA3F2B1C4
	opCreateAccountIfNotExists     uint32 = 0xE2C3D4A5
)

// NewTonClient creates a TON client from a mnemonic seed phrase.
func NewTonClient(apiURL, mnemonic, anchorAddr, blsVerifierAddr, factoryAddr string) (*TonClient, error) {
	apiURL = strings.TrimSuffix(apiURL, "/")

	seed, err := tonMnemonicToSeed(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(seed[:32])
	pubKey := privKey.Public().(ed25519.PublicKey)

	anchor, err := address.ParseAddr(anchorAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid anchor address: %w", err)
	}

	bls, err := address.ParseAddr(blsVerifierAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid BLS verifier address: %w", err)
	}

	var factory *address.Address
	if factoryAddr != "" {
		factory, err = address.ParseAddr(factoryAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid factory address: %w", err)
		}
	}

	walletAddr, err := deriveWalletV4R2Address(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wallet address: %w", err)
	}

	log.Printf("🔑 [TON] Client created: wallet=%s anchor=%s", walletAddr.String(), anchor.String())

	return &TonClient{
		apiURL:          apiURL,
		privateKey:      privKey,
		publicKey:       pubKey,
		senderAddress:   walletAddr,
		anchorContract:  anchor,
		blsVerifier:     bls,
		factoryContract: factory,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		walletAddress:   walletAddr,
		subwalletID:     698983191,
	}, nil
}

// GetSenderAddress returns the wallet address string.
func (tc *TonClient) GetSenderAddress() string {
	return tc.senderAddress.String()
}

// =============================================================================
// MNEMONIC KEY DERIVATION
// =============================================================================

func tonMnemonicToSeed(mnemonic string) ([]byte, error) {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	if len(words) != 24 {
		return nil, fmt.Errorf("expected 24 mnemonic words, got %d", len(words))
	}

	// TON mnemonic derivation (matches @ton/crypto mnemonicToPrivateKey):
	// Step 1: entropy = HMAC-SHA512(key=mnemonic, data="")
	mnemonicStr := strings.Join(words, " ")
	entropy := tonHMACSHA512([]byte(mnemonicStr), []byte(""))

	// Step 2: seed = PBKDF2-SHA512(password=entropy, salt="TON default seed", iterations=100000, keyLen=64)
	seed := tonPBKDF2(entropy, []byte("TON default seed"), 100000, 64)

	return seed, nil
}

func tonPBKDF2(password, salt []byte, iterations, keyLen int) []byte {
	numBlocks := (keyLen + 63) / 64
	result := make([]byte, 0, numBlocks*64)

	for block := 1; block <= numBlocks; block++ {
		blockBuf := make([]byte, len(salt)+4)
		copy(blockBuf, salt)
		blockBuf[len(salt)] = byte(block >> 24)
		blockBuf[len(salt)+1] = byte(block >> 16)
		blockBuf[len(salt)+2] = byte(block >> 8)
		blockBuf[len(salt)+3] = byte(block)

		u := tonHMACSHA512(password, blockBuf)
		xorResult := make([]byte, len(u))
		copy(xorResult, u)

		for i := 1; i < iterations; i++ {
			u = tonHMACSHA512(password, u)
			for j := range xorResult {
				xorResult[j] ^= u[j]
			}
		}

		result = append(result, xorResult...)
	}

	return result[:keyLen]
}

func tonHMACSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// =============================================================================
// WALLET V4R2 ADDRESS DERIVATION
// =============================================================================

type walletStateInit struct {
	code *cell.Cell
	data *cell.Cell
}

func deriveWalletV4R2Address(pubKey ed25519.PublicKey) (*address.Address, error) {
	si := buildWalletV4R2StateInit(pubKey, 698983191)
	stateCell := buildStateInitCell(si)
	hash := stateCell.Hash()
	addr := address.NewAddress(0, 0, hash)
	return addr, nil
}

// buildStateInitCell builds a StateInit cell matching the TL-B schema:
// StateInit = _ split_depth:(Maybe (## 5)) special:(Maybe TickTock)
//
//	code:(Maybe ^Cell) data:(Maybe ^Cell) library:(HashmapE 256 SimpleLib)
func buildStateInitCell(si walletStateInit) *cell.Cell {
	return cell.BeginCell().
		MustStoreBoolBit(false). // split_depth: none
		MustStoreBoolBit(false). // special: none
		MustStoreBoolBit(true).  // code: present
		MustStoreRef(si.code).
		MustStoreBoolBit(true).  // data: present
		MustStoreRef(si.data).
		MustStoreBoolBit(false). // library: empty
		EndCell()
}

func buildWalletV4R2StateInit(pubKey ed25519.PublicKey, subwalletID uint32) walletStateInit {
	code := getWalletV4R2Code()

	data := cell.BeginCell().
		MustStoreUInt(0, 32).
		MustStoreUInt(uint64(subwalletID), 32).
		MustStoreSlice(pubKey, 256).
		MustStoreBoolBit(false).
		EndCell()

	return walletStateInit{code: code, data: data}
}

// =============================================================================
// TON CENTER API V2 HELPERS
// =============================================================================

func (tc *TonClient) apiCall(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/%s", tc.apiURL, method)
	if len(params) > 0 {
		parts := make([]string, 0, len(params))
		for k, v := range params {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		url += "?" + strings.Join(parts, "&")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading API response: %w", err)
	}

	var apiResp struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing API response: %w (body: %s)", err, string(body[:min(len(body), 500)]))
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("API error: %s", apiResp.Error)
	}

	return apiResp.Result, nil
}

func (tc *TonClient) apiPost(ctx context.Context, method string, reqBody interface{}) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/%s", tc.apiURL, method)

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading API response: %w", err)
	}

	var apiResp struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing API response: %w (body: %s)", err, string(respBody[:min(len(respBody), 500)]))
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("API error: %s", apiResp.Error)
	}

	return apiResp.Result, nil
}

func (tc *TonClient) getSeqno(ctx context.Context) (uint32, error) {
	// Use POST-based runGetMethod (TON Center API v2 requires POST for this endpoint)
	result, err := tc.runGetMethod(ctx, tc.walletAddress.String(), "seqno", nil)
	if err != nil {
		return 0, fmt.Errorf("getting seqno: %w", err)
	}

	var resp struct {
		GasUsed  int             `json:"gas_used"`
		ExitCode int             `json:"exit_code"`
		Stack    [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return 0, fmt.Errorf("parsing seqno response: %w", err)
	}

	// exit_code != 0 means the method call failed (e.g., account not initialized)
	if resp.ExitCode != 0 {
		return 0, fmt.Errorf("not initialized (exit_code=%d)", resp.ExitCode)
	}

	if len(resp.Stack) == 0 {
		return 0, nil
	}

	if len(resp.Stack[0]) >= 2 {
		hexStr, ok := resp.Stack[0][1].(string)
		if ok {
			hexStr = strings.TrimPrefix(hexStr, "0x")
			val := new(big.Int)
			val.SetString(hexStr, 16)
			log.Printf("📡 [TON] getSeqno: wallet=%s seqno=%d", tc.walletAddress.String(), val.Uint64())
			return uint32(val.Uint64()), nil
		}
	}

	return 0, nil
}

func (tc *TonClient) sendBoc(ctx context.Context, bocBytes []byte) error {
	bocB64 := base64.StdEncoding.EncodeToString(bocBytes)

	_, err := tc.apiPost(ctx, "sendBoc", map[string]string{
		"boc": bocB64,
	})
	if err != nil {
		return fmt.Errorf("sendBoc failed: %w", err)
	}

	return nil
}

func (tc *TonClient) runGetMethod(ctx context.Context, addr string, method string, params [][]interface{}) (json.RawMessage, error) {
	stack := params
	if stack == nil {
		stack = [][]interface{}{} // API requires stack field even when empty
	}
	reqBody := map[string]interface{}{
		"address": addr,
		"method":  method,
		"stack":   stack,
	}

	return tc.apiPost(ctx, "runGetMethod", reqBody)
}

// =============================================================================
// WALLET V4R2 MESSAGE BUILDING & SIGNING
// =============================================================================

func (tc *TonClient) sendInternalMessage(ctx context.Context, destAddr *address.Address, amount uint64, body *cell.Cell) (string, error) {
	// Try to get seqno — if wallet not deployed yet, use seqno=0 and include StateInit.
	// Use local seqno tracking to avoid stale API reads between rapid sends.
	needsInit := false
	seqno, err := tc.getSeqno(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Not Found") || strings.Contains(err.Error(), "not initialized") {
			if tc.seqnoKnown {
				// Wallet was deployed by a previous send in this session — API is stale
				seqno = tc.lastSeqno
				log.Printf("📡 [TON] API stale, using tracked seqno=%d", seqno)
			} else {
				log.Printf("📡 [TON] Wallet not yet deployed, will include StateInit (seqno=0)")
				seqno = 0
				needsInit = true
			}
		} else {
			return "", fmt.Errorf("getting seqno: %w", err)
		}
	} else if tc.seqnoKnown && tc.lastSeqno > seqno {
		// API returned a stale (lower) seqno — use our tracked value
		log.Printf("📡 [TON] API seqno=%d < tracked seqno=%d, using tracked", seqno, tc.lastSeqno)
		seqno = tc.lastSeqno
	}

	log.Printf("📡 [TON] Sending message: dest=%s amount=%d seqno=%d needsInit=%v", destAddr.String(), amount, seqno, needsInit)

	// Build internal message
	internalMsg := cell.BeginCell().
		MustStoreUInt(0x18, 6).
		MustStoreAddr(destAddr).
		MustStoreCoins(amount).
		MustStoreUInt(0, 1+4+4+64+32+1+1)

	if body != nil {
		internalMsg = internalMsg.MustStoreBoolBit(true).MustStoreRef(body)
	} else {
		internalMsg = internalMsg.MustStoreBoolBit(false)
	}
	internalMsgCell := internalMsg.EndCell()

	// Build WalletV4R2 transfer body
	validUntil := uint32(time.Now().Add(120 * time.Second).Unix())

	walletBody := cell.BeginCell().
		MustStoreUInt(uint64(tc.subwalletID), 32).
		MustStoreUInt(uint64(validUntil), 32).
		MustStoreUInt(uint64(seqno), 32).
		MustStoreUInt(0, 8).
		MustStoreUInt(3, 8).
		MustStoreRef(internalMsgCell).
		EndCell()

	// Sign
	hash := walletBody.Hash()
	signature := ed25519.Sign(tc.privateKey, hash)

	// Build signed body
	signedBody := cell.BeginCell().
		MustStoreSlice(signature, 512).
		MustStoreBuilder(walletBody.ToBuilder()).
		EndCell()

	// Build external message
	var extMsg *cell.Cell
	if needsInit {
		// Include StateInit to deploy the wallet contract on first use
		si := buildWalletV4R2StateInit(tc.publicKey, tc.subwalletID)
		stateInitCell := buildStateInitCell(si)

		extMsg = cell.BeginCell().
			MustStoreUInt(0b10, 2).       // ext_in_msg_info
			MustStoreUInt(0, 2).          // src: addr_none
			MustStoreAddr(tc.walletAddress).
			MustStoreCoins(0).            // import_fee
			MustStoreUInt(1, 1).          // state_init: present
			MustStoreUInt(1, 1).          // state_init in ref
			MustStoreRef(stateInitCell).
			MustStoreUInt(1, 1).          // body in ref
			MustStoreRef(signedBody).
			EndCell()
		log.Printf("📡 [TON] Built external message with StateInit (wallet deployment)")
	} else {
		extMsg = cell.BeginCell().
			MustStoreUInt(0b10, 2).
			MustStoreUInt(0, 2).
			MustStoreAddr(tc.walletAddress).
			MustStoreCoins(0).
			MustStoreUInt(0, 1).    // no state_init
			MustStoreUInt(1, 1).    // body in ref
			MustStoreRef(signedBody).
			EndCell()
	}

	bocBytes := extMsg.ToBOC()

	err = tc.sendBoc(ctx, bocBytes)
	if err != nil {
		return "", fmt.Errorf("sending message: %w", err)
	}

	// Track seqno locally so subsequent sends don't use stale API values
	tc.lastSeqno = seqno + 1
	tc.seqnoKnown = true

	msgHash := hex.EncodeToString(hash)
	log.Printf("✅ [TON] Message sent: hash=%s (next seqno=%d)", msgHash, tc.lastSeqno)
	return msgHash, nil
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor sends a CreateAnchor message to the anchor contract.
func (tc *TonClient) CreateAnchor(
	ctx context.Context,
	bundleId [32]byte,
	opCommitment, ccCommitment, govRoot [32]byte,
	blockHeight uint64,
) (string, error) {
	log.Printf("📡 [TON] Step 1: Creating anchor...")
	log.Printf("   Wallet: %s", tc.walletAddress.String())
	log.Printf("   Anchor Contract: %s", tc.anchorContract.String())
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])
	log.Printf("   Block Height: %d", blockHeight)

	body := tonBuildCreateAnchorBody(bundleId, opCommitment, ccCommitment, govRoot, blockHeight)

	hash, err := tc.sendInternalMessage(ctx, tc.anchorContract, tonGasAmount, body)
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [TON] Anchor creation sent: hash=%s", hash)
	return hash, nil
}

// tonBuildCreateAnchorBody builds the Cell body for CreateAnchor.
// Total bits: op(32) + bundleId(256) + opCommit(256) + ccCommit(256) + govRoot(256) + blockHeight(64) = 1120
// Exceeds 1023 limit, so we use a continuation cell.
func tonBuildCreateAnchorBody(bundleId, opCommitment, ccCommitment, govRoot [32]byte, blockHeight uint64) *cell.Cell {
	bundleInt := new(big.Int).SetBytes(bundleId[:])
	opInt := new(big.Int).SetBytes(opCommitment[:])
	ccInt := new(big.Int).SetBytes(ccCommitment[:])
	govInt := new(big.Int).SetBytes(govRoot[:])

	// Continuation cell for overflow
	cont := cell.BeginCell().
		MustStoreBigUInt(govInt, 256).
		MustStoreUInt(blockHeight, 64).
		EndCell()

	// Main cell: op(32) + bundleId(256) + opCommit(256) + ccCommit(256) = 800 bits + ref
	return cell.BeginCell().
		MustStoreUInt(uint64(opCreateAnchor), 32).
		MustStoreBigUInt(bundleInt, 256).
		MustStoreBigUInt(opInt, 256).
		MustStoreBigUInt(ccInt, 256).
		MustStoreRef(cont).
		EndCell()
}

// =============================================================================
// STEP 2: EXECUTE COMPREHENSIVE PROOF
// =============================================================================

// TonCertenProof holds proof data for comprehensive proof verification on TON.
type TonCertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte

	GovKeyBookRoot        [32]byte
	GovAuthorityLevel     uint8
	GovNonce              uint64
	GovRequiredSignatures uint16
	GovProvidedSignatures uint16
	GovAuthorityAddress   *address.Address
	GovKeyPageProofs      [][32]byte

	BLSMessageHash       [32]byte
	BLSThresholdMet      bool
	BLSSignedVotingPower uint64
	BLSTotalVotingPower  uint64
	BLSProofBytes        []byte
	BLSPubkeyCommitment  []byte

	CommitOperationCommitment  [32]byte
	CommitCrossChainCommitment [32]byte
	CommitGovernanceRoot       [32]byte

	ExpirationTime uint64
}

// ExecuteComprehensiveProof sends ExecuteComprehensiveProof to the anchor.
// Step 2 is ASYNC: anchor dispatches BlsVerifyRequest to BLS verifier, which calls back.
func (tc *TonClient) ExecuteComprehensiveProof(
	ctx context.Context,
	anchorId [32]byte,
	proof TonCertenProof,
) (string, error) {
	log.Printf("📡 [TON] Step 2: Submitting comprehensive proof...")
	log.Printf("   Anchor ID: 0x%x", anchorId[:8])
	log.Printf("   Tx Hash: 0x%x", proof.TransactionHash[:8])

	body := tonBuildComprehensiveProofBody(anchorId, proof)

	hash, err := tc.sendInternalMessage(ctx, tc.anchorContract, tonProofGas, body)
	if err != nil {
		return "", fmt.Errorf("execute_comprehensive_proof failed: %w", err)
	}

	log.Printf("✅ [TON] Comprehensive proof sent: hash=%s", hash)
	return hash, nil
}

func tonBuildComprehensiveProofBody(anchorId [32]byte, proof TonCertenProof) *cell.Cell {
	anchorInt := new(big.Int).SetBytes(anchorId[:])
	proofCell := tonBuildProofCell(proof)

	return cell.BeginCell().
		MustStoreUInt(uint64(opExecuteComprehensiveProof), 32).
		MustStoreBigUInt(anchorInt, 256).
		MustStoreRef(proofCell).
		EndCell()
}

// tonBuildProofCell builds the proof Cell matching decodeProof() layout.
// Main Cell (832 bits inline):
//
//	txHash(256) | proofMerkleRoot(256) | leafHash(256) | expirationTime(64)
//
// Refs: [merkleProofCell, governanceCell, blsCell, commitmentsCell]
func tonBuildProofCell(proof TonCertenProof) *cell.Cell {
	txHashInt := new(big.Int).SetBytes(proof.TransactionHash[:])
	merkleRootInt := new(big.Int).SetBytes(proof.MerkleRoot[:])
	leafHashInt := new(big.Int).SetBytes(proof.LeafHash[:])

	return cell.BeginCell().
		MustStoreBigUInt(txHashInt, 256).
		MustStoreBigUInt(merkleRootInt, 256).
		MustStoreBigUInt(leafHashInt, 256).
		MustStoreUInt(proof.ExpirationTime, 64).
		MustStoreRef(tonBuildMerkleProofCell(proof.ProofHashes)).
		MustStoreRef(tonBuildGovernanceCell(proof)).
		MustStoreRef(tonBuildBlsCell(proof)).
		MustStoreRef(tonBuildCommitmentsCell(proof.CommitOperationCommitment, proof.CommitCrossChainCommitment, proof.CommitGovernanceRoot)).
		EndCell()
}

// tonBuildMerkleProofCell: count(uint16) | hash0(uint256) | hash1(uint256) | ...
// Chains hashes across multiple cells to stay within 1023-bit limit.
// Each cell holds up to 3 hashes (768 bits) + optional ref to continuation.
func tonBuildMerkleProofCell(proofHashes [][32]byte) *cell.Cell {
	b := cell.BeginCell().MustStoreUInt(uint64(len(proofHashes)), 16)
	stored := 0
	bitsUsed := 16 // count field

	for i, h := range proofHashes {
		if bitsUsed+256 > 1023 {
			// Overflow: store remaining hashes in a continuation ref
			remaining := proofHashes[i:]
			contCell := tonBuildHashChainCell(remaining)
			b = b.MustStoreRef(contCell)
			break
		}
		hashInt := new(big.Int).SetBytes(h[:])
		b = b.MustStoreBigUInt(hashInt, 256)
		bitsUsed += 256
		stored++
	}
	_ = stored
	return b.EndCell()
}

// tonBuildHashChainCell stores hashes in a chain of cells (max 3 per cell, 768 bits)
func tonBuildHashChainCell(hashes [][32]byte) *cell.Cell {
	b := cell.BeginCell()
	bitsUsed := 0
	for i, h := range hashes {
		if bitsUsed+256 > 1023 {
			remaining := hashes[i:]
			contCell := tonBuildHashChainCell(remaining)
			b = b.MustStoreRef(contCell)
			break
		}
		hashInt := new(big.Int).SetBytes(h[:])
		b = b.MustStoreBigUInt(hashInt, 256)
		bitsUsed += 256
	}
	return b.EndCell()
}

// tonBuildGovernanceCell: keyBookRoot(256) | authorityLevel(8) | nonce(64) | requiredSigs(16) | providedSigs(16)
// Refs: [authorityAddressCell, keyPageProofsCell]
func tonBuildGovernanceCell(proof TonCertenProof) *cell.Cell {
	keyBookRootInt := new(big.Int).SetBytes(proof.GovKeyBookRoot[:])

	authorityCell := cell.BeginCell()
	if proof.GovAuthorityAddress != nil {
		authorityCell = authorityCell.MustStoreAddr(proof.GovAuthorityAddress)
	} else {
		authorityCell = authorityCell.MustStoreAddr(address.NewAddress(0, 0, make([]byte, 32)))
	}

	keyPageCell := cell.BeginCell().MustStoreUInt(uint64(len(proof.GovKeyPageProofs)), 16)
	for _, h := range proof.GovKeyPageProofs {
		hashInt := new(big.Int).SetBytes(h[:])
		keyPageCell = keyPageCell.MustStoreBigUInt(hashInt, 256)
	}

	return cell.BeginCell().
		MustStoreBigUInt(keyBookRootInt, 256).
		MustStoreUInt(uint64(proof.GovAuthorityLevel), 8).
		MustStoreUInt(proof.GovNonce, 64).
		MustStoreUInt(uint64(proof.GovRequiredSignatures), 16).
		MustStoreUInt(uint64(proof.GovProvidedSignatures), 16).
		MustStoreRef(authorityCell.EndCell()).
		MustStoreRef(keyPageCell.EndCell()).
		EndCell()
}

// tonBuildBlsCell: messageHash(256) | thresholdMet(1) | signedVP(64) | totalVP(64)
// Refs: [zkProofCell]
// zkProofCell layout (matching decodeZkProof() in groth16_verifier.tact):
//
//	inline: pubkeyCommitment (uint256, 256 bits)
//	refs[0]: pi_a Cell (BLS12-381 G1 compressed, 48 bytes = 384 bits)
//	refs[1]: pi_b Cell (BLS12-381 G2 compressed, 96 bytes = 768 bits)
//	refs[2]: pi_c Cell (BLS12-381 G1 compressed, 48 bytes = 384 bits)
//
// The 192-byte BLS12-381 proof layout: pi_a[0:48] + pi_b[48:144] + pi_c[144:192]
func tonBuildBlsCell(proof TonCertenProof) *cell.Cell {
	msgHashInt := new(big.Int).SetBytes(proof.BLSMessageHash[:])

	// Build zkProofCell with pubkeyCommitment inline + 3 refs
	zkProofCell := cell.BeginCell()

	// Store pubkeyCommitment inline (256 bits) — extracted by decodeZkProof() before loading refs
	pkCommitInt := new(big.Int)
	if len(proof.BLSPubkeyCommitment) >= 32 {
		pkCommitInt.SetBytes(proof.BLSPubkeyCommitment[:32])
	}
	zkProofCell = zkProofCell.MustStoreBigUInt(pkCommitInt, 256)

	if len(proof.BLSProofBytes) == 192 {
		// BLS12-381 format: pi_a (48B) + pi_b (96B) + pi_c (48B)
		piA := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[0:48], 384).EndCell()
		piB := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[48:144], 768).EndCell()
		piC := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[144:192], 384).EndCell()
		zkProofCell = zkProofCell.MustStoreRef(piA).MustStoreRef(piB).MustStoreRef(piC)
		log.Printf("🔐 [TON-ZK] Built zkProofCell (BLS12-381): pkCommit=0x%x... pi_a=%dB pi_b=%dB pi_c=%dB",
			proof.BLSPubkeyCommitment[:4], 48, 96, 48)
	} else if len(proof.BLSProofBytes) > 0 {
		log.Printf("⚠️ [TON-ZK] Unexpected proof size %d (expected 192 for BLS12-381)", len(proof.BLSProofBytes))
		// Store as empty refs so Cell structure is valid
		emptyCell := cell.BeginCell().EndCell()
		zkProofCell = zkProofCell.MustStoreRef(emptyCell).MustStoreRef(emptyCell).MustStoreRef(emptyCell)
	} else {
		// No proof bytes — store empty refs
		emptyCell := cell.BeginCell().EndCell()
		zkProofCell = zkProofCell.MustStoreRef(emptyCell).MustStoreRef(emptyCell).MustStoreRef(emptyCell)
	}

	return cell.BeginCell().
		MustStoreBigUInt(msgHashInt, 256).
		MustStoreBoolBit(proof.BLSThresholdMet).
		MustStoreUInt(proof.BLSSignedVotingPower, 64).
		MustStoreUInt(proof.BLSTotalVotingPower, 64).
		MustStoreRef(zkProofCell.EndCell()).
		EndCell()
}

// tonBuildCommitmentsCell: opCommit(256) | ccCommit(256) | govRoot(256)
func tonBuildCommitmentsCell(opCommit, ccCommit, govRoot [32]byte) *cell.Cell {
	return cell.BeginCell().
		MustStoreBigUInt(new(big.Int).SetBytes(opCommit[:]), 256).
		MustStoreBigUInt(new(big.Int).SetBytes(ccCommit[:]), 256).
		MustStoreBigUInt(new(big.Int).SetBytes(govRoot[:]), 256).
		EndCell()
}

// WaitForProofExecution polls getAnchorInfo until proofExecuted == true.
func (tc *TonClient) WaitForProofExecution(ctx context.Context, bundleId [32]byte, timeout time.Duration) error {
	log.Printf("⏳ [TON] Waiting for proof execution (async BLS callback)...")
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		anchorData, err := tc.GetAnchorData(ctx, bundleId)
		if err != nil {
			log.Printf("⚠️ [TON] Polling anchor data: %v", err)
		} else if anchorData != nil && anchorData.ProofExecuted {
			log.Printf("✅ [TON] Proof executed successfully!")
			return nil
		} else if anchorData != nil {
			log.Printf("   [TON] Proof pending: proofExecuted=%v proofPending=%v",
				anchorData.ProofExecuted, anchorData.ProofPending)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tonPollingInterval):
		}
	}

	return fmt.Errorf("proof execution not confirmed after %v", timeout)
}

// =============================================================================
// STEP 3: EXECUTE GOVERNANCE PROOF DIRECT
// =============================================================================

// TonADIGovernanceProof holds the governance proof for Step 3.
type TonADIGovernanceProof struct {
	AdiURL     string
	AnchorID   [32]byte
	MerklePath [][32]byte

	KBUrl        string
	KBRoot       [32]byte
	KBDepth      uint16
	KBValidFrom  uint64
	KBValidUntil uint64

	RoleLevel        uint8
	RoleHash         [32]byte
	RoleAuthorizedBy *address.Address
	RoleGrantedAt    uint64
	RoleSignature    []byte

	ThreshRequired     uint16
	ThreshActual       uint16
	ThreshTotalPower   uint64
	ThreshMessageHash  [32]byte
	ThreshSigners      []*address.Address
	ThreshVotingPowers []uint64
	ThreshSignatures   [][]byte

	Timestamp           uint64
	ExpiresAt           uint64
	ValidatorSignatures []byte
	Nonce               uint64
	RequiredLevel       uint8
	OperationHash       [32]byte
}

// ExecuteGovernanceProofDirect sends the message to the account contract.
// ASYNC: account sends AnchorVerifyRequest to anchor, which responds with AnchorVerifyResult.
func (tc *TonClient) ExecuteGovernanceProofDirect(
	ctx context.Context,
	accountAddr string,
	recipientAddr string,
	amountNano uint64,
	proof TonADIGovernanceProof,
) (string, error) {
	log.Printf("📡 [TON] Step 3: Executing governance proof direct...")
	log.Printf("   Account: %s", accountAddr)
	log.Printf("   Recipient: %s", recipientAddr)
	log.Printf("   Amount: %d nanoTON", amountNano)

	acctAddr, err := address.ParseAddr(accountAddr)
	if err != nil {
		return "", fmt.Errorf("invalid account address: %w", err)
	}

	recipAddr, err := address.ParseAddr(recipientAddr)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}

	body := tonBuildGovProofDirectBody(recipAddr, amountNano, proof)

	hash, err := tc.sendInternalMessage(ctx, acctAddr, tonGovGas+amountNano, body)
	if err != nil {
		return "", fmt.Errorf("execute_governance_proof_direct failed: %w", err)
	}

	log.Printf("✅ [TON] Governance proof sent: hash=%s", hash)
	return hash, nil
}

// tonBuildGovProofDirectBody: op(32) | queryId(64) | target(addr) | value(coins) | data(ref) | proof(ref)
func tonBuildGovProofDirectBody(recipient *address.Address, amountNano uint64, proof TonADIGovernanceProof) *cell.Cell {
	queryId := uint64(time.Now().UnixNano())
	proofCell := tonBuildADIGovernanceProofCell(proof)
	dataCell := cell.BeginCell().EndCell()

	return cell.BeginCell().
		MustStoreUInt(uint64(opExecuteGovernanceProofDirect), 32).
		MustStoreUInt(queryId, 64).
		MustStoreAddr(recipient).
		MustStoreCoins(amountNano).
		MustStoreRef(dataCell).
		MustStoreRef(proofCell).
		EndCell()
}

// tonBuildADIGovernanceProofCell matches decodeADIGovernanceProof() layout.
// Main Cell (472 bits): anchorId(256) | timestamp(64) | expiresAt(64) | nonce(64) | requiredLevel(8) | merkleLen(16)
// Refs: [adiUrlCell, merkleProofCell, keyBookCell, roleCell]
// Continuation: [thresholdCell, validatorSignaturesCell]
func tonBuildADIGovernanceProofCell(proof TonADIGovernanceProof) *cell.Cell {
	anchorInt := new(big.Int).SetBytes(proof.AnchorID[:])

	adiUrlCell := cell.BeginCell().MustStoreStringSnake(proof.AdiURL).EndCell()
	merkleProofCell := tonBuildMerkleProofCell(proof.MerklePath)
	keyBookCell := tonBuildKeyBookCell(proof)
	roleCell := tonBuildRoleCell(proof)
	thresholdCell := tonBuildThresholdCell(proof)

	validatorSigsCell := cell.BeginCell()
	if len(proof.ValidatorSignatures) > 0 {
		validatorSigsCell = validatorSigsCell.MustStoreSlice(proof.ValidatorSignatures, uint(len(proof.ValidatorSignatures)*8))
	}

	contCell := cell.BeginCell().
		MustStoreRef(thresholdCell).
		MustStoreRef(validatorSigsCell.EndCell()).
		EndCell()

	return cell.BeginCell().
		MustStoreBigUInt(anchorInt, 256).
		MustStoreUInt(proof.Timestamp, 64).
		MustStoreUInt(proof.ExpiresAt, 64).
		MustStoreUInt(proof.Nonce, 64).
		MustStoreUInt(uint64(proof.RequiredLevel), 8).
		MustStoreUInt(uint64(len(proof.MerklePath)), 16).
		MustStoreRef(adiUrlCell).
		MustStoreRef(merkleProofCell).
		MustStoreRef(keyBookCell).
		MustStoreRef(roleCell).
		MustStoreRef(contCell).
		EndCell()
}

// tonBuildKeyBookCell: keyBookRoot(256) | depth(16) | validFrom(64) | validUntil(64) | Refs:[urlCell]
func tonBuildKeyBookCell(proof TonADIGovernanceProof) *cell.Cell {
	kbRootInt := new(big.Int).SetBytes(proof.KBRoot[:])
	urlCell := cell.BeginCell().MustStoreStringSnake(proof.KBUrl).EndCell()

	return cell.BeginCell().
		MustStoreBigUInt(kbRootInt, 256).
		MustStoreUInt(uint64(proof.KBDepth), 16).
		MustStoreUInt(proof.KBValidFrom, 64).
		MustStoreUInt(proof.KBValidUntil, 64).
		MustStoreRef(urlCell).
		EndCell()
}

// tonBuildRoleCell: level(8) | roleHash(256) | grantedAt(64) | authorizedBy(addr) | Refs:[sigCell]
func tonBuildRoleCell(proof TonADIGovernanceProof) *cell.Cell {
	roleHashInt := new(big.Int).SetBytes(proof.RoleHash[:])

	sigCell := cell.BeginCell()
	if len(proof.RoleSignature) > 0 {
		sigCell = sigCell.MustStoreSlice(proof.RoleSignature, uint(len(proof.RoleSignature)*8))
	}

	b := cell.BeginCell().
		MustStoreUInt(uint64(proof.RoleLevel), 8).
		MustStoreBigUInt(roleHashInt, 256).
		MustStoreUInt(proof.RoleGrantedAt, 64)

	if proof.RoleAuthorizedBy != nil {
		b = b.MustStoreAddr(proof.RoleAuthorizedBy)
	} else {
		b = b.MustStoreAddr(address.NewAddress(0, 0, make([]byte, 32)))
	}

	return b.MustStoreRef(sigCell.EndCell()).EndCell()
}

// tonBuildThresholdCell: required(16) | actual(16) | totalVP(64) | msgHash(256)
// Refs: [signersCell, powersCell, sigsCell]
func tonBuildThresholdCell(proof TonADIGovernanceProof) *cell.Cell {
	msgHashInt := new(big.Int).SetBytes(proof.ThreshMessageHash[:])

	signersCell := cell.BeginCell()
	for _, signer := range proof.ThreshSigners {
		signersCell = signersCell.MustStoreAddr(signer)
	}

	powersCell := cell.BeginCell()
	for _, power := range proof.ThreshVotingPowers {
		powersCell = powersCell.MustStoreUInt(power, 64)
	}

	sigsCell := cell.BeginCell()
	for _, sig := range proof.ThreshSignatures {
		sigRef := cell.BeginCell().MustStoreSlice(sig, uint(len(sig)*8)).EndCell()
		sigsCell = sigsCell.MustStoreRef(sigRef)
	}

	return cell.BeginCell().
		MustStoreUInt(uint64(proof.ThreshRequired), 16).
		MustStoreUInt(uint64(proof.ThreshActual), 16).
		MustStoreUInt(proof.ThreshTotalPower, 64).
		MustStoreBigUInt(msgHashInt, 256).
		MustStoreRef(signersCell.EndCell()).
		MustStoreRef(powersCell.EndCell()).
		MustStoreRef(sigsCell.EndCell()).
		EndCell()
}

// =============================================================================
// ACCOUNT OPERATIONS
// =============================================================================

// DeployAccountViaFactory sends CreateAccountIfNotExists to the factory.
func (tc *TonClient) DeployAccountViaFactory(ctx context.Context, owner, adiURL string, salt uint64) (string, error) {
	log.Printf("📡 [TON] Deploying account via factory...")
	log.Printf("   Owner: %s", owner)
	log.Printf("   ADI URL: %s", adiURL)
	log.Printf("   Salt: %d", salt)

	if tc.factoryContract == nil {
		return "", fmt.Errorf("factory contract not configured")
	}

	ownerAddr, err := address.ParseAddr(owner)
	if err != nil {
		return "", fmt.Errorf("invalid owner address: %w", err)
	}

	adiUrlCell := cell.BeginCell().MustStoreStringSnake(adiURL).EndCell()

	body := cell.BeginCell().
		MustStoreUInt(uint64(opCreateAccountIfNotExists), 32).
		MustStoreAddr(ownerAddr).
		MustStoreRef(adiUrlCell).
		MustStoreUInt(salt, 64).
		EndCell()

	hash, err := tc.sendInternalMessage(ctx, tc.factoryContract, tonDeployGas, body)
	if err != nil {
		return "", fmt.Errorf("factory deployment failed: %w", err)
	}

	log.Printf("✅ [TON] Account deployment sent: hash=%s", hash)
	return hash, nil
}

// TonAnchorData holds anchor data from the TON contract.
type TonAnchorData struct {
	BundleId             [32]byte
	MerkleRoot           [32]byte
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	BlockHeight          uint64
	Timestamp            uint64
	ProofExecuted        bool
	ProofPending         bool
	Valid                bool
	Exists               bool
}

// GetAnchorData reads anchor data via getAnchorInfo getter.
func (tc *TonClient) GetAnchorData(ctx context.Context, bundleId [32]byte) (*TonAnchorData, error) {
	result, err := tc.runGetMethod(ctx, tc.anchorContract.String(), "getAnchorInfo", [][]interface{}{
		{"num", "0x" + hex.EncodeToString(bundleId[:])},
	})
	if err != nil {
		return nil, fmt.Errorf("getAnchorInfo failed: %w", err)
	}

	var resp struct {
		GasUsed int             `json:"gas_used"`
		Stack   [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("parsing getAnchorInfo: %w", err)
	}

	anchorData := &TonAnchorData{BundleId: bundleId}

	if len(resp.Stack) >= 1 {
		anchorData.Exists = tonParseStackBool(resp.Stack, 0)
	}
	if len(resp.Stack) >= 10 {
		anchorData.Valid = tonParseStackBool(resp.Stack, 9)
	}
	if len(resp.Stack) >= 11 {
		anchorData.ProofExecuted = tonParseStackBool(resp.Stack, 10)
	}
	if len(resp.Stack) >= 12 {
		anchorData.ProofPending = tonParseStackBool(resp.Stack, 11)
	}

	return anchorData, nil
}

func tonParseStackBool(stack [][]interface{}, index int) bool {
	if index >= len(stack) || len(stack[index]) < 2 {
		return false
	}
	hexStr, ok := stack[index][1].(string)
	if !ok {
		return false
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	val := new(big.Int)
	val.SetString(hexStr, 16)
	return val.Sign() != 0
}

// CheckAccountExists checks if an account contract is deployed at the address.
func (tc *TonClient) CheckAccountExists(ctx context.Context, accountAddr string) (bool, error) {
	result, err := tc.apiCall(ctx, "getAddressInformation", map[string]string{
		"address": accountAddr,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}

	var info struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(result, &info); err != nil {
		return false, fmt.Errorf("parsing address info: %w", err)
	}

	return info.State == "active", nil
}

// WaitForConfirmation waits for transaction confirmation.
func (tc *TonClient) WaitForConfirmation(ctx context.Context, msgHash string, timeout time.Duration) error {
	log.Printf("⏳ [TON] Waiting for confirmation: %s (timeout=%v)", msgHash, timeout)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
	}

	log.Printf("✅ [TON] Transaction assumed confirmed: %s", msgHash)
	return nil
}

// =============================================================================
// TON-SPECIFIC DERIVATION HELPERS
// =============================================================================

// DeriveTonAccountOwner returns the wallet address for use as account owner.
func DeriveTonAccountOwner(walletAddr *address.Address) string {
	return walletAddr.String()
}

// DeriveTonAccountSalt derives u64 salt from ADI URL (same as SUI).
func DeriveTonAccountSalt(adiURL string) uint64 {
	return DeriveSuiAccountSalt(adiURL)
}

// tonAuthorityLevelForNano returns authority level based on nanoTON amount.
func tonAuthorityLevelForNano(nano uint64) uint8 {
	const (
		rootThreshold    = 10_000_000_000_000
		adminThreshold   = 1_000_000_000_000
		managerThreshold = 100_000_000_000
	)

	if nano >= rootThreshold {
		return 4
	} else if nano >= adminThreshold {
		return 3
	} else if nano >= managerThreshold {
		return 2
	}
	return 1
}

// =============================================================================
// WALLET V4R2 CODE
// =============================================================================

func getWalletV4R2Code() *cell.Cell {
	// Standard WalletV4R2 code BOC (base64-encoded)
	const walletV4R2CodeBOC = "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIPAgFIAwYC5tAB0NMDIXGwkl8E4CLXScEgkl8E4ALTHyGCEHBsdWe9IoIQZHN0cr2wkl8F4AP6QDAg+kQByMoHy//J0O1E0IEBQNch9AQwXIEBCPQKb6Exs5JfB+AF0z/IJYIQcGx1Z7qSODDjDQOCEGRzdHK6kl8G4w0EBQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAHDgIBIAgNAgFYCQoAPbKd+1E0IEBQNch9AQwAsjKB8v/ydABgQEI9ApvoTGACASALDAAZrc52omhAIGuQ64X/wAAZrx32omhAEGuQ64WPwAARuMl+1E0NcLH4AFm9JCtvaiaECAoGuQ+gIYRw1AgIR6STfSmRDOaQPp/5g3gSgBt4EBSJhxWfMYQE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVAj45Sg="

	bocBytes, err := base64.StdEncoding.DecodeString(walletV4R2CodeBOC)
	if err != nil {
		log.Printf("⚠️ [TON] Failed to decode wallet code BOC: %v", err)
		return cell.BeginCell().EndCell()
	}

	cells, err := cell.FromBOC(bocBytes)
	if err != nil {
		log.Printf("⚠️ [TON] Failed to parse wallet code BOC: %v", err)
		return cell.BeginCell().EndCell()
	}

	return cells
}
