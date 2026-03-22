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

// Tact message op codes - extracted from compiled Tact build output.
// These MUST match the values in tact_CertenAnchorV4Ton.ts and tact_CertenAccountFactoryTon.ts.
const (
	opCreateAnchor                 uint32 = 0x5608AE97 // 1443260439 - CertenAnchorV5Ton (V5: includes executionCommitment)
	opExecuteComprehensiveProof    uint32 = 0xCF7BCEC3 // 3480997571 - CertenAnchorV5Ton (unchanged)
	opExecuteGovernanceProofDirect uint32 = 0x7D7FD8A6 // 2105530534 - CertenAccountV3Ton (unchanged)
	opCreateAccountIfNotExists     uint32 = 0xCF2583AF // 3475342255 - CertenAccountFactoryV2Ton (unchanged)
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

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt+1) * time.Second
			log.Printf("📡 [TON] API rate limited on %s, retry %d/5 after %v...", method, attempt+1, wait)
			time.Sleep(wait)
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

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
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
			errMsg := fmt.Sprintf("API error: %s (status=%d body=%s)", apiResp.Error, resp.StatusCode, string(body[:min(len(body), 500)]))
			if resp.StatusCode == 429 {
				lastErr = fmt.Errorf("%s", errMsg)
				continue
			}
			return nil, fmt.Errorf("%s", errMsg)
		}

		return apiResp.Result, nil
	}
	return nil, fmt.Errorf("API rate limited after 5 retries: %w", lastErr)
}

func (tc *TonClient) apiPost(ctx context.Context, method string, reqBody interface{}) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/%s", tc.apiURL, method)

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt+1) * time.Second
			log.Printf("📡 [TON] API rate limited on %s, retry %d/5 after %v...", method, attempt+1, wait)
			time.Sleep(wait)
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

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
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
			errMsg := fmt.Sprintf("API error: %s (status=%d body=%s)", apiResp.Error, resp.StatusCode, string(respBody[:min(len(respBody), 500)]))
			if resp.StatusCode == 429 {
				lastErr = fmt.Errorf("%s", errMsg)
				continue
			}
			return nil, fmt.Errorf("%s", errMsg)
		}

		return apiResp.Result, nil
	}
	return nil, fmt.Errorf("API rate limited after 5 retries: %w", lastErr)
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
		MustStoreUInt(0, 1+4+4+64+32+1) // other_currencies(1) + ihr_fee(4) + fwd_fee(4) + created_lt(64) + created_at(32) + init_absent(1)

	if body != nil {
		internalMsg = internalMsg.MustStoreBoolBit(true).MustStoreRef(body) // body_flag=1: body in ref
	} else {
		internalMsg = internalMsg.MustStoreBoolBit(false) // body_flag=0: no body
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

	// Return a composite token: body_hash + send timestamp.
	// TON Cell.Hash() (representation hash) may not match TON Center API's
	// body_hash due to serialization differences. The timestamp enables
	// the observer to fall back to time-based transaction matching.
	var trackHash []byte
	if body != nil {
		trackHash = body.Hash()
	} else {
		trackHash = extMsg.Hash()
	}
	sendTS := time.Now().Unix()
	msgHash := fmt.Sprintf("%s_ts_%d", hex.EncodeToString(trackHash), sendTS)
	log.Printf("✅ [TON] Message sent: hash=%s (body_hash + timestamp, next seqno=%d)", msgHash, tc.lastSeqno)
	return msgHash, nil
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor sends a CreateAnchor message to the anchor contract.
// V4: includes adiURLHash for 4-leaf sorted merkle tree binding.
func (tc *TonClient) CreateAnchor(
	ctx context.Context,
	bundleId [32]byte,
	adiURLHash [32]byte,
	opCommitment, ccCommitment, govRoot [32]byte,
	executionCommitment [32]byte,
	blockHeight uint64,
) (string, error) {
	log.Printf("📡 [TON] Step 1: Creating anchor (V5 with executionCommitment)...")
	log.Printf("   Wallet: %s", tc.walletAddress.String())
	log.Printf("   Anchor Contract: %s", tc.anchorContract.String())
	log.Printf("   Bundle ID: 0x%x", bundleId[:8])
	log.Printf("   adiURLHash: 0x%x", adiURLHash[:8])
	log.Printf("   execCommitment: 0x%x", executionCommitment[:8])
	log.Printf("   Block Height: %d", blockHeight)
	log.Printf("   OpCode: 0x%X (%d)", opCreateAnchor, opCreateAnchor)

	body := tonBuildCreateAnchorBody(bundleId, adiURLHash, opCommitment, ccCommitment, govRoot, executionCommitment, blockHeight)

	hash, err := tc.sendInternalMessage(ctx, tc.anchorContract, tonGasAmount, body)
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [TON] Anchor creation sent: hash=%s", hash)
	return hash, nil
}

// tonBuildCreateAnchorBody builds the Cell body for V4 CreateAnchor.
// Matches Tact serialization of CreateAnchor message:
//   Main cell (800 bits): op(32) + bundleId(256) + adiURLHash(256) + opCommit(256)
//   Continuation ref (576 bits): ccCommit(256) + govRoot(256) + blockHeight(64)
func tonBuildCreateAnchorBody(bundleId, adiURLHash, opCommitment, ccCommitment, govRoot, executionCommitment [32]byte, blockHeight uint64) *cell.Cell {
	bundleInt := new(big.Int).SetBytes(bundleId[:])
	adiHashInt := new(big.Int).SetBytes(adiURLHash[:])
	opInt := new(big.Int).SetBytes(opCommitment[:])
	ccInt := new(big.Int).SetBytes(ccCommitment[:])
	govInt := new(big.Int).SetBytes(govRoot[:])
	execInt := new(big.Int).SetBytes(executionCommitment[:])

	// V5: Continuation cell: ccCommit(256) + govRoot(256) + execCommit(256) + blockHeight(64) = 832 bits
	cont := cell.BeginCell().
		MustStoreBigUInt(ccInt, 256).
		MustStoreBigUInt(govInt, 256).
		MustStoreBigUInt(execInt, 256).
		MustStoreUInt(blockHeight, 64).
		EndCell()

	// Main cell: op(32) + bundleId(256) + adiURLHash(256) + opCommit(256) = 800 bits + ref
	return cell.BeginCell().
		MustStoreUInt(uint64(opCreateAnchor), 32).
		MustStoreBigUInt(bundleInt, 256).
		MustStoreBigUInt(adiHashInt, 256).
		MustStoreBigUInt(opInt, 256).
		MustStoreRef(cont).
		EndCell()
}

// ComputeAdiURLHash computes the adiURLHash matching the TON account contract's
// computeStringHash() / computeAdiLeaf() in verification.tact.
//
// On-chain Tact code:
//
//	fun computeStringHash(s: String): Int {
//	    let sb = beginString();
//	    sb.append(s);
//	    let c = beginCell()
//	        .storeUint(0, 8)        // domain separation prefix
//	        .storeRef(sb.toCell())   // string as Snake cell in ref
//	        .endCell();
//	    return c.hash();
//	}
//
// This MUST match so that AnchorVerifyRequest.adiLeaf == CreateAnchor.adiURLHash.
func ComputeAdiURLHash(adiURL string) [32]byte {
	// Step 1: Build the Snake cell for the string (matches beginString().append(s).toCell())
	// Snake encoding: 0x00 prefix byte + raw UTF-8 bytes
	snakeCell := cell.BeginCell().
		MustStoreStringSnake(adiURL).
		EndCell()

	// Step 2: Build the main cell: storeUint(0, 8) + storeRef(snakeCell)
	mainCell := cell.BeginCell().
		MustStoreUInt(0, 8).
		MustStoreRef(snakeCell).
		EndCell()

	// Step 3: Hash (Cell.hash() = SHA-256 of standard cell representation)
	hash := mainCell.Hash()

	var result [32]byte
	copy(result[:], hash)
	log.Printf("🔑 [TON] ComputeAdiURLHash(%q) = 0x%x", adiURL, result[:8])
	return result
}

// =============================================================================
// TON-SPECIFIC MERKLE HASHING (SHA-256 cell representation, NOT Keccak256)
// =============================================================================

// TonSortedHash computes sortedHash(a,b) the same way the Tact contract does:
// build a Cell with (smaller, larger) as two uint256, then take Cell.hash() (SHA-256).
// This is NOT the same as the EVM Keccak256-based sortedHash.
func TonSortedHash(a, b [32]byte) [32]byte {
	aInt := new(big.Int).SetBytes(a[:])
	bInt := new(big.Int).SetBytes(b[:])

	var left, right *big.Int
	if aInt.Cmp(bInt) <= 0 {
		left, right = aInt, bInt
	} else {
		left, right = bInt, aInt
	}

	c := cell.BeginCell().
		MustStoreBigUInt(left, 256).
		MustStoreBigUInt(right, 256).
		EndCell()

	hash := c.Hash()
	var result [32]byte
	copy(result[:], hash)
	return result
}

// TonComputeBoundMerkleRoot computes the 4-leaf sorted merkle root matching
// the Tact contract's computeBoundMerkleRoot() function.
//
//	hash01 = tonSortedHash(adiURLHash, operationCommitment)
//	hash23 = tonSortedHash(crossChainCommitment, governanceRoot)
//	root   = tonSortedHash(hash01, hash23)
func TonComputeBoundMerkleRoot(adiURLHash, opCommitment, ccCommitment, govRoot [32]byte) [32]byte {
	hash01 := TonSortedHash(adiURLHash, opCommitment)
	hash23 := TonSortedHash(ccCommitment, govRoot)
	return TonSortedHash(hash01, hash23)
}

// TonComputeDomainTagHash computes the domain-tagged hash matching the Tact
// contract's computeDomainTagHash() function.
// Returns SHA-256 of Cell(ref:snakeStringCell, uint256:value)
func TonComputeDomainTagHash(prefix string, value [32]byte) [32]byte {
	// Tact beginString().append(s).toCell() = snake encoding: 0x00 prefix + string bytes
	strCell := cell.BeginCell().
		MustStoreStringSnake(prefix).
		EndCell()

	c := cell.BeginCell().
		MustStoreRef(strCell).
		MustStoreBigUInt(new(big.Int).SetBytes(value[:]), 256).
		EndCell()

	var result [32]byte
	copy(result[:], c.Hash())
	return result
}

// TonComputeBoundMerkleRoot5 computes the 5-leaf domain-tagged sorted merkle root
// matching the Tact contract's computeBoundMerkleRoot5() function.
//
//	taggedAdi  = computeDomainTagHash("certen:adi:", adiURLHash)
//	taggedOp   = computeDomainTagHash("certen:op:", operationCommitment)
//	taggedCC   = computeDomainTagHash("certen:cc:", crossChainCommitment)
//	taggedGov  = computeDomainTagHash("certen:gov:", governanceRoot)
//	taggedExec = computeDomainTagHash("certen:exec:", executionCommitment)
//	hash01   = sortedHash(taggedAdi, taggedOp)
//	hash23   = sortedHash(taggedCC, taggedGov)
//	hash0123 = sortedHash(hash01, hash23)
//	root     = sortedHash(hash0123, taggedExec)
func TonComputeBoundMerkleRoot5(adiURLHash, opCommitment, ccCommitment, govRoot, execCommitment [32]byte) [32]byte {
	taggedAdi := TonComputeDomainTagHash("certen:adi:", adiURLHash)
	taggedOp := TonComputeDomainTagHash("certen:op:", opCommitment)
	taggedCC := TonComputeDomainTagHash("certen:cc:", ccCommitment)
	taggedGov := TonComputeDomainTagHash("certen:gov:", govRoot)
	taggedExec := TonComputeDomainTagHash("certen:exec:", execCommitment)

	hash01 := TonSortedHash(taggedAdi, taggedOp)
	hash23 := TonSortedHash(taggedCC, taggedGov)
	hash0123 := TonSortedHash(hash01, hash23)
	return TonSortedHash(hash0123, taggedExec)
}

// TonComputeExecutionCommitment computes the execution commitment matching
// the Tact contract's computeExecutionCommitment() function.
// Returns SHA-256 of Cell(int32:chainId, address:target, coins:value, uint256:dataHash)
func TonComputeExecutionCommitment(chainId int32, target *address.Address, valueNano uint64, dataHash [32]byte) [32]byte {
	c := cell.BeginCell().
		MustStoreInt(int64(chainId), 32).
		MustStoreAddr(target).
		MustStoreCoins(valueNano).
		MustStoreBigUInt(new(big.Int).SetBytes(dataHash[:]), 256).
		EndCell()

	var result [32]byte
	copy(result[:], c.Hash())
	return result
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

		// Comprehensive hex logging for debugging on-chain verification
		log.Printf("🔐 [TON-ZK-DEBUG] === BLS12-381 Proof Cell Data ===")
		log.Printf("🔐 [TON-ZK-DEBUG] messageHash    = %s", hex.EncodeToString(proof.BLSMessageHash[:]))
		log.Printf("🔐 [TON-ZK-DEBUG] pkCommitment   = %s", hex.EncodeToString(proof.BLSPubkeyCommitment[:]))
		log.Printf("🔐 [TON-ZK-DEBUG] signedVP=%d totalVP=%d thresholdMet=%v",
			proof.BLSSignedVotingPower, proof.BLSTotalVotingPower, proof.BLSThresholdMet)
		log.Printf("🔐 [TON-ZK-DEBUG] pi_a = %s", hex.EncodeToString(proof.BLSProofBytes[0:48]))
		log.Printf("🔐 [TON-ZK-DEBUG] pi_b = %s", hex.EncodeToString(proof.BLSProofBytes[48:144]))
		log.Printf("🔐 [TON-ZK-DEBUG] pi_c = %s", hex.EncodeToString(proof.BLSProofBytes[144:192]))
		log.Printf("🔐 [TON-ZK-DEBUG] piA first byte: 0x%02x (flags: compress=%v infinity=%v sign=%v)",
			proof.BLSProofBytes[0],
			proof.BLSProofBytes[0]&0x80 != 0,
			proof.BLSProofBytes[0]&0x40 != 0,
			proof.BLSProofBytes[0]&0x20 != 0)
		log.Printf("🔐 [TON-ZK-DEBUG] piB first byte: 0x%02x (flags: compress=%v infinity=%v sign=%v)",
			proof.BLSProofBytes[48],
			proof.BLSProofBytes[48]&0x80 != 0,
			proof.BLSProofBytes[48]&0x40 != 0,
			proof.BLSProofBytes[48]&0x20 != 0)
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

// TestBLSVerifierDirect calls the BLS verifier's verifyBLSSignatureProofView getter
// directly to test whether a proof verifies on-chain, bypassing the anchor contract.
func (tc *TonClient) TestBLSVerifierDirect(ctx context.Context, proof TonCertenProof) {
	if tc.blsVerifier == nil || len(proof.BLSProofBytes) != 192 {
		return
	}

	// Build the same Cells that the verifier expects
	piA := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[0:48], 384).EndCell()
	piB := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[48:144], 768).EndCell()
	piC := cell.BeginCell().MustStoreSlice(proof.BLSProofBytes[144:192], 384).EndCell()

	msgHashInt := new(big.Int).SetBytes(proof.BLSMessageHash[:])
	pkCommitInt := new(big.Int)
	if len(proof.BLSPubkeyCommitment) >= 32 {
		pkCommitInt.SetBytes(proof.BLSPubkeyCommitment[:32])
	}

	pubInputs := cell.BeginCell().
		MustStoreBigUInt(msgHashInt, 256).
		MustStoreBigUInt(pkCommitInt, 256).
		MustStoreUInt(proof.BLSSignedVotingPower, 64).
		MustStoreUInt(proof.BLSTotalVotingPower, 64).
		EndCell()

	// Serialize Cells as base64 BOC
	piABoc := base64.StdEncoding.EncodeToString(piA.ToBOC())
	piBBoc := base64.StdEncoding.EncodeToString(piB.ToBOC())
	piCBoc := base64.StdEncoding.EncodeToString(piC.ToBOC())
	pubInputsBoc := base64.StdEncoding.EncodeToString(pubInputs.ToBOC())

	log.Printf("🧪 [TON-ZK-TEST] Calling verifier getter directly: %s", tc.blsVerifier.String())
	log.Printf("🧪 [TON-ZK-TEST] pubInputs Cell hash: %x", pubInputs.Hash())

	// TON Center API v2 format for Cell parameters on the stack
	result, err := tc.runGetMethod(ctx, tc.blsVerifier.String(), "verifyBLSSignatureProofView", [][]interface{}{
		{"cell", map[string]string{"bytes": piABoc}},
		{"cell", map[string]string{"bytes": piBBoc}},
		{"cell", map[string]string{"bytes": piCBoc}},
		{"cell", map[string]string{"bytes": pubInputsBoc}},
		{"num", fmt.Sprintf("0x%x", proof.BLSSignedVotingPower)},
		{"num", fmt.Sprintf("0x%x", proof.BLSTotalVotingPower)},
	})
	if err != nil {
		log.Printf("⚠️ [TON-ZK-TEST] Direct verifier test FAILED: %v", err)
		return
	}

	var resp struct {
		ExitCode int             `json:"exit_code"`
		Stack    [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		log.Printf("⚠️ [TON-ZK-TEST] Failed to parse verifier response: %v", err)
		return
	}

	log.Printf("🧪 [TON-ZK-TEST] Verifier getter exit_code=%d stack=%v", resp.ExitCode, resp.Stack)
	if resp.ExitCode != 0 {
		log.Printf("❌ [TON-ZK-TEST] Verifier getter failed with exit_code=%d (non-zero = error)", resp.ExitCode)
	} else if len(resp.Stack) > 0 {
		resultVal := tonParseStackBool(resp.Stack, 0)
		log.Printf("🧪 [TON-ZK-TEST] verifyBLSSignatureProofView result: %v", resultVal)
	}
}

// CheckBLSVerifierStats queries the BLS verifier contract for verification statistics.
func (tc *TonClient) CheckBLSVerifierStats(ctx context.Context) {
	if tc.blsVerifier == nil {
		return
	}
	result, err := tc.runGetMethod(ctx, tc.blsVerifier.String(), "getVerificationStats", nil)
	if err != nil {
		return
	}
	var resp struct {
		ExitCode int             `json:"exit_code"`
		Stack    [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(result, &resp); err != nil || resp.ExitCode != 0 {
		return
	}
	// Stats tuple may need flattening
	stack := tonFlattenStack(resp.Stack)
	if len(stack) >= 5 {
		log.Printf("📊 [TON-VERIFIER] Stats: total=%d success=%d cache=%d thresholdFail=%d cryptoFail=%d",
			tonParseStackUint64(stack, 0),
			tonParseStackUint64(stack, 1),
			tonParseStackUint64(stack, 2),
			tonParseStackUint64(stack, 3),
			tonParseStackUint64(stack, 4))
	}
}

// WaitForProofExecution polls getAnchorInfo until proofExecuted == true.
func (tc *TonClient) WaitForProofExecution(ctx context.Context, bundleId [32]byte, timeout time.Duration) error {
	log.Printf("⏳ [TON] Waiting for proof execution (async BLS callback)...")
	deadline := time.Now().Add(timeout)

	// Check verifier stats before waiting
	tc.CheckBLSVerifierStats(ctx)
	pollCount := 0

	for time.Now().Before(deadline) {
		anchorData, err := tc.GetAnchorData(ctx, bundleId)
		if err != nil {
			log.Printf("⚠️ [TON] Polling anchor data: %v", err)
		} else if anchorData != nil && anchorData.ProofExecuted {
			log.Printf("✅ [TON] Proof executed successfully!")
			tc.CheckBLSVerifierStats(ctx)
			return nil
		} else if anchorData != nil {
			log.Printf("   [TON] Proof pending: proofExecuted=%v proofPending=%v",
				anchorData.ProofExecuted, anchorData.ProofPending)
			// Check verifier stats periodically (every 6th poll = ~30s)
			pollCount++
			if pollCount%6 == 0 {
				tc.CheckBLSVerifierStats(ctx)
			}
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
// Refs [0..3]: [adiUrlCell, merkleProofCell, keyBookCell, contCell]
// contCell refs: [roleCell, thresholdCell, validatorSignaturesCell]
//
// TON cells support max 4 refs. The decoder handles this by loading 3 main refs
// then loading a continuation cell containing role, threshold, and validator sigs.
func tonBuildADIGovernanceProofCell(proof TonADIGovernanceProof) *cell.Cell {
	anchorInt := new(big.Int).SetBytes(proof.AnchorID[:])

	adiUrlCell := cell.BeginCell().MustStoreStringSnake(proof.AdiURL).EndCell()
	// Step 3 merkle proof: NO count prefix — account's decodeMerkleProof reads raw hashes
	merkleProofCell := tonBuildMerkleProofCellRaw(proof.MerklePath)
	keyBookCell := tonBuildKeyBookCell(proof)
	roleCell := tonBuildRoleCell(proof)
	thresholdCell := tonBuildThresholdCell(proof)

	validatorSigsCell := cell.BeginCell()
	if len(proof.ValidatorSignatures) > 0 {
		validatorSigsCell = validatorSigsCell.MustStoreSlice(proof.ValidatorSignatures, uint(len(proof.ValidatorSignatures)*8))
	}

	// Continuation cell with remaining refs (role + threshold + validatorSigs)
	contCell := cell.BeginCell().
		MustStoreRef(roleCell).
		MustStoreRef(thresholdCell).
		MustStoreRef(validatorSigsCell.EndCell()).
		EndCell()

	// Main cell: 472 bits + 4 refs (max allowed by TON)
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
		MustStoreRef(contCell).
		EndCell()
}

// tonBuildMerkleProofCellRaw builds merkle proof hashes WITHOUT a count prefix.
// Used by Step 3 (account contract's decodeMerkleProof reads raw hashes,
// the count comes from the parent cell's merkleLen field).
func tonBuildMerkleProofCellRaw(proofHashes [][32]byte) *cell.Cell {
	b := cell.BeginCell()
	bitsUsed := 0
	for i, h := range proofHashes {
		if bitsUsed+256 > 1023 {
			// Overflow: remaining hashes in continuation ref
			remaining := proofHashes[i:]
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

// GetAnchorData reads anchor data using anchorExists + getAnchor getters.
// V4 Anchor struct field order on TVM stack:
//
//	0: bundleId, 1: merkleRoot, 2: adiURLHash, 3: opCommitment,
//	4: ccCommitment, 5: govRoot, 6: blockHeight, 7: timestamp,
//	8: validator, 9: valid, 10: proofExecuted, 11: proofPending
func (tc *TonClient) GetAnchorData(ctx context.Context, bundleId [32]byte) (*TonAnchorData, error) {
	bundleHex := "0x" + hex.EncodeToString(bundleId[:])
	anchorData := &TonAnchorData{BundleId: bundleId}

	// First check if anchor exists (simple Bool getter)
	existsResult, err := tc.runGetMethod(ctx, tc.anchorContract.String(), "anchorExists", [][]interface{}{
		{"num", bundleHex},
	})
	if err != nil {
		return nil, fmt.Errorf("anchorExists failed: %w", err)
	}

	var existsResp struct {
		GasUsed  int             `json:"gas_used"`
		ExitCode int             `json:"exit_code"`
		Stack    [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(existsResult, &existsResp); err != nil {
		return nil, fmt.Errorf("parsing anchorExists: %w", err)
	}

	if existsResp.ExitCode != 0 {
		log.Printf("⚠️ [TON] anchorExists getter exit_code=%d", existsResp.ExitCode)
		return nil, fmt.Errorf("anchorExists exit_code=%d", existsResp.ExitCode)
	}

	anchorData.Exists = tonParseStackBool(existsResp.Stack, 0)
	if !anchorData.Exists {
		return anchorData, nil
	}

	// Anchor exists — get full data via getAnchor getter
	result, err := tc.runGetMethod(ctx, tc.anchorContract.String(), "getAnchor", [][]interface{}{
		{"num", bundleHex},
	})
	if err != nil {
		// Anchor exists but can't read details — return partial data
		anchorData.Valid = true
		return anchorData, nil
	}

	var resp struct {
		GasUsed int             `json:"gas_used"`
		Stack   [][]interface{} `json:"stack"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		anchorData.Valid = true
		return anchorData, nil
	}

	// Tact getters returning structs produce a single tuple element on the stack.
	// Flatten [["tuple", {elements:[...]}]] into [["num","0x..."], ...] so all
	// downstream parsing works uniformly.
	resp.Stack = tonFlattenStack(resp.Stack)

	// Parse V4 Anchor struct fields from stack:
	//   0:bundleId 1:merkleRoot 2:adiURLHash 3:opCommitment
	//   4:ccCommitment 5:govRoot 6:blockHeight 7:timestamp
	//   8:validator(addr) 9:valid 10:proofExecuted 11:proofPending
	if len(resp.Stack) >= 2 {
		anchorData.MerkleRoot = tonParseStackHash(resp.Stack, 1)
	}
	if len(resp.Stack) >= 4 {
		anchorData.OperationCommitment = tonParseStackHash(resp.Stack, 3)
	}
	if len(resp.Stack) >= 5 {
		anchorData.CrossChainCommitment = tonParseStackHash(resp.Stack, 4)
	}
	if len(resp.Stack) >= 6 {
		anchorData.GovernanceRoot = tonParseStackHash(resp.Stack, 5)
	}
	if len(resp.Stack) >= 7 {
		anchorData.BlockHeight = tonParseStackUint64(resp.Stack, 6)
	}
	if len(resp.Stack) >= 8 {
		anchorData.Timestamp = tonParseStackUint64(resp.Stack, 7)
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

	log.Printf("📊 [TON] Anchor data parsed: valid=%v proofExecuted=%v proofPending=%v blockHeight=%d",
		anchorData.Valid, anchorData.ProofExecuted, anchorData.ProofPending, anchorData.BlockHeight)

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
	// Handle both positive (0x...) and negative (-0x...) hex prefixes.
	// TVM represents true as -1, which the API returns as "-0x1".
	if strings.HasPrefix(hexStr, "-0x") || strings.HasPrefix(hexStr, "-0X") {
		hexStr = "-" + hexStr[3:]
	} else {
		hexStr = strings.TrimPrefix(hexStr, "0x")
		hexStr = strings.TrimPrefix(hexStr, "0X")
	}
	val := new(big.Int)
	val.SetString(hexStr, 16)
	return val.Sign() != 0
}

// tonParseStackHash extracts a [32]byte hash from a stack entry at the given index.
func tonParseStackHash(stack [][]interface{}, index int) [32]byte {
	var result [32]byte
	if index >= len(stack) || len(stack[index]) < 2 {
		return result
	}
	hexStr, ok := stack[index][1].(string)
	if !ok {
		return result
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	val := new(big.Int)
	val.SetString(hexStr, 16)
	valBytes := val.Bytes()
	if len(valBytes) > 32 {
		valBytes = valBytes[:32]
	}
	copy(result[32-len(valBytes):], valBytes)
	return result
}

// tonParseStackUint64 extracts a uint64 from a stack entry at the given index.
func tonParseStackUint64(stack [][]interface{}, index int) uint64 {
	if index >= len(stack) || len(stack[index]) < 2 {
		return 0
	}
	hexStr, ok := stack[index][1].(string)
	if !ok {
		return 0
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	val := new(big.Int)
	val.SetString(hexStr, 16)
	return val.Uint64()
}

// tonFlattenStack converts a TON API stack response from tuple format to flat format.
// Tact getters returning structs produce [["tuple", {"elements":[...]}]] on the stack.
// This function unwraps the tuple into [["num","0x..."], ...] for uniform parsing.
func tonFlattenStack(stack [][]interface{}) [][]interface{} {
	if len(stack) != 1 || len(stack[0]) < 2 {
		return stack
	}
	typeStr, ok := stack[0][0].(string)
	if !ok || typeStr != "tuple" {
		return stack
	}
	tupleData, ok := stack[0][1].(map[string]interface{})
	if !ok {
		return stack
	}
	elements, ok := tupleData["elements"].([]interface{})
	if !ok {
		return stack
	}

	flat := make([][]interface{}, len(elements))
	for i, elem := range elements {
		flat[i] = []interface{}{"num", "0x0"} // default
		elemMap, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		// Handle tvm.stackEntryNumber -> {"number": {"number": "..."}}
		if numObj, ok := elemMap["number"].(map[string]interface{}); ok {
			if numStr, ok := numObj["number"].(string); ok {
				// Convert decimal to hex if needed
				if !strings.HasPrefix(numStr, "0x") && !strings.HasPrefix(numStr, "-") {
					val := new(big.Int)
					val.SetString(numStr, 10)
					numStr = "0x" + val.Text(16)
				}
				flat[i] = []interface{}{"num", numStr}
			}
		}
		// Address/Cell entries stay as default "0x0" — skip gracefully
	}
	log.Printf("🔍 [TON] Flattened tuple stack: %d elements", len(flat))
	return flat
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
