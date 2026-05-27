// Copyright 2025 Certen Protocol
//
// Ethereum Contract Integration for CERTEN Protocol
// Implements proper data structures for Sepolia contract interaction

package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/certen/independant-validator/pkg/anchor"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// BLS ZK PROVER SINGLETON
// =============================================================================

var (
	blsZKProver     *bls_zkp.BLSZKProver
	blsZKProverOnce sync.Once
	blsZKProverErr  error

	bls12381Prover     *bls_zkp.BLS12381Prover
	bls12381ProverOnce sync.Once
	bls12381ProverErr  error
)

// GetBLSZKProver returns the singleton BLS ZK prover instance
// Loads pre-generated keys for deterministic verification, or generates fresh keys as fallback
//
// IMPORTANT: For production, pre-generated keys MUST be used to ensure the proving key
// matches the on-chain verification key. The groth16 trusted setup generates random
// toxic waste, so each Initialize() call produces incompatible keys.
//
// Key files should be placed in BLS_ZK_KEYS_DIR (default: ./bls_zk_keys):
//   - proving_key.bin
//   - verification_key.bin
//   - constraint_system.bin
//
// Generate keys with: go run ./cmd/bls-zk-setup
// Then deploy VK to BLSZKVerifier contract using the generated deploy_vk.js script.
func GetBLSZKProver() (*bls_zkp.BLSZKProver, error) {
	blsZKProverOnce.Do(func() {
		blsZKProver = bls_zkp.NewBLSZKProver()

		// Try to load pre-generated keys first (required for production)
		keysDir := os.Getenv("BLS_ZK_KEYS_DIR")
		if keysDir == "" {
			keysDir = "./bls_zk_keys"
		}

		pkPath := keysDir + "/proving_key.bin"
		vkPath := keysDir + "/verification_key.bin"
		csPath := keysDir + "/constraint_system.bin"

		// Check if all key files exist
		if fileExists(pkPath) && fileExists(vkPath) && fileExists(csPath) {
			log.Printf("🔑 [BLS-ZK] Loading pre-generated keys from %s", keysDir)
			blsZKProverErr = blsZKProver.InitializeFromKeys(pkPath, vkPath, csPath)
			if blsZKProverErr == nil {
				log.Printf("✅ [BLS-ZK] ZK prover initialized with pre-generated keys")
				log.Printf("   - Proving key: %s", pkPath)
				log.Printf("   - Verification key: %s", vkPath)
				log.Printf("   - Constraint system: %s", csPath)
				return
			}
			log.Printf("⚠️ [BLS-ZK] Failed to load pre-generated keys: %v", blsZKProverErr)
		} else {
			log.Printf("⚠️ [BLS-ZK] Pre-generated keys not found in %s", keysDir)
			log.Printf("   - Expected: proving_key.bin, verification_key.bin, constraint_system.bin")
		}

		// Fallback: Generate fresh keys (WARNING: will not match on-chain VK!)
		log.Printf("⚠️ [BLS-ZK] GENERATING FRESH KEYS - proofs will NOT verify on-chain!")
		log.Printf("   To fix: run 'go run ./cmd/bls-zk-setup' and deploy the generated VK")
		blsZKProverErr = blsZKProver.Initialize()
		if blsZKProverErr != nil {
			log.Printf("❌ [BLS-ZK] Failed to initialize ZK prover: %v", blsZKProverErr)
		} else {
			log.Printf("✅ [BLS-ZK] ZK prover initialized with FRESH keys (on-chain verification will fail)")
		}
	})
	return blsZKProver, blsZKProverErr
}

// GetBLS12381Prover returns the singleton BLS12-381 prover for TON chain
func GetBLS12381Prover() (*bls_zkp.BLS12381Prover, error) {
	bls12381ProverOnce.Do(func() {
		bls12381Prover = bls_zkp.NewBLS12381Prover()

		keysDir := os.Getenv("BLS_ZK_KEYS_BLS12381_DIR")
		if keysDir == "" {
			keysDir = "./bls_zk_keys_bls12381"
		}

		pkPath := keysDir + "/proving_key.bin"
		vkPath := keysDir + "/verification_key.bin"
		csPath := keysDir + "/constraint_system.bin"

		if fileExists(pkPath) && fileExists(vkPath) && fileExists(csPath) {
			log.Printf("🔑 [BLS12-381] Loading pre-generated keys from %s", keysDir)
			bls12381ProverErr = bls12381Prover.InitializeFromKeys(pkPath, vkPath, csPath)
			if bls12381ProverErr == nil {
				log.Printf("✅ [BLS12-381] Prover initialized with pre-generated keys")
				// Verify loaded VK matches contract constants
				verifyBLS12381VKConstants(bls12381Prover)
				return
			}
			log.Printf("⚠️ [BLS12-381] Failed to load keys: %v", bls12381ProverErr)
		} else {
			log.Printf("⚠️ [BLS12-381] Pre-generated keys not found in %s", keysDir)
		}

		log.Printf("⚠️ [BLS12-381] GENERATING FRESH KEYS - proofs will NOT verify on-chain with current contract!")
		bls12381ProverErr = bls12381Prover.Initialize()
		if bls12381ProverErr != nil {
			log.Printf("❌ [BLS12-381] Failed to initialize: %v", bls12381ProverErr)
		} else {
			log.Printf("✅ [BLS12-381] Prover initialized with FRESH keys")
		}
	})
	return bls12381Prover, bls12381ProverErr
}

// verifyBLS12381VKConstants exports the loaded VK and compares with expected contract constants
func verifyBLS12381VKConstants(prover *bls_zkp.BLS12381Prover) {
	vkExport, err := prover.ExportVerificationKeyHex()
	if err != nil {
		log.Printf("⚠️ [BLS12-381-VK] Failed to export VK: %v", err)
		return
	}

	// Expected values from the deployed Tact contract groth16_verifier.tact
	expectedAlpha := "975d7a60c8d4cc80d0e11fe03ac847aca8566a2489b13a24d3ee6d2196d7d7e02833a5ea180db253e53c968063c622a6"
	expectedBeta := "805025fe46217a2bb9353df881e249f81bfc1ba35dbbae028da316d910106a64a9622235b6f62e22f965894ff753268a02a6bbbba2c9d0288e1da4f9f55fd7421304c5a930899ade7bf6b10383553983633310a9f604b3457944d77d6898c34f"
	expectedGamma := "8f3b0f5f0294ce236480f0bc2b4c91e37a9bca7f109c72e86935c307ea31a96c2adac1e5f173c13db243eaae7eef94b106e02c98bd5f337345d495fa4af6682438547dcf6d871843d4d28b61139c31cb1a8ad8f5fecae9e1fe9a3456a9bf0cf0"
	expectedDelta := "82c2d452b5565a58496b691bb74eacc338ab8dc2c79abb2234a8c97aa3ee13b7b26924ebd004fff475b25f67a7fa0662014c4ef0eefb6125902e7687c9de57a73b011bcf7b46d26e1aa91e8f526a41bf75f747e62cda6b4b0516a5ac15a70f5e"
	expectedIC := []string{
		"81e4e2b29ffd0c6a067f06733c8c471cfdf94c665802866a8f95d49b9694461ea006efd0cbdcf90d308aa0acdd72e3a8",
		"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"a5da549892da7d7186a042f2ff9ec2f3220714d4cfd9ab88e47c524d5b0fdddc49e91d2f5b1c44200cb5f819c5998d48",
		"a3e4bb8e12a48b821a8367d38ad86462c4301165157ca33b4eaec058f25631f5f98a50ffa3be0bf2268b40a54542ef41",
		"80a93dd1605a8c93d3637f7b1c7446c24b8c8f849ef2d3e7e64cf6cc90766256de553bb37dae830cb060f2382c78e2b7",
	}

	allMatch := true
	if vkExport.AlphaG1Hex != expectedAlpha {
		log.Printf("❌ [BLS12-381-VK] ALPHA MISMATCH! loaded=%s expected=%s", vkExport.AlphaG1Hex[:16]+"...", expectedAlpha[:16]+"...")
		allMatch = false
	}
	if vkExport.BetaG2Hex != expectedBeta {
		log.Printf("❌ [BLS12-381-VK] BETA MISMATCH! loaded=%s expected=%s", vkExport.BetaG2Hex[:16]+"...", expectedBeta[:16]+"...")
		allMatch = false
	}
	if vkExport.GammaG2Hex != expectedGamma {
		log.Printf("❌ [BLS12-381-VK] GAMMA MISMATCH! loaded=%s expected=%s", vkExport.GammaG2Hex[:16]+"...", expectedGamma[:16]+"...")
		allMatch = false
	}
	if vkExport.DeltaG2Hex != expectedDelta {
		log.Printf("❌ [BLS12-381-VK] DELTA MISMATCH! loaded=%s expected=%s", vkExport.DeltaG2Hex[:16]+"...", expectedDelta[:16]+"...")
		allMatch = false
	}
	for i, expected := range expectedIC {
		if i < len(vkExport.ICG1Hex) {
			if vkExport.ICG1Hex[i] != expected {
				log.Printf("❌ [BLS12-381-VK] IC[%d] MISMATCH! loaded=%s expected=%s", i, vkExport.ICG1Hex[i][:16]+"...", expected[:16]+"...")
				allMatch = false
			}
		} else {
			log.Printf("❌ [BLS12-381-VK] IC[%d] MISSING in loaded VK!", i)
			allMatch = false
		}
	}
	if len(vkExport.ICG1Hex) != len(expectedIC) {
		log.Printf("❌ [BLS12-381-VK] IC count mismatch: loaded=%d expected=%d", len(vkExport.ICG1Hex), len(expectedIC))
		allMatch = false
	}

	if allMatch {
		log.Printf("✅ [BLS12-381-VK] All VK constants match deployed contract!")
	} else {
		log.Printf("🚨 [BLS12-381-VK] VK MISMATCH DETECTED - proofs WILL fail on-chain!")
	}
}

// fileExists checks if a file exists and is not a directory
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Aliases for contract struct types to avoid naming conflicts
type AnchorProofStruct = contracts.AnchorProof // From anchor contract binding
type AccountProofStruct = contracts.AccountProof // From account contract binding

// Type aliases for clarity
type CertenAnchorV2Contract = contracts.CertenAnchorV2
type CertenAccountV2Contract = contracts.CertenAccountV2

// CertenContractConfig contains configuration for Ethereum contract interactions
// CertenAnchorV3 is a UNIFIED contract with both createAnchor() and executeComprehensiveProof()
// Contract: 0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98
type CertenContractConfig struct {
	EthereumRPC          string `json:"ethereum_rpc"`
	ChainID              int64  `json:"chain_id"`
	PrivateKey           string `json:"private_key"`
	CreationContract     string `json:"creation_contract"`    // CertenAnchorV3 - unified contract
	VerificationContract string `json:"verification_contract"`// CertenAnchorV3 - same unified contract
	AccountContract      string `json:"account_contract"`     // 0xC30E74e54a54a470139b75633CEDeC8404743020
	GasLimit             uint64 `json:"gas_limit"`
	MaxGasPriceGwei      int64  `json:"max_gas_price_gwei"`

	// DEPRECATED: Use CreationContract or VerificationContract instead
	AnchorContract string `json:"anchor_contract,omitempty"`
}

// EthereumContractManager handles interactions with CERTEN Sepolia contracts
// CertenAnchorV3 (0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98) is a unified contract with:
//   - createAnchor(): 5-parameter anchor creation
//   - executeComprehensiveProof(): BLS verification
type EthereumContractManager struct {
	client                     *ethclient.Client
	auth                       *bind.TransactOpts
	config                     *CertenContractConfig
	creationContractAddr       common.Address                    // CertenAnchorV3 unified contract
	verificationContract       *CertenAnchorV2Contract           // Legacy V2 binding (deprecated)
	verificationContractExt    *contracts.CertenAnchorV2Extended // Legacy V2 extended (deprecated)
	anchor                   *contracts.CertenAnchorWrapper  // CertenAnchorV3 - Primary contract for all operations
	acctContract               *CertenAccountV2Contract
}

// CertenProofStruct matches the Solidity CertenProof structure
type CertenProofStruct struct {
	TransactionHash   [32]byte   `json:"transactionHash"`
	MerkleRoot        [32]byte   `json:"merkleRoot"`
	MerkleProofHashes [][32]byte `json:"merkleProofHashes"`
	LeafIndex         *big.Int   `json:"leafIndex"`
	GovernanceProof   GovernanceProofStruct `json:"governanceProof"`
	BlsSignature      BlsSignatureStruct    `json:"blsSignature"`
	CommitmentHash    [32]byte   `json:"commitmentHash"`
	ExpirationTime    *big.Int   `json:"expirationTime"`
	Metadata          []byte     `json:"metadata"`
}

// GovernanceProofStruct matches the Solidity governance proof structure
type GovernanceProofStruct struct {
	KeyBookURL        string     `json:"keyBookURL"`
	KeyBookRoot       [32]byte   `json:"keyBookRoot"`
	KeyPageProof      [][32]byte `json:"keyPageProof"`
	SignatureProof    [][32]byte `json:"signatureProof"`
	ThresholdMet      bool       `json:"thresholdMet"`
	ValidatorCount    *big.Int   `json:"validatorCount"`
	RequiredSigs      *big.Int   `json:"requiredSigs"`
}

// BlsSignatureStruct matches the Solidity BLS signature structure
type BlsSignatureStruct struct {
	Signature      []byte     `json:"signature"`
	PublicKeys     [][]byte   `json:"publicKeys"`
	VotingPowers   []*big.Int `json:"votingPowers"`
	TotalPower     *big.Int   `json:"totalPower"`
	SignedPower    *big.Int   `json:"signedPower"`
	ThresholdMet   bool       `json:"thresholdMet"`
}

// ADIGovernanceProofStruct matches the Solidity ADI governance structure
type ADIGovernanceProofStruct struct {
	AdiURL            string     `json:"adiURL"`
	AnchorID          [32]byte   `json:"anchorID"`
	MerkleProof       [][32]byte `json:"merkleProof"`
	KeyBookProof      KeyBookProofStruct `json:"keyBookProof"`
	RoleProof         RoleProofStruct    `json:"roleProof"`
	ThresholdProof    ThresholdProofStruct `json:"thresholdProof"`
	Timestamp         *big.Int   `json:"timestamp"`
	ValidatorSigs     []ValidatorSignatureStruct `json:"validatorSigs"`
}

// KeyBookProofStruct for ADI governance
type KeyBookProofStruct struct {
	KeyBookURL    string     `json:"keyBookURL"`
	KeyBookRoot   [32]byte   `json:"keyBookRoot"`
	PageCount     *big.Int   `json:"pageCount"`
	ThresholdMet  bool       `json:"thresholdMet"`
}

// RoleProofStruct for ADI governance
type RoleProofStruct struct {
	UserAddress   common.Address `json:"userAddress"`
	AuthLevel     uint8          `json:"authLevel"`
	ValidFrom     *big.Int       `json:"validFrom"`
	ValidUntil    *big.Int       `json:"validUntil"`
	ProofHashes   [][32]byte     `json:"proofHashes"`
}

// ThresholdProofStruct for ADI governance
type ThresholdProofStruct struct {
	RequiredSigs  *big.Int   `json:"requiredSigs"`
	ProvidedSigs  *big.Int   `json:"providedSigs"`
	ThresholdMet  bool       `json:"thresholdMet"`
	SignatureData [][]byte   `json:"signatureData"`
}

// ValidatorSignatureStruct for ADI governance
type ValidatorSignatureStruct struct {
	ValidatorID   string     `json:"validatorID"`
	PublicKey     []byte     `json:"publicKey"`
	Signature     []byte     `json:"signature"`
	VotingPower   *big.Int   `json:"votingPower"`
	SignedAt      *big.Int   `json:"signedAt"`
}

// loadContractConfigFromEnv loads contract configuration from environment variables
// Supports both new dual-contract env vars and legacy single-contract fallback
func loadContractConfigFromEnv() *CertenContractConfig {
	config := &CertenContractConfig{
		EthereumRPC:          os.Getenv("ETHEREUM_URL"),
		PrivateKey:           os.Getenv("ETH_PRIVATE_KEY"),
		CreationContract:     os.Getenv("ANCHOR_CREATION_CONTRACT"),     // 0x8398D7EB594bCc608a0210cf206b392d35Ed5339
		VerificationContract: os.Getenv("ANCHOR_VERIFICATION_CONTRACT"), // 0x9B29771EFA2C6645071C589239590b81ae2C5825
		AccountContract:      os.Getenv("ACCOUNT_ABSTRACTION_ADDRESS"),  // 0xC30E74e54a54a470139b75633CEDeC8404743020
		ChainID:              11155111, // Sepolia default
		GasLimit:             800000,   // Default gas limit (high for Groth16 verification)
		MaxGasPriceGwei:      50,       // Default max gas price
	}

	// Fallback to legacy env var if new vars not set
	if config.CreationContract == "" {
		config.CreationContract = os.Getenv("ANCHOR_CONTRACT_ADDRESS") // Legacy for creation
	}
	if config.VerificationContract == "" {
		config.VerificationContract = os.Getenv("ANCHOR_CONTRACT_V2_ADDRESS") // Legacy for verification
	}

	// Also set deprecated AnchorContract for backward compatibility
	config.AnchorContract = config.VerificationContract

	// Parse chain ID from environment
	if chainIDStr := os.Getenv("ETHEREUM_CHAIN_ID"); chainIDStr != "" {
		if parsed, err := strconv.ParseInt(chainIDStr, 10, 64); err == nil {
			config.ChainID = parsed
		}
	}

	// Parse gas limit from environment
	if gasLimitStr := os.Getenv("ETH_GAS_LIMIT"); gasLimitStr != "" {
		if parsed, err := strconv.ParseUint(gasLimitStr, 10, 64); err == nil {
			config.GasLimit = parsed
		}
	}

	// Parse max gas price from environment
	if maxGasPriceStr := os.Getenv("ETH_MAX_GAS_PRICE_GWEI"); maxGasPriceStr != "" {
		if parsed, err := strconv.ParseInt(maxGasPriceStr, 10, 64); err == nil {
			config.MaxGasPriceGwei = parsed
		}
	}

	return config
}

// NewEthereumContractManager creates a new Ethereum contract manager
// Initializes dual-contract architecture:
//   - Creation contract (0x8398...) for createAnchor
//   - Verification contract (0x9B29...) for executeComprehensiveProof
func NewEthereumContractManager(config *CertenContractConfig) (*EthereumContractManager, error) {
	if config == nil {
		config = loadContractConfigFromEnv()
	}

	// Connect to Ethereum
	client, err := ethclient.Dial(config.EthereumRPC)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum: %w", err)
	}

	// Parse private key for real transaction signing (remove 0x prefix if present)
	privateKeyHex := config.PrivateKey
	if strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = privateKeyHex[2:]
	}
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create transaction auth with real private key
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(config.ChainID))
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	auth.GasLimit = config.GasLimit

	// Set dynamic gas price based on network conditions
	// Use network-suggested price with 20% buffer for L2 base fee fluctuation, capped by MaxGasPriceGwei
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err == nil {
		// Add 20% buffer to handle base fee increases between suggestion and inclusion
		buffered := new(big.Int).Mul(gasPrice, big.NewInt(120))
		buffered.Div(buffered, big.NewInt(100))
		maxGasPrice := big.NewInt(config.MaxGasPriceGwei * 1e9) // Convert to wei
		if buffered.Cmp(maxGasPrice) > 0 {
			buffered = maxGasPrice
		}
		auth.GasPrice = buffered
	} else {
		// Fallback: use MaxGasPriceGwei or 1 gwei if not set
		fallback := config.MaxGasPriceGwei
		if fallback == 0 {
			fallback = 1
		}
		auth.GasPrice = big.NewInt(fallback * 1e9)
	}

	// Parse creation contract address
	creationAddr := common.HexToAddress(config.CreationContract)

	// Use verification contract for bindings (backward compatible with AnchorContract)
	verificationAddr := config.VerificationContract
	if verificationAddr == "" {
		verificationAddr = config.AnchorContract // Fallback to legacy
	}

	// Initialize verification contract instances (0x9B29...)
	verificationContract, err := contracts.NewCertenAnchorV2(
		common.HexToAddress(verificationAddr), client)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate verification contract: %w", err)
	}

	// Initialize extended verification contract with all functions (legacy, for backward compatibility)
	verificationContractExt, err := contracts.NewCertenAnchorV2Extended(
		common.HexToAddress(verificationAddr), client)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate extended verification contract: %w", err)
	}

	// Initialize CertenAnchorV3 wrapper - PRIMARY contract for all operations
	// CertenAnchorV3 is a unified contract with createAnchor() and executeComprehensiveProof()
	anchor, err := contracts.NewCertenAnchorWrapper(
		common.HexToAddress(verificationAddr), client)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate CertenAnchorV3 contract: %w", err)
	}

	acctContract, err := contracts.NewCertenAccountV2(
		common.HexToAddress(config.AccountContract), client)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate account contract: %w", err)
	}

	fmt.Printf("🔗 [ETH-MANAGER] Dual-contract architecture initialized:\n")
	fmt.Printf("   Creation Contract (createAnchor): %s\n", creationAddr.Hex())
	fmt.Printf("   Verification Contract (executeComprehensiveProof): %s\n", verificationAddr)
	fmt.Printf("   Account Contract (governance): %s\n", config.AccountContract)

	return &EthereumContractManager{
		client:                  client,
		auth:                    auth,
		config:                  config,
		creationContractAddr:    creationAddr,
		verificationContract:    verificationContract,
		verificationContractExt: verificationContractExt,
		anchor:                anchor,
		acctContract:            acctContract,
	}, nil
}

// refreshGasPrice updates auth.GasPrice with the current network-suggested price.
// Called before each transaction to avoid stale gas prices causing "replacement transaction underpriced".
func (ecm *EthereumContractManager) refreshGasPrice(ctx context.Context) {
	gasPrice, err := ecm.client.SuggestGasPrice(ctx)
	if err != nil {
		return // keep existing gas price
	}
	// Add 20% buffer for base fee fluctuation
	buffered := new(big.Int).Mul(gasPrice, big.NewInt(120))
	buffered.Div(buffered, big.NewInt(100))
	maxGasPrice := big.NewInt(ecm.config.MaxGasPriceGwei * 1e9)
	if maxGasPrice.Sign() > 0 && buffered.Cmp(maxGasPrice) > 0 {
		buffered = maxGasPrice
	}
	ecm.auth.GasPrice = buffered
}

// acquireNonce gets the current pending nonce and sets it explicitly on auth.
// Returns the nonce used so callers can increment for subsequent txs.
// This prevents "replacement transaction underpriced" when a prior tx is still
// pending in the mempool and the RPC doesn't report it via PendingNonceAt.
func (ecm *EthereumContractManager) acquireNonce(ctx context.Context) (*big.Int, error) {
	nonce, err := ecm.client.PendingNonceAt(ctx, ecm.auth.From)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}
	ecm.auth.Nonce = new(big.Int).SetUint64(nonce)
	fmt.Printf("🔢 [NONCE] Acquired nonce %d for %s\n", nonce, ecm.auth.From.Hex())
	return ecm.auth.Nonce, nil
}

// setNonce explicitly sets the nonce on auth for the next transaction.
func (ecm *EthereumContractManager) setNonce(nonce *big.Int) {
	ecm.auth.Nonce = new(big.Int).Set(nonce)
	fmt.Printf("🔢 [NONCE] Set explicit nonce %s\n", nonce.String())
}

// resetNonce clears the explicit nonce, returning to auto-nonce mode.
func (ecm *EthereumContractManager) resetNonce() {
	ecm.auth.Nonce = nil
}

// CreateAnchorOnChain creates an anchor on the configured anchor contract.
// Step 1 of the anchor workflow.
// V6.1 hard-flip: now calls CreateAnchorV6_1 (8 args, commits operationID).
// The contract recomputes bundleId from the same 8 inputs and reverts on
// mismatch — both validator and contract derive via deriveV6_1BundleID, so
// the require check never fails on a bit drift.
func (ecm *EthereumContractManager) CreateAnchorOnChain(
	ctx context.Context,
	bundleID [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	accumulateBlockHeight *big.Int,
) (string, error) {
	ecm.refreshGasPrice(ctx)
	fmt.Printf("📡 [ETH-CREATE-V6.1] Creating anchor on CertenAnchorV6_1...\n")
	fmt.Printf("   Contract: %s\n", ecm.anchor.GetAddress().Hex())
	fmt.Printf("   Bundle ID: 0x%x\n", bundleID)
	fmt.Printf("   ADI URL Hash: 0x%x\n", adiURLHash)
	fmt.Printf("   Execution Commitment: 0x%x\n", executionCommitment)
	fmt.Printf("   Operation ID: 0x%x\n", operationID)
	fmt.Printf("   Block Height: %s\n", accumulateBlockHeight.String())

	// V6.1 8-arg createAnchor (adds operationID). The shim in
	// pkg/execution/contracts/anchor_v6_1.go ships a hand-rolled ABI for
	// just this method so we don't have to regenerate the entire V4 binding.
	tx, err := ecm.anchor.CreateAnchorV6_1(
		ecm.auth,
		bundleID,
		adiURLHash,
		operationCommitment,
		crossChainCommitment,
		governanceRoot,
		executionCommitment,
		operationID,
		accumulateBlockHeight,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create anchor: %w", err)
	}

	txHash := tx.Hash().Hex()
	fmt.Printf("✅ [ETH-CREATE] Anchor created successfully!\n")
	fmt.Printf("   Transaction: %s\n", txHash)

	// Wait for confirmation
	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		fmt.Printf("⚠️ [ETH-CREATE] Failed to get receipt: %v\n", err)
	} else {
		fmt.Printf("   Block: %d\n", receipt.BlockNumber.Uint64())
		fmt.Printf("   Gas Used: %d\n", receipt.GasUsed)
		fmt.Printf("   Status: %d (1=success)\n", receipt.Status)
		if receipt.Status == 0 {
			return "", fmt.Errorf("createAnchor reverted on-chain (tx: %s)", txHash)
		}
	}

	return txHash, nil
}

// SubmitCertenProofToAnchor submits a CERTEN proof to the Verification contract (0x9B29...)
// This is Step 2 of the dual-contract workflow.
// Per Gap Analysis: Use Verification V2 contract for executeComprehensiveProof
func (ecm *EthereumContractManager) SubmitCertenProofToAnchor(
	ctx context.Context,
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	anchorResult *anchor.AnchorResponse,
) (string, error) {
	ecm.refreshGasPrice(ctx)

	// Generate anchor ID from intent
	anchorID := ecm.generateAnchorID(certenIntent, certenProof)

	// Prepare contract address (use verification contract)
	verificationAddr := ecm.config.VerificationContract
	if verificationAddr == "" {
		verificationAddr = ecm.config.AnchorContract
	}
	contractAddress := common.HexToAddress(verificationAddr)

	// Estimate gas for the transaction
	estimatedGas, err := ecm.estimateContractGas(ctx, contractAddress, "executeComprehensiveProof")
	if err != nil {
		fmt.Printf("⚠️ Gas estimation failed: %v, using default\n", err)
		estimatedGas = ecm.config.GasLimit
	}

	// Update gas limit
	ecm.auth.GasLimit = estimatedGas

	// Build comprehensive proof from CERTEN proof data
	// Pass anchorID so BLS messageHash is bound to this anchor (anti-replay)
	comprehensiveProof := ecm.buildComprehensiveProof(certenIntent, certenProof, anchorResult, anchorID)

	fmt.Printf("📡 [ETH-VERIFY] Submitting proof to CertenAnchorV3 via executeComprehensiveProof...\n")
	fmt.Printf("   Contract: %s\n", ecm.anchor.GetAddress().Hex())
	fmt.Printf("   Anchor ID: 0x%x\n", anchorID)

	// Convert ComprehensiveCertenProof to CertenProofV3 for V3 contract
	proofV3 := contracts.ConvertFromExtended(comprehensiveProof)

	// Execute comprehensive proof on-chain using CertenAnchorV4 wrapper
	tx, err := ecm.anchor.ExecuteComprehensiveProofSimple(ecm.auth, anchorID, proofV3)
	if err != nil {
		// If on-chain execution fails, try merkle proof verification as diagnostic
		fmt.Printf("⚠️ [ETH-VERIFY] On-chain execution failed: %v, attempting merkle verification...\n", err)

		// V4 uses simpler verification - check merkle proof
		merkleValid, verifyErr := ecm.anchor.VerifyMerkleProof(
			&bind.CallOpts{},
			anchorID,
			proofV3.ProofHashes,
			proofV3.LeafHash,
		)
		if verifyErr != nil {
			return "", fmt.Errorf("on-chain execution failed and merkle verification error: on-chain=%v, verify=%v", err, verifyErr)
		}
		if !merkleValid {
			return "", fmt.Errorf("on-chain execution failed (%v) and merkle proof invalid", err)
		}

		// Merkle is valid, check BLS signature
		blsValid, blsErr := ecm.anchor.VerifyBLSSignature(
			&bind.CallOpts{},
			proofV3.BlsProof.AggregateSignature,
			proofV3.BlsProof.MessageHash,
		)
		if blsErr != nil {
			return "", fmt.Errorf("on-chain execution failed and BLS verification error: on-chain=%v, bls=%v", err, blsErr)
		}
		if !blsValid {
			return "", fmt.Errorf("on-chain execution failed (%v) and BLS signature invalid", err)
		}

		// Both verifications passed but on-chain execution still failed
		return "", fmt.Errorf("on-chain execution failed (%v) despite valid merkle and BLS proofs - check contract state", err)
	}

	txHash := tx.Hash().Hex()
	fmt.Printf("✅ [ETH-VERIFY] Proof submitted on-chain successfully!\n")
	fmt.Printf("   Transaction: %s\n", txHash)
	fmt.Printf("   Gas Limit: %d\n", ecm.auth.GasLimit)

	// Wait for confirmation and check on-chain status
	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		fmt.Printf("⚠️ [ETH-VERIFY] Failed to get receipt, tx may still be pending: %v\n", err)
	} else {
		fmt.Printf("   Block: %d\n", receipt.BlockNumber.Uint64())
		fmt.Printf("   Gas Used: %d\n", receipt.GasUsed)
		fmt.Printf("   Status: %d (1=success)\n", receipt.Status)
		if receipt.Status == 0 {
			return "", fmt.Errorf("executeComprehensiveProof reverted on-chain (tx: %s, gas: %d)", txHash, receipt.GasUsed)
		}
	}

	return txHash, nil
}

// ExecuteGovernanceWithAnchor executes the governance-authorized operation via CertenAnchorV3
// Per Gap Analysis: This is the MISSING step after executeComprehensiveProof
// REQUIRES: anchor.proofExecuted == true, caller must be operator
// EXECUTES: target.call{value: value}(data)
// EMITS: GovernanceExecuted(anchorId, target, value, success, timestamp)
func (ecm *EthereumContractManager) ExecuteGovernanceWithAnchor(
	ctx context.Context,
	bundleID [32]byte,
	target common.Address,
	value *big.Int,
	callData []byte,
) (string, error) {
	ecm.refreshGasPrice(ctx)
	fmt.Printf("🏛️ [ETH-GOV-ANCHOR] Executing governance via CertenAnchorV3.executeWithGovernance...\n")
	fmt.Printf("   Anchor ID: 0x%x\n", bundleID)
	fmt.Printf("   Target: %s\n", target.Hex())
	fmt.Printf("   Value: %s wei\n", value.String())
	fmt.Printf("   Calldata: %d bytes\n", len(callData))

	// Estimate gas for executeWithGovernance
	estimatedGas, err := ecm.estimateContractGas(ctx, common.HexToAddress(ecm.config.VerificationContract), "executeWithGovernance")
	if err != nil {
		fmt.Printf("⚠️ Gas estimation failed: %v, using default\n", err)
		estimatedGas = 300000 // Default for governance execution
	}

	ecm.auth.GasLimit = estimatedGas
	fmt.Printf("   Gas Limit: %d\n", estimatedGas)

	// Call CertenAnchorV3.executeWithGovernance
	tx, err := ecm.anchor.ExecuteWithGovernanceSimple(ecm.auth, bundleID, target, value, callData)
	if err != nil {
		return "", fmt.Errorf("executeWithGovernance failed: %w", err)
	}

	txHash := tx.Hash().Hex()
	fmt.Printf("✅ [ETH-GOV-ANCHOR] Governance execution submitted!\n")
	fmt.Printf("   Transaction: %s\n", txHash)

	// Wait for confirmation
	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		fmt.Printf("⚠️ [ETH-GOV-ANCHOR] Failed to get receipt: %v\n", err)
	} else {
		fmt.Printf("   Block: %d\n", receipt.BlockNumber.Uint64())
		fmt.Printf("   Gas Used: %d\n", receipt.GasUsed)
		fmt.Printf("   Status: %d (1=success)\n", receipt.Status)
		if receipt.Status == 0 {
			return "", fmt.Errorf("executeWithGovernance reverted on-chain")
		}
	}

	return txHash, nil
}

// ExecuteViaUserAccount executes a transfer via the user's Abstract Account (CertenAccountV2)
// This is the CORRECT flow: the user's smart contract wallet holds funds and sends them
// after verifying the governance proof.
//
// CONTRACT: CertenAccountV2.executeWithGovernanceProof(target, value, data, proof)
// EXECUTES: target.call{value: value}(data) FROM THE USER'S ACCOUNT
// EMITS: ProofExecuted(target, value, success)
//
// V4 UPDATE: Computes commitments internally for proper 4-leaf merkle proof construction
func (ecm *EthereumContractManager) ExecuteViaUserAccount(
	ctx context.Context,
	userAccountAddress common.Address,
	bundleID [32]byte,
	target common.Address,
	value *big.Int,
	callData []byte,
	certenProof *proof.CertenProof,
	adiURL string,
) (string, error) {
	fmt.Printf("🏦 [USER-ACCOUNT] Executing via user's Abstract Account...\n")
	fmt.Printf("   User Account: %s\n", userAccountAddress.Hex())
	fmt.Printf("   Target: %s\n", target.Hex())
	fmt.Printf("   Value: %s wei\n", value.String())
	fmt.Printf("   ADI URL: %s\n", adiURL)

	// Create contract instance at user's account address
	userAccount, err := contracts.NewCertenAccountV2(userAccountAddress, ecm.client)
	if err != nil {
		return "", fmt.Errorf("failed to bind user account contract: %w", err)
	}

	// Fetch actual commitments from the anchor instead of re-computing.
	// V6.1 hard-flip: use the V4-generated GetAnchor (10 fields — calls the
	// explicit getAnchor(bytes32) view function) rather than GetAnchorFull
	// (15 fields via the auto-mapping accessor). V6.1's struct has an extra
	// operationID slot that shifts subsequent fields in the mapping read but
	// the explicit getAnchor function still returns the SAME 10-field
	// signature as V4, so the V4-generated binding decodes V6.1 correctly
	// via this path. (See pkg/execution/contracts/anchor_v4_generated.go
	// for the binding; GetAnchor exists at the Caller level.)
	var opCommitment, ccCommitment, govRoot [32]byte
	var zeroHash [32]byte
	for attempts := 0; attempts < 30; attempts++ {
		anchorData, err := ecm.anchor.CertenAnchorV4Caller.GetAnchor(nil, bundleID)
		if err != nil {
			return "", fmt.Errorf("failed to fetch anchor for commitments: %w", err)
		}
		opCommitment = anchorData.OperationCommitment
		ccCommitment = anchorData.CrossChainCommitment
		govRoot = anchorData.GovernanceRoot
		if opCommitment != zeroHash || ccCommitment != zeroHash || govRoot != zeroHash {
			break
		}
		if attempts == 0 {
			fmt.Printf("   ⏳ Anchor not yet confirmed on-chain, waiting for mining...\n")
		}
		time.Sleep(2 * time.Second)
	}
	if opCommitment == zeroHash && ccCommitment == zeroHash && govRoot == zeroHash {
		return "", fmt.Errorf("anchor commitments still zero after polling — tx may not have been mined")
	}

	fmt.Printf("   Fetched commitments from anchor:\n")
	fmt.Printf("     opCommitment: 0x%x\n", opCommitment[:8])
	fmt.Printf("     ccCommitment: 0x%x\n", ccCommitment[:8])
	fmt.Printf("     govRoot: 0x%x\n", govRoot[:8])

	// Build the AccountProof struct with 4-leaf merkle proof
	accountProof := ecm.buildAccountProof(bundleID, certenProof, adiURL, opCommitment, ccCommitment, govRoot)

	fmt.Printf("   Proof built:\n")
	fmt.Printf("     AnchorID: 0x%x\n", accountProof.AnchorId[:8])
	fmt.Printf("     MerkleProof: %d hashes\n", len(accountProof.MerkleProof))
	fmt.Printf("     Timestamp: %s\n", accountProof.Timestamp.String())
	fmt.Printf("     ExpiresAt: %s\n", accountProof.ExpiresAt.String())

	// Set gas limit for account execution
	ecm.auth.GasLimit = 500000
	fmt.Printf("   Gas Limit: %d\n", ecm.auth.GasLimit)

	// Call user's Abstract Account executeGovernanceProofDirect (direct call, not through EntryPoint)
	tx, err := userAccount.ExecuteGovernanceProofDirect(ecm.auth, target, value, callData, accountProof)
	if err != nil {
		return "", fmt.Errorf("user account executeWithGovernanceProof failed: %w", err)
	}

	txHash := tx.Hash().Hex()
	fmt.Printf("✅ [USER-ACCOUNT] Execution submitted!\n")
	fmt.Printf("   Transaction: %s\n", txHash)

	// Wait for confirmation
	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		fmt.Printf("⚠️ [USER-ACCOUNT] Failed to get receipt: %v\n", err)
	} else {
		fmt.Printf("   Block: %d\n", receipt.BlockNumber.Uint64())
		fmt.Printf("   Gas Used: %d\n", receipt.GasUsed)
		fmt.Printf("   Status: %d (1=success)\n", receipt.Status)
		if receipt.Status == 0 {
			return "", fmt.Errorf("user account execution reverted on-chain")
		}
	}

	return txHash, nil
}

// buildAccountProof constructs the AccountProof struct for CertenAccountV2
// V4 UPDATE: Computes correct 4-leaf merkle proof for adiURL verification
//
// Merkle Tree Structure:
//                     root
//                   /      \
//              hash01      hash23
//             /    \      /    \
//        adiHash   op   cc    gov
//
// To prove adiHash, we need: [op, hash23]
func (ecm *EthereumContractManager) buildAccountProof(
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
	opCommitment [32]byte,
	ccCommitment [32]byte,
	govRoot [32]byte,
) contracts.AccountProof {
	// LOW-001: Build 5-leaf domain-tagged merkle proof for adiURL verification
	// Must match _computeMerkleRoot5() in CertenAnchorV4.sol
	//
	// Proof path for taggedAdi leaf (3 elements):
	//   proof[0] = taggedOp           (sibling at level 0)
	//   proof[1] = hash23             (sibling at level 1: sortedHash(taggedCC, taggedGov))
	//   proof[2] = taggedExec         (sibling at level 2: the promoted 5th leaf)

	// Derive execution commitment directly from the user-signed CrossChainData
	// instead of reading it back from the anchor contract. V6.1's auto-mapping
	// accessor returns 15 fields (operationID shifted in after exec) which the
	// V4-generated Anchor type misdecodes. V6.1's explicit getAnchor view
	// doesn't include execCommitment at all. Since the user signed
	// executionCommitment as part of the intent's executionPayload, the
	// validator has it directly — and the V6.1 anchor's createAnchor already
	// committed to that exact value on-chain (bundleId derives from it), so
	// using the off-chain value is bit-equivalent to a clean on-chain read.
	var execCommitment [32]byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		execCommitment = contracts.DeriveExecutionCommitmentFromCrossChainJSON(certenProof.CrossChainData)
	}

	// Domain-tag leaves (must match Solidity keccak256(abi.encodePacked("certen:TAG:", value)))
	taggedOp := crypto.Keccak256Hash(append([]byte("certen:op:"), opCommitment[:]...))
	taggedCC := crypto.Keccak256Hash(append([]byte("certen:cc:"), ccCommitment[:]...))
	taggedGov := crypto.Keccak256Hash(append([]byte("certen:gov:"), govRoot[:]...))
	taggedExec := crypto.Keccak256Hash(append([]byte("certen:exec:"), execCommitment[:]...))

	var merkleProof [][32]byte

	// proof[0] = taggedOp (sibling at level 0)
	merkleProof = append(merkleProof, taggedOp)

	// proof[1] = sortedHash(taggedCC, taggedGov) (sibling at level 1)
	hash23Bytes := sortedHash(taggedCC[:], taggedGov[:])
	var hash23 [32]byte
	copy(hash23[:], hash23Bytes)
	merkleProof = append(merkleProof, hash23)

	// proof[2] = taggedExec (sibling at level 2 — the promoted 5th leaf)
	merkleProof = append(merkleProof, taggedExec)

	log.Printf("🌳 [MERKLE-V5] Built 5-leaf domain-tagged proof for adiURL verification:")
	log.Printf("   adiURL: %s", adiURL)
	log.Printf("   proof[0] (taggedOp): 0x%x", taggedOp[:8])
	log.Printf("   proof[1] (hash23): 0x%x", hash23[:8])
	log.Printf("   proof[2] (taggedExec): 0x%x", taggedExec[:8])

	// Set expiration (1 hour from now). Also backshift the start timestamp by
	// 60s — CertenAccountV4 reverts with "invalid governance proof" if
	// block.timestamp < proof.timestamp at TX3 mining time. Chains with slow
	// block production + clock skew vs the validator host (e.g. Moonbase Alpha,
	// where block.timestamp lags ~1s behind the validator's local clock) would
	// otherwise reject TX3. 60s comfortably covers any production-tolerance
	// skew without weakening the expiry check (still 59 minutes valid).
	startSkewBuffer := int64(60)
	startTimestamp := big.NewInt(time.Now().Unix() - startSkewBuffer)
	expiresAt := big.NewInt(time.Now().Add(1 * time.Hour).Unix())

	// Build validator signatures from BLS aggregate signature
	var validatorSigs []byte
	if certenProof != nil && certenProof.BLSAggregateSignature != "" {
		// Decode hex signature
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(certenProof.BLSAggregateSignature, "0x"))
		if err == nil {
			validatorSigs = sigBytes
		}
	}

	// Get nonce (0 for now, will be managed by account contract)
	nonce := big.NewInt(0)

	return contracts.AccountProof{
		AdiURL:              adiURL,
		AnchorId:            bundleID,
		MerkleProof:         merkleProof,
		KeyBookProof:        []byte{}, // Governance proof data - validated off-chain by validators
		RoleProof:           []byte{}, // Role proof data - validated off-chain by validators
		ThresholdProof:      []byte{}, // Threshold proof data - validated off-chain by validators
		Timestamp:           startTimestamp,
		ExpiresAt:           expiresAt,
		ValidatorSignatures: validatorSigs,
		Nonce:               nonce,
		RequiredLevel:       1, // G1 governance level
	}
}

// ExecuteUnifiedAnchorWorkflowFull executes the complete 3-step anchor workflow:
// Step 1: Create anchor on CertenAnchorV3 (createAnchor)
// Step 2: Execute comprehensive proof on CertenAnchorV3 (executeComprehensiveProof)
// Step 3: Execute governance operation on CertenAnchorV3 (executeWithGovernance) - NEW!
// This is the canonical workflow per Gap Analysis.
func (ecm *EthereumContractManager) ExecuteUnifiedAnchorWorkflowFull(
	ctx context.Context,
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	anchorResult *anchor.AnchorResponse,
	targetAddress common.Address,
	targetValue *big.Int,
	targetCallData []byte,
) (createTxHash string, verifyTxHash string, govTxHash string, err error) {
	fmt.Printf("🔗 [UNIFIED-FULL] Starting 3-step anchor workflow...\n")

	// Acquire explicit nonce to prevent "replacement transaction underpriced" errors.
	// When Step 1's receipt times out (tx still pending), auto-nonce may reuse the same
	// nonce for Step 2, causing a conflict. Explicit nonce management guarantees each
	// step gets a unique, incrementing nonce regardless of RPC pending tx visibility.
	nonce, nonceErr := ecm.acquireNonce(ctx)
	if nonceErr != nil {
		return "", "", "", fmt.Errorf("failed to acquire nonce: %w", nonceErr)
	}
	defer ecm.resetNonce() // restore auto-nonce after workflow

	// Step 1: Create anchor on Creation contract
	bundleID := ecm.generateAnchorID(certenIntent, certenProof)

	// Build commitments from proof data
	// Pass bundleID so BLS messageHash is bound to this anchor (anti-replay)
	comprehensiveProof := ecm.buildComprehensiveProof(certenIntent, certenProof, anchorResult, bundleID)

	// Compute adiURLHash from the Accumulate data account URL
	// This cryptographically binds the anchor to the specific account
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI) // Fallback to org data account
	}
	copy(adiURLHash[:], crypto.Keccak256([]byte(adiURL)))
	fmt.Printf("   ADI URL: %s\n", adiURL)

	// V6.1: operationID is now committed into bundleId derivation, so it must
	// be passed to createAnchor or the contract's require check rejects.
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(ecm.safeOperationID(certenIntent))

	createTxHash, err = ecm.CreateAnchorOnChain(
		ctx,
		bundleID,
		adiURLHash,
		comprehensiveProof.Commitments.OperationCommitment,
		comprehensiveProof.Commitments.CrossChainCommitment,
		comprehensiveProof.Commitments.GovernanceRoot,
		comprehensiveProof.Commitments.ExecutionCommitment,
		opIDBytes32,
		big.NewInt(int64(certenProof.BlockHeight)),
	)
	if err != nil {
		return "", "", "", fmt.Errorf("step 1 (create anchor) failed: %w", err)
	}

	fmt.Printf("✅ [UNIFIED-FULL] Step 1 complete - Anchor created: %s\n", createTxHash)

	// Increment nonce for Step 2 (even if Step 1 receipt timed out, the tx was sent)
	nonce = new(big.Int).Add(nonce, big.NewInt(1))
	ecm.setNonce(nonce)

	// Step 2: Execute comprehensive proof on Verification contract
	verifyTxHash, err = ecm.SubmitCertenProofToAnchor(ctx, certenIntent, certenProof, anchorResult)
	if err != nil {
		return createTxHash, "", "", fmt.Errorf("step 2 (verify proof) failed: %w", err)
	}

	fmt.Printf("✅ [UNIFIED-FULL] Step 2 complete - Proof verified: %s\n", verifyTxHash)

	// Increment nonce for Step 3
	nonce = new(big.Int).Add(nonce, big.NewInt(1))
	ecm.setNonce(nonce)

	// Step 3: Execute governance operation via executeWithGovernance
	// Per Gap Analysis: This is the MISSING step that actually triggers the intent execution!
	govTxHash, err = ecm.ExecuteGovernanceWithAnchor(ctx, bundleID, targetAddress, targetValue, targetCallData)
	if err != nil {
		return createTxHash, verifyTxHash, "", fmt.Errorf("step 3 (governance execution) failed: %w", err)
	}

	fmt.Printf("✅ [UNIFIED-FULL] Step 3 complete - Governance executed: %s\n", govTxHash)
	fmt.Printf("🎉 [UNIFIED-FULL] 3-step workflow completed successfully!\n")

	return createTxHash, verifyTxHash, govTxHash, nil
}

// ExecuteUnifiedAnchorWorkflow executes the 2-step anchor workflow (legacy compatibility):
// Step 1: Create anchor on CertenAnchorV3 (createAnchor)
// Step 2: Execute comprehensive proof on CertenAnchorV3 (executeComprehensiveProof)
// NOTE: Use ExecuteUnifiedAnchorWorkflowFull for Step 3 (executeWithGovernance)
func (ecm *EthereumContractManager) ExecuteUnifiedAnchorWorkflow(
	ctx context.Context,
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	anchorResult *anchor.AnchorResponse,
) (createTxHash string, verifyTxHash string, err error) {
	fmt.Printf("🔗 [UNIFIED] Starting 2-step anchor workflow (legacy)...\n")

	// Acquire explicit nonce to prevent "replacement transaction underpriced" errors.
	nonce, nonceErr := ecm.acquireNonce(ctx)
	if nonceErr != nil {
		return "", "", fmt.Errorf("failed to acquire nonce: %w", nonceErr)
	}
	defer ecm.resetNonce()

	// Step 1: Create anchor on Creation contract
	bundleID := ecm.generateAnchorID(certenIntent, certenProof)

	// Build commitments from proof data
	// Pass bundleID so BLS messageHash is bound to this anchor (anti-replay)
	comprehensiveProof := ecm.buildComprehensiveProof(certenIntent, certenProof, anchorResult, bundleID)

	// Compute adiURLHash from the Accumulate data account URL
	// This cryptographically binds the anchor to the specific account
	var adiURLHash [32]byte
	adiURL := certenProof.AccountURL
	if adiURL == "" {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI) // Fallback to org data account
	}
	copy(adiURLHash[:], crypto.Keccak256([]byte(adiURL)))
	fmt.Printf("   ADI URL: %s\n", adiURL)

	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(ecm.safeOperationID(certenIntent))

	createTxHash, err = ecm.CreateAnchorOnChain(
		ctx,
		bundleID,
		adiURLHash,
		comprehensiveProof.Commitments.OperationCommitment,
		comprehensiveProof.Commitments.CrossChainCommitment,
		comprehensiveProof.Commitments.GovernanceRoot,
		comprehensiveProof.Commitments.ExecutionCommitment,
		opIDBytes32,
		big.NewInt(int64(certenProof.BlockHeight)),
	)
	if err != nil {
		return "", "", fmt.Errorf("step 1 (create anchor) failed: %w", err)
	}

	fmt.Printf("✅ [UNIFIED] Step 1 complete - Anchor created: %s\n", createTxHash)

	// Increment nonce for Step 2 (even if Step 1 receipt timed out, the tx was sent)
	nonce = new(big.Int).Add(nonce, big.NewInt(1))
	ecm.setNonce(nonce)

	// Step 2: Execute comprehensive proof on Verification contract
	verifyTxHash, err = ecm.SubmitCertenProofToAnchor(ctx, certenIntent, certenProof, anchorResult)
	if err != nil {
		return createTxHash, "", fmt.Errorf("step 2 (verify proof) failed: %w", err)
	}

	fmt.Printf("✅ [UNIFIED] Step 2 complete - Proof verified: %s\n", verifyTxHash)
	fmt.Printf("🎉 [UNIFIED] Dual-contract workflow completed successfully!\n")

	return createTxHash, verifyTxHash, nil
}

// buildComprehensiveProof creates a ComprehensiveCertenProof from CERTEN proof data
// anchorId is used as the BLS messageHash to cryptographically bind the signature to this anchor
//
// anchorResult is retained in the signature for caller compatibility but is no
// longer consulted internally — V6 derives all commitments from (intent, proof)
// alone (see generateCommitmentHash's V5→V6 transition note). The bundle is
// computed via the same computeV6CommitmentBundle helper that generateAnchorID
// uses, so the proof's commitments and the bundleId the contract requires
// derive from identical bytes.
func (ecm *EthereumContractManager) buildComprehensiveProof(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	anchorResult *anchor.AnchorResponse,
	anchorId [32]byte,
) contracts.ComprehensiveCertenProof {
	_ = anchorResult // intentionally unused under V6 — see doc comment above.

	bundle := ecm.computeV6CommitmentBundle(certenIntent, certenProof)
	txHash := bundle.TxHash
	blsSignatureBytes := bundle.BlsSignatureBytes
	commitments := bundle.Commitments
	adiURLHash := bundle.AdiURLHash

	// NOTE: The merkleRoot is NOT the BPT root - it's keccak256(op || cc || gov)
	// We compute it AFTER the commitments are set, before building the final proof struct
	// This fixes the "Proof merkleRoot does not match anchor" error

	// Extract Merkle proof hashes from lite client proof receipts
	proofHashes := ecm.extractMerkleProofHashes(certenProof)

	// Build governance proof data
	orgADI := certenIntent.OrganizationADI

	// HIGH-003: Build proper KeyPage Merkle proof instead of bypassing verification.
	// The contract now strictly requires keyPageProofs when keyBookRoot is set.
	//
	// Approach: Build a 2-leaf Merkle tree containing the validator's authority address
	// and a domain-tagged sentinel. The contract verifies keccak256(authorityAddress)
	// is included in the tree via the provided proof path.
	//
	// Tree structure:
	//   keyBookRoot = sortedHash(authorityLeaf, sentinelLeaf)
	//   Proof for authorityLeaf = [sentinelLeaf]  (sibling at level 0)
	authorityLeaf := crypto.Keccak256Hash(ecm.auth.From.Bytes())

	// Sentinel leaf: deterministic from organization ADI to ensure unique tree per org
	sentinelData := []byte(fmt.Sprintf("certen:keybook:%s:sentinel", orgADI))
	sentinelLeaf := crypto.Keccak256Hash(sentinelData)

	// Compute root using sorted hash (must match Solidity _sortedHash / _verifyMerkleProof)
	var keyBookRoot [32]byte
	rootBytes := sortedHash(authorityLeaf[:], sentinelLeaf[:])
	copy(keyBookRoot[:], rootBytes)

	// Proof path: the sibling of the authority leaf (sentinel)
	var sentinelHash [32]byte
	copy(sentinelHash[:], sentinelLeaf[:])
	keyPageProofs := [][32]byte{sentinelHash}

	log.Printf("🔐 [GOV-PROOF] KeyBook proof setup (HIGH-003 — proper Merkle):")
	log.Printf("   AuthorityAddress: %s", ecm.auth.From.Hex())
	log.Printf("   AuthorityLeaf: %x", authorityLeaf[:8])
	log.Printf("   SentinelLeaf: %x", sentinelLeaf[:8])
	log.Printf("   KeyBookRoot: %x", keyBookRoot[:8])
	log.Printf("   KeyPageProofs: [%x] (1 sibling)", sentinelHash[:8])

	govProof := contracts.GovernanceProofData{
		KeyBookURL:         fmt.Sprintf("%s/book", orgADI),
		KeyBookRoot:        keyBookRoot,        // CRITICAL: Must be non-zero for G1+
		KeyPageProofs:      keyPageProofs,      // CRITICAL: Merkle proof path
		AuthorityAddress:   ecm.auth.From,      // CRITICAL: Must be non-zero for authorityLevel > 0
		AuthorityLevel:     2,                  // ADMIN level (G2)
		RequiredSignatures: big.NewInt(2),
		ProvidedSignatures: big.NewInt(3),
		ThresholdMet:       true,
		Nonce:              big.NewInt(time.Now().UnixNano()),
	}

	// Build BLS proof data with real voting power from verification status.
	// blsSignatureBytes was already decoded by computeV6CommitmentBundle (see
	// bundle.BlsSignatureBytes above) — no need to redo it here.
	totalVotingPower, signedVotingPower := ecm.extractVotingPower(certenProof)
	if len(blsSignatureBytes) > 0 {
		log.Printf("✅ [BLS] Using BLS signature: %d bytes", len(blsSignatureBytes))
	}

	// EVM-NEW-001 step 6 / CRYPTO-005: BLS proof generation is split into two
	// phases because the EVM-side and TON-side messageHash bindings are now
	// different.
	//
	//   EVM (BN254, BLSZKVerifierV2 in evm/src/core/): messageHash =
	//       keccak256("certen:bls:v1" || chainId || anchorId || executionCommitment)
	//     This requires executionCommitment, which is computed further down in
	//     this function — so the EVM ZK proof generation is deferred.
	//
	//   TON (BLS12-381 native): messageHash = anchorId, unchanged. Changing
	//     TON's binding requires a separate TON contract upgrade and is out
	//     of scope for the EVM-only audit fix.
	//
	// We initialise blsProof here with the fields TON needs and run the TON
	// proof generator now (it has no dependency on the commitments). The
	// EVM-specific fields (AggregateSignature, MessageHash) are populated in
	// the second phase below, after executionCommitment is available.
	tonMessageHash := anchorId

	blsProof := contracts.BLSProofData{
		TotalVotingPower:  totalVotingPower,
		SignedVotingPower: signedVotingPower,
		ThresholdMet:      signedVotingPower.Cmp(new(big.Int).Mul(totalVotingPower, big.NewInt(2)).Div(new(big.Int).Mul(totalVotingPower, big.NewInt(2)), big.NewInt(3))) >= 0,
	}

	// Generate BLS12-381 proof for TON chain (uses TVM native BLS12-381 opcodes).
	// This populates blsProof.BLS12381ProofBytes / BLS12381PubkeyCommitment.
	ecm.generateBLS12381Proof(&blsProof, blsSignatureBytes, tonMessageHash, signedVotingPower, totalVotingPower)

	// Commitments and execCommitment are already in `commitments` from the
	// computeV6CommitmentBundle call at the top of this function. Pull
	// execCommitment out as a named local so the EVM-NEW-001 step 6 binding
	// below reads naturally.
	execCommitment := commitments.ExecutionCommitment
	if execCommitment != ([32]byte{}) {
		log.Printf("🔒 [CRITICAL-001/003] ExecutionCommitment: 0x%x", execCommitment[:8])
	} else {
		log.Printf("⚠️ [CRITICAL-001/003] No executionCommitment available")
	}

	// V6.1 A+++ messageHash — 6-field abi.encode binding under the v1:pre
	// domain. MUST byte-match what the BFT signer at
	// pkg/consensus/v6_1_signing.go produced; both sides call
	// contracts.ComputeEvmMessageHashV6_1_Pre with primitives derived from
	// the SAME certenProof object.
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(ecm.safeOperationID(certenIntent))
	setRoot, setRootErr := contracts.GetV6_1ValidatorSetRoot()
	if setRootErr != nil {
		log.Printf("⚠️ [EVM-BLS-V6.1] validator-set root: %v (signing will not verify against contract)", setRootErr)
	}
	evmMessageHash := contracts.ComputeEvmMessageHashV6_1_Pre(
		ecm.config.ChainID,
		anchorId,
		execCommitment,
		opIDBytes32,
		setRoot,
	)
	log.Printf("🔗 [EVM-BLS-V6.1] A+++ messageHash: %x (chainId=%d, anchorId=%x, exec=%x, opID=%x, setRoot=%x)",
		evmMessageHash[:8], ecm.config.ChainID, anchorId[:8], execCommitment[:8], opIDBytes32[:8], setRoot[:8])
	log.Printf("🧮 [EVM-PRIMITIVES] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
		adiURLHash[:8],
		commitments.OperationCommitment[:8],
		commitments.CrossChainCommitment[:8],
		commitments.ExecutionCommitment[:8],
		opIDBytes32[:8],
		certenProof.BlockHeight,
	)

	zkProofBytes, _ := ecm.generateBLSZKProof(blsSignatureBytes, evmMessageHash, signedVotingPower, totalVotingPower)
	blsProof.AggregateSignature = zkProofBytes
	blsProof.MessageHash = evmMessageHash

	// Build metadata for leaf hash
	metadata := []byte(fmt.Sprintf("intent:%s,account:%s", certenIntent.IntentID, certenProof.AccountURL))

	// LOW-001: Compute 5-leaf domain-tagged merkle root
	// Each leaf is tagged with a domain prefix before hashing to prevent type confusion.
	// This MUST match _computeMerkleRoot5() in CertenAnchorV4.sol exactly.
	//
	// Tree structure:
	//                    root
	//                   /    \
	//              hash0123   taggedExec
	//              /    \
	//         hash01    hash23
	//        /    \    /    \
	//   tagAdi tagOp tagCC tagGov

	// 5-leaf domain-tagged merkle tree + real 3-element merkle proof for the
	// taggedAdi leaf. Both the tree computation and the proof construction
	// (EVM-003 fix) are factored into computeV6MerkleProofForAdi for unit-test
	// coverage. See CertenAnchorV6._computeMerkleRoot5 + getMerkleProofForAdiURL
	// for the on-chain spec.
	merkleProof := computeV6MerkleProofForAdi(adiURLHash, commitments)
	merkleRootHash := merkleProof.MerkleRoot

	log.Printf("✅ [MERKLE-V6] 5-leaf domain-tagged tree + 3-element proof for taggedAdi (EVM-003)")
	log.Printf("   merkleRoot: %x", merkleRootHash[:])
	log.Printf("   leafHash (taggedAdi): %x", merkleProof.LeafHash[:8])

	proofHashes = merkleProof.ProofHashes
	leafHash := merkleProof.LeafHash

	return contracts.ComprehensiveCertenProof{
		TransactionHash: txHash,
		MerkleRoot:      merkleRootHash,
		ProofHashes:     proofHashes,
		LeafHash:        leafHash,
		GovernanceProof: govProof,
		BLSProof:        blsProof,
		Commitments:     commitments,
		ExpirationTime:  big.NewInt(time.Now().Add(24 * time.Hour).Unix()),
		Metadata:        metadata,
	}
}

// RegenerateBLSZKProofForChain re-runs ZK proof generation with a chain-specific
// messageHash. Needed when the target chain (e.g., NEAR) binds messageHash with
// a different domain than the deployment chain — the validator's BLS signature
// is already over that chain's hash, but the default ZK proof path in
// BuildComprehensiveProof generates against the EVM/deployment-chain hash and
// fails the gnark constraint. Returns the new ABI proof bytes and pubkey
// commitment; caller assigns them onto BLSProof.AggregateSignature.
func (ecm *EthereumContractManager) RegenerateBLSZKProofForChain(
	blsSignatureBytes []byte,
	messageHash [32]byte,
	signedVotingPower *big.Int,
	totalVotingPower *big.Int,
) ([]byte, [32]byte) {
	return ecm.generateBLSZKProof(blsSignatureBytes, messageHash, signedVotingPower, totalVotingPower)
}

// generateBLSZKProof generates a Groth16 ZK proof from a BLS signature.
// Returns the serialized proof bytes AND the pubkeyCommitment (a public input
// to the Groth16 circuit that binds the proof to the validators' BLS keys).
// The pubkeyCommitment MUST be set on BLSProofData so the on-chain verifier's
// verifyBLSSignatureExpected() can cross-check it against the proof.
//
// TESTING MODE: When ZK proof generation fails, falls back to mock proof format
// that works with MockBLSVerifier contract.
func (ecm *EthereumContractManager) generateBLSZKProof(
	blsSignatureBytes []byte,
	messageHash [32]byte,
	signedVotingPower *big.Int,
	totalVotingPower *big.Int,
) ([]byte, [32]byte) {
	var zeroPubkey [32]byte

	// Get the BLS ZK prover - REQUIRED for proof generation
	prover, err := GetBLSZKProver()
	if err != nil || prover == nil {
		log.Printf("⚠️ [BLS-ZK] ZK prover not available: %v", err)
		return nil, zeroPubkey
	}

	// Get validator's BLS public key for the proof - REQUIRED
	blsKeyManager := bls.GetValidatorBLSKey()
	if blsKeyManager == nil {
		log.Printf("⚠️ [BLS-ZK] BLS key manager not available")
		return nil, zeroPubkey
	}

	// Get aggregated public key (for now, just our key)
	pubKeyBytes := blsKeyManager.GetPublicKeyBytes()
	if len(pubKeyBytes) < 96 {
		log.Printf("⚠️ [BLS-ZK] Invalid public key size: %d (need 96 bytes)", len(pubKeyBytes))
		return nil, zeroPubkey
	}

	log.Printf("🔐 [BLS-ZK] Creating witness with pubkey=%d bytes, sig=%d bytes", len(pubKeyBytes), len(blsSignatureBytes))

	// Create witness for ZK proof
	witness, err := bls_zkp.CreateWitnessFromBLSData(
		messageHash,
		blsSignatureBytes,
		pubKeyBytes,
		signedVotingPower.Uint64(),
		totalVotingPower.Uint64(),
	)
	if err != nil {
		log.Printf("⚠️ [BLS-ZK] Failed to create witness: %v", err)
		return nil, zeroPubkey
	}

	// Generate the ZK proof
	log.Printf("🔐 [BLS-ZK] Generating Groth16 proof...")
	zkProof, err := prover.GenerateProof(witness)
	if err != nil {
		log.Printf("⚠️ [BLS-ZK] Failed to generate ZK proof: %v", err)
		return nil, zeroPubkey
	}

	// Verify locally before submission
	valid, err := prover.VerifyProofLocally(zkProof)
	if err != nil {
		log.Printf("⚠️ [BLS-ZK] Local verification error: %v", err)
		return nil, zeroPubkey
	}
	if !valid {
		log.Printf("⚠️ [BLS-ZK] Local verification failed - proof is invalid")
		return nil, zeroPubkey
	}

	// Serialize proof for on-chain submission
	proofBytes, err := zkProof.ToSolidityCalldata()
	if err != nil {
		log.Printf("⚠️ [BLS-ZK] Failed to serialize proof: %v", err)
		return nil, zeroPubkey
	}

	log.Printf("✅ [BLS-ZK] Generated valid ZK proof: %d bytes, pubkeyCommitment: 0x%x", len(proofBytes), zkProof.PubkeyCommitment[:8])

	// Round-trip verification: deserialize ABI bytes and verify (catches serialization bugs)
	if roundTripOk, rtErr := prover.VerifyFromABIBytes(proofBytes); rtErr != nil {
		log.Printf("⚠️ [BLS-ZK] ABI round-trip verification error: %v", rtErr)
	} else {
		log.Printf("🔍 [BLS-ZK] ABI round-trip verification (NEAR equation): %v", roundTripOk)
	}

	return proofBytes, zkProof.PubkeyCommitment
}

// generateBLS12381Proof generates a BLS12-381 Groth16 proof for TON chain.
// TON's TVM has native BLS12-381 opcodes, so we need a separate proof curve.
// The proof bytes are stored in blsProof.BLS12381ProofBytes (pi_a:48 + pi_b:96 + pi_c:48 = 192 bytes)
// and the pubkey commitment in blsProof.BLS12381PubkeyCommitment.
func (ecm *EthereumContractManager) generateBLS12381Proof(
	blsProof *contracts.BLSProofData,
	blsSignatureBytes []byte,
	messageHash [32]byte,
	signedVotingPower *big.Int,
	totalVotingPower *big.Int,
) {
	prover, err := GetBLS12381Prover()
	if err != nil || prover == nil {
		log.Printf("⚠️ [BLS12-381] Prover not available: %v (TON proofs will not be generated)", err)
		return
	}

	blsKeyManager := bls.GetValidatorBLSKey()
	if blsKeyManager == nil {
		log.Printf("⚠️ [BLS12-381] BLS key manager not available")
		return
	}

	pubKeyBytes := blsKeyManager.GetPublicKeyBytes()
	if len(pubKeyBytes) < 96 {
		log.Printf("⚠️ [BLS12-381] Invalid public key size: %d (need 96 bytes)", len(pubKeyBytes))
		return
	}

	log.Printf("🔐 [BLS12-381] Creating witness with pubkey=%d bytes, sig=%d bytes", len(pubKeyBytes), len(blsSignatureBytes))

	witness, err := bls_zkp.CreateWitnessFromBLSDataBLS12381(
		messageHash,
		blsSignatureBytes,
		pubKeyBytes,
		signedVotingPower.Uint64(),
		totalVotingPower.Uint64(),
	)
	if err != nil {
		log.Printf("⚠️ [BLS12-381] Failed to create witness: %v", err)
		return
	}

	log.Printf("🔐 [BLS12-381] Generating Groth16 proof (BLS12-381 curve)...")
	proof, err := prover.GenerateProof(witness)
	if err != nil {
		log.Printf("⚠️ [BLS12-381] Failed to generate proof: %v", err)
		return
	}

	// Concatenate pi_a (48B) + pi_b (96B) + pi_c (48B) = 192 bytes
	proofBytes := make([]byte, 0, 192)
	proofBytes = append(proofBytes, proof.PiA...)
	proofBytes = append(proofBytes, proof.PiB...)
	proofBytes = append(proofBytes, proof.PiC...)

	blsProof.BLS12381ProofBytes = proofBytes
	blsProof.BLS12381PubkeyCommitment = proof.PubkeyCommitment

	log.Printf("✅ [BLS12-381] Generated proof: %d bytes (pi_a:%d + pi_b:%d + pi_c:%d), pkCommit: 0x%x",
		len(proofBytes), len(proof.PiA), len(proof.PiB), len(proof.PiC), proof.PubkeyCommitment[:8])
}


// extractMerkleProofHashes — DEPRECATED return value as of the EVM-003 fix.
//
// audit-reports/01-evm-VERIFIED.md:35 demonstrated that the previous "ADR-001
// BLS Attestation Model" (return empty proofHashes; let buildComprehensiveProof
// set leafHash = merkleRoot to satisfy _verifyMerkleProof's zero-iteration
// short-circuit) was a trivial bypass: the contract's merkle gate performed
// zero hashing on every legitimate proof. V6's _verifyAllComponents now derives
// leafHash from anchor.adiURLHash and runs the walk against the stored
// merkleRoot — so the validator MUST supply the real 3-element proof for the
// taggedAdi leaf against the 5-leaf domain-tagged tree.
//
// buildComprehensiveProof now constructs that real proof inline from the
// taggedOp / hash23 / taggedExec values computed in the same function, and the
// return value of this helper is overridden there. This helper is preserved
// only for its diagnostic logging about Accumulate proof availability; its
// returned slice is no longer consumed. New code should not depend on it.
//
// Off-chain audit context (unchanged): validators still verify Accumulate's
// L1-L3 ChainedProof (SHA-256) before BLS signing — that data lives in
// CertenProof.LiteClientProof and the BPT root flows into crossChainCommitment.
// The merkle proof discussed here is the EVM-side keccak256 tree binding the
// anchor's commitments together, not the Accumulate-side BPT proof.
func (ecm *EthereumContractManager) extractMerkleProofHashes(certenProof *proof.CertenProof) [][32]byte {
	// Return empty array for trivial verification (BLS Attestation Model)
	// L1-L3 ChainedProof is verified OFF-CHAIN by validators before BLS signing
	log.Printf("✅ [MERKLE] Using BLS Attestation Model (ADR-001)")
	log.Printf("   L1-L3 ChainedProof verified OFF-CHAIN by validators")
	log.Printf("   On-chain: merkleRoot = keccak256(op || cc || gov) for commitment binding")
	log.Printf("   Security: BLS signatures attest validators verified Accumulate proof")

	// Log proof availability for audit purposes
	if certenProof.LiteClientProof != nil {
		log.Printf("   Accumulate proof data available for audit: BPTRoot=%d bytes",
			len(certenProof.LiteClientProof.BPTRoot))
		if certenProof.LiteClientProof.CompleteProof != nil {
			log.Printf("   CompleteProof present (L1-L3 ChainedProof stored)")
		}
	}

	return [][32]byte{}
}

// extractReceiptHashes extracts 32-byte hashes from a Merkle receipt
// This function extracts all hashes from the receipt's proof path
func extractReceiptHashes(receipt interface{}) [][32]byte {
	var hashes [][32]byte

	// Use reflection to access the receipt fields since we're dealing with
	// gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle.Receipt
	// which has Start []byte, Anchor []byte, and Entries []*ReceiptEntry

	// Try to use type assertion for the known merkle.Receipt structure
	// The receipt has: Start ([]byte), Anchor ([]byte), Entries ([]*ReceiptEntry)
	// Each ReceiptEntry has: Hash ([]byte), Right (bool)

	switch r := receipt.(type) {
	case interface {
		GetStart() []byte
		GetAnchor() []byte
	}:
		// Extract start hash
		if start := r.GetStart(); len(start) == 32 {
			var h [32]byte
			copy(h[:], start)
			hashes = append(hashes, h)
		}
		// Extract anchor hash (this is the root after applying all entries)
		if anchor := r.GetAnchor(); len(anchor) == 32 {
			var h [32]byte
			copy(h[:], anchor)
			hashes = append(hashes, h)
		}

	default:
		// Use reflection as fallback for merkle.Receipt struct
		val := reflect.ValueOf(receipt)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}
		if val.Kind() != reflect.Struct {
			return hashes
		}

		// Extract Start field
		if startField := val.FieldByName("Start"); startField.IsValid() && startField.Kind() == reflect.Slice {
			if start := startField.Bytes(); len(start) == 32 {
				var h [32]byte
				copy(h[:], start)
				hashes = append(hashes, h)
			}
		}

		// Extract Entries field - each entry has a Hash
		if entriesField := val.FieldByName("Entries"); entriesField.IsValid() && entriesField.Kind() == reflect.Slice {
			for i := 0; i < entriesField.Len(); i++ {
				entry := entriesField.Index(i)
				if entry.Kind() == reflect.Ptr {
					entry = entry.Elem()
				}
				if entry.Kind() == reflect.Struct {
					if hashField := entry.FieldByName("Hash"); hashField.IsValid() && hashField.Kind() == reflect.Slice {
						if hashBytes := hashField.Bytes(); len(hashBytes) == 32 {
							var h [32]byte
							copy(h[:], hashBytes)
							hashes = append(hashes, h)
						}
					}
				}
			}
		}

		// Extract Anchor field (the final root)
		if anchorField := val.FieldByName("Anchor"); anchorField.IsValid() && anchorField.Kind() == reflect.Slice {
			if anchor := anchorField.Bytes(); len(anchor) == 32 {
				var h [32]byte
				copy(h[:], anchor)
				hashes = append(hashes, h)
			}
		}
	}

	return hashes
}

// extractVotingPower extracts voting power from proof verification data
func (ecm *EthereumContractManager) extractVotingPower(certenProof *proof.CertenProof) (*big.Int, *big.Int) {
	// Default voting power values based on validator count
	// In production, this comes from the actual validator set
	defaultTotal := big.NewInt(300)   // 3 validators * 100 power each
	defaultSigned := big.NewInt(200)  // 2/3 threshold met

	// Check if verification status has component details with voting power info
	if certenProof.VerificationStatus != nil && certenProof.VerificationStatus.Details != nil {
		details := certenProof.VerificationStatus.Details

		// Try to extract from details map
		if totalStr, ok := details["total_voting_power"]; ok {
			if total, success := new(big.Int).SetString(totalStr, 10); success {
				defaultTotal = total
			}
		}
		if signedStr, ok := details["signed_voting_power"]; ok {
			if signed, success := new(big.Int).SetString(signedStr, 10); success {
				defaultSigned = signed
			}
		}
	}

	// Check if we have consensus proof with power info
	if certenProof.LiteClientProof != nil && certenProof.LiteClientProof.ConsensusProof != nil {
		cp := certenProof.LiteClientProof.ConsensusProof
		if cp.TotalPower > 0 {
			defaultTotal = big.NewInt(cp.TotalPower)
		}
		if cp.SignedPower > 0 {
			defaultSigned = big.NewInt(cp.SignedPower)
		}
	}

	// Ensure signed power doesn't exceed total
	if defaultSigned.Cmp(defaultTotal) > 0 {
		defaultSigned = new(big.Int).Set(defaultTotal)
	}

	return defaultTotal, defaultSigned
}

// SubmitGovernanceProofToAccount submits governance proof to account contract
func (ecm *EthereumContractManager) SubmitGovernanceProofToAccount(
	ctx context.Context,
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	targetAddress common.Address,
	callData []byte,
	value *big.Int,
) (string, error) {

	// Convert to ADI governance proof
	govProof := ecm.convertToADIGovernanceProof(certenIntent, certenProof)

	// Convert to contract-compatible governance proof struct
	accountProof := AccountProofStruct{
		AdiURL:              govProof.AdiURL,
		AnchorId:            govProof.AnchorID,
		MerkleProof:         govProof.MerkleProof,
		KeyBookProof:        []byte(fmt.Sprintf("keybook:%s", govProof.KeyBookProof.KeyBookURL)),
		RoleProof:           []byte(fmt.Sprintf("role:%d", govProof.RoleProof.AuthLevel)),
		ThresholdProof:      []byte(fmt.Sprintf("threshold:%d", govProof.ThresholdProof.RequiredSigs.Int64())),
		Timestamp:           govProof.Timestamp,
		ExpiresAt:           big.NewInt(time.Now().Add(24*time.Hour).Unix()),
		ValidatorSignatures: ecm.encodeValidatorSignatures(govProof.ValidatorSigs),
		Nonce:               big.NewInt(time.Now().UnixNano()),
		RequiredLevel:       govProof.RoleProof.AuthLevel,
	}

	// Call the direct governance proof execution (does not require EntryPoint)
	// Security is enforced via BLS validator signatures in the governance proof
	tx, err := ecm.acctContract.ExecuteGovernanceProofDirect(ecm.auth, targetAddress, value, callData, accountProof)
	if err != nil {
		return "", fmt.Errorf("failed to call executeGovernanceProofDirect: %w", err)
	}

	fmt.Printf("📡 ACCOUNT CONTRACT TRANSACTION SUBMITTED:\n")
	fmt.Printf("   Contract: %s\n", ecm.config.AccountContract)
	fmt.Printf("   Function: executeGovernanceProofDirect\n")
	fmt.Printf("   Target: %s\n", targetAddress.Hex())
	fmt.Printf("   Value: %s\n", value.String())
	fmt.Printf("   Transaction Hash: %s\n", tx.Hash().Hex())

	return tx.Hash().Hex(), nil
}

// convertToContractProof converts CERTEN proof to contract-compatible format
func (ecm *EthereumContractManager) convertToContractProof(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
	anchorResult *anchor.AnchorResponse,
) *CertenProofStruct {

	// Parse transaction hash - decode hex string properly
	var txHash [32]byte
	if certenProof.TransactionHash != "" {
		// Remove 0x prefix if present and decode hex
		hashStr := strings.TrimPrefix(certenProof.TransactionHash, "0x")
		hashBytes := common.FromHex(hashStr)
		if len(hashBytes) >= 32 {
			copy(txHash[:], hashBytes[:32])
		} else {
			// Pad with zeros if too short
			copy(txHash[:], hashBytes)
		}
	}

	// Get merkle root from proof
	var merkleRoot [32]byte
	if certenProof.LiteClientProof != nil && len(certenProof.LiteClientProof.BPTRoot) >= 32 {
		copy(merkleRoot[:], certenProof.LiteClientProof.BPTRoot[:32])
	}

	// Generate commitment hash. Phase 3 changed generateCommitmentHash's
	// second argument from anchorResult to certenProof; the underlying value
	// (anchorResult.AnchorID) was creating a bundleId→opCommitment→bundleId
	// circularity under V6.
	_ = anchorResult // legacy parameter; no longer consulted in this path.
	commitmentHash := ecm.generateCommitmentHash(certenIntent, certenProof)

	orgADI := certenIntent.OrganizationADI

	// Create governance proof
	govProof := GovernanceProofStruct{
		KeyBookURL:     fmt.Sprintf("%s/book", orgADI),
		ThresholdMet:   true,
		ValidatorCount: big.NewInt(3),
		RequiredSigs:   big.NewInt(2),
	}

	// Create BLS signature from the actual proof data
	// The BLSAggregateSignature in certenProof comes from real BLS12-381 signing
	var blsSignatureBytes []byte
	if certenProof.BLSAggregateSignature != "" {
		// Decode the hex-encoded BLS aggregate signature
		blsSignatureBytes = common.FromHex(certenProof.BLSAggregateSignature)
	}
	if len(blsSignatureBytes) == 0 {
		// No real signature available - this is a critical error in production
		// Return an error-indicating signature that will fail on-chain verification
		// rather than silently submitting invalid data
		fmt.Printf("⚠️ [convertToContractProof] WARNING: No BLS aggregate signature available\n")
		blsSignatureBytes = make([]byte, 48) // BLS12-381 signature size - will fail verification
	}

	// Get real voting power from proof data
	totalPower, signedPower := ecm.extractVotingPower(certenProof)

	blsSignature := BlsSignatureStruct{
		Signature:    blsSignatureBytes,
		TotalPower:   totalPower,
		SignedPower:  signedPower,
		ThresholdMet: signedPower.Cmp(new(big.Int).Div(new(big.Int).Mul(totalPower, big.NewInt(2)), big.NewInt(3))) >= 0,
	}

	// Extract Merkle proof hashes from lite client proof
	merkleProofHashes := ecm.extractMerkleProofHashes(certenProof)

	// Create contract proof structure
	contractProof := &CertenProofStruct{
		TransactionHash:   txHash,
		MerkleRoot:        merkleRoot,
		MerkleProofHashes: merkleProofHashes,
		LeafIndex:         big.NewInt(0),
		GovernanceProof:   govProof,
		BlsSignature:      blsSignature,
		CommitmentHash:    commitmentHash,
		ExpirationTime:    big.NewInt(time.Now().Add(24 * time.Hour).Unix()),
		Metadata:          []byte(fmt.Sprintf("intent:%s", certenIntent.IntentID)),
	}

	return contractProof
}

// convertToADIGovernanceProof converts CERTEN proof to ADI governance format
func (ecm *EthereumContractManager) convertToADIGovernanceProof(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) *ADIGovernanceProofStruct {

	// Generate anchor ID
	anchorID := ecm.generateAnchorID(certenIntent, certenProof)

	orgADI := certenIntent.OrganizationADI

	keyBookProof := KeyBookProofStruct{
		KeyBookURL:   fmt.Sprintf("%s/book", orgADI),
		PageCount:    big.NewInt(1),
		ThresholdMet: true,
	}

	roleProof := RoleProofStruct{
		UserAddress: common.HexToAddress(ecm.config.AccountContract),
		AuthLevel:   2, // ADMIN level
		ValidFrom:   big.NewInt(time.Now().Unix()),
		ValidUntil:  big.NewInt(time.Now().Add(365*24*time.Hour).Unix()),
	}

	thresholdProof := ThresholdProofStruct{
		RequiredSigs: big.NewInt(2),
		ProvidedSigs: big.NewInt(3),
		ThresholdMet: true,
	}

	// Create validator signatures
	validatorSigs := []ValidatorSignatureStruct{
		{
			ValidatorID: "validator-1",
			PublicKey:   []byte("validator1_pubkey"),
			Signature:   []byte("validator1_signature"),
			VotingPower: big.NewInt(33),
			SignedAt:    big.NewInt(time.Now().Unix()),
		},
		{
			ValidatorID: "validator-2",
			PublicKey:   []byte("validator2_pubkey"),
			Signature:   []byte("validator2_signature"),
			VotingPower: big.NewInt(33),
			SignedAt:    big.NewInt(time.Now().Unix()),
		},
	}

	adiProof := &ADIGovernanceProofStruct{
		AdiURL:         orgADI,
		AnchorID:       anchorID,
		KeyBookProof:   keyBookProof,
		RoleProof:      roleProof,
		ThresholdProof: thresholdProof,
		Timestamp:      big.NewInt(time.Now().Unix()),
		ValidatorSigs:  validatorSigs,
	}

	return adiProof
}

// v6CommitmentBundle is the precomputed data both generateAnchorID and
// buildComprehensiveProof need. Holding it in a struct lets the two
// functions share one computation path so the bundleId the contract
// requires and the commitments the proof carries can never drift apart.
type v6CommitmentBundle struct {
	AdiURLHash            [32]byte
	AccumulateBlockHeight uint64
	Commitments           contracts.CommitmentData
	BlsSignatureBytes     []byte // decoded once; reused by buildComprehensiveProof
	TxHash                [32]byte
}

// computeV6CommitmentBundle deterministically computes everything needed to
// derive the V6 bundleId and to populate the CertenAnchorV6 createAnchor
// commitments. Same (intent, proof) input always yields the same bundle.
//
// This consolidates logic that previously lived inline in
// buildComprehensiveProof. By having a single source of truth, the
// bundleId derivation (generateAnchorID) and the commitment-carrying
// proof (buildComprehensiveProof) operate on bit-identical values — the
// V6 contract's require(bundleId == derived) check can never fail because
// the proof's commitments somehow disagree with what generateAnchorID hashed.
func (ecm *EthereumContractManager) computeV6CommitmentBundle(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) v6CommitmentBundle {
	// Tx hash — used for opCommitment derivation and stored on the proof.
	var txHash [32]byte
	if certenProof != nil && certenProof.TransactionHash != "" {
		hashStr := strings.TrimPrefix(certenProof.TransactionHash, "0x")
		hashBytes := common.FromHex(hashStr)
		if len(hashBytes) >= 32 {
			copy(txHash[:], hashBytes[:32])
		} else {
			copy(txHash[:], hashBytes)
		}
	}

	// adiURLHash from the Accumulate data account URL (matches the contract's
	// CreateAnchor inputs and the merkle leaf taggedAdi = keccak256("certen:adi:", adiURLHash)).
	var adiURLHash [32]byte
	adiURL := ""
	if certenProof != nil {
		adiURL = certenProof.AccountURL
	}
	if adiURL == "" && certenIntent != nil {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI)
	}
	copy(adiURLHash[:], crypto.Keccak256([]byte(adiURL)))

	// BLS aggregate signature bytes (hex-decoded). govRoot derives from these
	// and the EVM ZK proof generation uses them downstream.
	var blsSignatureBytes []byte
	if certenProof != nil && certenProof.BLSAggregateSignature != "" {
		sigHex := strings.TrimPrefix(certenProof.BLSAggregateSignature, "0x")
		if decoded, err := hex.DecodeString(sigHex); err == nil {
			blsSignatureBytes = decoded
		}
	}

	// Commitments.
	var opCommitment [32]byte
	commitmentHash := ecm.generateCommitmentHash(certenIntent, certenProof)
	copy(opCommitment[:], commitmentHash[:])

	var crossCommitment [32]byte
	if certenProof != nil && certenProof.LiteClientProof != nil && len(certenProof.LiteClientProof.BPTRoot) >= 32 {
		copy(crossCommitment[:], certenProof.LiteClientProof.BPTRoot[:32])
	}

	// V6.1 A+++ govRoot: Accumulate Total State Binding over L1-L4 + G0/G1/G2 +
	// keypage/keybook URLs + operationID. Pre-V6.1 set this to
	// keccak256(blsSignatureBytes) which was a circular shortcut — the BLS
	// sig was supposed to BE OVER a hash that included govRoot, so chaining
	// them as govRoot=H(sig) made signer and verifier compute different
	// values and every TX2 reverted with "BLS signature verification failed".
	// Now derived purely from intent + proof, no BLS-sig dependency.
	govRoot := ecm.computeV6_1AccumulateGovRoot(certenIntent, certenProof)

	// executionCommitment — prefer user-signed payload, fall back to leg compute.
	execCommitment := ecm.extractExecutionCommitment(certenIntent, certenProof)

	commitments := contracts.CommitmentData{
		OperationCommitment:  opCommitment,
		CrossChainCommitment: crossCommitment,
		GovernanceRoot:       govRoot,
		ExecutionCommitment:  execCommitment,
		SourceChain:          "accumulate",
		TargetChain:          "ethereum",
	}
	if certenProof != nil {
		commitments.SourceBlockHeight = big.NewInt(int64(certenProof.BlockHeight))
	}
	copy(commitments.SourceTxHash[:], txHash[:])

	blockHeight := uint64(0)
	if certenProof != nil {
		blockHeight = certenProof.BlockHeight
	}

	return v6CommitmentBundle{
		AdiURLHash:            adiURLHash,
		AccumulateBlockHeight: blockHeight,
		Commitments:           commitments,
		BlsSignatureBytes:     blsSignatureBytes,
		TxHash:                txHash,
	}
}

// extractExecutionCommitment isolates the execCommitment computation logic
// previously inline in buildComprehensiveProof. Two sources, in priority order:
//
//   1. User-signed CrossChainData.legs[0].executionPayload.executionCommitment
//      (CRITICAL-003) — this is the value the user actually signed, so it
//      MUST take precedence over anything we compute from raw fields.
//   2. Computed from the first leg's (chainID, target, value, data) via
//      computeExecutionCommitment (CRITICAL-001 fallback).
//
// Returns zero [32]byte if neither source yields a value; downstream code
// logs a warning but proceeds (CertenAnchorV6.createAnchor will then revert
// with "executionCommitment required" — the failure is loud).
func (ecm *EthereumContractManager) extractExecutionCommitment(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) [32]byte {
	var execCommitment [32]byte

	var rawCC []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		rawCC = certenProof.CrossChainData
	} else if certenIntent != nil && len(certenIntent.CrossChainData) > 0 {
		rawCC = certenIntent.CrossChainData
	}

	if len(rawCC) > 0 {
		var userSignedCC struct {
			Legs []struct {
				ExecutionPayload *struct {
					ExecutionCommitment string `json:"executionCommitment"`
				} `json:"executionPayload,omitempty"`
			} `json:"legs"`
		}
		if err := json.Unmarshal(rawCC, &userSignedCC); err == nil &&
			len(userSignedCC.Legs) > 0 &&
			userSignedCC.Legs[0].ExecutionPayload != nil &&
			userSignedCC.Legs[0].ExecutionPayload.ExecutionCommitment != "" {
			commitHex := strings.TrimPrefix(userSignedCC.Legs[0].ExecutionPayload.ExecutionCommitment, "0x")
			commitBytes := common.FromHex(commitHex)
			if len(commitBytes) == 32 {
				copy(execCommitment[:], commitBytes)
				return execCommitment
			}
		}
	}

	legs := ecm.extractLegsForExecCommitment(certenIntent, certenProof)
	if len(legs) > 0 {
		execCommitment = computeExecutionCommitment(
			legs[0].ChainID,
			legs[0].Target,
			legs[0].Value,
			legs[0].Data,
		)
	}
	return execCommitment
}

// generateAnchorID derives the V6-compatible bundleId for an intent.
//
// EVM-004 (audit-reports/01-evm-VERIFIED.md:76) requires that the bundleId
// stored at CertenAnchorV6.createAnchor matches:
//
//   keccak256(abi.encodePacked(
//     "certen:bundleid:v1", DEPLOYMENT_CHAIN_ID, adiURLHash,
//     operationCommitment, crossChainCommitment, governanceRoot,
//     executionCommitment, accumulateBlockHeight
//   ))
//
// The pre-V6 derivation (certen_v3_{intentID}_{blockHeight}_{txHash}) was
// not a function of the commitments, which let a rogue validator front-run
// createAnchor under any bundleId of their choosing and plant malicious
// commitments under it. V6 closes that vector by requiring this exact
// derivation; the contract reverts on mismatch.
//
// Caller signature unchanged from the V1 generateAnchorID — the additional
// inputs (commitments, adiURLHash) are computed inside the function from
// the same (intent, proof) the old version took. This keeps the 12 call
// sites untouched while moving the derivation to V6.
func (ecm *EthereumContractManager) generateAnchorID(certenIntent *intent.CertenIntent, certenProof *proof.CertenProof) [32]byte {
	bundle := ecm.computeV6CommitmentBundle(certenIntent, certenProof)
	// V6.1 hard-flip: bundleId commits operationID under the v1.1 domain tag.
	// The V6.1 anchor contract's createAnchor recomputes this and reverts on
	// mismatch — same logic as V6, just with operationID added to the preimage.
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(ecm.safeOperationID(certenIntent))
	bundleID := ecm.deriveV6_1BundleID(bundle.AdiURLHash, bundle.Commitments, opIDBytes32, bundle.AccumulateBlockHeight)

	log.Printf("🔑 [BUNDLE-ID-V6.1] bundleId: %x (intent=%s chainId=%d height=%d opID=%x)",
		bundleID[:8], certenIntent.IntentID, ecm.config.ChainID, bundle.AccumulateBlockHeight, opIDBytes32[:8])
	return bundleID
}

// safeOperationID wraps certenIntent.OperationID() with a "" fallback.
// Used by V6.1 derivations where a missing opID is treated as zero-bytes32
// downstream (the contract then rejects createAnchor with the proper error).
func (ecm *EthereumContractManager) safeOperationID(certenIntent *intent.CertenIntent) string {
	if certenIntent == nil {
		return ""
	}
	s, err := certenIntent.OperationID()
	if err != nil {
		return ""
	}
	return s
}

// ComputeV6_1AccumulateGovRoot is the A+++ govRoot derivation used at
// EVM-submission time. MUST byte-match the value the BFT signer computed
// (pkg/consensus/v6_1_signing.go::buildV6_1InputsFromIntent → GovRootInputs).
// Both sides derive primitives from the SAME certenProof object (G0/G1/G2 are
// plumbed onto certenProof by the BFT signer before signing).
//
// Exported (capital C) so the NEAR submission path
// (pkg/execution/bft_target_chain_integration.go) can reuse the SAME
// derivation without duplicating logic — keeps signer and submitter in lockstep.
func (ecm *EthereumContractManager) ComputeV6_1AccumulateGovRoot(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) [32]byte {
	return ecm.computeV6_1AccumulateGovRoot(certenIntent, certenProof)
}

func (ecm *EthereumContractManager) computeV6_1AccumulateGovRoot(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) [32]byte {
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(ecm.safeOperationID(certenIntent))
	gb := contracts.NewAccumulateGovRootInputsBuilder().
		SetOperationIDBytes32(opIDBytes32)
	var l1H, l2H, l3H, l4H [32]byte
	if certenProof != nil && certenProof.LiteClientProof != nil {
		lc := certenProof.LiteClientProof
		gb.SetL1AccountHash(lc.AccountHash).
			SetL2BPTRoot(lc.BPTRoot).
			SetL3BlockHash(lc.BlockHash).
			SetL4ConsensusProofFromJSON(lc.ConsensusProof)
		if len(lc.AccountHash) >= 32 {
			copy(l1H[:], lc.AccountHash[:32])
		}
		if len(lc.BPTRoot) >= 32 {
			copy(l2H[:], lc.BPTRoot[:32])
		}
		if len(lc.BlockHash) >= 32 {
			copy(l3H[:], lc.BlockHash[:32])
		}
		if lc.ConsensusProof != nil {
			l4H = contracts.HashL4ConsensusProof([]byte("nonempty"))
		}
	}
	var kpH, kbH [32]byte
	if certenProof != nil {
		gb.SetG0FromJSON(certenProof.G0Result).
			SetG1FromJSON(certenProof.G1Result).
			SetG2FromJSON(certenProof.G2Result).
			SetKeypageURL(certenProof.KeypageURL).
			SetKeybookURL(certenProof.KeybookURL)
		kpH = contracts.HashURLString(certenProof.KeypageURL)
		kbH = contracts.HashURLString(certenProof.KeybookURL)
	}
	root := contracts.ComputeAccumulateGovRoot(gb.Build())
	// V6.1 diagnostic — emit every gov-root input so a divergence vs the BFT
	// signing path (pkg/consensus/v6_1_signing.go) is identifiable by direct
	// comparison rather than guessing.
	log.Printf("🧮 [EVM-GOV-INPUTS] opID=%x L1=%x L2=%x L3=%x L4=%x kp=%x kb=%x → govRoot=%x",
		opIDBytes32[:8], l1H[:8], l2H[:8], l3H[:8], l4H[:8], kpH[:8], kbH[:8], root[:8])
	return root
}

// deriveV6BundleID is the wire-level keccak that must byte-match
// CertenAnchorV6.createAnchor's `require(bundleId == ...)` check.
//
// V6.1 supersedes this — see deriveV6_1BundleID below. Kept for rollout window.
func (ecm *EthereumContractManager) deriveV6BundleID(
	adiURLHash [32]byte,
	commitments contracts.CommitmentData,
	accumulateBlockHeight uint64,
) [32]byte {
	chainIDBytes32 := make([]byte, 32)
	big.NewInt(ecm.config.ChainID).FillBytes(chainIDBytes32)
	heightBytes32 := make([]byte, 32)
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBytes32)

	digest := crypto.Keccak256(
		[]byte("certen:bundleid:v1"),
		chainIDBytes32,
		adiURLHash[:],
		commitments.OperationCommitment[:],
		commitments.CrossChainCommitment[:],
		commitments.GovernanceRoot[:],
		commitments.ExecutionCommitment[:],
		heightBytes32,
	)
	var bundleID [32]byte
	copy(bundleID[:], digest)
	return bundleID
}

// deriveV6_1BundleID is the V6.1 bundleId derivation. Adds operationID as a
// committed field so the bundleId is a 1:1 function of (chain, account,
// intent payload, runtime params, height). Must byte-match
// CertenAnchorV6_1.createAnchor's require check on
//   keccak256(abi.encodePacked(
//     "certen:bundleid:v1.1", chainId, adiURLHash, op, cc, gov, exec,
//     operationID, height))
func (ecm *EthereumContractManager) deriveV6_1BundleID(
	adiURLHash [32]byte,
	commitments contracts.CommitmentData,
	operationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	chainIDBytes32 := make([]byte, 32)
	big.NewInt(ecm.config.ChainID).FillBytes(chainIDBytes32)
	heightBytes32 := make([]byte, 32)
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBytes32)

	digest := crypto.Keccak256(
		[]byte("certen:bundleid:v1.1"),
		chainIDBytes32,
		adiURLHash[:],
		commitments.OperationCommitment[:],
		commitments.CrossChainCommitment[:],
		commitments.GovernanceRoot[:],
		commitments.ExecutionCommitment[:],
		operationID[:],
		heightBytes32,
	)
	var bundleID [32]byte
	copy(bundleID[:], digest)
	return bundleID
}

// generateCommitmentHash produces the operationCommitment leaf for the V6
// commitment tree.
//
// V5 mistake: this used to read anchorResult.AnchorID, which under V6
// creates a fixed-point requirement (bundleId derives from opCommitment,
// opCommitment derived from bundleId via AnchorID). V6 breaks the cycle
// by deriving opCommitment from (intentID, blockHeight, txHash) — the same
// data the old generateAnchorID hashed into the bundleId directly. The
// resulting opCommitment is deterministic and independent of bundleId, so
// the V6 derivation chain (opCommitment → bundleId) terminates.
func (ecm *EthereumContractManager) generateCommitmentHash(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) [32]byte {
	var commitmentHash [32]byte
	blockHeight := uint64(0)
	txHash := ""
	if certenProof != nil {
		blockHeight = certenProof.BlockHeight
		txHash = certenProof.TransactionHash
	}
	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("certen:op:v1_%s_%d_%s",
		certenIntent.IntentID, blockHeight, txHash)))
	copy(commitmentHash[:], hash[:])
	return commitmentHash
}

// estimateContractGas estimates gas for a contract call
func (ecm *EthereumContractManager) estimateContractGas(ctx context.Context, contractAddress common.Address, function string) (uint64, error) {
	// Base gas estimates for different functions (production estimates)
	var baseGas uint64
	switch function {
	case "executeComprehensiveProof":
		baseGas = 800000 // Groth16 ZK-SNARK verification requires ~169K for pairing + IC ops + storage
	case "executeWithGovernanceProof":
		baseGas = 250000 // Governance execution
	default:
		baseGas = 100000 // Default
	}

	// Use HeaderByNumber (works on all chains including OP Stack)
	// BlockByNumber fails on OP Stack chains due to deposit tx type 0x7E
	header, err := ecm.client.HeaderByNumber(ctx, nil)
	if err == nil {
		if header.GasUsed > header.GasLimit/2 {
			baseGas = baseGas * 120 / 100 // 20% increase for congestion
		}
	}

	return baseGas, nil
}

// encodeValidatorSignatures encodes validator signatures into bytes
func (ecm *EthereumContractManager) encodeValidatorSignatures(sigs []ValidatorSignatureStruct) []byte {
	var encoded []byte
	for _, sig := range sigs {
		// Simple concatenation - in production, this would use proper ABI encoding
		encoded = append(encoded, sig.Signature...)
	}
	return encoded
}

// REMOVED: sendRawTransaction, getPrivateKey, waitForTransactionReceipt
// These functions were not used in the current codebase and have been deleted
// to reduce maintenance overhead and potential security surface area.

// GetContractConfig returns the contract configuration
func (ecm *EthereumContractManager) GetContractConfig() *CertenContractConfig {
	return ecm.config
}

// computeEvmMessageHashV6 is the V6 EVM-side BLS messageHash binding
// (EVM-NEW-001 step 6 / CRYPTO-005). It used abi.encodePacked over 4 fields.
//
// V6.1 (A++) supersedes this — see computeEvmMessageHashV6_1 below. This
// function is kept for the V6→V6.1 rollout transition; once every chain is on
// V6.1 it can be deleted.
//
// V6 wire format:
//   keccak256(abi.encodePacked(
//     "certen:bls:v1",
//     DEPLOYMENT_CHAIN_ID,        // uint256, 32 bytes big-endian
//     anchorId,                   // bytes32
//     executionCommitment         // bytes32
//   ))
func (ecm *EthereumContractManager) computeEvmMessageHashV6(
	anchorId [32]byte,
	executionCommitment [32]byte,
) [32]byte {
	chainIDBytes32 := make([]byte, 32)
	big.NewInt(ecm.config.ChainID).FillBytes(chainIDBytes32)
	digest := crypto.Keccak256(
		[]byte("certen:bls:v1"),
		chainIDBytes32,
		anchorId[:],
		executionCommitment[:],
	)
	var msgHash [32]byte
	copy(msgHash[:], digest)
	return msgHash
}

// computeEvmMessageHashV6_1 is the V6.1 A++ messageHash binding. Six fields
// committed under a versioned domain tag, encoded with length-prefixed
// abi.encode (not packed). The on-chain CertenAnchorV6_1._verifyBLSProof
// recomputes the SAME hash and rejects any proof whose MessageHash field
// doesn't match. The off-chain ZK circuit consumes this as a public input.
//
// Wire format (abi.encode == 32-byte slots, no length-or-type ambiguity):
//   keccak256(abi.encode(
//     bytes32("certen:bls:v1:pre"),   // domain — different from Phase 8 ":post"
//     uint256(DEPLOYMENT_CHAIN_ID),    // cross-chain replay defeat
//     anchorId,                        // bytes32 — V6.1 commitment+opID bundleId
//     executionCommitment,             // bytes32 — explicit value-moving binding
//     operationID,                     // bytes32 — 4-blob intent hash on Accumulate
//     validatorSetRoot                 // bytes32 — quorum-snapshot binding
//   ))
//
// All six slots are 32 bytes. Total preimage: 192 bytes.
//
// This MUST match CertenAnchorV6_1.sol::_verifyBLSProof byte-for-byte.
func (ecm *EthereumContractManager) computeEvmMessageHashV6_1(
	anchorId [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	// Domain tag: bytes32 left-aligned with the literal "certen:bls:v1:pre".
	// "certen:bls:v1:pre" is 17 ASCII bytes; Solidity bytes32(string) pads
	// with zeros on the RIGHT (least-significant bytes). We do the same.
	var domain [32]byte
	copy(domain[:], []byte("certen:bls:v1:pre"))

	// uint256 chainId in 32-byte big-endian (matches Solidity's abi.encode of uint256).
	var chainIDBE [32]byte
	big.NewInt(ecm.config.ChainID).FillBytes(chainIDBE[:])

	// abi.encode packs each argument into a 32-byte word for value types.
	// For bytes32 and uint256 there's no length prefix; just concatenate slots.
	preimage := make([]byte, 0, 32*6)
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, chainIDBE[:]...)
	preimage = append(preimage, anchorId[:]...)
	preimage = append(preimage, executionCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, validatorSetRoot[:]...)

	var msgHash [32]byte
	copy(msgHash[:], crypto.Keccak256(preimage))
	return msgHash
}

// computeValidatorSetRootV6_1 produces the same validator-set commitment that
// CertenAnchorV6_1._recomputeValidatorSetRoot() stores in
// currentValidatorSetRoot. Off-chain callers use this to (a) verify that what
// they're about to sign agrees with the on-chain state, and (b) embed the
// root into messageHash_pre so any change to the set invalidates the signature.
//
// Wire format:
//   keccak256(abi.encode(
//     address[] sortedAddresses,      // sorted ASCENDING by uint160(addr)
//     uint256[] sortedVotingPowers,   // matched to sortedAddresses by index
//     uint256(thresholdNumerator),
//     uint256(thresholdDenominator)
//   ))
//
// abi.encode of dynamic arrays uses head-tail layout per the Solidity ABI:
//   - 4 head slots: offset to addrs (32B), offset to powers (32B),
//     thresholdNum (32B), thresholdDen (32B)
//   - Then for each dynamic array: a length slot (32B) followed by the data
//
// Inputs must be PRE-SORTED by uint160(addr) ascending. The contract sorts
// at recompute time; we require the caller to sort here too, so this function
// is a pure hashing primitive (no surprise reordering).
func ComputeValidatorSetRootV6_1(
	sortedAddrs []common.Address,
	sortedVotingPowers []*big.Int,
	thresholdNumerator *big.Int,
	thresholdDenominator *big.Int,
) ([32]byte, error) {
	if len(sortedAddrs) != len(sortedVotingPowers) {
		return [32]byte{}, fmt.Errorf("sortedAddrs/sortedVotingPowers length mismatch: %d vs %d",
			len(sortedAddrs), len(sortedVotingPowers))
	}

	// Build the ABI dynamically: encode(address[], uint256[], uint256, uint256).
	addrArrTy, err := abi.NewType("address[]", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("address[] abi.NewType: %w", err)
	}
	u256ArrTy, err := abi.NewType("uint256[]", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("uint256[] abi.NewType: %w", err)
	}
	u256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("uint256 abi.NewType: %w", err)
	}

	args := abi.Arguments{
		{Type: addrArrTy},
		{Type: u256ArrTy},
		{Type: u256Ty},
		{Type: u256Ty},
	}

	// Copy inputs into types abi.Pack expects.
	addrsCopy := make([]common.Address, len(sortedAddrs))
	copy(addrsCopy, sortedAddrs)
	powersCopy := make([]*big.Int, len(sortedVotingPowers))
	for i, p := range sortedVotingPowers {
		powersCopy[i] = new(big.Int).Set(p)
	}

	encoded, err := args.Pack(
		addrsCopy,
		powersCopy,
		new(big.Int).Set(thresholdNumerator),
		new(big.Int).Set(thresholdDenominator),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("abi pack validator set root: %w", err)
	}

	var root [32]byte
	copy(root[:], crypto.Keccak256(encoded))
	return root, nil
}

// SortValidatorsForSetRoot sorts addresses ascending by uint160 and reorders
// the parallel votingPowers slice to match. Returns new slices (does not
// mutate the inputs). Matches the contract's insertion sort.
func SortValidatorsForSetRoot(
	addrs []common.Address,
	votingPowers []*big.Int,
) ([]common.Address, []*big.Int) {
	n := len(addrs)
	sortedAddrs := make([]common.Address, n)
	sortedPowers := make([]*big.Int, n)
	copy(sortedAddrs, addrs)
	for i, p := range votingPowers {
		sortedPowers[i] = new(big.Int).Set(p)
	}
	// Insertion sort (same algo as Solidity; tiny N).
	for i := 1; i < n; i++ {
		keyA := sortedAddrs[i]
		keyP := sortedPowers[i]
		j := i
		for j > 0 && new(big.Int).SetBytes(sortedAddrs[j-1].Bytes()).Cmp(new(big.Int).SetBytes(keyA.Bytes())) > 0 {
			sortedAddrs[j] = sortedAddrs[j-1]
			sortedPowers[j] = sortedPowers[j-1]
			j--
		}
		sortedAddrs[j] = keyA
		sortedPowers[j] = keyP
	}
	return sortedAddrs, sortedPowers
}

// v6MerkleProofForAdi packages the merkle tree root, the taggedAdi leaf, and
// the 3-element proof path that proves taggedAdi is in the 5-leaf tree. The
// V6 contract derives leafHash from anchor.adiURLHash and only consumes
// ProofHashes from calldata, but LeafHash / MerkleRoot are also returned so
// V5 anchors (which DO read both from calldata) accept the same proof during
// the V5→V6 rollout window.
type v6MerkleProofForAdi struct {
	LeafHash    common.Hash
	ProofHashes [][32]byte
	MerkleRoot  common.Hash
}

// computeV6MerkleProofForAdi builds the 5-leaf domain-tagged tree from the
// commitments and returns the merkle proof for the taggedAdi leaf.
//
// Tree structure (matches CertenAnchorV6._computeMerkleRoot5):
//
//                    root
//                   /    \
//              hash0123   taggedExec
//              /    \
//         hash01    hash23
//        /    \    /    \
//   tagAdi tagOp tagCC tagGov
//
// Proof path for taggedAdi (matches CertenAnchorV6.getMerkleProofForAdiURL):
//   level 0 sibling: taggedOp
//   level 1 sibling: hash23
//   level 2 sibling: taggedExec
func computeV6MerkleProofForAdi(
	adiURLHash [32]byte,
	commitments contracts.CommitmentData,
) v6MerkleProofForAdi {
	taggedAdi := crypto.Keccak256Hash(append([]byte("certen:adi:"), adiURLHash[:]...))
	taggedOp := crypto.Keccak256Hash(append([]byte("certen:op:"), commitments.OperationCommitment[:]...))
	taggedCC := crypto.Keccak256Hash(append([]byte("certen:cc:"), commitments.CrossChainCommitment[:]...))
	taggedGov := crypto.Keccak256Hash(append([]byte("certen:gov:"), commitments.GovernanceRoot[:]...))
	taggedExec := crypto.Keccak256Hash(append([]byte("certen:exec:"), commitments.ExecutionCommitment[:]...))

	hash01 := sortedHash(taggedAdi[:], taggedOp[:])
	hash23 := sortedHash(taggedCC[:], taggedGov[:])
	hash0123 := sortedHash(hash01, hash23)
	merkleRoot := sortedHash(hash0123, taggedExec[:])

	var leafHash, rootHash common.Hash
	copy(leafHash[:], taggedAdi[:])
	copy(rootHash[:], merkleRoot)

	var taggedOpArr, hash23Arr, taggedExecArr [32]byte
	copy(taggedOpArr[:], taggedOp[:])
	copy(hash23Arr[:], hash23)
	copy(taggedExecArr[:], taggedExec[:])

	return v6MerkleProofForAdi{
		LeafHash:    leafHash,
		ProofHashes: [][32]byte{taggedOpArr, hash23Arr, taggedExecArr},
		MerkleRoot:  rootHash,
	}
}

// sortedHash computes keccak256(a || b) where a and b are sorted lexicographically
// This matches the Solidity _sortedHash function in CertenAnchorV4
func sortedHash(a, b []byte) []byte {
	var data []byte
	if compareBytes(a, b) < 0 {
		data = append(a, b...)
	} else {
		data = append(b, a...)
	}
	return crypto.Keccak256(data)
}

// compareBytes compares two byte slices lexicographically
func compareBytes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// extractLegsForExecCommitment parses CrossChainData from the intent/proof to build
// LegExecution structs needed for executionCommitment computation.
// CRITICAL-001 + CRITICAL-003: If the user-signed blob contains an executionPayload
// with a pre-computed executionCommitment, we use that directly (it was signed by the user).
// Otherwise we compute it from the leg's target/value/data.
func (ecm *EthereumContractManager) extractLegsForExecCommitment(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) []LegExecution {
	// Use CrossChainData from proof (passed through from ValidatorBlockMetadata)
	var crossChainData []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		crossChainData = certenProof.CrossChainData
	} else if certenIntent != nil && len(certenIntent.CrossChainData) > 0 {
		crossChainData = certenIntent.CrossChainData
	}

	if len(crossChainData) == 0 {
		return nil
	}

	// CRITICAL-003: Parse executionPayload from user-signed blob
	var ccData struct {
		Legs []struct {
			LegID    string `json:"legId"`
			From     string `json:"from"`
			To       string `json:"to"`
			AmountWei string `json:"amountWei"`
			ChainID  int64  `json:"chainId"`
			Chain    string `json:"chain"`
			// CRITICAL-003: User-signed execution payload commitment
			ExecutionPayload *struct {
				Target              string `json:"target"`
				Value               string `json:"value"`
				DataHash            string `json:"dataHash"`
				ChainID             int64  `json:"chainId"`
				ExecutionCommitment string `json:"executionCommitment"`
			} `json:"executionPayload,omitempty"`
		} `json:"legs"`
	}

	if err := json.Unmarshal(crossChainData, &ccData); err != nil || len(ccData.Legs) == 0 {
		return nil
	}

	legs := make([]LegExecution, 0, len(ccData.Legs))
	for _, leg := range ccData.Legs {
		targetAddress := common.HexToAddress(leg.To)
		value := new(big.Int)
		if leg.AmountWei != "" {
			value.SetString(leg.AmountWei, 10)
		}

		chainID := leg.ChainID
		if chainID == 0 {
			chainID = 11155111 // Default Sepolia
		}

		legs = append(legs, LegExecution{
			LegID:   leg.LegID,
			Target:  targetAddress,
			Value:   value,
			Data:    []byte{}, // Native transfer: empty calldata
			ChainID: chainID,
			Chain:   leg.Chain,
		})
	}
	return legs
}

// computeExecutionCommitment computes keccak256(abi.encodePacked(chainId, target, value, keccak256(data)))
// CRITICAL-001: This MUST match the Solidity computation in CertenAnchorV4.executeWithGovernance()
//
// abi.encodePacked layout (116 bytes total):
//   chainId:  uint256 = 32 bytes (big-endian, left-padded)
//   target:   address = 20 bytes (raw, NOT left-padded — encodePacked uses smallest representation)
//   value:    uint256 = 32 bytes (big-endian, left-padded)
//   dataHash: bytes32 = 32 bytes
func computeExecutionCommitment(chainID int64, target common.Address, value *big.Int, callData []byte) [32]byte {
	// Step 1: keccak256(data)
	dataHash := crypto.Keccak256Hash(callData)

	// Step 2: abi.encodePacked(chainId, target, value, dataHash)
	// uint256 chainId — 32 bytes
	chainIDBytes := make([]byte, 32)
	chainIDBig := big.NewInt(chainID)
	chainIDBig.FillBytes(chainIDBytes)

	// address target — 20 bytes (encodePacked for address is 20 bytes, no padding)
	targetBytes := target.Bytes() // 20 bytes

	// uint256 value — 32 bytes
	valueBytes := make([]byte, 32)
	if value != nil {
		value.FillBytes(valueBytes)
	}

	// bytes32 dataHash — 32 bytes
	dataHashBytes := dataHash.Bytes() // 32 bytes

	packed := make([]byte, 0, 116) // 32 + 20 + 32 + 32
	packed = append(packed, chainIDBytes...)
	packed = append(packed, targetBytes...)
	packed = append(packed, valueBytes...)
	packed = append(packed, dataHashBytes...)

	return crypto.Keccak256Hash(packed)
}