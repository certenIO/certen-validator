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

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

// =============================================================================
// SOLANA CLIENT
// =============================================================================

// SolanaClient handles Solana blockchain interactions using JSON-RPC.
// Mirrors NearClient pattern but uses Solana transaction format and Borsh-encoded
// Anchor instructions instead of JSON args.
type SolanaClient struct {
	rpcEndpoint string
	privateKey  ed25519.PrivateKey // 64-byte Ed25519
	publicKey   ed25519.PublicKey  // 32-byte
	publicKeyB58 string            // Base58 Solana address
	httpClient  *http.Client

	// Program IDs (Pubkey = [32]byte)
	anchorProgramID      [32]byte
	blsVerifierProgramID [32]byte
	accountProgramID     [32]byte
	factoryProgramID     [32]byte
}

// System program and sysvar addresses
var (
	solSystemProgram = [32]byte{} // 11111111111111111111111111111111 = all zeros
	solRentSysvar    [32]byte
)

func init() {
	// Solana Rent sysvar address (full 44-char base58)
	rentBytes, _ := base58.Decode("SysvarRent111111111111111111111111111111111")
	copy(solRentSysvar[:], rentBytes)
}

// NewSolanaClient creates a Solana client from an RPC endpoint and Ed25519 keypair.
// Key format: base58-encoded 64-byte keypair (first 32 = seed, last 32 = pubkey).
func NewSolanaClient(rpcEndpoint, privateKeyBase58, anchorProgramID, blsVerifierProgramID, factoryProgramID, accountProgramID string) (*SolanaClient, error) {
	rpcEndpoint = strings.TrimSuffix(rpcEndpoint, "/")

	// Decode the base58-encoded 64-byte keypair
	keyData, err := base58.Decode(privateKeyBase58)
	if err != nil {
		return nil, fmt.Errorf("failed to base58-decode Solana private key: %w", err)
	}
	if len(keyData) != 64 {
		return nil, fmt.Errorf("Solana private key must be 64 bytes (seed+pubkey), got %d", len(keyData))
	}

	// First 32 bytes = seed, last 32 bytes = public key
	seed := keyData[:32]
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Verify derived public key matches embedded public key
	if !bytes.Equal(pubKey, keyData[32:]) {
		return nil, fmt.Errorf("derived public key does not match embedded public key in Solana keypair")
	}

	pubKeyB58 := base58.Encode(pubKey)

	// Parse program IDs
	parseProgram := func(name, b58 string) ([32]byte, error) {
		var id [32]byte
		data, err := base58.Decode(b58)
		if err != nil {
			return id, fmt.Errorf("invalid %s program ID '%s': %w", name, b58, err)
		}
		if len(data) != 32 {
			return id, fmt.Errorf("%s program ID must be 32 bytes, got %d", name, len(data))
		}
		copy(id[:], data)
		return id, nil
	}

	anchor, err := parseProgram("anchor", anchorProgramID)
	if err != nil {
		return nil, err
	}
	bls, err := parseProgram("bls_verifier", blsVerifierProgramID)
	if err != nil {
		return nil, err
	}
	factory, err := parseProgram("factory", factoryProgramID)
	if err != nil {
		return nil, err
	}
	account, err := parseProgram("account", accountProgramID)
	if err != nil {
		return nil, err
	}

	log.Printf("🔑 [SOLANA] Client created: pubKey=%s", pubKeyB58)

	return &SolanaClient{
		rpcEndpoint:          rpcEndpoint,
		privateKey:           privKey,
		publicKey:            pubKey,
		publicKeyB58:         pubKeyB58,
		httpClient:           &http.Client{Timeout: 30 * time.Second},
		anchorProgramID:      anchor,
		blsVerifierProgramID: bls,
		accountProgramID:     account,
		factoryProgramID:     factory,
	}, nil
}

// GetSignerPubkey returns the signer's 32-byte public key.
func (sc *SolanaClient) GetSignerPubkey() [32]byte {
	var pk [32]byte
	copy(pk[:], sc.publicKey)
	return pk
}

// GetSignerAddress returns the signer's base58 address.
func (sc *SolanaClient) GetSignerAddress() string {
	return sc.publicKeyB58
}

// =============================================================================
// SOLANA DATA TYPES
// =============================================================================

// SolInstruction represents a compiled Solana instruction.
type SolInstruction struct {
	ProgramID [32]byte
	Accounts  []SolAccountMeta
	Data      []byte
}

// SolAccountMeta describes an account in a Solana instruction.
type SolAccountMeta struct {
	Pubkey     [32]byte
	IsSigner   bool
	IsWritable bool
}

// SolanaAnchorData holds anchor data read from the Solana anchor program.
// Field order must match Rust AnchorAccount struct in state/anchor.rs.
// V5: Added ExecutionCommitment, GovernanceExecuted, GovernanceLevel fields.
type SolanaAnchorData struct {
	BundleId             [32]byte
	MerkleRoot           [32]byte
	AdiURLHash           [32]byte
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	ExecutionCommitment  [32]byte // V5 CRITICAL-001
	BlockHeight          uint64
	Timestamp            int64
	Validator            [32]byte
	Valid                bool
	ProofExecuted        bool
	GovernanceExecuted   bool // V5 CRITICAL-001
	GovernanceLevel      uint8 // V5 CRITICAL-001
}

// SolanaCertenProof is the Borsh-serialized proof for Step 2.
type SolanaCertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof SolanaGovernanceProofData
	BlsProof        SolanaBLSProofData
	Commitments     SolanaCommitmentData
	ExpirationTime  int64
	Metadata        []byte
}

// SolanaGovernanceProofData is the governance section of CertenProof.
// Field order must match Rust GovernanceProofData for Borsh serialization.
type SolanaGovernanceProofData struct {
	KeyBookUrl         string
	KeyBookRoot        [32]byte
	KeyPageProofs      [][32]byte
	AuthorityAddress   [20]byte
	AuthorityLevel     uint8
	Nonce              uint64
	RequiredSignatures uint64
	ProvidedSignatures uint64
	ThresholdMet       bool
}

// SolanaBLSProofData is the BLS section of CertenProof.
// Field order must match Rust BLSProofData for Borsh serialization.
type SolanaBLSProofData struct {
	AggregateSignature []byte
	ValidatorPubkeys   [][]byte
	VotingPowers       []uint64
	TotalVotingPower   uint64
	SignedVotingPower  uint64
	ThresholdMet       bool
	MessageHash        [32]byte
}

// SolanaCommitmentData is the commitments section.
// Field order must match Rust CommitmentData for Borsh serialization.
type SolanaCommitmentData struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	SourceChain          string
	SourceBlockHeight    uint64
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        [32]byte
}

// SolanaADIGovernanceProof is the proof for Step 3 (execute_governance_proof_direct).
type SolanaADIGovernanceProof struct {
	AdiUrl              string
	AnchorId            [32]byte
	MerkleProof         [][32]byte
	KeyBookProof        []byte // Borsh-encoded KeyBookHierarchyProof
	RoleProof           []byte // Borsh-encoded RoleAuthorizationProof
	ThresholdProof      []byte // Borsh-encoded ThresholdSignatureProof
	Timestamp           int64
	ExpiresAt           int64
	ValidatorSignatures []byte
	Nonce               uint64
	RequiredLevel       uint8 // AuthorityLevel enum (0-4)
}

// =============================================================================
// PDA DERIVATION
// =============================================================================

// FindProgramAddress mimics Solana's Pubkey::find_program_address.
// Tries bump seeds from 255 down to 0 until a valid off-curve point is found.
func FindProgramAddress(seeds [][]byte, programID [32]byte) ([32]byte, uint8, error) {
	for bump := uint8(255); ; bump-- {
		addr, err := createProgramAddress(seeds, bump, programID)
		if err == nil {
			return addr, bump, nil
		}
		if bump == 0 {
			break
		}
	}
	return [32]byte{}, 0, fmt.Errorf("could not find program address")
}

// createProgramAddress creates a program-derived address with the given bump.
func createProgramAddress(seeds [][]byte, bump uint8, programID [32]byte) ([32]byte, error) {
	h := sha256.New()
	for _, seed := range seeds {
		h.Write(seed)
	}
	h.Write([]byte{bump})
	h.Write(programID[:])
	h.Write([]byte("ProgramDerivedAddress"))
	hash := h.Sum(nil)

	var addr [32]byte
	copy(addr[:], hash[:32])

	// Check that the point is NOT on the ed25519 curve (it must be off-curve)
	if isOnCurve(addr[:]) {
		return [32]byte{}, fmt.Errorf("address is on curve")
	}

	return addr, nil
}

// isOnCurve checks if the given 32 bytes represent a valid ed25519 curve point.
// Uses the compressed point deserialization check.
func isOnCurve(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	// Try to decompress as an ed25519 point using the verify function trick:
	// A valid point will decompress successfully. We check by attempting to
	// construct a point. The simplest way in Go is to use the edwards25519
	// package, but since we don't have it, we use a known property:
	// Solana's isOnCurve checks if the bytes are a valid compressed edwards point.
	//
	// Implementation: try ed25519.Verify with a dummy signature — if the public key
	// is a valid point, Verify won't panic (though it will return false for bad sig).
	// If the public key is NOT a valid point, the decompression will fail.
	defer func() { recover() }()

	// ed25519.Verify will internally decompress the public key.
	// If decompression fails, it returns false.
	// We need a way to distinguish "valid point, bad sig" from "invalid point".
	//
	// Actually, Go's ed25519.Verify just returns false for both cases.
	// Let's use a different approach: attempt verification with zero message and sig.
	// In Go's implementation, ed25519.PublicKey is just []byte that gets decompressed
	// during Verify. Unfortunately Go doesn't expose the decompression failure separately.
	//
	// Alternative: Use the mathematical check. A compressed edwards25519 point y
	// is valid if x^2 = (y^2 - 1) / (d * y^2 + 1) mod p has a solution.
	return edwardsDecompress(b)
}

// edwardsDecompress checks if bytes represent a valid compressed edwards25519 point.
func edwardsDecompress(b []byte) bool {
	if len(b) != 32 {
		return false
	}

	// Edwards25519 prime: p = 2^255 - 19
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	// Edwards25519 d constant
	// d = -121665/121666 mod p
	// d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
	d, _ := new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)

	// Decode y coordinate (little-endian, high bit is sign of x)
	yBytes := make([]byte, 32)
	copy(yBytes, b)
	xSign := (yBytes[31] >> 7) & 1
	yBytes[31] &= 0x7f // clear sign bit

	// Convert little-endian bytes to big.Int
	// Reverse for big-endian
	for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
		yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
	}
	y := new(big.Int).SetBytes(yBytes)

	if y.Cmp(p) >= 0 {
		return false
	}

	// Check: x^2 = (y^2 - 1) / (d * y^2 + 1) mod p
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)

	// numerator = y^2 - 1
	num := new(big.Int).Sub(y2, big.NewInt(1))
	num.Mod(num, p)

	// denominator = d * y^2 + 1
	den := new(big.Int).Mul(d, y2)
	den.Add(den, big.NewInt(1))
	den.Mod(den, p)

	// x^2 = num * den^(-1) mod p
	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return false
	}

	x2 := new(big.Int).Mul(num, denInv)
	x2.Mod(x2, p)

	if x2.Sign() == 0 {
		return xSign == 0
	}

	// Check if x2 is a quadratic residue mod p
	// Using Euler's criterion: x2^((p-1)/2) == 1 mod p
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Rsh(exp, 1)
	result := new(big.Int).Exp(x2, exp, p)

	return result.Cmp(big.NewInt(1)) == 0
}

// PDA helper methods — seeds must match Anchor program's #[account] constraints

func (sc *SolanaClient) anchorPDA(bundleId [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("anchor"), bundleId[:]}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) statePDA() ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("state")}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) validatorPDA(validatorPubkey [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("validator"), validatorPubkey[:]}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) accountPDA(ownerPubkey [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("certen_account"), ownerPubkey[:]}, sc.accountProgramID)
	return addr, bump
}

func (sc *SolanaClient) accountVaultPDA(accountStatePDA [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("account_vault"), accountStatePDA[:]}, sc.accountProgramID)
	return addr, bump
}

func (sc *SolanaClient) usedCommitmentPDA(commitment [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("usedc"), commitment[:]}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) usedNoncePDA(authorityEth [20]byte, nonce uint64) ([32]byte, uint8) {
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, nonce)
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("usedn"), authorityEth[:], nonceBytes}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) proofBufferPDA(anchorId [32]byte, authority [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("proof_buf"), anchorId[:], authority[:]}, sc.anchorProgramID)
	return addr, bump
}

func (sc *SolanaClient) factoryStatePDA() ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("factory_state")}, sc.factoryProgramID)
	return addr, bump
}

func (sc *SolanaClient) adiRegistryPDA(adiURL string) ([32]byte, uint8) {
	adiHash := ethcrypto.Keccak256([]byte(adiURL))
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("adi_registry"), adiHash}, sc.factoryProgramID)
	return addr, bump
}

func (sc *SolanaClient) deployedRegistryPDA(accountPDA [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("deployed_account"), accountPDA[:]}, sc.factoryProgramID)
	return addr, bump
}

func (sc *SolanaClient) feeVaultPDA() ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("fee_vault")}, sc.factoryProgramID)
	return addr, bump
}

func (sc *SolanaClient) userRolePDA(accountStatePDA [32]byte, userKey [32]byte) ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("user_role"), accountStatePDA[:], userKey[:]}, sc.accountProgramID)
	return addr, bump
}

// blsVerifierStatePDA returns the BLS verifier's state PDA (seeds: ["state"]).
func (sc *SolanaClient) blsVerifierStatePDA() ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("state")}, sc.blsVerifierProgramID)
	return addr, bump
}

// blsVerifierVkPDA returns the BLS verifier's verification key PDA (seeds: ["vk"]).
func (sc *SolanaClient) blsVerifierVkPDA() ([32]byte, uint8) {
	addr, bump, _ := FindProgramAddress([][]byte{[]byte("vk")}, sc.blsVerifierProgramID)
	return addr, bump
}

// =============================================================================
// ANCHOR DISCRIMINATOR
// =============================================================================

// anchorDiscriminator computes the 8-byte Anchor instruction discriminator:
// sha256("global:<method_name>")[0..8]
func anchorDiscriminator(methodName string) [8]byte {
	h := sha256.Sum256([]byte("global:" + methodName))
	var disc [8]byte
	copy(disc[:], h[:8])
	return disc
}

// =============================================================================
// BORSH INSTRUCTION DATA BUILDERS
// =============================================================================

// V6.1: Added operationID (8th param, before blockHeight) — the create_anchor arg
// order is (bundle_id, adi, op, cc, gov, exec, operation_id, block_height).
func (sc *SolanaClient) buildCreateAnchorIx(bundleId, adiURLHash, opCommit, ccCommit, govRoot, execCommitment, operationID [32]byte, blockHeight uint64) []byte {
	disc := anchorDiscriminator("create_anchor")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(bundleId[:])
	buf.Write(adiURLHash[:])
	buf.Write(opCommit[:])
	buf.Write(ccCommit[:])
	buf.Write(govRoot[:])
	buf.Write(execCommitment[:])
	buf.Write(operationID[:])
	solBorshWriteU64(&buf, blockHeight)
	return buf.Bytes()
}

func (sc *SolanaClient) buildExecuteComprehensiveProofIx(anchorId [32]byte, proof SolanaCertenProof) []byte {
	disc := anchorDiscriminator("execute_comprehensive_proof")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(anchorId[:])
	sc.borshWriteCertenProof(&buf, proof)
	return buf.Bytes()
}

func (sc *SolanaClient) buildExecuteGovernanceProofDirectIx(lamportsValue uint64, instructionData []byte, proof SolanaADIGovernanceProof, expectedRecipient [32]byte) []byte {
	disc := anchorDiscriminator("execute_governance_proof_direct")
	var buf bytes.Buffer
	buf.Write(disc[:])
	solBorshWriteU64(&buf, lamportsValue)
	solBorshWriteVecU8(&buf, instructionData)
	sc.borshWriteADIGovernanceProof(&buf, proof)
	// CRITICAL-001: expected_recipient: Pubkey (32 raw bytes, last arg). Bound to
	// the anchor execution_commitment + asserted as the System-Transfer destination.
	buf.Write(expectedRecipient[:])
	return buf.Bytes()
}

func (sc *SolanaClient) buildCreateAccountIx(owner [32]byte, adiURL string, salt uint64) []byte {
	disc := anchorDiscriminator("create_account")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(owner[:])
	solBorshWriteString(&buf, adiURL)
	solBorshWriteU64(&buf, salt)
	return buf.Bytes()
}

// =============================================================================
// BORSH INSTRUCTION DATA BUILDERS — PROOF BUFFER
// =============================================================================

func (sc *SolanaClient) buildInitProofBufferIx(anchorId [32]byte, totalSize uint32) []byte {
	disc := anchorDiscriminator("init_proof_buffer")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(anchorId[:])
	solBorshWriteU32(&buf, totalSize)
	return buf.Bytes()
}

func (sc *SolanaClient) buildWriteProofChunkIx(anchorId [32]byte, offset uint32, data []byte) []byte {
	disc := anchorDiscriminator("write_proof_chunk")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(anchorId[:])
	solBorshWriteU32(&buf, offset)
	solBorshWriteVecU8(&buf, data)
	return buf.Bytes()
}

func (sc *SolanaClient) buildExecuteProofFromBufferIx(anchorId [32]byte) []byte {
	disc := anchorDiscriminator("execute_proof_from_buffer")
	var buf bytes.Buffer
	buf.Write(disc[:])
	buf.Write(anchorId[:])
	return buf.Bytes()
}

// =============================================================================
// BORSH SERIALIZATION FOR PROOF TYPES
// =============================================================================

func (sc *SolanaClient) borshWriteCertenProof(buf *bytes.Buffer, p SolanaCertenProof) {
	// CertenProof fields in exact Rust declaration order
	buf.Write(p.TransactionHash[:])
	buf.Write(p.MerkleRoot[:])

	// Vec<[u8;32]> proof_hashes
	solBorshWriteU32(buf, uint32(len(p.ProofHashes)))
	for _, h := range p.ProofHashes {
		buf.Write(h[:])
	}

	buf.Write(p.LeafHash[:])

	// GovernanceProofData — Rust order: key_book_url, key_book_root, key_page_proofs,
	// authority_eth, authority_level, nonce, required_signatures, provided_signatures, threshold_met
	solBorshWriteString(buf, p.GovernanceProof.KeyBookUrl)
	buf.Write(p.GovernanceProof.KeyBookRoot[:])
	solBorshWriteU32(buf, uint32(len(p.GovernanceProof.KeyPageProofs)))
	for _, h := range p.GovernanceProof.KeyPageProofs {
		buf.Write(h[:])
	}
	buf.Write(p.GovernanceProof.AuthorityAddress[:])
	buf.WriteByte(p.GovernanceProof.AuthorityLevel)
	solBorshWriteU64(buf, p.GovernanceProof.Nonce)
	solBorshWriteU64(buf, p.GovernanceProof.RequiredSignatures)
	solBorshWriteU64(buf, p.GovernanceProof.ProvidedSignatures)
	solBorshWriteBool(buf, p.GovernanceProof.ThresholdMet)

	// BLSProofData — Rust order: aggregate_signature, validator_pubkeys (Vec<Vec<u8>>),
	// voting_powers (Vec<u64>), total_voting_power, signed_voting_power, threshold_met, message_hash
	solBorshWriteVecU8(buf, p.BlsProof.AggregateSignature)
	// Vec<Vec<u8>> — outer vec length, then each inner vec with its own length prefix
	solBorshWriteU32(buf, uint32(len(p.BlsProof.ValidatorPubkeys)))
	for _, pk := range p.BlsProof.ValidatorPubkeys {
		solBorshWriteVecU8(buf, pk)
	}
	// Vec<u64> voting_powers
	solBorshWriteU32(buf, uint32(len(p.BlsProof.VotingPowers)))
	for _, vp := range p.BlsProof.VotingPowers {
		solBorshWriteU64(buf, vp)
	}
	solBorshWriteU64(buf, p.BlsProof.TotalVotingPower)
	solBorshWriteU64(buf, p.BlsProof.SignedVotingPower)
	solBorshWriteBool(buf, p.BlsProof.ThresholdMet)
	buf.Write(p.BlsProof.MessageHash[:])

	// CommitmentData — Rust order: operation_commitment, cross_chain_commitment, governance_root,
	// source_chain, source_block_height, source_tx_hash, target_chain, target_address (Pubkey=32 bytes)
	buf.Write(p.Commitments.OperationCommitment[:])
	buf.Write(p.Commitments.CrossChainCommitment[:])
	buf.Write(p.Commitments.GovernanceRoot[:])
	solBorshWriteString(buf, p.Commitments.SourceChain)
	solBorshWriteU64(buf, p.Commitments.SourceBlockHeight)
	buf.Write(p.Commitments.SourceTxHash[:])
	solBorshWriteString(buf, p.Commitments.TargetChain)
	buf.Write(p.Commitments.TargetAddress[:])

	// ExpirationTime (i64)
	solBorshWriteI64(buf, p.ExpirationTime)

	// Metadata Vec<u8>
	solBorshWriteVecU8(buf, p.Metadata)
}

func (sc *SolanaClient) borshWriteADIGovernanceProof(buf *bytes.Buffer, p SolanaADIGovernanceProof) {
	// String
	solBorshWriteString(buf, p.AdiUrl)
	// [u8;32]
	buf.Write(p.AnchorId[:])
	// Vec<[u8;32]>
	solBorshWriteU32(buf, uint32(len(p.MerkleProof)))
	for _, h := range p.MerkleProof {
		buf.Write(h[:])
	}
	// Vec<u8> fields (pre-encoded Borsh)
	solBorshWriteVecU8(buf, p.KeyBookProof)
	solBorshWriteVecU8(buf, p.RoleProof)
	solBorshWriteVecU8(buf, p.ThresholdProof)
	// i64
	solBorshWriteI64(buf, p.Timestamp)
	solBorshWriteI64(buf, p.ExpiresAt)
	// Vec<u8>
	solBorshWriteVecU8(buf, p.ValidatorSignatures)
	// u64
	solBorshWriteU64(buf, p.Nonce)
	// u8 (enum variant)
	buf.WriteByte(p.RequiredLevel)
}

// =============================================================================
// STEP 1: CREATE ANCHOR
// =============================================================================

// CreateAnchor calls create_anchor on the Solana CertenAnchorV6_1 program.
// V6.1: Added operationID parameter. bundleId MUST be the V6.1 derivation
// (DeriveSolanaBundleIDV6_1) or the contract reverts with BundleIdMismatch.
func (sc *SolanaClient) CreateAnchor(
	ctx context.Context,
	bundleId, adiURLHash, opCommit, ccCommit, govRoot, execCommitment, operationID [32]byte,
	blockHeight uint64,
) (string, error) {
	log.Printf("📡 [SOLANA] Creating anchor (V6.1)...")
	log.Printf("   Bundle ID: 0x%x  opID: 0x%x", bundleId[:8], operationID[:8])

	signerPubkey := sc.GetSignerPubkey()

	// Derive PDAs
	statePDA, _ := sc.statePDA()
	validatorRecordPDA, _ := sc.validatorPDA(signerPubkey)
	anchorPDA, _ := sc.anchorPDA(bundleId)

	// Build instruction data (V6.1: includes execution commitment + operation_id)
	ixData := sc.buildCreateAnchorIx(bundleId, adiURLHash, opCommit, ccCommit, govRoot, execCommitment, operationID, blockHeight)

	// Build instruction with accounts in order
	ix := SolInstruction{
		ProgramID: sc.anchorProgramID,
		Accounts: []SolAccountMeta{
			{Pubkey: statePDA, IsSigner: false, IsWritable: true},
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: false},
			{Pubkey: validatorRecordPDA, IsSigner: false, IsWritable: true},
			{Pubkey: anchorPDA, IsSigner: false, IsWritable: true},
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: true},
			{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false},
		},
		Data: ixData,
	}

	// Add compute budget instruction for 200K units
	computeIx := buildSetComputeUnitLimitIx(200_000)

	txSig, err := sc.buildSignAndSend(ctx, []SolInstruction{computeIx, ix})
	if err != nil {
		return "", fmt.Errorf("create_anchor failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Anchor created: txSig=%s", txSig)
	return txSig, nil
}

// =============================================================================
// STEP 2: EXECUTE COMPREHENSIVE PROOF (via Proof Buffer Pattern)
// =============================================================================

// InitProofBuffer creates a proof buffer PDA for chunked proof upload.
func (sc *SolanaClient) InitProofBuffer(
	ctx context.Context,
	anchorId [32]byte,
	totalSize uint32,
) (string, error) {
	signerPubkey := sc.GetSignerPubkey()

	proofBufPDA, _ := sc.proofBufferPDA(anchorId, signerPubkey)
	anchorPDA, _ := sc.anchorPDA(anchorId)

	ixData := sc.buildInitProofBufferIx(anchorId, totalSize)

	ix := SolInstruction{
		ProgramID: sc.anchorProgramID,
		Accounts: []SolAccountMeta{
			{Pubkey: proofBufPDA, IsSigner: false, IsWritable: true},
			{Pubkey: anchorPDA, IsSigner: false, IsWritable: false},
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: true},
			{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false},
		},
		Data: ixData,
	}

	computeIx := buildSetComputeUnitLimitIx(100_000)

	txSig, err := sc.buildSignAndSend(ctx, []SolInstruction{computeIx, ix})
	if err != nil {
		return "", fmt.Errorf("init_proof_buffer failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Proof buffer initialized: txSig=%s", txSig)
	return txSig, nil
}

// WriteProofChunk writes a chunk of proof data to the buffer at the given offset.
func (sc *SolanaClient) WriteProofChunk(
	ctx context.Context,
	anchorId [32]byte,
	offset uint32,
	chunk []byte,
) (string, error) {
	signerPubkey := sc.GetSignerPubkey()

	proofBufPDA, _ := sc.proofBufferPDA(anchorId, signerPubkey)

	ixData := sc.buildWriteProofChunkIx(anchorId, offset, chunk)

	ix := SolInstruction{
		ProgramID: sc.anchorProgramID,
		Accounts: []SolAccountMeta{
			{Pubkey: proofBufPDA, IsSigner: false, IsWritable: true},
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: false},
		},
		Data: ixData,
	}

	computeIx := buildSetComputeUnitLimitIx(50_000)

	txSig, err := sc.buildSignAndSend(ctx, []SolInstruction{computeIx, ix})
	if err != nil {
		return "", fmt.Errorf("write_proof_chunk (offset=%d, len=%d) failed: %w", offset, len(chunk), err)
	}

	log.Printf("✅ [SOLANA] Proof chunk written: offset=%d len=%d txSig=%s", offset, len(chunk), txSig)
	return txSig, nil
}

// ExecuteProofFromBuffer deserializes the proof from the buffer, verifies it,
// marks the anchor as executed, and closes the buffer (reclaiming rent).
func (sc *SolanaClient) ExecuteProofFromBuffer(
	ctx context.Context,
	anchorId [32]byte,
	proof SolanaCertenProof,
) (string, error) {
	signerPubkey := sc.GetSignerPubkey()

	statePDA, _ := sc.statePDA()
	anchorPDA, _ := sc.anchorPDA(anchorId)
	proofBufPDA, _ := sc.proofBufferPDA(anchorId, signerPubkey)
	usedCommitPDA, _ := sc.usedCommitmentPDA(proof.Commitments.OperationCommitment)
	usedNoncePDA, _ := sc.usedNoncePDA(proof.GovernanceProof.AuthorityAddress, proof.GovernanceProof.Nonce)

	// BLS verifier PDAs needed for CPI during verify_all_components
	blsStatePDA, _ := sc.blsVerifierStatePDA()
	blsVkPDA, _ := sc.blsVerifierVkPDA()

	ixData := sc.buildExecuteProofFromBufferIx(anchorId)

	ix := SolInstruction{
		ProgramID: sc.anchorProgramID,
		Accounts: []SolAccountMeta{
			// 8 accounts defined in the Anchor ExecuteProofFromBuffer struct
			{Pubkey: statePDA, IsSigner: false, IsWritable: true},
			{Pubkey: anchorPDA, IsSigner: false, IsWritable: true},
			{Pubkey: proofBufPDA, IsSigner: false, IsWritable: true},
			{Pubkey: usedCommitPDA, IsSigner: false, IsWritable: true},
			{Pubkey: usedNoncePDA, IsSigner: false, IsWritable: true},
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: true},
			{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false},
			{Pubkey: solRentSysvar, IsSigner: false, IsWritable: false},
			// Additional accounts for CPI to BLS verifier during proof verification
			{Pubkey: sc.blsVerifierProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: blsStatePDA, IsSigner: false, IsWritable: false},
			{Pubkey: blsVkPDA, IsSigner: false, IsWritable: false},
		},
		Data: ixData,
	}

	computeIx := buildSetComputeUnitLimitIx(400_000)

	txSig, err := sc.buildSignAndSend(ctx, []SolInstruction{computeIx, ix})
	if err != nil {
		return "", fmt.Errorf("execute_proof_from_buffer failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Proof executed from buffer: txSig=%s", txSig)
	return txSig, nil
}

// ExecuteComprehensiveProof uploads proof data via the buffer pattern and executes it.
// Uses a multi-transaction flow: init buffer → write chunks → execute from buffer.
// The method signature is unchanged — callers don't need modification.
func (sc *SolanaClient) ExecuteComprehensiveProof(
	ctx context.Context,
	anchorId [32]byte,
	proof SolanaCertenProof,
) (string, error) {
	log.Printf("📡 [SOLANA] Submitting comprehensive proof via buffer pattern...")

	// 1. Serialize the full proof to Borsh bytes
	var proofBuf bytes.Buffer
	sc.borshWriteCertenProof(&proofBuf, proof)
	proofBytes := proofBuf.Bytes()
	log.Printf("   Serialized proof: %d bytes", len(proofBytes))

	// 2. Init proof buffer
	initSig, err := sc.InitProofBuffer(ctx, anchorId, uint32(len(proofBytes)))
	if err != nil {
		return "", fmt.Errorf("buffer init failed: %w", err)
	}
	if err := sc.WaitForConfirmation(ctx, initSig, 30*time.Second); err != nil {
		return "", fmt.Errorf("buffer init confirmation failed: %w", err)
	}

	// 3. Write proof data in chunks (800 bytes each, ~430 byte margin within 1232 TX limit)
	const chunkSize = 800
	for offset := 0; offset < len(proofBytes); offset += chunkSize {
		end := offset + chunkSize
		if end > len(proofBytes) {
			end = len(proofBytes)
		}
		chunk := proofBytes[offset:end]

		writeSig, writeErr := sc.WriteProofChunk(ctx, anchorId, uint32(offset), chunk)
		if writeErr != nil {
			return "", fmt.Errorf("buffer write at offset %d failed: %w", offset, writeErr)
		}
		if err := sc.WaitForConfirmation(ctx, writeSig, 30*time.Second); err != nil {
			return "", fmt.Errorf("buffer write confirmation at offset %d failed: %w", offset, err)
		}
	}

	// 4. Execute proof from buffer (verifies + closes buffer)
	txSig, err := sc.ExecuteProofFromBuffer(ctx, anchorId, proof)
	if err != nil {
		return "", fmt.Errorf("execute from buffer failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Comprehensive proof submitted via buffer: txSig=%s", txSig)
	return txSig, nil
}

// =============================================================================
// STEP 3: EXECUTE GOVERNANCE PROOF DIRECT
// =============================================================================

// ExecuteGovernanceProofDirect calls execute_governance_proof_direct on the user's account program.
func (sc *SolanaClient) ExecuteGovernanceProofDirect(
	ctx context.Context,
	ownerPubkey [32]byte,
	lamportsValue uint64,
	instructionData []byte,
	proof SolanaADIGovernanceProof,
	recipientPubkey [32]byte,
) (string, error) {
	log.Printf("📡 [SOLANA] Executing governance proof direct...")
	log.Printf("   Owner: %s", base58.Encode(ownerPubkey[:]))
	log.Printf("   Lamports: %d", lamportsValue)

	signerPubkey := sc.GetSignerPubkey()

	// Derive PDAs
	accountStatePDA, _ := sc.accountPDA(ownerPubkey)
	accountVaultPDA, _ := sc.accountVaultPDA(accountStatePDA)
	anchorPDA, _ := sc.anchorPDA(proof.AnchorId)
	log.Printf("   Account PDA: %s", base58.Encode(accountStatePDA[:]))
	log.Printf("   Vault PDA:   %s", base58.Encode(accountVaultPDA[:]))
	log.Printf("   Anchor PDA:  %s", base58.Encode(anchorPDA[:]))
	blsStatePDA, _ := sc.blsVerifierStatePDA()
	blsVkPDA, _ := sc.blsVerifierVkPDA()

	// Build instruction data
	ixData := sc.buildExecuteGovernanceProofDirectIx(lamportsValue, instructionData, proof, recipientPubkey)

	// Accounts in order per the Anchor program
	accounts := []SolAccountMeta{
		{Pubkey: accountStatePDA, IsSigner: false, IsWritable: true},
		{Pubkey: accountVaultPDA, IsSigner: false, IsWritable: true},
		{Pubkey: signerPubkey, IsSigner: true, IsWritable: true},
		{Pubkey: sc.anchorProgramID, IsSigner: false, IsWritable: false},
		{Pubkey: sc.blsVerifierProgramID, IsSigner: false, IsWritable: false},
		{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false}, // target_program (system for native SOL transfer)
		{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false},
	}

	// Remaining accounts required by the contract:
	// 1. Anchor PDA — for anchor verification and merkle proof
	// 2. BLS Verifier State PDA ["state"] — needed for BLS CPI verification
	// 3. BLS Verifier VK PDA ["vk"] — needed for Groth16 verification key
	// 4. Recipient account — target of the SOL transfer
	accounts = append(accounts,
		SolAccountMeta{Pubkey: anchorPDA, IsSigner: false, IsWritable: false},
		SolAccountMeta{Pubkey: blsStatePDA, IsSigner: false, IsWritable: false},
		SolAccountMeta{Pubkey: blsVkPDA, IsSigner: false, IsWritable: false},
		SolAccountMeta{Pubkey: recipientPubkey, IsSigner: false, IsWritable: true},
	)

	ix := SolInstruction{
		ProgramID: sc.accountProgramID,
		Accounts:  accounts,
		Data:      ixData,
	}

	computeIx := buildSetComputeUnitLimitIx(400_000)

	txSig, err := sc.buildSignAndSend(ctx, []SolInstruction{computeIx, ix})
	if err != nil {
		return "", fmt.Errorf("execute_governance_proof_direct failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Governance proof direct executed: txSig=%s", txSig)
	return txSig, nil
}

// =============================================================================
// DEPLOY ACCOUNT VIA FACTORY
// =============================================================================

// DeployAccountViaFactory calls create_account on the Solana account factory program.
// ownerPrivateKey is required because the Anchor program expects the owner to sign.
// The API bridge derives the owner keypair from keccak256(adiUrl) and signs with it.
func (sc *SolanaClient) DeployAccountViaFactory(
	ctx context.Context,
	ownerPubkey [32]byte,
	ownerPrivateKey ed25519.PrivateKey,
	adiURL string,
	salt uint64,
) (string, error) {
	log.Printf("📡 [SOLANA] Deploying account via factory...")
	log.Printf("   Owner: %s", base58.Encode(ownerPubkey[:]))
	log.Printf("   ADI URL: %s", adiURL)
	log.Printf("   Salt: %d", salt)

	signerPubkey := sc.GetSignerPubkey()

	// Derive PDAs
	factoryState, _ := sc.factoryStatePDA()
	adiRegistry, _ := sc.adiRegistryPDA(adiURL)
	accountState, _ := sc.accountPDA(ownerPubkey)
	deployedRegistry, _ := sc.deployedRegistryPDA(accountState)
	feeVault, _ := sc.feeVaultPDA()
	ownerRole, _ := sc.userRolePDA(accountState, ownerPubkey)

	// Build instruction data
	ixData := sc.buildCreateAccountIx(ownerPubkey, adiURL, salt)

	ix := SolInstruction{
		ProgramID: sc.factoryProgramID,
		Accounts: []SolAccountMeta{
			{Pubkey: factoryState, IsSigner: false, IsWritable: true},
			{Pubkey: adiRegistry, IsSigner: false, IsWritable: true},
			{Pubkey: deployedRegistry, IsSigner: false, IsWritable: true},
			{Pubkey: feeVault, IsSigner: false, IsWritable: true},
			{Pubkey: accountState, IsSigner: false, IsWritable: true},
			{Pubkey: ownerRole, IsSigner: false, IsWritable: true},
			{Pubkey: ownerPubkey, IsSigner: true, IsWritable: false}, // account_owner (MUST sign per API bridge)
			{Pubkey: signerPubkey, IsSigner: true, IsWritable: true}, // payer
			{Pubkey: sc.accountProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: sc.anchorProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: sc.blsVerifierProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solSystemProgram, IsSigner: false, IsWritable: false},
		},
		Data: ixData,
	}

	computeIx := buildSetComputeUnitLimitIx(300_000)

	// Build and sign with BOTH validator (payer) and owner keypairs
	txSig, err := sc.buildSignAndSendMultiSigner(ctx, []SolInstruction{computeIx, ix}, ownerPrivateKey)
	if err != nil {
		return "", fmt.Errorf("factory create_account failed: %w", err)
	}

	log.Printf("✅ [SOLANA] Account deployment submitted: txSig=%s", txSig)
	return txSig, nil
}

// =============================================================================
// READ OPERATIONS
// =============================================================================

// GetAnchorData reads anchor data from the Anchor V4 program via getAccountInfo.
func (sc *SolanaClient) GetAnchorData(ctx context.Context, bundleId [32]byte) (*SolanaAnchorData, error) {
	anchorAddr, _ := sc.anchorPDA(bundleId)

	data, err := sc.getAccountData(ctx, anchorAddr)
	if err != nil {
		return nil, fmt.Errorf("get anchor account data: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("anchor not found on-chain (account has no data)")
	}

	// Anchor accounts have an 8-byte discriminator prefix
	if len(data) < 8 {
		return nil, fmt.Errorf("anchor account data too short: %d bytes", len(data))
	}
	data = data[8:] // Skip discriminator

	// Parse Borsh-encoded anchor data
	// V5 field order must match Rust AnchorAccount struct in state/anchor.rs:
	// bundle_id([32]), merkle_root([32]), adi_url_hash([32]), op_commit([32]),
	// cc_commit([32]), gov_root([32]), execution_commitment([32]),
	// block_height(u64), timestamp(i64), validator([32]),
	// valid(bool), proof_executed(bool), governance_executed(bool), governance_level(u8),
	// reserved([64])
	expectedMinSize := 32*8 + 8 + 8 + 4
	if len(data) < expectedMinSize {
		return nil, fmt.Errorf("anchor data too short: %d bytes (need >= %d)", len(data), expectedMinSize)
	}

	anchor := &SolanaAnchorData{}
	off := 0

	copy(anchor.BundleId[:], data[off:off+32]); off += 32
	copy(anchor.MerkleRoot[:], data[off:off+32]); off += 32
	copy(anchor.AdiURLHash[:], data[off:off+32]); off += 32
	copy(anchor.OperationCommitment[:], data[off:off+32]); off += 32
	copy(anchor.CrossChainCommitment[:], data[off:off+32]); off += 32
	copy(anchor.GovernanceRoot[:], data[off:off+32]); off += 32
	copy(anchor.ExecutionCommitment[:], data[off:off+32]); off += 32
	anchor.BlockHeight = binary.LittleEndian.Uint64(data[off:off+8]); off += 8
	anchor.Timestamp = int64(binary.LittleEndian.Uint64(data[off:off+8])); off += 8
	copy(anchor.Validator[:], data[off:off+32]); off += 32
	anchor.Valid = data[off] != 0; off++
	anchor.ProofExecuted = data[off] != 0; off++
	anchor.GovernanceExecuted = data[off] != 0; off++
	anchor.GovernanceLevel = data[off]

	log.Printf("✅ [SOLANA] Anchor read-back: bundleId=0x%x opCommit=0x%x execCommit=0x%x proofExecuted=%v govExecuted=%v",
		anchor.BundleId[:8], anchor.OperationCommitment[:8], anchor.ExecutionCommitment[:8], anchor.ProofExecuted, anchor.GovernanceExecuted)

	return anchor, nil
}

// CheckAccountExists checks if a Solana account exists (has data or lamports).
func (sc *SolanaClient) CheckAccountExists(ctx context.Context, pubkey [32]byte) (bool, error) {
	params := []interface{}{
		base58.Encode(pubkey[:]),
		map[string]interface{}{
			"encoding":   "base64",
			"commitment": "confirmed",
		},
	}

	result, err := sc.rpcCall(ctx, "getAccountInfo", params)
	if err != nil {
		return false, err
	}

	var response struct {
		Value *json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return false, fmt.Errorf("parsing getAccountInfo response: %w", err)
	}

	return response.Value != nil && string(*response.Value) != "null", nil
}

// =============================================================================
// TRANSACTION CONFIRMATION
// =============================================================================

// WaitForConfirmation polls for transaction confirmation using getSignatureStatuses.
func (sc *SolanaClient) WaitForConfirmation(ctx context.Context, txSig string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		params := []interface{}{
			[]string{txSig},
			map[string]interface{}{
				"searchTransactionHistory": true,
			},
		}

		result, err := sc.rpcCall(ctx, "getSignatureStatuses", params)
		if err != nil {
			log.Printf("⚠️ [SOLANA] Polling sig status: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
				continue
			}
		}

		var response struct {
			Value []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		if len(response.Value) > 0 && string(response.Value[0]) != "null" {
			var status struct {
				Err                *json.RawMessage `json:"err"`
				ConfirmationStatus string           `json:"confirmationStatus"`
			}
			if err := json.Unmarshal(response.Value[0], &status); err == nil {
				if status.Err != nil && string(*status.Err) != "null" {
					return fmt.Errorf("transaction failed: %s", string(*status.Err))
				}
				if status.ConfirmationStatus == "confirmed" || status.ConfirmationStatus == "finalized" {
					log.Printf("✅ [SOLANA] Transaction confirmed (%s): %s", status.ConfirmationStatus, txSig)
					return nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return fmt.Errorf("transaction %s not confirmed after %v", txSig, timeout)
}

// =============================================================================
// PRIVATE: TRANSACTION BUILDING & SIGNING
// =============================================================================

// getRecentBlockhash fetches the latest blockhash for transaction freshness.
func (sc *SolanaClient) getRecentBlockhash(ctx context.Context) ([32]byte, error) {
	result, err := sc.rpcCall(ctx, "getLatestBlockhash", []interface{}{
		map[string]interface{}{"commitment": "finalized"},
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("getLatestBlockhash failed: %w", err)
	}

	var response struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return [32]byte{}, fmt.Errorf("parsing blockhash response: %w", err)
	}

	hashBytes, err := base58.Decode(response.Value.Blockhash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decoding blockhash: %w", err)
	}

	var blockhash [32]byte
	copy(blockhash[:], hashBytes)
	return blockhash, nil
}

// buildSignAndSend builds a transaction, signs it, and sends it.
func (sc *SolanaClient) buildSignAndSend(ctx context.Context, instructions []SolInstruction) (string, error) {
	blockhash, err := sc.getRecentBlockhash(ctx)
	if err != nil {
		return "", err
	}

	signerPubkey := sc.GetSignerPubkey()
	txBytes := sc.buildTransaction(instructions, signerPubkey, blockhash)

	return sc.signAndSend(ctx, txBytes)
}

// buildSignAndSendMultiSigner builds a transaction signed by both the validator
// and an additional signer (e.g., the derived owner keypair for factory deployment).
func (sc *SolanaClient) buildSignAndSendMultiSigner(ctx context.Context, instructions []SolInstruction, additionalSigner ed25519.PrivateKey) (string, error) {
	blockhash, err := sc.getRecentBlockhash(ctx)
	if err != nil {
		return "", err
	}

	signerPubkey := sc.GetSignerPubkey()
	txBytes := sc.buildTransaction(instructions, signerPubkey, blockhash)

	return sc.signAndSendMulti(ctx, txBytes, additionalSigner)
}

// buildTransaction serializes a Solana transaction in the legacy message format.
func (sc *SolanaClient) buildTransaction(instructions []SolInstruction, signerPubkey [32]byte, recentBlockhash [32]byte) []byte {
	// Collect all unique account keys and classify them
	type accountInfo struct {
		pubkey     [32]byte
		isSigner   bool
		isWritable bool
	}

	accountMap := make(map[[32]byte]*accountInfo)
	accountOrder := [][32]byte{}

	addAccount := func(pubkey [32]byte, isSigner, isWritable bool) {
		if info, exists := accountMap[pubkey]; exists {
			info.isSigner = info.isSigner || isSigner
			info.isWritable = info.isWritable || isWritable
		} else {
			accountMap[pubkey] = &accountInfo{
				pubkey:     pubkey,
				isSigner:   isSigner,
				isWritable: isWritable,
			}
			accountOrder = append(accountOrder, pubkey)
		}
	}

	// Fee payer (signer) is always first
	addAccount(signerPubkey, true, true)

	// Add all instruction accounts
	for _, ix := range instructions {
		for _, acc := range ix.Accounts {
			addAccount(acc.Pubkey, acc.IsSigner, acc.IsWritable)
		}
		// Program IDs are also accounts (read-only, non-signer)
		addAccount(ix.ProgramID, false, false)
	}

	// Sort accounts into 4 groups:
	// 1. Writable signers
	// 2. Read-only signers
	// 3. Writable non-signers
	// 4. Read-only non-signers
	var writableSigners, readonlySigners, writableNonSigners, readonlyNonSigners [][32]byte

	for _, pubkey := range accountOrder {
		info := accountMap[pubkey]
		if info.isSigner && info.isWritable {
			writableSigners = append(writableSigners, pubkey)
		} else if info.isSigner && !info.isWritable {
			readonlySigners = append(readonlySigners, pubkey)
		} else if !info.isSigner && info.isWritable {
			writableNonSigners = append(writableNonSigners, pubkey)
		} else {
			readonlyNonSigners = append(readonlyNonSigners, pubkey)
		}
	}

	// Final account list in proper order
	sortedAccounts := make([][32]byte, 0)
	sortedAccounts = append(sortedAccounts, writableSigners...)
	sortedAccounts = append(sortedAccounts, readonlySigners...)
	sortedAccounts = append(sortedAccounts, writableNonSigners...)
	sortedAccounts = append(sortedAccounts, readonlyNonSigners...)

	// Build account index map
	accountIndex := make(map[[32]byte]uint8)
	for i, pubkey := range sortedAccounts {
		accountIndex[pubkey] = uint8(i)
	}

	numRequiredSigs := uint8(len(writableSigners) + len(readonlySigners))
	numReadonlySigned := uint8(len(readonlySigners))
	numReadonlyUnsigned := uint8(len(readonlyNonSigners))

	// Serialize the message
	var msg bytes.Buffer

	// Message header
	msg.WriteByte(numRequiredSigs)
	msg.WriteByte(numReadonlySigned)
	msg.WriteByte(numReadonlyUnsigned)

	// Account addresses
	writeCompactU16(&msg, uint16(len(sortedAccounts)))
	for _, pubkey := range sortedAccounts {
		msg.Write(pubkey[:])
	}

	// Recent blockhash
	msg.Write(recentBlockhash[:])

	// Instructions
	writeCompactU16(&msg, uint16(len(instructions)))
	for _, ix := range instructions {
		// Program ID index
		msg.WriteByte(accountIndex[ix.ProgramID])

		// Account indexes
		writeCompactU16(&msg, uint16(len(ix.Accounts)))
		for _, acc := range ix.Accounts {
			msg.WriteByte(accountIndex[acc.Pubkey])
		}

		// Instruction data
		writeCompactU16(&msg, uint16(len(ix.Data)))
		msg.Write(ix.Data)
	}

	return msg.Bytes()
}

// signAndSend signs a transaction message and sends it.
func (sc *SolanaClient) signAndSend(ctx context.Context, messageBytes []byte) (string, error) {
	// Sign the message
	signature := ed25519.Sign(sc.privateKey, messageBytes)

	// Build the full transaction:
	// CompactU16(num_signatures) + [64-byte signatures] + message
	var tx bytes.Buffer
	writeCompactU16(&tx, 1) // 1 signature
	tx.Write(signature[:64])
	tx.Write(messageBytes)

	// Base64 encode for RPC
	txBase64 := base64.StdEncoding.EncodeToString(tx.Bytes())

	// Send via sendTransaction
	params := []interface{}{
		txBase64,
		map[string]interface{}{
			"encoding":                "base64",
			"skipPreflight":           false,
			"preflightCommitment":     "confirmed",
			"maxRetries":              3,
		},
	}

	result, err := sc.rpcCall(ctx, "sendTransaction", params)
	if err != nil {
		return "", fmt.Errorf("sendTransaction failed: %w", err)
	}

	// Result is the transaction signature as a JSON string
	var txSig string
	if err := json.Unmarshal(result, &txSig); err != nil {
		return "", fmt.Errorf("parsing sendTransaction result: %w", err)
	}

	return txSig, nil
}

// signAndSendMulti signs a transaction with both the validator key and an additional signer.
// The additional signer's signature is placed after the validator's signature in the
// transaction. Signature order must match the account order in the message.
func (sc *SolanaClient) signAndSendMulti(ctx context.Context, messageBytes []byte, additionalSigner ed25519.PrivateKey) (string, error) {
	// Sign with validator (fee payer — first signer)
	sig1 := ed25519.Sign(sc.privateKey, messageBytes)

	// Sign with additional signer (e.g., derived owner key)
	sig2 := ed25519.Sign(additionalSigner, messageBytes)

	// Build the full transaction with 2 signatures
	var tx bytes.Buffer
	writeCompactU16(&tx, 2) // 2 signatures
	tx.Write(sig1[:64])     // Fee payer signature first
	tx.Write(sig2[:64])     // Additional signer second
	tx.Write(messageBytes)

	txBase64 := base64.StdEncoding.EncodeToString(tx.Bytes())

	params := []interface{}{
		txBase64,
		map[string]interface{}{
			"encoding":            "base64",
			"skipPreflight":       false,
			"preflightCommitment": "confirmed",
			"maxRetries":          3,
		},
	}

	result, err := sc.rpcCall(ctx, "sendTransaction", params)
	if err != nil {
		return "", fmt.Errorf("sendTransaction failed: %w", err)
	}

	var txSig string
	if err := json.Unmarshal(result, &txSig); err != nil {
		return "", fmt.Errorf("parsing sendTransaction result: %w", err)
	}

	return txSig, nil
}

// getAccountData fetches account data via getAccountInfo.
func (sc *SolanaClient) getAccountData(ctx context.Context, pubkey [32]byte) ([]byte, error) {
	params := []interface{}{
		base58.Encode(pubkey[:]),
		map[string]interface{}{
			"encoding":   "base64",
			"commitment": "confirmed",
		},
	}

	result, err := sc.rpcCall(ctx, "getAccountInfo", params)
	if err != nil {
		return nil, err
	}

	var response struct {
		Value *struct {
			Data []string `json:"data"` // [base64_data, "base64"]
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("parsing getAccountInfo: %w", err)
	}

	if response.Value == nil || len(response.Value.Data) < 1 {
		return nil, nil // Account doesn't exist
	}

	data, err := base64.StdEncoding.DecodeString(response.Value.Data[0])
	if err != nil {
		return nil, fmt.Errorf("decoding account data: %w", err)
	}

	return data, nil
}

// GetSolBalance returns the SOL balance (lamports) of an address via getBalance.
func (sc *SolanaClient) GetSolBalance(ctx context.Context, addr string) (uint64, error) {
	res, err := sc.rpcCall(ctx, "getBalance", []interface{}{addr})
	if err != nil {
		return 0, err
	}
	var r struct {
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return 0, fmt.Errorf("parse SOL balance: %w", err)
	}
	return r.Value, nil
}

// ConfirmRecipientCredited cryptographically confirms the Step-3 transfer credited
// the recipient by polling its SOL balance until it rises at least minDelta lamports
// above the pre-transfer baseline — the on-chain proof the funds actually moved.
func (sc *SolanaClient) ConfirmRecipientCredited(ctx context.Context, recipientAddr string, baseline uint64, minDelta uint64, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		bal, err := sc.GetSolBalance(ctx, recipientAddr)
		if err == nil && bal >= baseline+minDelta {
			return bal, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return 0, fmt.Errorf("recipient %s SOL balance did not rise by >= %d lamports above %d within %v", recipientAddr, minDelta, baseline, timeout)
}

// =============================================================================
// PRIVATE: JSON-RPC
// =============================================================================

// rpcCall makes a generic JSON-RPC 2.0 call to the Solana node.
func (sc *SolanaClient) rpcCall(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
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

	req, err := http.NewRequestWithContext(ctx, "POST", sc.rpcEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading RPC response: %w", err)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		truncated := string(respBody)
		if len(truncated) > 200 {
			truncated = truncated[:200]
		}
		return nil, fmt.Errorf("parsing RPC response: %w (body: %s)", err, truncated)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s (data: %s)", rpcResp.Error.Code, rpcResp.Error.Message, string(rpcResp.Error.Data))
	}

	return rpcResp.Result, nil
}

// =============================================================================
// SOLANA BORSH SERIALIZATION HELPERS
// =============================================================================

func solBorshWriteU8(buf *bytes.Buffer, v uint8) {
	buf.WriteByte(v)
}

func solBorshWriteU16(buf *bytes.Buffer, v uint16) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	buf.Write(b)
}

func solBorshWriteU32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	buf.Write(b)
}

func solBorshWriteU64(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

func solBorshWriteI64(buf *bytes.Buffer, v int64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	buf.Write(b)
}

func solBorshWriteString(buf *bytes.Buffer, s string) {
	solBorshWriteU32(buf, uint32(len(s)))
	buf.WriteString(s)
}

func solBorshWriteVecU8(buf *bytes.Buffer, data []byte) {
	solBorshWriteU32(buf, uint32(len(data)))
	buf.Write(data)
}

func solBorshWriteBool(buf *bytes.Buffer, v bool) {
	if v {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
}

// =============================================================================
// SOLANA COMPACT-U16 ENCODING
// =============================================================================

// writeCompactU16 writes a Solana compact-u16 encoding (NOT Borsh).
// Used in the transaction wire format for lengths.
func writeCompactU16(buf *bytes.Buffer, val uint16) {
	if val < 0x80 {
		buf.WriteByte(byte(val))
	} else if val < 0x4000 {
		buf.WriteByte(byte(val&0x7F) | 0x80)
		buf.WriteByte(byte(val >> 7))
	} else {
		buf.WriteByte(byte(val&0x7F) | 0x80)
		buf.WriteByte(byte((val>>7)&0x7F) | 0x80)
		buf.WriteByte(byte(val >> 14))
	}
}

// =============================================================================
// COMPUTE BUDGET PROGRAM
// =============================================================================

// buildSetComputeUnitLimitIx creates a ComputeBudget::SetComputeUnitLimit instruction.
// Program ID: ComputeBudget111111111111111111111111111111
func buildSetComputeUnitLimitIx(units uint32) SolInstruction {
	// ComputeBudget program ID
	computeBudgetProgramID, _ := base58.Decode("ComputeBudget111111111111111111111111111111")
	var programID [32]byte
	copy(programID[:], computeBudgetProgramID)

	// SetComputeUnitLimit = instruction type 2 (u8) + units (u32 LE)
	data := make([]byte, 5)
	data[0] = 2 // SetComputeUnitLimit variant
	binary.LittleEndian.PutUint32(data[1:], units)

	return SolInstruction{
		ProgramID: programID,
		Accounts:  []SolAccountMeta{},
		Data:      data,
	}
}

// =============================================================================
// SOLANA-SPECIFIC DERIVATION HELPERS
// =============================================================================

// DeriveSolanaAccountOwner derives the owner keypair and pubkey from an ADI URL.
// Matches the API bridge's deriveOwnerKeypair: keccak256(adiUrl) is used as an
// Ed25519 seed to derive a Keypair, and the PUBLIC KEY becomes the owner.
// Returns the 32-byte public key (owner) and the 64-byte private key (for signing).
func DeriveSolanaAccountOwner(adiURL string) ([32]byte, ed25519.PrivateKey) {
	seed := ethcrypto.Keccak256([]byte(adiURL))
	privKey := ed25519.NewKeyFromSeed(seed[:32])
	pubKey := privKey.Public().(ed25519.PublicKey)
	var owner [32]byte
	copy(owner[:], pubKey)
	return owner, privKey
}

// DeriveSolanaAccountSalt derives the deterministic salt from an ADI URL.
// Uses mod 2^64 matching the API bridge's deriveSaltU64 (full u64 range).
// Unlike NEAR (which truncates to 2^53 for JSON safety), Solana uses Borsh
// encoding so no precision issues.
func DeriveSolanaAccountSalt(adiURL string) uint64 {
	hash := ethcrypto.Keccak256([]byte(adiURL))
	// Take first 8 bytes as little-endian u64 (matches BigInt % 2^64)
	return binary.LittleEndian.Uint64(hash[:8])
}

// DeriveSolanaRecipient converts a hex address or base58 to a 32-byte Solana pubkey.
// If it looks like a hex address (0x prefix), it pads the 20-byte EVM address to 32 bytes.
// If it looks like base58, it decodes directly.
func DeriveSolanaRecipient(addr string) ([32]byte, error) {
	var pubkey [32]byte

	if strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X") {
		// EVM hex address — pad to 32 bytes (right-aligned)
		hexStr := strings.TrimPrefix(strings.TrimPrefix(addr, "0x"), "0X")
		addrBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return pubkey, fmt.Errorf("invalid hex address: %w", err)
		}
		// Right-align in 32 bytes
		copy(pubkey[32-len(addrBytes):], addrBytes)
		return pubkey, nil
	}

	// Try base58 decode
	data, err := base58.Decode(addr)
	if err != nil {
		return pubkey, fmt.Errorf("invalid Solana address '%s': %w", addr, err)
	}
	if len(data) != 32 {
		return pubkey, fmt.Errorf("Solana address must decode to 32 bytes, got %d", len(data))
	}
	copy(pubkey[:], data)
	return pubkey, nil
}

// solanaAuthorityLevelForLamports returns the Solana contract AuthorityLevel enum value
// matching the deposit-based thresholds.
func solanaAuthorityLevelForLamports(lamports uint64) uint8 {
	// Thresholds in lamports (1 SOL = 10^9 lamports)
	const (
		rootThreshold    = 10_000_000_000 // 10 SOL
		adminThreshold   = 1_000_000_000  // 1 SOL
		managerThreshold = 100_000_000    // 0.1 SOL
	)

	if lamports >= rootThreshold {
		return 4 // ROOT
	} else if lamports >= adminThreshold {
		return 3 // ADMIN
	} else if lamports >= managerThreshold {
		return 2 // MANAGER
	}
	return 1 // OPERATOR
}
