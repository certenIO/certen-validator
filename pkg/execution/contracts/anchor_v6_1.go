// CertenAnchorV6_1 binding shim. The pre-V6.1 generated binding
// (CertenAnchorV4) hard-codes the 7-arg createAnchor signature; V6.1 adds an
// operationID parameter for an 8-arg signature, so calling the V4 binding's
// CreateAnchor against a V6.1 contract would hit the wrong function selector
// and revert.
//
// Rather than regenerating the entire abigen output (the V4 binding is
// otherwise compatible: V6.1 anchors share the same executeComprehensiveProof,
// addOperator, registerValidator, etc.), we ship a minimal hand-rolled ABI
// for just the V6.1-changed surface: createAnchor (8 args) and the new
// getValidatorSetRoot / getAnchorOperationID view methods.
//
// Both signer (BFT) and submitter (this file) compute the same V6.1 bundleId
// via DeriveV6_1BundleID, so the contract's `require(bundleId == derived)`
// check inside createAnchor never fails on a bit mismatch.
package contracts

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// v6_1ABIFragment is the minimal JSON ABI for V6.1-specific functions. Kept
// intentionally small — only the methods that diverge from V4's binding.
const v6_1ABIFragment = `[
  {
    "type": "function",
    "name": "createAnchor",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "bundleId",              "type": "bytes32"},
      {"name": "adiURLHash",            "type": "bytes32"},
      {"name": "operationCommitment",   "type": "bytes32"},
      {"name": "crossChainCommitment",  "type": "bytes32"},
      {"name": "governanceRoot",        "type": "bytes32"},
      {"name": "executionCommitment",   "type": "bytes32"},
      {"name": "operationID",           "type": "bytes32"},
      {"name": "accumulateBlockHeight", "type": "uint256"}
    ],
    "outputs": []
  },
  {
    "type": "function",
    "name": "getValidatorSetRoot",
    "stateMutability": "view",
    "inputs": [],
    "outputs": [{"name": "", "type": "bytes32"}]
  },
  {
    "type": "function",
    "name": "getAnchorOperationID",
    "stateMutability": "view",
    "inputs": [{"name": "anchorId", "type": "bytes32"}],
    "outputs": [{"name": "", "type": "bytes32"}]
  },
  {
    "type": "function",
    "name": "anchors",
    "stateMutability": "view",
    "inputs": [{"name": "", "type": "bytes32"}],
    "outputs": [
      {"name": "bundleId",              "type": "bytes32"},
      {"name": "merkleRoot",            "type": "bytes32"},
      {"name": "adiURLHash",            "type": "bytes32"},
      {"name": "operationCommitment",   "type": "bytes32"},
      {"name": "crossChainCommitment",  "type": "bytes32"},
      {"name": "governanceRoot",        "type": "bytes32"},
      {"name": "executionCommitment",   "type": "bytes32"},
      {"name": "operationID",           "type": "bytes32"},
      {"name": "accumulateBlockHeight", "type": "uint256"},
      {"name": "timestamp",             "type": "uint256"},
      {"name": "validator",             "type": "address"},
      {"name": "valid",                 "type": "bool"},
      {"name": "proofExecuted",         "type": "bool"},
      {"name": "governanceExecuted",    "type": "bool"},
      {"name": "governanceLevel",       "type": "uint8"}
    ]
  }
]`

// AnchorV6_1 mirrors the V6.1 contract's Anchor storage layout (V4 binding
// adds operationID after executionCommitment, shifting subsequent fields).
// Reading via the V4 getAnchorFull on a V6.1 anchor produces "improperly
// encoded boolean value" because the V4 ABI expects governanceExecuted at
// the slot V6.1 stores operationID. This struct + GetAnchorV6_1 below fix
// that.
type AnchorV6_1 struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	ExecutionCommitment   [32]byte
	OperationID           [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
	ProofExecuted         bool
	GovernanceExecuted    bool
	GovernanceLevel       uint8
}

var parsedV6_1ABI abi.ABI

func init() {
	a, err := abi.JSON(strings.NewReader(v6_1ABIFragment))
	if err != nil {
		panic(fmt.Sprintf("parse V6.1 ABI fragment: %v", err))
	}
	parsedV6_1ABI = a
}

// CreateAnchorV6_1 calls CertenAnchorV6_1.createAnchor with the 8-arg
// signature that commits operationID. Use this instead of CreateAnchorSimple
// whenever the on-chain anchor is V6.1.
func (w *CertenAnchorWrapper) CreateAnchorV6_1(
	opts *bind.TransactOpts,
	bundleId [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	accumulateBlockHeight *big.Int,
) (*types.Transaction, error) {
	bound := bind.NewBoundContract(w.address, parsedV6_1ABI, nil, w.backend, nil)
	return bound.Transact(opts, "createAnchor",
		bundleId,
		adiURLHash,
		operationCommitment,
		crossChainCommitment,
		governanceRoot,
		executionCommitment,
		operationID,
		accumulateBlockHeight,
	)
}

// GetValidatorSetRootV6_1 reads the V6.1 contract's currentValidatorSetRoot.
// Used at validator startup to AUDIT that the locally-computed setRoot
// (from contracts.GetV6_1ValidatorSetRoot) matches what the chain holds —
// any mismatch silently breaks BLS verification on TX2.
func (w *CertenAnchorWrapper) GetValidatorSetRootV6_1(ctx context.Context) ([32]byte, error) {
	bound := bind.NewBoundContract(w.address, parsedV6_1ABI, w.backend, nil, nil)
	out := []interface{}{new([32]byte)}
	callOpts := &bind.CallOpts{Context: ctx}
	if err := bound.Call(callOpts, &out, "getValidatorSetRoot"); err != nil {
		return [32]byte{}, fmt.Errorf("getValidatorSetRoot: %w", err)
	}
	return *out[0].(*[32]byte), nil
}

// GetAnchorOperationIDV6_1 reads the stored operationID for an anchor.
// Useful for forensic debugging when verification fails — confirms the
// contract recorded the operationID we expected during createAnchor.
func (w *CertenAnchorWrapper) GetAnchorOperationIDV6_1(ctx context.Context, anchorId [32]byte) ([32]byte, error) {
	bound := bind.NewBoundContract(w.address, parsedV6_1ABI, w.backend, nil, nil)
	out := []interface{}{new([32]byte)}
	callOpts := &bind.CallOpts{Context: ctx}
	if err := bound.Call(callOpts, &out, "getAnchorOperationID", anchorId); err != nil {
		return [32]byte{}, fmt.Errorf("getAnchorOperationID: %w", err)
	}
	return *out[0].(*[32]byte), nil
}

// GetAnchorV6_1 reads the stored Anchor struct from the V6.1 contract using
// the correct field layout. The V4 binding's getAnchorFull misdecodes V6.1
// data because operationID was added after executionCommitment, shifting
// every later field. Callers that need an anchor's commitments to perform
// step-3 leg execution MUST use this method when targeting a V6.1 contract.
func (w *CertenAnchorWrapper) GetAnchorV6_1(ctx context.Context, anchorId [32]byte) (*AnchorV6_1, error) {
	bound := bind.NewBoundContract(w.address, parsedV6_1ABI, w.backend, nil, nil)
	out := []interface{}{
		new([32]byte), // bundleId
		new([32]byte), // merkleRoot
		new([32]byte), // adiURLHash
		new([32]byte), // operationCommitment
		new([32]byte), // crossChainCommitment
		new([32]byte), // governanceRoot
		new([32]byte), // executionCommitment
		new([32]byte), // operationID
		new(*big.Int), // accumulateBlockHeight
		new(*big.Int), // timestamp
		new(common.Address), // validator
		new(bool),     // valid
		new(bool),     // proofExecuted
		new(bool),     // governanceExecuted
		new(uint8),    // governanceLevel
	}
	callOpts := &bind.CallOpts{Context: ctx}
	if err := bound.Call(callOpts, &out, "anchors", anchorId); err != nil {
		return nil, fmt.Errorf("anchors(%x): %w", anchorId, err)
	}
	return &AnchorV6_1{
		BundleId:              *out[0].(*[32]byte),
		MerkleRoot:            *out[1].(*[32]byte),
		AdiURLHash:            *out[2].(*[32]byte),
		OperationCommitment:   *out[3].(*[32]byte),
		CrossChainCommitment:  *out[4].(*[32]byte),
		GovernanceRoot:        *out[5].(*[32]byte),
		ExecutionCommitment:   *out[6].(*[32]byte),
		OperationID:           *out[7].(*[32]byte),
		AccumulateBlockHeight: *out[8].(**big.Int),
		Timestamp:             *out[9].(**big.Int),
		Validator:             *out[10].(*common.Address),
		Valid:                 *out[11].(*bool),
		ProofExecuted:         *out[12].(*bool),
		GovernanceExecuted:    *out[13].(*bool),
		GovernanceLevel:       *out[14].(*uint8),
	}, nil
}

// Silence unused-import warnings — common is pulled in transitively but the
// linker complains in some go versions if no direct use is present.
var _ = common.Address{}
var _ types.Transaction
