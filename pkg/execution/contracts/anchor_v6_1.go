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
    "name": "getAnchor",
    "stateMutability": "view",
    "inputs": [{"name": "anchorId", "type": "bytes32"}],
    "outputs": [
      {"name": "bundleId",              "type": "bytes32"},
      {"name": "merkleRoot",            "type": "bytes32"},
      {"name": "adiURLHash",            "type": "bytes32"},
      {"name": "operationCommitment",   "type": "bytes32"},
      {"name": "crossChainCommitment",  "type": "bytes32"},
      {"name": "governanceRoot",        "type": "bytes32"},
      {"name": "accumulateBlockHeight", "type": "uint256"},
      {"name": "timestamp",             "type": "uint256"},
      {"name": "validator",             "type": "address"},
      {"name": "valid",                 "type": "bool"}
    ]
  }
]`

// AnchorV6_1 holds the fields returned by V6.1's explicit getAnchor() view
// function — a 10-tuple that excludes the V6.1-only operationID and the
// runtime status flags (proofExecuted, governanceExecuted, governanceLevel).
// Step 3 (leg execution) only needs the commitments + validator + valid
// fields, which are all here. If full anchor state is ever required, add a
// dedicated ABI entry for getAnchorOperationID / getAnchorStatus and call
// those separately.
type AnchorV6_1 struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
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

// GetAnchorV6_1 calls the V6.1 contract's explicit getAnchor(bytes32) view
// function (10 fields) instead of the auto-generated mapping accessor
// (15 fields including the V6.1-only operationID + runtime status). The V4
// Go binding's GetAnchorFull misdecodes the 15-field response — operationID
// shifts every later field by 32 bytes, manifesting as "improperly encoded
// boolean value" or "[32]uint8 into uint8" at decode time. Using the
// 10-field explicit getter sidesteps the layout mismatch entirely.
func (w *CertenAnchorWrapper) GetAnchorV6_1(ctx context.Context, anchorId [32]byte) (*AnchorV6_1, error) {
	bound := bind.NewBoundContract(w.address, parsedV6_1ABI, w.backend, nil, nil)
	out := []interface{}{
		new([32]byte),       // bundleId
		new([32]byte),       // merkleRoot
		new([32]byte),       // adiURLHash
		new([32]byte),       // operationCommitment
		new([32]byte),       // crossChainCommitment
		new([32]byte),       // governanceRoot
		new(*big.Int),       // accumulateBlockHeight
		new(*big.Int),       // timestamp
		new(common.Address), // validator
		new(bool),           // valid
	}
	callOpts := &bind.CallOpts{Context: ctx}
	if err := bound.Call(callOpts, &out, "getAnchor", anchorId); err != nil {
		return nil, fmt.Errorf("getAnchor(%x): %w", anchorId, err)
	}
	return &AnchorV6_1{
		BundleId:              *out[0].(*[32]byte),
		MerkleRoot:            *out[1].(*[32]byte),
		AdiURLHash:            *out[2].(*[32]byte),
		OperationCommitment:   *out[3].(*[32]byte),
		CrossChainCommitment:  *out[4].(*[32]byte),
		GovernanceRoot:        *out[5].(*[32]byte),
		AccumulateBlockHeight: *out[6].(**big.Int),
		Timestamp:             *out[7].(**big.Int),
		Validator:             *out[8].(*common.Address),
		Valid:                 *out[9].(*bool),
	}, nil
}

// Silence unused-import warnings — common is pulled in transitively but the
// linker complains in some go versions if no direct use is present.
var _ = common.Address{}
var _ types.Transaction
