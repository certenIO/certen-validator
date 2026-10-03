package contracts

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// CertenAnchorV8_2BatchABI is the batch surface of CertenAnchorV8_2, extracted VERBATIM from the Foundry artifact
// out/CertenAnchorV8_2.sol/CertenAnchorV8_2.json (certen-contracts feat/v8-2-rollout; the entries are regenerated from
// the artifact of the exact commit deployed - RB5 Phase C.2). TestCertenAnchorV8_2BatchABI pins every signature the
// batch path depends on, including the seven-argument createBatchAnchor and the seventeen-field anchors getter.
const CertenAnchorV8_2BatchABI = `[
  {"type":"function","name":"createBatchAnchor","inputs":[{"name":"bundleId","type":"bytes32","internalType":"bytes32"},{"name":"batchRoot","type":"bytes32","internalType":"bytes32"},{"name":"leafCount","type":"uint256","internalType":"uint256"},{"name":"batchOperationID","type":"bytes32","internalType":"bytes32"},{"name":"accumulateBlockHeight","type":"uint256","internalType":"uint256"},{"name":"accumulateValidatorSetRoot","type":"bytes32","internalType":"bytes32"},{"name":"accumulateIncarnation","type":"bytes32","internalType":"bytes32"}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"isBatchAnchor","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"batchLeafCount","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"verifyProof","inputs":[{"name":"anchorId","type":"bytes32","internalType":"bytes32"},{"name":"merkleProof","type":"bytes32[]","internalType":"bytes32[]"},{"name":"leaf","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"anchorExists","inputs":[{"name":"anchorId","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"getExecutionCommitment","inputs":[{"name":"anchorId","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"bundleId","type":"bytes32","internalType":"bytes32"},{"name":"merkleRoot","type":"bytes32","internalType":"bytes32"},{"name":"adiURLHash","type":"bytes32","internalType":"bytes32"},{"name":"operationCommitment","type":"bytes32","internalType":"bytes32"},{"name":"crossChainCommitment","type":"bytes32","internalType":"bytes32"},{"name":"governanceRoot","type":"bytes32","internalType":"bytes32"},{"name":"executionCommitment","type":"bytes32","internalType":"bytes32"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"accumulateBlockHeight","type":"uint256","internalType":"uint256"},{"name":"timestamp","type":"uint256","internalType":"uint256"},{"name":"validator","type":"address","internalType":"address"},{"name":"valid","type":"bool","internalType":"bool"},{"name":"proofExecuted","type":"bool","internalType":"bool"},{"name":"governanceExecuted","type":"bool","internalType":"bool"},{"name":"governanceLevel","type":"uint8","internalType":"uint8"},{"name":"accumulateValidatorSetRoot","type":"bytes32","internalType":"bytes32"},{"name":"accumulateIncarnation","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"currentValidatorSetRoot","inputs":[],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"}
]`

// CreateBatchAnchorV8_2Signature is the V8.2 batch anchor call: the V8.1 five arguments plus the Accumulate validator
// set root and incarnation the anchor commits (RB5).
const CreateBatchAnchorV8_2Signature = "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32)"

// CertenAnchorV8_2Batch binds the batch surface of a deployed CertenAnchorV8_2.
type CertenAnchorV8_2Batch struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

// NewCertenAnchorV8_2Batch binds to a CertenAnchorV8_2 at address.
func NewCertenAnchorV8_2Batch(address common.Address, backend bind.ContractBackend) (*CertenAnchorV8_2Batch, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV8_2BatchABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAnchorV8_2 batch ABI: %w", err)
	}
	return &CertenAnchorV8_2Batch{address: address, abi: parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend)}, nil
}

func (a *CertenAnchorV8_2Batch) Address() common.Address { return a.address }

// CreateBatchAnchor writes ONE anchor covering N intents and the Accumulate validator set and incarnation they were
// proven on. bundleID MUST equal DeriveV8_2BatchBundleID over the other six arguments or the contract reverts.
func (a *CertenAnchorV8_2Batch) CreateBatchAnchor(
	opts *bind.TransactOpts,
	bundleID, batchRoot [32]byte,
	leafCount *big.Int,
	batchOperationID [32]byte,
	accumulateBlockHeight *big.Int,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "createBatchAnchor", bundleID, batchRoot, leafCount, batchOperationID,
		accumulateBlockHeight, accumulateValidatorSetRoot, accumulateIncarnation)
}

func (a *CertenAnchorV8_2Batch) call1(opts *bind.CallOpts, method string, args ...interface{}) (interface{}, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, method, args...); err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("%s returned %d values, want 1", method, len(out))
	}
	return out[0], nil
}

// CurrentValidatorSetRoot is the CERTEN validator set root the anchor checks quorums against now - the value the
// outcome message (ComputeEvmMessageHashV8_2_Outcome) commits when an outcome is recorded.
func (a *CertenAnchorV8_2Batch) CurrentValidatorSetRoot(opts *bind.CallOpts) ([32]byte, error) {
	v, err := a.call1(opts, "currentValidatorSetRoot")
	if err != nil {
		return [32]byte{}, err
	}
	return v.([32]byte), nil
}

func (a *CertenAnchorV8_2Batch) IsBatchAnchor(opts *bind.CallOpts, bundleID [32]byte) (bool, error) {
	v, err := a.call1(opts, "isBatchAnchor", bundleID)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAnchorV8_2Batch) BatchLeafCount(opts *bind.CallOpts, bundleID [32]byte) (*big.Int, error) {
	v, err := a.call1(opts, "batchLeafCount", bundleID)
	if err != nil {
		return nil, err
	}
	return *abi.ConvertType(v, new(*big.Int)).(**big.Int), nil
}

func (a *CertenAnchorV8_2Batch) AnchorExists(opts *bind.CallOpts, bundleID [32]byte) (bool, error) {
	v, err := a.call1(opts, "anchorExists", bundleID)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAnchorV8_2Batch) VerifyProof(opts *bind.CallOpts, anchorID [32]byte, merkleProof [][32]byte, leaf [32]byte) (bool, error) {
	v, err := a.call1(opts, "verifyProof", anchorID, merkleProof, leaf)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAnchorV8_2Batch) GetExecutionCommitment(opts *bind.CallOpts, anchorID [32]byte) ([32]byte, error) {
	v, err := a.call1(opts, "getExecutionCommitment", anchorID)
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(v, new([32]byte)).(*[32]byte), nil
}

// AnchorV8_2 is CertenAnchorV8_2.anchors(bundleId): the V8.1 fifteen fields plus the Accumulate half.
type AnchorV8_2 struct {
	BundleID                   [32]byte
	MerkleRoot                 [32]byte
	AdiURLHash                 [32]byte
	OperationCommitment        [32]byte
	CrossChainCommitment       [32]byte
	GovernanceRoot             [32]byte
	ExecutionCommitment        [32]byte
	OperationID                [32]byte
	AccumulateBlockHeight      *big.Int
	Timestamp                  *big.Int
	Validator                  common.Address
	Valid                      bool
	ProofExecuted              bool
	GovernanceExecuted         bool
	GovernanceLevel            uint8
	AccumulateValidatorSetRoot [32]byte
	AccumulateIncarnation      [32]byte
}

// Anchors reads anchors(bundleId) with all seventeen fields.
func (a *CertenAnchorV8_2Batch) Anchors(opts *bind.CallOpts, bundleID [32]byte) (*AnchorV8_2, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "anchors", bundleID); err != nil {
		return nil, err
	}
	if len(out) != 17 {
		return nil, fmt.Errorf("anchors returned %d values, want the 17 of CertenAnchorV8_2", len(out))
	}
	r := &AnchorV8_2{}
	b32 := func(i int) [32]byte { return *abi.ConvertType(out[i], new([32]byte)).(*[32]byte) }
	r.BundleID, r.MerkleRoot, r.AdiURLHash, r.OperationCommitment = b32(0), b32(1), b32(2), b32(3)
	r.CrossChainCommitment, r.GovernanceRoot, r.ExecutionCommitment, r.OperationID = b32(4), b32(5), b32(6), b32(7)
	r.AccumulateBlockHeight = *abi.ConvertType(out[8], new(*big.Int)).(**big.Int)
	r.Timestamp = *abi.ConvertType(out[9], new(*big.Int)).(**big.Int)
	r.Validator = *abi.ConvertType(out[10], new(common.Address)).(*common.Address)
	r.Valid = *abi.ConvertType(out[11], new(bool)).(*bool)
	r.ProofExecuted = *abi.ConvertType(out[12], new(bool)).(*bool)
	r.GovernanceExecuted = *abi.ConvertType(out[13], new(bool)).(*bool)
	r.GovernanceLevel = *abi.ConvertType(out[14], new(uint8)).(*uint8)
	r.AccumulateValidatorSetRoot, r.AccumulateIncarnation = b32(15), b32(16)
	return r, nil
}
