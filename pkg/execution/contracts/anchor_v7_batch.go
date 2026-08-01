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

// CertenAnchorV7BatchABI is the minimal ABI for the V7 batch additions.
//
// Everything else on CertenAnchorV7 is identical to CertenAnchorV6_1, so the existing
// bindings continue to serve the single-intent path unchanged.
const CertenAnchorV7BatchABI = `[
  {"type":"function","name":"createBatchAnchor","inputs":[
    {"name":"bundleId","type":"bytes32"},
    {"name":"batchRoot","type":"bytes32"},
    {"name":"leafCount","type":"uint256"},
    {"name":"batchOperationID","type":"bytes32"},
    {"name":"accumulateBlockHeight","type":"uint256"}],
   "outputs":[],"stateMutability":"nonpayable"},

  {"type":"function","name":"isBatchAnchor","inputs":[{"name":"","type":"bytes32"}],
   "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},

  {"type":"function","name":"batchLeafCount","inputs":[{"name":"","type":"bytes32"}],
   "outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},

  {"type":"function","name":"verifyProof","inputs":[
    {"name":"anchorId","type":"bytes32"},
    {"name":"merkleProof","type":"bytes32[]"},
    {"name":"leaf","type":"bytes32"}],
   "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},

  {"type":"function","name":"anchorExists","inputs":[{"name":"anchorId","type":"bytes32"}],
   "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},

  {"type":"function","name":"getExecutionCommitment","inputs":[{"name":"anchorId","type":"bytes32"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"}
]`

// CertenAnchorV7Batch binds the batch surface of a deployed CertenAnchorV7.
type CertenAnchorV7Batch struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

// NewCertenAnchorV7Batch binds to a CertenAnchorV7 at the given address.
func NewCertenAnchorV7Batch(address common.Address, backend bind.ContractBackend) (*CertenAnchorV7Batch, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV7BatchABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAnchorV7 batch ABI: %w", err)
	}
	return &CertenAnchorV7Batch{
		address:  address,
		abi:      parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend),
	}, nil
}

func (a *CertenAnchorV7Batch) Address() common.Address { return a.address }

// CreateBatchAnchor writes ONE anchor covering N intents.
//
// bundleId MUST equal DeriveBatchBundleID(chainID, batchRoot, leafCount, batchOperationID,
// height) or the contract reverts — that binding is what stops a rogue validator storing a
// different root under an id the quorum signed for another batch.
func (a *CertenAnchorV7Batch) CreateBatchAnchor(
	opts *bind.TransactOpts,
	bundleID [32]byte,
	batchRoot [32]byte,
	leafCount *big.Int,
	batchOperationID [32]byte,
	accumulateBlockHeight *big.Int,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "createBatchAnchor",
		bundleID, batchRoot, leafCount, batchOperationID, accumulateBlockHeight)
}

func (a *CertenAnchorV7Batch) IsBatchAnchor(opts *bind.CallOpts, bundleID [32]byte) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "isBatchAnchor", bundleID); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("isBatchAnchor returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

func (a *CertenAnchorV7Batch) BatchLeafCount(opts *bind.CallOpts, bundleID [32]byte) (*big.Int, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "batchLeafCount", bundleID); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("batchLeafCount returned no value")
	}
	return *abi.ConvertType(out[0], new(*big.Int)).(**big.Int), nil
}

func (a *CertenAnchorV7Batch) AnchorExists(opts *bind.CallOpts, bundleID [32]byte) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "anchorExists", bundleID); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("anchorExists returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

// VerifyProof asks the DEPLOYED anchor whether a leaf is in its stored root.
//
// The validator calls this for every member before submitting any account transaction. A
// branch that fails here would revert on-chain too, after gas had been spent — and worse,
// would leave the operator unsure whether the batch or the branch was at fault.
func (a *CertenAnchorV7Batch) VerifyProof(
	opts *bind.CallOpts,
	anchorID [32]byte,
	merkleProof [][32]byte,
	leaf [32]byte,
) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "verifyProof", anchorID, merkleProof, leaf); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("verifyProof returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

func (a *CertenAnchorV7Batch) GetExecutionCommitment(opts *bind.CallOpts, anchorID [32]byte) ([32]byte, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "getExecutionCommitment", anchorID); err != nil {
		return [32]byte{}, err
	}
	if len(out) == 0 {
		return [32]byte{}, fmt.Errorf("getExecutionCommitment returned no value")
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

// =============================================================================
// CertenAccountV7
// =============================================================================

// CertenAccountV7ABI is the minimal ABI for the leaf-authorized account.
//
// Difference from V6 that matters to the validator: the proof struct gains operationID, and
// merkleProof is now the branch from THIS account's leaf to the batch root rather than a
// path to a per-intent adiURL leaf.
const CertenAccountV7ABI = `[
  {"type":"function","name":"executeGovernanceProofDirect","inputs":[
    {"name":"target","type":"address"},
    {"name":"value","type":"uint256"},
    {"name":"data","type":"bytes"},
    {"name":"proof","type":"tuple","components":[
      {"name":"adiURL","type":"string"},
      {"name":"anchorId","type":"bytes32"},
      {"name":"merkleProof","type":"bytes32[]"},
      {"name":"operationID","type":"bytes32"},
      {"name":"keyBookProof","type":"bytes"},
      {"name":"roleProof","type":"bytes"},
      {"name":"thresholdProof","type":"bytes"},
      {"name":"timestamp","type":"uint256"},
      {"name":"expiresAt","type":"uint256"},
      {"name":"validatorSignatures","type":"bytes"},
      {"name":"nonce","type":"uint256"},
      {"name":"requiredLevel","type":"uint8"}]}],
   "outputs":[],"stateMutability":"nonpayable"},

  {"type":"function","name":"batchExecuteGovernanceProofDirect","inputs":[
    {"name":"targets","type":"address[]"},
    {"name":"values","type":"uint256[]"},
    {"name":"datas","type":"bytes[]"},
    {"name":"proof","type":"tuple","components":[
      {"name":"adiURL","type":"string"},
      {"name":"anchorId","type":"bytes32"},
      {"name":"merkleProof","type":"bytes32[]"},
      {"name":"operationID","type":"bytes32"},
      {"name":"keyBookProof","type":"bytes"},
      {"name":"roleProof","type":"bytes"},
      {"name":"thresholdProof","type":"bytes"},
      {"name":"timestamp","type":"uint256"},
      {"name":"expiresAt","type":"uint256"},
      {"name":"validatorSignatures","type":"bytes"},
      {"name":"nonce","type":"uint256"},
      {"name":"requiredLevel","type":"uint8"}]}],
   "outputs":[],"stateMutability":"nonpayable"},

  {"type":"function","name":"computeLeaf","inputs":[
    {"name":"executionCommitment","type":"bytes32"},
    {"name":"operationID","type":"bytes32"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},

  {"type":"function","name":"computeSingleCommitment","inputs":[
    {"name":"target","type":"address"},
    {"name":"value","type":"uint256"},
    {"name":"data","type":"bytes"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},

  {"type":"function","name":"computeBatchCommitment","inputs":[
    {"name":"targets","type":"address[]"},
    {"name":"values","type":"uint256[]"},
    {"name":"datas","type":"bytes[]"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},

  {"type":"function","name":"isLeafConsumed","inputs":[{"name":"leaf","type":"bytes32"}],
   "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"isKeylessOwner","inputs":[],
   "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"adiURLHash","inputs":[],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"owner","inputs":[],
   "outputs":[{"name":"","type":"address"}],"stateMutability":"view"}
]`

// AccountProofV7 mirrors CertenAccountV7.ADIGovernanceProof.
//
// Field ORDER matters — abi encoding is positional, so a reordered struct silently produces
// a different calldata layout and the contract reads garbage.
type AccountProofV7 struct {
	AdiURL              string
	AnchorId            [32]byte
	MerkleProof         [][32]byte
	OperationID         [32]byte
	KeyBookProof        []byte
	RoleProof           []byte
	ThresholdProof      []byte
	Timestamp           *big.Int
	ExpiresAt           *big.Int
	ValidatorSignatures []byte
	Nonce               *big.Int
	RequiredLevel       uint8
}

// CertenAccountV7 binds a deployed leaf-authorized account.
type CertenAccountV7 struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

func NewCertenAccountV7(address common.Address, backend bind.ContractBackend) (*CertenAccountV7, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV7ABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAccountV7 ABI: %w", err)
	}
	return &CertenAccountV7{
		address:  address,
		abi:      parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend),
	}, nil
}

func (a *CertenAccountV7) Address() common.Address { return a.address }

func (a *CertenAccountV7) ExecuteGovernanceProofDirect(
	opts *bind.TransactOpts,
	target common.Address,
	value *big.Int,
	data []byte,
	proof AccountProofV7,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "executeGovernanceProofDirect", target, value, data, proof)
}

func (a *CertenAccountV7) BatchExecuteGovernanceProofDirect(
	opts *bind.TransactOpts,
	targets []common.Address,
	values []*big.Int,
	datas [][]byte,
	proof AccountProofV7,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "batchExecuteGovernanceProofDirect", targets, values, datas, proof)
}

// ComputeLeaf asks the DEPLOYED account for its own leaf. Used to cross-check the Go
// computation against real bytecode before an anchor is paid for.
func (a *CertenAccountV7) ComputeLeaf(
	opts *bind.CallOpts,
	executionCommitment [32]byte,
	operationID [32]byte,
) ([32]byte, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "computeLeaf", executionCommitment, operationID); err != nil {
		return [32]byte{}, err
	}
	if len(out) == 0 {
		return [32]byte{}, fmt.Errorf("computeLeaf returned no value")
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

func (a *CertenAccountV7) ComputeSingleCommitment(
	opts *bind.CallOpts,
	target common.Address,
	value *big.Int,
	data []byte,
) ([32]byte, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "computeSingleCommitment", target, value, data); err != nil {
		return [32]byte{}, err
	}
	if len(out) == 0 {
		return [32]byte{}, fmt.Errorf("computeSingleCommitment returned no value")
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

func (a *CertenAccountV7) ComputeBatchCommitment(
	opts *bind.CallOpts,
	targets []common.Address,
	values []*big.Int,
	datas [][]byte,
) ([32]byte, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "computeBatchCommitment", targets, values, datas); err != nil {
		return [32]byte{}, err
	}
	if len(out) == 0 {
		return [32]byte{}, fmt.Errorf("computeBatchCommitment returned no value")
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}

func (a *CertenAccountV7) IsLeafConsumed(opts *bind.CallOpts, leaf [32]byte) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "isLeafConsumed", leaf); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("isLeafConsumed returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

func (a *CertenAccountV7) IsKeylessOwner(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "isKeylessOwner"); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("isKeylessOwner returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

// ADIURLHash returns the account's own immutable identity hash — the value it binds into
// every leaf, and the reason a foreign authorization can never be spent here.
func (a *CertenAccountV7) ADIURLHash(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "adiURLHash"); err != nil {
		return [32]byte{}, err
	}
	if len(out) == 0 {
		return [32]byte{}, fmt.Errorf("adiURLHash returned no value")
	}
	return *abi.ConvertType(out[0], new([32]byte)).(*[32]byte), nil
}
