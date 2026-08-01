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

// CertenAccountV6ABI is the minimal ABI for CertenAccountV6 — the keyless account.
//
// Differences from CertenAccountV2/V4/V5 that matter to the validator:
//   - executeWithGovernanceProof and batchExecuteWithGovernanceProof are GONE. They were
//     onlyEntryPoint, and V6 can never validate a UserOperation (it holds no key), so those
//     paths were unreachable. Calling them reverts with "function does not exist".
//   - batchExecuteGovernanceProofDirect is NEW: the permissionless batch path, bound to an
//     anchor-side ARRAY commitment rather than the single-call commitment.
//   - execute() (the unproved owner escape hatch) is GONE.
const CertenAccountV6ABI = `[
  {"type":"function","name":"executeGovernanceProofDirect","inputs":[
    {"name":"target","type":"address"},
    {"name":"value","type":"uint256"},
    {"name":"data","type":"bytes"},
    {"name":"proof","type":"tuple","components":[
      {"name":"adiURL","type":"string"},
      {"name":"anchorId","type":"bytes32"},
      {"name":"merkleProof","type":"bytes32[]"},
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
      {"name":"keyBookProof","type":"bytes"},
      {"name":"roleProof","type":"bytes"},
      {"name":"thresholdProof","type":"bytes"},
      {"name":"timestamp","type":"uint256"},
      {"name":"expiresAt","type":"uint256"},
      {"name":"validatorSignatures","type":"bytes"},
      {"name":"nonce","type":"uint256"},
      {"name":"requiredLevel","type":"uint8"}]}],
   "outputs":[],"stateMutability":"nonpayable"},

  {"type":"function","name":"computeBatchCommitment","inputs":[
    {"name":"targets","type":"address[]"},
    {"name":"values","type":"uint256[]"},
    {"name":"datas","type":"bytes[]"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},

  {"type":"function","name":"computeSingleCommitment","inputs":[
    {"name":"target","type":"address"},
    {"name":"value","type":"uint256"},
    {"name":"data","type":"bytes"}],
   "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},

  {"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
  {"type":"function","name":"adiURL","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
  {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"isAnchorConsumed","inputs":[{"name":"anchorId","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"}
]`

// CertenAccountV6 is a binding around a deployed CertenAccountV6.
type CertenAccountV6 struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

// NewCertenAccountV6 binds to a CertenAccountV6 at the given address.
func NewCertenAccountV6(address common.Address, backend bind.ContractBackend) (*CertenAccountV6, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV6ABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAccountV6 ABI: %w", err)
	}
	return &CertenAccountV6{
		address:  address,
		abi:      parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend),
	}, nil
}

// Address returns the bound account address.
func (a *CertenAccountV6) Address() common.Address { return a.address }

// ExecuteGovernanceProofDirect submits a single anchored call. On-demand path.
func (a *CertenAccountV6) ExecuteGovernanceProofDirect(
	opts *bind.TransactOpts,
	target common.Address,
	value *big.Int,
	data []byte,
	proof AccountProof,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "executeGovernanceProofDirect", target, value, data, proof)
}

// BatchExecuteGovernanceProofDirect submits an anchored ordered batch. On-cadence path.
//
// The anchor must have been created with the BATCH execution commitment
// (ComputeBatchExecutionCommitment), not the single-call one — CertenAccountV6 keeps the two
// preimages disjoint via a domain tag, so a single-call anchor cannot be spent here.
//
// All-or-nothing: CertenAccountV6._executeOperation bubbles any leg's revert, so the whole
// batch reverts and the anchor is NOT consumed (state is rolled back). The batch can be
// retried against the same anchor once the failing leg's cause is resolved.
func (a *CertenAccountV6) BatchExecuteGovernanceProofDirect(
	opts *bind.TransactOpts,
	targets []common.Address,
	values []*big.Int,
	datas [][]byte,
	proof AccountProof,
) (*types.Transaction, error) {
	return a.contract.Transact(opts, "batchExecuteGovernanceProofDirect", targets, values, datas, proof)
}

// ComputeBatchCommitment asks the deployed contract for the batch commitment. Used to
// cross-check the Go computation against the on-chain one before spending gas.
func (a *CertenAccountV6) ComputeBatchCommitment(
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

// Owner returns the account's ADI-derived identity address.
func (a *CertenAccountV6) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "owner"); err != nil {
		return common.Address{}, err
	}
	if len(out) == 0 {
		return common.Address{}, fmt.Errorf("owner returned no value")
	}
	return *abi.ConvertType(out[0], new(common.Address)).(*common.Address), nil
}

// IsKeylessOwner asks the contract to confirm owner == keccak256(adiURL)[12:].
func (a *CertenAccountV6) IsKeylessOwner(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "isKeylessOwner"); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("isKeylessOwner returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}

// IsAnchorConsumed reports whether the anchor has already been spent on this account.
// Checked before submitting, so a doomed replay is not paid for in gas.
func (a *CertenAccountV6) IsAnchorConsumed(opts *bind.CallOpts, anchorID [32]byte) (bool, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, "isAnchorConsumed", anchorID); err != nil {
		return false, err
	}
	if len(out) == 0 {
		return false, fmt.Errorf("isAnchorConsumed returned no value")
	}
	return *abi.ConvertType(out[0], new(bool)).(*bool), nil
}
