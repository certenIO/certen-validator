package contracts

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// CertenOutcomeRegistryV1ABI is the complete ABI of CertenOutcomeRegistryV1 (RB5 D4), extracted VERBATIM from the Foundry
// artifact of certen-contracts origin/main (`forge inspect CertenOutcomeRegistryV1 abi`), the source of the registries
// deployed on Ethereum Sepolia, Base Sepolia and Arbitrum Sepolia. TestCertenOutcomeRegistryV1ABI pins every signature
// the outcome path depends on.
const CertenOutcomeRegistryV1ABI = `[
  {"type":"constructor","inputs":[{"name":"anchor_","type":"address","internalType":"contract CertenAnchorV8_2"}],"stateMutability":"nonpayable"},
  {"type":"function","name":"DEPLOYMENT_CHAIN_ID","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"anchor","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract CertenAnchorV8_2"}],"stateMutability":"view"},
  {"type":"function","name":"outcomeMessage","inputs":[{"name":"bundleId","type":"bytes32","internalType":"bytes32"},{"name":"outcomeRoot","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"outcomeRoots","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"recordBatchOutcome","inputs":[{"name":"bundleId","type":"bytes32","internalType":"bytes32"},{"name":"outcomeRoot","type":"bytes32","internalType":"bytes32"},{"name":"blsProof","type":"tuple","internalType":"struct CertenAnchorV8_2.BLSProofData","components":[{"name":"aggregateSignature","type":"bytes","internalType":"bytes"},{"name":"validatorAddresses","type":"address[]","internalType":"address[]"},{"name":"votingPowers","type":"uint256[]","internalType":"uint256[]"},{"name":"totalVotingPower","type":"uint256","internalType":"uint256"},{"name":"signedVotingPower","type":"uint256","internalType":"uint256"},{"name":"thresholdMet","type":"bool","internalType":"bool"},{"name":"messageHash","type":"bytes32","internalType":"bytes32"}]}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"recordedInBlock","inputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},
  {"type":"event","name":"BatchOutcomeRecorded","inputs":[{"name":"bundleId","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"outcomeRoot","type":"bytes32","indexed":true,"internalType":"bytes32"},{"name":"recorder","type":"address","indexed":true,"internalType":"address"},{"name":"messageHash","type":"bytes32","indexed":false,"internalType":"bytes32"}],"anonymous":false},
  {"type":"error","name":"AnchorNotAttested","inputs":[]},
  {"type":"error","name":"AnchorNotV8_2","inputs":[]},
  {"type":"error","name":"AnchorRequired","inputs":[]},
  {"type":"error","name":"ChainIDMismatch","inputs":[]},
  {"type":"error","name":"OnlyRegisteredValidator","inputs":[]},
  {"type":"error","name":"OutcomeAlreadyRecorded","inputs":[]},
  {"type":"error","name":"OutcomeRootRequired","inputs":[]},
  {"type":"error","name":"QuorumAttestationInvalid","inputs":[]}
]`

// RecordBatchOutcomeSignature is the registry's write: the anchor's outcome root under a quorum attestation of the
// outcome message (ComputeEvmMessageHashV8_2_Outcome).
const RecordBatchOutcomeSignature = "recordBatchOutcome(bytes32,bytes32,(bytes,address[],uint256[],uint256,uint256,bool,bytes32))"

// CertenOutcomeRegistryV1 binds a deployed CertenOutcomeRegistryV1.
type CertenOutcomeRegistryV1 struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

// NewCertenOutcomeRegistryV1 binds to the registry at address.
func NewCertenOutcomeRegistryV1(address common.Address, backend bind.ContractBackend) (*CertenOutcomeRegistryV1, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenOutcomeRegistryV1ABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenOutcomeRegistryV1 ABI: %w", err)
	}
	return &CertenOutcomeRegistryV1{address: address, abi: parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend)}, nil
}

func (r *CertenOutcomeRegistryV1) Address() common.Address { return r.address }

// ABI is the registry's parsed ABI (for decoding its custom errors and events).
func (r *CertenOutcomeRegistryV1) ABI() abi.ABI { return r.abi }

func (r *CertenOutcomeRegistryV1) call1(opts *bind.CallOpts, method string, args ...interface{}) (interface{}, error) {
	var out []interface{}
	if err := r.contract.Call(opts, &out, method, args...); err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("%s returned %d values", method, len(out))
	}
	return out[0], nil
}

// Anchor is the CertenAnchorV8_2 the registry records outcomes of (immutable).
func (r *CertenOutcomeRegistryV1) Anchor(opts *bind.CallOpts) (common.Address, error) {
	v, err := r.call1(opts, "anchor")
	if err != nil {
		return common.Address{}, err
	}
	return v.(common.Address), nil
}

// DeploymentChainID is the chain the registry was deployed on (immutable).
func (r *CertenOutcomeRegistryV1) DeploymentChainID(opts *bind.CallOpts) (*big.Int, error) {
	v, err := r.call1(opts, "DEPLOYMENT_CHAIN_ID")
	if err != nil {
		return nil, err
	}
	return v.(*big.Int), nil
}

// OutcomeMessage is the message the quorum signs for (bundleID, outcomeRoot), exactly as recordBatchOutcome checks it.
// It reverts with AnchorNotAttested for an anchor that is not valid.
func (r *CertenOutcomeRegistryV1) OutcomeMessage(opts *bind.CallOpts, bundleID, outcomeRoot [32]byte) ([32]byte, error) {
	v, err := r.call1(opts, "outcomeMessage", bundleID, outcomeRoot)
	if err != nil {
		return [32]byte{}, err
	}
	return v.([32]byte), nil
}

// OutcomeRoots is the outcome root recorded for bundleID; zero until recorded.
func (r *CertenOutcomeRegistryV1) OutcomeRoots(opts *bind.CallOpts, bundleID [32]byte) ([32]byte, error) {
	v, err := r.call1(opts, "outcomeRoots", bundleID)
	if err != nil {
		return [32]byte{}, err
	}
	return v.([32]byte), nil
}

// RecordedInBlock is the block the outcome of bundleID was recorded in; zero until recorded.
func (r *CertenOutcomeRegistryV1) RecordedInBlock(opts *bind.CallOpts, bundleID [32]byte) (*big.Int, error) {
	v, err := r.call1(opts, "recordedInBlock", bundleID)
	if err != nil {
		return nil, err
	}
	return v.(*big.Int), nil
}

// RecordBatchOutcome records bundleID's outcome root under the quorum's attestation of the outcome message. It is
// write-once; only a registered validator of the anchor may send it.
func (r *CertenOutcomeRegistryV1) RecordBatchOutcome(opts *bind.TransactOpts, bundleID, outcomeRoot [32]byte, proof CertenAnchorV4BLSProofData) (*types.Transaction, error) {
	return r.contract.Transact(opts, "recordBatchOutcome", bundleID, outcomeRoot, proof)
}

// OutcomeRegistryError names the registry's custom error in a revert, or "" when err carries none of them.
func (r *CertenOutcomeRegistryV1) OutcomeRegistryError(err error) string {
	var de rpc.DataError
	if !errors.As(err, &de) {
		return ""
	}
	data, ok := de.ErrorData().(string)
	if !ok {
		return ""
	}
	raw := common.FromHex(data)
	if len(raw) < 4 {
		return ""
	}
	for name, e := range r.abi.Errors {
		if string(e.ID[:4]) == string(raw[:4]) {
			return name
		}
	}
	return ""
}
