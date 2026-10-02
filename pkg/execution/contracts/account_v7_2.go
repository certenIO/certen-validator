// Copyright 2026 Certen Protocol

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

// CertenAccountV7_2ABI is the surface of CertenAccountV7_2 - the account CertenAccountFactoryV10 creates, settling
// against CertenAnchorV8_2 - extracted VERBATIM from the Foundry artifact out/CertenAccountV7_2.sol/CertenAccountV7_2.json
// (certen-contracts feat/v8-2-rollout 0cbc2fa). TestCertenAccountV7_2ABI pins every signature the batch path depends on.
//
// What differs from CertenAccountV7: the leaf binds the index of the ADI key page that authorized the intent
// (certen:batchleaf:v2, RB3-F39), so computeLeaf takes it and the proof's last field is uint64 authorityPage in place
// of the self-declared uint8 requiredLevel - the account derives every leg's level from the page.
const CertenAccountV7_2ABI = `[
  {"type":"function","name":"executeGovernanceProofDirect","inputs":[{"name":"target","type":"address","internalType":"address"},{"name":"value","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"proof","type":"tuple","internalType":"struct CertenAccountV7_2.ADIGovernanceProof","components":[{"name":"adiURL","type":"string","internalType":"string"},{"name":"anchorId","type":"bytes32","internalType":"bytes32"},{"name":"merkleProof","type":"bytes32[]","internalType":"bytes32[]"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"keyBookProof","type":"bytes","internalType":"bytes"},{"name":"roleProof","type":"bytes","internalType":"bytes"},{"name":"thresholdProof","type":"bytes","internalType":"bytes"},{"name":"timestamp","type":"uint256","internalType":"uint256"},{"name":"expiresAt","type":"uint256","internalType":"uint256"},{"name":"validatorSignatures","type":"bytes","internalType":"bytes"},{"name":"nonce","type":"uint256","internalType":"uint256"},{"name":"authorityPage","type":"uint64","internalType":"uint64"}]}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"batchExecuteGovernanceProofDirect","inputs":[{"name":"targets","type":"address[]","internalType":"address[]"},{"name":"values","type":"uint256[]","internalType":"uint256[]"},{"name":"datas","type":"bytes[]","internalType":"bytes[]"},{"name":"proof","type":"tuple","internalType":"struct CertenAccountV7_2.ADIGovernanceProof","components":[{"name":"adiURL","type":"string","internalType":"string"},{"name":"anchorId","type":"bytes32","internalType":"bytes32"},{"name":"merkleProof","type":"bytes32[]","internalType":"bytes32[]"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"keyBookProof","type":"bytes","internalType":"bytes"},{"name":"roleProof","type":"bytes","internalType":"bytes"},{"name":"thresholdProof","type":"bytes","internalType":"bytes"},{"name":"timestamp","type":"uint256","internalType":"uint256"},{"name":"expiresAt","type":"uint256","internalType":"uint256"},{"name":"validatorSignatures","type":"bytes","internalType":"bytes"},{"name":"nonce","type":"uint256","internalType":"uint256"},{"name":"authorityPage","type":"uint64","internalType":"uint64"}]}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"computeLeaf","inputs":[{"name":"executionCommitment","type":"bytes32","internalType":"bytes32"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"authorityPage","type":"uint64","internalType":"uint64"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"computeSingleCommitment","inputs":[{"name":"target","type":"address","internalType":"address"},{"name":"value","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"computeBatchCommitment","inputs":[{"name":"targets","type":"address[]","internalType":"address[]"},{"name":"values","type":"uint256[]","internalType":"uint256[]"},{"name":"datas","type":"bytes[]","internalType":"bytes[]"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"isLeafConsumed","inputs":[{"name":"leaf","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"adiURLHash","inputs":[],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},
  {"type":"function","name":"LEAF_DOMAIN","inputs":[],"outputs":[{"name":"","type":"string","internalType":"string"}],"stateMutability":"view"},
  {"type":"function","name":"authorityLevelOfPage","inputs":[{"name":"page","type":"uint64","internalType":"uint64"}],"outputs":[{"name":"","type":"uint8","internalType":"enum CertenAccountV7_2.AuthorityLevel"}],"stateMutability":"view"},
  {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract CertenAnchorV8_2"}],"stateMutability":"view"}
]`

// LeafDomainV7_2 is CertenAccountV7_2.LEAF_DOMAIN - what an account must report to take a v2 leaf.
const LeafDomainV7_2 = "certen:batchleaf:v2"

// AccountProofV7_2 mirrors CertenAccountV7_2.ADIGovernanceProof. Field ORDER matters: abi encoding is positional.
type AccountProofV7_2 struct {
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
	AuthorityPage       uint64
}

// CertenAccountV7_2 binds a deployed CertenAccountV7_2.
type CertenAccountV7_2 struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

func NewCertenAccountV7_2(address common.Address, backend bind.ContractBackend) (*CertenAccountV7_2, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV7_2ABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAccountV7_2 ABI: %w", err)
	}
	return &CertenAccountV7_2{address: address, abi: parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend)}, nil
}

func (a *CertenAccountV7_2) Address() common.Address { return a.address }

func (a *CertenAccountV7_2) ExecuteGovernanceProofDirect(opts *bind.TransactOpts, target common.Address, value *big.Int,
	data []byte, proof AccountProofV7_2) (*types.Transaction, error) {
	return a.contract.Transact(opts, "executeGovernanceProofDirect", target, value, data, proof)
}

func (a *CertenAccountV7_2) BatchExecuteGovernanceProofDirect(opts *bind.TransactOpts, targets []common.Address,
	values []*big.Int, datas [][]byte, proof AccountProofV7_2) (*types.Transaction, error) {
	return a.contract.Transact(opts, "batchExecuteGovernanceProofDirect", targets, values, datas, proof)
}

func (a *CertenAccountV7_2) call1(opts *bind.CallOpts, method string, args ...interface{}) (interface{}, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, method, args...); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s returned no value", method)
	}
	return out[0], nil
}

func (a *CertenAccountV7_2) ComputeLeaf(opts *bind.CallOpts, executionCommitment, operationID [32]byte,
	authorityPage uint64) ([32]byte, error) {
	v, err := a.call1(opts, "computeLeaf", executionCommitment, operationID, authorityPage)
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(v, new([32]byte)).(*[32]byte), nil
}

func (a *CertenAccountV7_2) IsLeafConsumed(opts *bind.CallOpts, leaf [32]byte) (bool, error) {
	v, err := a.call1(opts, "isLeafConsumed", leaf)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAccountV7_2) IsKeylessOwner(opts *bind.CallOpts) (bool, error) {
	v, err := a.call1(opts, "isKeylessOwner")
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAccountV7_2) ADIURLHash(opts *bind.CallOpts) ([32]byte, error) {
	v, err := a.call1(opts, "adiURLHash")
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(v, new([32]byte)).(*[32]byte), nil
}

// LeafDomain is the account's LEAF_DOMAIN: the leaf generation it verifies. A constant of its code.
func (a *CertenAccountV7_2) LeafDomain(opts *bind.CallOpts) (string, error) {
	v, err := a.call1(opts, "LEAF_DOMAIN")
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("LEAF_DOMAIN returned %T", v)
	}
	return s, nil
}

// AnchorContract is the anchor the account settles against.
func (a *CertenAccountV7_2) AnchorContract(opts *bind.CallOpts) (common.Address, error) {
	v, err := a.call1(opts, "anchorContract")
	if err != nil {
		return common.Address{}, err
	}
	return *abi.ConvertType(v, new(common.Address)).(*common.Address), nil
}
