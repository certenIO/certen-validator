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

// CertenAccountV7_3ABI is the surface of CertenAccountV7_3 - the account CertenAccountFactoryV11 creates, settling
// against CertenAnchorV8_2 - extracted from the Foundry artifact out/CertenAccountV7_3.sol/CertenAccountV7_3.json
// (certen-contracts feat/rb5-f57-deadline-leaf). TestCertenAccountV7_3ABI pins every signature the batch path uses.
//
// What differs from CertenAccountV7_2 (RB5-F57): the leaf (certen:batchleaf:v4) binds the member's execution window,
// so computeLeaf takes notBefore and notAfter, and the proof ends in uint64 notBefore, uint64 notAfter after the
// authority book and page. The account refuses an execution outside the window the leaf binds: LeafNotYetValid before
// notBefore, LeafExpired after notAfter.
const CertenAccountV7_3ABI = `[
  {"type":"function","name":"executeGovernanceProofDirect","inputs":[{"name":"target","type":"address","internalType":"address"},{"name":"value","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"},{"name":"proof","type":"tuple","internalType":"struct CertenAccountV7_3.ADIGovernanceProof","components":[{"name":"adiURL","type":"string","internalType":"string"},{"name":"anchorId","type":"bytes32","internalType":"bytes32"},{"name":"merkleProof","type":"bytes32[]","internalType":"bytes32[]"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"keyBookProof","type":"bytes","internalType":"bytes"},{"name":"roleProof","type":"bytes","internalType":"bytes"},{"name":"thresholdProof","type":"bytes","internalType":"bytes"},{"name":"timestamp","type":"uint256","internalType":"uint256"},{"name":"expiresAt","type":"uint256","internalType":"uint256"},{"name":"validatorSignatures","type":"bytes","internalType":"bytes"},{"name":"nonce","type":"uint256","internalType":"uint256"},{"name":"authorityBook","type":"bytes32","internalType":"bytes32"},{"name":"authorityPage","type":"uint64","internalType":"uint64"},{"name":"notBefore","type":"uint64","internalType":"uint64"},{"name":"notAfter","type":"uint64","internalType":"uint64"}]}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"batchExecuteGovernanceProofDirect","inputs":[{"name":"targets","type":"address[]","internalType":"address[]"},{"name":"values","type":"uint256[]","internalType":"uint256[]"},{"name":"datas","type":"bytes[]","internalType":"bytes[]"},{"name":"proof","type":"tuple","internalType":"struct CertenAccountV7_3.ADIGovernanceProof","components":[{"name":"adiURL","type":"string","internalType":"string"},{"name":"anchorId","type":"bytes32","internalType":"bytes32"},{"name":"merkleProof","type":"bytes32[]","internalType":"bytes32[]"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"keyBookProof","type":"bytes","internalType":"bytes"},{"name":"roleProof","type":"bytes","internalType":"bytes"},{"name":"thresholdProof","type":"bytes","internalType":"bytes"},{"name":"timestamp","type":"uint256","internalType":"uint256"},{"name":"expiresAt","type":"uint256","internalType":"uint256"},{"name":"validatorSignatures","type":"bytes","internalType":"bytes"},{"name":"nonce","type":"uint256","internalType":"uint256"},{"name":"authorityBook","type":"bytes32","internalType":"bytes32"},{"name":"authorityPage","type":"uint64","internalType":"uint64"},{"name":"notBefore","type":"uint64","internalType":"uint64"},{"name":"notAfter","type":"uint64","internalType":"uint64"}]}],"outputs":[],"stateMutability":"nonpayable"},
  {"type":"function","name":"computeLeaf","inputs":[{"name":"executionCommitment","type":"bytes32","internalType":"bytes32"},{"name":"operationID","type":"bytes32","internalType":"bytes32"},{"name":"authorityBook","type":"bytes32","internalType":"bytes32"},{"name":"authorityPage","type":"uint64","internalType":"uint64"},{"name":"notBefore","type":"uint64","internalType":"uint64"},{"name":"notAfter","type":"uint64","internalType":"uint64"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"computeSingleCommitment","inputs":[{"name":"target","type":"address","internalType":"address"},{"name":"value","type":"uint256","internalType":"uint256"},{"name":"data","type":"bytes","internalType":"bytes"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"computeBatchCommitment","inputs":[{"name":"targets","type":"address[]","internalType":"address[]"},{"name":"values","type":"uint256[]","internalType":"uint256[]"},{"name":"datas","type":"bytes[]","internalType":"bytes[]"}],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"isLeafConsumed","inputs":[{"name":"leaf","type":"bytes32","internalType":"bytes32"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"adiURLHash","inputs":[],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},
  {"type":"function","name":"LEAF_DOMAIN","inputs":[],"outputs":[{"name":"","type":"string","internalType":"string"}],"stateMutability":"view"},
  {"type":"function","name":"authorityLevelOfPage","inputs":[{"name":"book","type":"bytes32","internalType":"bytes32"},{"name":"page","type":"uint64","internalType":"uint64"}],"outputs":[{"name":"","type":"uint8","internalType":"enum CertenAccountV7_3.AuthorityLevel"}],"stateMutability":"view"},
  {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address","internalType":"contract CertenAnchorV8_2"}],"stateMutability":"view"},
  {"type":"function","name":"governingBook","inputs":[],"outputs":[{"name":"","type":"string","internalType":"string"}],"stateMutability":"view"},
  {"type":"function","name":"governingBookHash","inputs":[],"outputs":[{"name":"","type":"bytes32","internalType":"bytes32"}],"stateMutability":"view"},
  {"type":"error","name":"LeafExpired","inputs":[{"name":"notAfter","type":"uint64","internalType":"uint64"},{"name":"blockTimestamp","type":"uint256","internalType":"uint256"}]},
  {"type":"error","name":"LeafNotYetValid","inputs":[{"name":"notBefore","type":"uint64","internalType":"uint64"},{"name":"blockTimestamp","type":"uint256","internalType":"uint256"}]}
]`

// LeafDomainV7_3 is CertenAccountV7_3.LEAF_DOMAIN - what an account must report to take a v4 leaf.
const LeafDomainV7_3 = "certen:batchleaf:v4"

// AccountProofV7_3 mirrors CertenAccountV7_3.ADIGovernanceProof: CertenAccountV7_2's proof followed by the member's
// window. Field ORDER matters: abi encoding is positional.
type AccountProofV7_3 struct {
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
	AuthorityBook       [32]byte
	AuthorityPage       uint64
	NotBefore           uint64
	NotAfter            uint64
}

// AccountProofV7_3Of is p with the member's window: the proof a CertenAccountV7_3 takes for the leaf p names.
func AccountProofV7_3Of(p AccountProofV7_2, notBefore, notAfter uint64) AccountProofV7_3 {
	return AccountProofV7_3{AdiURL: p.AdiURL, AnchorId: p.AnchorId, MerkleProof: p.MerkleProof, OperationID: p.OperationID,
		KeyBookProof: p.KeyBookProof, RoleProof: p.RoleProof, ThresholdProof: p.ThresholdProof, Timestamp: p.Timestamp,
		ExpiresAt: p.ExpiresAt, ValidatorSignatures: p.ValidatorSignatures, Nonce: p.Nonce, AuthorityBook: p.AuthorityBook,
		AuthorityPage: p.AuthorityPage, NotBefore: notBefore, NotAfter: notAfter}
}

// V7_2Fields is the proof without its window: the fields it shares with CertenAccountV7_2's.
func (p AccountProofV7_3) V7_2Fields() AccountProofV7_2 {
	return AccountProofV7_2{AdiURL: p.AdiURL, AnchorId: p.AnchorId, MerkleProof: p.MerkleProof, OperationID: p.OperationID,
		KeyBookProof: p.KeyBookProof, RoleProof: p.RoleProof, ThresholdProof: p.ThresholdProof, Timestamp: p.Timestamp,
		ExpiresAt: p.ExpiresAt, ValidatorSignatures: p.ValidatorSignatures, Nonce: p.Nonce, AuthorityBook: p.AuthorityBook,
		AuthorityPage: p.AuthorityPage}
}

// CertenAccountV7_3 binds a deployed CertenAccountV7_3.
type CertenAccountV7_3 struct {
	address  common.Address
	abi      abi.ABI
	contract *bind.BoundContract
}

func NewCertenAccountV7_3(address common.Address, backend bind.ContractBackend) (*CertenAccountV7_3, error) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV7_3ABI))
	if err != nil {
		return nil, fmt.Errorf("parse CertenAccountV7_3 ABI: %w", err)
	}
	return &CertenAccountV7_3{address: address, abi: parsed,
		contract: bind.NewBoundContract(address, parsed, backend, backend, backend)}, nil
}

func (a *CertenAccountV7_3) Address() common.Address { return a.address }

func (a *CertenAccountV7_3) ExecuteGovernanceProofDirect(opts *bind.TransactOpts, target common.Address, value *big.Int,
	data []byte, proof AccountProofV7_3) (*types.Transaction, error) {
	return a.contract.Transact(opts, "executeGovernanceProofDirect", target, value, data, proof)
}

func (a *CertenAccountV7_3) BatchExecuteGovernanceProofDirect(opts *bind.TransactOpts, targets []common.Address,
	values []*big.Int, datas [][]byte, proof AccountProofV7_3) (*types.Transaction, error) {
	return a.contract.Transact(opts, "batchExecuteGovernanceProofDirect", targets, values, datas, proof)
}

func (a *CertenAccountV7_3) call1(opts *bind.CallOpts, method string, args ...interface{}) (interface{}, error) {
	var out []interface{}
	if err := a.contract.Call(opts, &out, method, args...); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s returned no value", method)
	}
	return out[0], nil
}

// ComputeLeaf is the account's own v4 leaf for the commitment, operation, authority and window.
func (a *CertenAccountV7_3) ComputeLeaf(opts *bind.CallOpts, executionCommitment, operationID, authorityBook [32]byte,
	authorityPage, notBefore, notAfter uint64) ([32]byte, error) {
	v, err := a.call1(opts, "computeLeaf", executionCommitment, operationID, authorityBook, authorityPage, notBefore, notAfter)
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(v, new([32]byte)).(*[32]byte), nil
}

func (a *CertenAccountV7_3) IsLeafConsumed(opts *bind.CallOpts, leaf [32]byte) (bool, error) {
	v, err := a.call1(opts, "isLeafConsumed", leaf)
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAccountV7_3) IsKeylessOwner(opts *bind.CallOpts) (bool, error) {
	v, err := a.call1(opts, "isKeylessOwner")
	if err != nil {
		return false, err
	}
	return *abi.ConvertType(v, new(bool)).(*bool), nil
}

func (a *CertenAccountV7_3) ADIURLHash(opts *bind.CallOpts) ([32]byte, error) {
	v, err := a.call1(opts, "adiURLHash")
	if err != nil {
		return [32]byte{}, err
	}
	return *abi.ConvertType(v, new([32]byte)).(*[32]byte), nil
}

// LeafDomain is the account's LEAF_DOMAIN: the leaf generation it verifies. A constant of its code.
func (a *CertenAccountV7_3) LeafDomain(opts *bind.CallOpts) (string, error) {
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

// AuthorityLevelOfPage is the account's authority level for a page of a key book (0 NONE .. 4 ROOT).
func (a *CertenAccountV7_3) AuthorityLevelOfPage(opts *bind.CallOpts, book [32]byte, page uint64) (uint8, error) {
	v, err := a.call1(opts, "authorityLevelOfPage", book, page)
	if err != nil {
		return 0, err
	}
	return *abi.ConvertType(v, new(uint8)).(*uint8), nil
}
