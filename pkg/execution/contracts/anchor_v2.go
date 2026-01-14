// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// AnchorProof is an auto generated low-level Go binding around an user-defined struct.
type AnchorProof struct {
	TransactionHash     [32]byte
	MerkleRoot          [32]byte
	ProofHashes         [][32]byte
	LeafHash            [32]byte
	ValidatorSignatures []byte
	Timestamp           *big.Int
}

// CertenAnchorV2MetaData contains all meta data concerning the CertenAnchorV2 contract.
var CertenAnchorV2MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"addBLSValidator\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\"},{\"name\":\"votingPower\",\"type\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeBLSValidator\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateBLSValidatorPower\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\"},{\"name\":\"newVotingPower\",\"type\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setBLSThreshold\",\"inputs\":[{\"name\":\"newThreshold\",\"type\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"verifyCertenProof\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"tuple\",\"components\":[{\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"name\":\"proofHashes\",\"type\":\"bytes32[]\"},{\"name\":\"leafHash\",\"type\":\"bytes32\"},{\"name\":\"validatorSignatures\",\"type\":\"bytes\"},{\"name\":\"timestamp\",\"type\":\"uint256\"}]}],\"outputs\":[{\"type\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"anchors\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"outputs\":[{\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"verified\",\"type\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsValidators\",\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"outputs\":[{\"name\":\"votingPower\",\"type\":\"uint256\"},{\"name\":\"active\",\"type\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsThreshold\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\"}]",
}

// CertenAnchorV2ABI is the input ABI used to generate the binding from.
// Deprecated: Use CertenAnchorV2MetaData.ABI instead.
var CertenAnchorV2ABI = CertenAnchorV2MetaData.ABI

// CertenAnchorV2 is an auto generated Go binding around an Ethereum contract.
type CertenAnchorV2 struct {
	CertenAnchorV2Caller     // Read-only binding to the contract
	CertenAnchorV2Transactor // Write-only binding to the contract
	CertenAnchorV2Filterer   // Log filterer for contract events
}

// CertenAnchorV2Caller is an auto generated read-only Go binding around an Ethereum contract.
type CertenAnchorV2Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV2Transactor is an auto generated write-only Go binding around an Ethereum contract.
type CertenAnchorV2Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV2Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type CertenAnchorV2Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV2Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type CertenAnchorV2Session struct {
	Contract     *CertenAnchorV2   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// CertenAnchorV2CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type CertenAnchorV2CallerSession struct {
	Contract *CertenAnchorV2Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// CertenAnchorV2TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type CertenAnchorV2TransactorSession struct {
	Contract     *CertenAnchorV2Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// CertenAnchorV2Raw is an auto generated low-level Go binding around an Ethereum contract.
type CertenAnchorV2Raw struct {
	Contract *CertenAnchorV2 // Generic contract binding to access the raw methods on
}

// CertenAnchorV2CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type CertenAnchorV2CallerRaw struct {
	Contract *CertenAnchorV2Caller // Generic read-only contract binding to access the raw methods on
}

// CertenAnchorV2TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type CertenAnchorV2TransactorRaw struct {
	Contract *CertenAnchorV2Transactor // Generic write-only contract binding to access the raw methods on
}

// NewCertenAnchorV2 creates a new instance of CertenAnchorV2, bound to a specific deployed contract.
func NewCertenAnchorV2(address common.Address, backend bind.ContractBackend) (*CertenAnchorV2, error) {
	contract, err := bindCertenAnchorV2(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV2{CertenAnchorV2Caller: CertenAnchorV2Caller{contract: contract}, CertenAnchorV2Transactor: CertenAnchorV2Transactor{contract: contract}, CertenAnchorV2Filterer: CertenAnchorV2Filterer{contract: contract}}, nil
}

// NewCertenAnchorV2Caller creates a new read-only instance of CertenAnchorV2, bound to a specific deployed contract.
func NewCertenAnchorV2Caller(address common.Address, caller bind.ContractCaller) (*CertenAnchorV2Caller, error) {
	contract, err := bindCertenAnchorV2(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV2Caller{contract: contract}, nil
}

// NewCertenAnchorV2Transactor creates a new write-only instance of CertenAnchorV2, bound to a specific deployed contract.
func NewCertenAnchorV2Transactor(address common.Address, transactor bind.ContractTransactor) (*CertenAnchorV2Transactor, error) {
	contract, err := bindCertenAnchorV2(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV2Transactor{contract: contract}, nil
}

// NewCertenAnchorV2Filterer creates a new log filterer instance of CertenAnchorV2, bound to a specific deployed contract.
func NewCertenAnchorV2Filterer(address common.Address, filterer bind.ContractFilterer) (*CertenAnchorV2Filterer, error) {
	contract, err := bindCertenAnchorV2(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV2Filterer{contract: contract}, nil
}

// bindCertenAnchorV2 binds a generic wrapper to an already deployed contract.
func bindCertenAnchorV2(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := CertenAnchorV2MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV2 *CertenAnchorV2Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV2.Contract.CertenAnchorV2Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV2 *CertenAnchorV2Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.CertenAnchorV2Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV2 *CertenAnchorV2Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.CertenAnchorV2Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV2 *CertenAnchorV2CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV2.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV2 *CertenAnchorV2TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV2 *CertenAnchorV2TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.contract.Transact(opts, method, params...)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 merkleRoot, uint256 timestamp, bool verified)
func (_CertenAnchorV2 *CertenAnchorV2Caller) Anchors(opts *bind.CallOpts, arg0 [32]byte) (struct {
	MerkleRoot [32]byte
	Timestamp  *big.Int
	Verified   bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV2.contract.Call(opts, &out, "anchors", arg0)

	outstruct := new(struct {
		MerkleRoot [32]byte
		Timestamp  *big.Int
		Verified   bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.MerkleRoot = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.Timestamp = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.Verified = *abi.ConvertType(out[2], new(bool)).(*bool)

	return *outstruct, err

}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 merkleRoot, uint256 timestamp, bool verified)
func (_CertenAnchorV2 *CertenAnchorV2Session) Anchors(arg0 [32]byte) (struct {
	MerkleRoot [32]byte
	Timestamp  *big.Int
	Verified   bool
}, error) {
	return _CertenAnchorV2.Contract.Anchors(&_CertenAnchorV2.CallOpts, arg0)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 merkleRoot, uint256 timestamp, bool verified)
func (_CertenAnchorV2 *CertenAnchorV2CallerSession) Anchors(arg0 [32]byte) (struct {
	MerkleRoot [32]byte
	Timestamp  *big.Int
	Verified   bool
}, error) {
	return _CertenAnchorV2.Contract.Anchors(&_CertenAnchorV2.CallOpts, arg0)
}

// BlsThreshold is a free data retrieval call binding the contract method 0x2a8921bc.
//
// Solidity: function blsThreshold() view returns(uint256)
func (_CertenAnchorV2 *CertenAnchorV2Caller) BlsThreshold(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV2.contract.Call(opts, &out, "blsThreshold")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlsThreshold is a free data retrieval call binding the contract method 0x2a8921bc.
//
// Solidity: function blsThreshold() view returns(uint256)
func (_CertenAnchorV2 *CertenAnchorV2Session) BlsThreshold() (*big.Int, error) {
	return _CertenAnchorV2.Contract.BlsThreshold(&_CertenAnchorV2.CallOpts)
}

// BlsThreshold is a free data retrieval call binding the contract method 0x2a8921bc.
//
// Solidity: function blsThreshold() view returns(uint256)
func (_CertenAnchorV2 *CertenAnchorV2CallerSession) BlsThreshold() (*big.Int, error) {
	return _CertenAnchorV2.Contract.BlsThreshold(&_CertenAnchorV2.CallOpts)
}

// BlsValidators is a free data retrieval call binding the contract method 0x8e1c6447.
//
// Solidity: function blsValidators(address ) view returns(uint256 votingPower, bool active)
func (_CertenAnchorV2 *CertenAnchorV2Caller) BlsValidators(opts *bind.CallOpts, arg0 common.Address) (struct {
	VotingPower *big.Int
	Active      bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV2.contract.Call(opts, &out, "blsValidators", arg0)

	outstruct := new(struct {
		VotingPower *big.Int
		Active      bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.VotingPower = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Active = *abi.ConvertType(out[1], new(bool)).(*bool)

	return *outstruct, err

}

// BlsValidators is a free data retrieval call binding the contract method 0x8e1c6447.
//
// Solidity: function blsValidators(address ) view returns(uint256 votingPower, bool active)
func (_CertenAnchorV2 *CertenAnchorV2Session) BlsValidators(arg0 common.Address) (struct {
	VotingPower *big.Int
	Active      bool
}, error) {
	return _CertenAnchorV2.Contract.BlsValidators(&_CertenAnchorV2.CallOpts, arg0)
}

// BlsValidators is a free data retrieval call binding the contract method 0x8e1c6447.
//
// Solidity: function blsValidators(address ) view returns(uint256 votingPower, bool active)
func (_CertenAnchorV2 *CertenAnchorV2CallerSession) BlsValidators(arg0 common.Address) (struct {
	VotingPower *big.Int
	Active      bool
}, error) {
	return _CertenAnchorV2.Contract.BlsValidators(&_CertenAnchorV2.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV2 *CertenAnchorV2Caller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV2.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV2 *CertenAnchorV2Session) Owner() (common.Address, error) {
	return _CertenAnchorV2.Contract.Owner(&_CertenAnchorV2.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV2 *CertenAnchorV2CallerSession) Owner() (common.Address, error) {
	return _CertenAnchorV2.Contract.Owner(&_CertenAnchorV2.CallOpts)
}

// VerifyCertenProof is a free data retrieval call binding the contract method 0x7491dc1b.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,bytes,uint256) proof) view returns(bool)
func (_CertenAnchorV2 *CertenAnchorV2Caller) VerifyCertenProof(opts *bind.CallOpts, anchorId [32]byte, proof AnchorProof) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV2.contract.Call(opts, &out, "verifyCertenProof", anchorId, proof)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyCertenProof is a free data retrieval call binding the contract method 0x7491dc1b.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,bytes,uint256) proof) view returns(bool)
func (_CertenAnchorV2 *CertenAnchorV2Session) VerifyCertenProof(anchorId [32]byte, proof AnchorProof) (bool, error) {
	return _CertenAnchorV2.Contract.VerifyCertenProof(&_CertenAnchorV2.CallOpts, anchorId, proof)
}

// VerifyCertenProof is a free data retrieval call binding the contract method 0x7491dc1b.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,bytes,uint256) proof) view returns(bool)
func (_CertenAnchorV2 *CertenAnchorV2CallerSession) VerifyCertenProof(anchorId [32]byte, proof AnchorProof) (bool, error) {
	return _CertenAnchorV2.Contract.VerifyCertenProof(&_CertenAnchorV2.CallOpts, anchorId, proof)
}

// AddBLSValidator is a paid mutator transaction binding the contract method 0x91105949.
//
// Solidity: function addBLSValidator(address validator, uint256 votingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2Transactor) AddBLSValidator(opts *bind.TransactOpts, validator common.Address, votingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.contract.Transact(opts, "addBLSValidator", validator, votingPower)
}

// AddBLSValidator is a paid mutator transaction binding the contract method 0x91105949.
//
// Solidity: function addBLSValidator(address validator, uint256 votingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2Session) AddBLSValidator(validator common.Address, votingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.AddBLSValidator(&_CertenAnchorV2.TransactOpts, validator, votingPower)
}

// AddBLSValidator is a paid mutator transaction binding the contract method 0x91105949.
//
// Solidity: function addBLSValidator(address validator, uint256 votingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2TransactorSession) AddBLSValidator(validator common.Address, votingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.AddBLSValidator(&_CertenAnchorV2.TransactOpts, validator, votingPower)
}

// RemoveBLSValidator is a paid mutator transaction binding the contract method 0xb45d6ba5.
//
// Solidity: function removeBLSValidator(address validator) returns()
func (_CertenAnchorV2 *CertenAnchorV2Transactor) RemoveBLSValidator(opts *bind.TransactOpts, validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV2.contract.Transact(opts, "removeBLSValidator", validator)
}

// RemoveBLSValidator is a paid mutator transaction binding the contract method 0xb45d6ba5.
//
// Solidity: function removeBLSValidator(address validator) returns()
func (_CertenAnchorV2 *CertenAnchorV2Session) RemoveBLSValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.RemoveBLSValidator(&_CertenAnchorV2.TransactOpts, validator)
}

// RemoveBLSValidator is a paid mutator transaction binding the contract method 0xb45d6ba5.
//
// Solidity: function removeBLSValidator(address validator) returns()
func (_CertenAnchorV2 *CertenAnchorV2TransactorSession) RemoveBLSValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.RemoveBLSValidator(&_CertenAnchorV2.TransactOpts, validator)
}

// SetBLSThreshold is a paid mutator transaction binding the contract method 0x2849e2eb.
//
// Solidity: function setBLSThreshold(uint256 newThreshold) returns()
func (_CertenAnchorV2 *CertenAnchorV2Transactor) SetBLSThreshold(opts *bind.TransactOpts, newThreshold *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.contract.Transact(opts, "setBLSThreshold", newThreshold)
}

// SetBLSThreshold is a paid mutator transaction binding the contract method 0x2849e2eb.
//
// Solidity: function setBLSThreshold(uint256 newThreshold) returns()
func (_CertenAnchorV2 *CertenAnchorV2Session) SetBLSThreshold(newThreshold *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.SetBLSThreshold(&_CertenAnchorV2.TransactOpts, newThreshold)
}

// SetBLSThreshold is a paid mutator transaction binding the contract method 0x2849e2eb.
//
// Solidity: function setBLSThreshold(uint256 newThreshold) returns()
func (_CertenAnchorV2 *CertenAnchorV2TransactorSession) SetBLSThreshold(newThreshold *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.SetBLSThreshold(&_CertenAnchorV2.TransactOpts, newThreshold)
}

// UpdateBLSValidatorPower is a paid mutator transaction binding the contract method 0x7c08e8b2.
//
// Solidity: function updateBLSValidatorPower(address validator, uint256 newVotingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2Transactor) UpdateBLSValidatorPower(opts *bind.TransactOpts, validator common.Address, newVotingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.contract.Transact(opts, "updateBLSValidatorPower", validator, newVotingPower)
}

// UpdateBLSValidatorPower is a paid mutator transaction binding the contract method 0x7c08e8b2.
//
// Solidity: function updateBLSValidatorPower(address validator, uint256 newVotingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2Session) UpdateBLSValidatorPower(validator common.Address, newVotingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.UpdateBLSValidatorPower(&_CertenAnchorV2.TransactOpts, validator, newVotingPower)
}

// UpdateBLSValidatorPower is a paid mutator transaction binding the contract method 0x7c08e8b2.
//
// Solidity: function updateBLSValidatorPower(address validator, uint256 newVotingPower) returns()
func (_CertenAnchorV2 *CertenAnchorV2TransactorSession) UpdateBLSValidatorPower(validator common.Address, newVotingPower *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV2.Contract.UpdateBLSValidatorPower(&_CertenAnchorV2.TransactOpts, validator, newVotingPower)
}
