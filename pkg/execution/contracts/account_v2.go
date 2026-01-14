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

// AccountProof is an auto generated low-level Go binding around an user-defined struct.
type AccountProof struct {
	AdiURL              string
	AnchorId            [32]byte
	MerkleProof         [][32]byte
	KeyBookProof        []byte
	RoleProof           []byte
	ThresholdProof      []byte
	Timestamp           *big.Int
	ExpiresAt           *big.Int
	ValidatorSignatures []byte
	Nonce               *big.Int
	RequiredLevel       uint8
}

// CertenAccountV2MetaData contains all meta data concerning the CertenAccountV2 contract.
var CertenAccountV2MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"entryPointAddr\",\"type\":\"address\"},{\"name\":\"_owner\",\"type\":\"address\"},{\"name\":\"_adiURL\",\"type\":\"string\"},{\"name\":\"_anchorContractV2\",\"type\":\"address\"}]},{\"type\":\"function\",\"name\":\"executeWithGovernanceProof\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\"},{\"name\":\"proof\",\"type\":\"tuple\",\"components\":[{\"name\":\"adiURL\",\"type\":\"string\"},{\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"name\":\"merkleProof\",\"type\":\"bytes32[]\"},{\"name\":\"keyBookProof\",\"type\":\"bytes\"},{\"name\":\"roleProof\",\"type\":\"bytes\"},{\"name\":\"thresholdProof\",\"type\":\"bytes\"},{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"expiresAt\",\"type\":\"uint256\"},{\"name\":\"validatorSignatures\",\"type\":\"bytes\"},{\"name\":\"nonce\",\"type\":\"uint256\"},{\"name\":\"requiredLevel\",\"type\":\"uint8\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeGovernanceProofDirect\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\"},{\"name\":\"proof\",\"type\":\"tuple\",\"components\":[{\"name\":\"adiURL\",\"type\":\"string\"},{\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"name\":\"merkleProof\",\"type\":\"bytes32[]\"},{\"name\":\"keyBookProof\",\"type\":\"bytes\"},{\"name\":\"roleProof\",\"type\":\"bytes\"},{\"name\":\"thresholdProof\",\"type\":\"bytes\"},{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"expiresAt\",\"type\":\"uint256\"},{\"name\":\"validatorSignatures\",\"type\":\"bytes\"},{\"name\":\"nonce\",\"type\":\"uint256\"},{\"name\":\"requiredLevel\",\"type\":\"uint8\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"batchExecuteWithGovernanceProof\",\"inputs\":[{\"name\":\"targets\",\"type\":\"address[]\"},{\"name\":\"values\",\"type\":\"uint256[]\"},{\"name\":\"datas\",\"type\":\"bytes[]\"},{\"name\":\"proof\",\"type\":\"tuple\",\"components\":[{\"name\":\"adiURL\",\"type\":\"string\"},{\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"name\":\"merkleProof\",\"type\":\"bytes32[]\"},{\"name\":\"keyBookProof\",\"type\":\"bytes\"},{\"name\":\"roleProof\",\"type\":\"bytes\"},{\"name\":\"thresholdProof\",\"type\":\"bytes\"},{\"name\":\"timestamp\",\"type\":\"uint256\"},{\"name\":\"expiresAt\",\"type\":\"uint256\"},{\"name\":\"validatorSignatures\",\"type\":\"bytes\"},{\"name\":\"nonce\",\"type\":\"uint256\"},{\"name\":\"requiredLevel\",\"type\":\"uint8\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getAdiURL\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"nonce\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\"}]",
}

// CertenAccountV2ABI is the input ABI used to generate the binding from.
// Deprecated: Use CertenAccountV2MetaData.ABI instead.
var CertenAccountV2ABI = CertenAccountV2MetaData.ABI

// CertenAccountV2 is an auto generated Go binding around an Ethereum contract.
type CertenAccountV2 struct {
	CertenAccountV2Caller     // Read-only binding to the contract
	CertenAccountV2Transactor // Write-only binding to the contract
	CertenAccountV2Filterer   // Log filterer for contract events
}

// CertenAccountV2Caller is an auto generated read-only Go binding around an Ethereum contract.
type CertenAccountV2Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAccountV2Transactor is an auto generated write-only Go binding around an Ethereum contract.
type CertenAccountV2Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAccountV2Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type CertenAccountV2Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAccountV2Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type CertenAccountV2Session struct {
	Contract     *CertenAccountV2  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// CertenAccountV2CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type CertenAccountV2CallerSession struct {
	Contract *CertenAccountV2Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// CertenAccountV2TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type CertenAccountV2TransactorSession struct {
	Contract     *CertenAccountV2Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// CertenAccountV2Raw is an auto generated low-level Go binding around an Ethereum contract.
type CertenAccountV2Raw struct {
	Contract *CertenAccountV2 // Generic contract binding to access the raw methods on
}

// CertenAccountV2CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type CertenAccountV2CallerRaw struct {
	Contract *CertenAccountV2Caller // Generic read-only contract binding to access the raw methods on
}

// CertenAccountV2TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type CertenAccountV2TransactorRaw struct {
	Contract *CertenAccountV2Transactor // Generic write-only contract binding to access the raw methods on
}

// NewCertenAccountV2 creates a new instance of CertenAccountV2, bound to a specific deployed contract.
func NewCertenAccountV2(address common.Address, backend bind.ContractBackend) (*CertenAccountV2, error) {
	contract, err := bindCertenAccountV2(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAccountV2{CertenAccountV2Caller: CertenAccountV2Caller{contract: contract}, CertenAccountV2Transactor: CertenAccountV2Transactor{contract: contract}, CertenAccountV2Filterer: CertenAccountV2Filterer{contract: contract}}, nil
}

// NewCertenAccountV2Caller creates a new read-only instance of CertenAccountV2, bound to a specific deployed contract.
func NewCertenAccountV2Caller(address common.Address, caller bind.ContractCaller) (*CertenAccountV2Caller, error) {
	contract, err := bindCertenAccountV2(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAccountV2Caller{contract: contract}, nil
}

// NewCertenAccountV2Transactor creates a new write-only instance of CertenAccountV2, bound to a specific deployed contract.
func NewCertenAccountV2Transactor(address common.Address, transactor bind.ContractTransactor) (*CertenAccountV2Transactor, error) {
	contract, err := bindCertenAccountV2(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAccountV2Transactor{contract: contract}, nil
}

// NewCertenAccountV2Filterer creates a new log filterer instance of CertenAccountV2, bound to a specific deployed contract.
func NewCertenAccountV2Filterer(address common.Address, filterer bind.ContractFilterer) (*CertenAccountV2Filterer, error) {
	contract, err := bindCertenAccountV2(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &CertenAccountV2Filterer{contract: contract}, nil
}

// bindCertenAccountV2 binds a generic wrapper to an already deployed contract.
func bindCertenAccountV2(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := CertenAccountV2MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAccountV2 *CertenAccountV2Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAccountV2.Contract.CertenAccountV2Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAccountV2 *CertenAccountV2Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.CertenAccountV2Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAccountV2 *CertenAccountV2Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.CertenAccountV2Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAccountV2 *CertenAccountV2CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAccountV2.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAccountV2 *CertenAccountV2TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAccountV2 *CertenAccountV2TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.contract.Transact(opts, method, params...)
}

// GetAdiURL is a free data retrieval call binding the contract method 0x05f3a74b.
//
// Solidity: function getAdiURL() view returns(string)
func (_CertenAccountV2 *CertenAccountV2Caller) GetAdiURL(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _CertenAccountV2.contract.Call(opts, &out, "getAdiURL")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// GetAdiURL is a free data retrieval call binding the contract method 0x05f3a74b.
//
// Solidity: function getAdiURL() view returns(string)
func (_CertenAccountV2 *CertenAccountV2Session) GetAdiURL() (string, error) {
	return _CertenAccountV2.Contract.GetAdiURL(&_CertenAccountV2.CallOpts)
}

// GetAdiURL is a free data retrieval call binding the contract method 0x05f3a74b.
//
// Solidity: function getAdiURL() view returns(string)
func (_CertenAccountV2 *CertenAccountV2CallerSession) GetAdiURL() (string, error) {
	return _CertenAccountV2.Contract.GetAdiURL(&_CertenAccountV2.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CertenAccountV2 *CertenAccountV2Caller) Nonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAccountV2.contract.Call(opts, &out, "nonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CertenAccountV2 *CertenAccountV2Session) Nonce() (*big.Int, error) {
	return _CertenAccountV2.Contract.Nonce(&_CertenAccountV2.CallOpts)
}

// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
//
// Solidity: function nonce() view returns(uint256)
func (_CertenAccountV2 *CertenAccountV2CallerSession) Nonce() (*big.Int, error) {
	return _CertenAccountV2.Contract.Nonce(&_CertenAccountV2.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAccountV2 *CertenAccountV2Caller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAccountV2.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAccountV2 *CertenAccountV2Session) Owner() (common.Address, error) {
	return _CertenAccountV2.Contract.Owner(&_CertenAccountV2.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAccountV2 *CertenAccountV2CallerSession) Owner() (common.Address, error) {
	return _CertenAccountV2.Contract.Owner(&_CertenAccountV2.CallOpts)
}

// BatchExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0x4601b159.
//
// Solidity: function batchExecuteWithGovernanceProof(address[] targets, uint256[] values, bytes[] datas, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2Transactor) BatchExecuteWithGovernanceProof(opts *bind.TransactOpts, targets []common.Address, values []*big.Int, datas [][]byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.contract.Transact(opts, "batchExecuteWithGovernanceProof", targets, values, datas, proof)
}

// BatchExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0x4601b159.
//
// Solidity: function batchExecuteWithGovernanceProof(address[] targets, uint256[] values, bytes[] datas, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2Session) BatchExecuteWithGovernanceProof(targets []common.Address, values []*big.Int, datas [][]byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.BatchExecuteWithGovernanceProof(&_CertenAccountV2.TransactOpts, targets, values, datas, proof)
}

// BatchExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0x4601b159.
//
// Solidity: function batchExecuteWithGovernanceProof(address[] targets, uint256[] values, bytes[] datas, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2TransactorSession) BatchExecuteWithGovernanceProof(targets []common.Address, values []*big.Int, datas [][]byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.BatchExecuteWithGovernanceProof(&_CertenAccountV2.TransactOpts, targets, values, datas, proof)
}

// ExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0xc3bdecfb.
//
// Solidity: function executeWithGovernanceProof(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2Transactor) ExecuteWithGovernanceProof(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.contract.Transact(opts, "executeWithGovernanceProof", target, value, data, proof)
}

// ExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0xc3bdecfb.
//
// Solidity: function executeWithGovernanceProof(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2Session) ExecuteWithGovernanceProof(target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.ExecuteWithGovernanceProof(&_CertenAccountV2.TransactOpts, target, value, data, proof)
}

// ExecuteWithGovernanceProof is a paid mutator transaction binding the contract method 0xc3bdecfb.
//
// Solidity: function executeWithGovernanceProof(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns(bytes)
func (_CertenAccountV2 *CertenAccountV2TransactorSession) ExecuteWithGovernanceProof(target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.ExecuteWithGovernanceProof(&_CertenAccountV2.TransactOpts, target, value, data, proof)
}

// ExecuteGovernanceProofDirect is a paid mutator transaction binding the contract method for direct validator execution.
// Does NOT require EntryPoint - security is enforced via BLS validator signatures in proof.
//
// Solidity: function executeGovernanceProofDirect(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns()
func (_CertenAccountV2 *CertenAccountV2Transactor) ExecuteGovernanceProofDirect(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.contract.Transact(opts, "executeGovernanceProofDirect", target, value, data, proof)
}

// ExecuteGovernanceProofDirect is a paid mutator transaction binding the contract method for direct validator execution.
// Does NOT require EntryPoint - security is enforced via BLS validator signatures in proof.
//
// Solidity: function executeGovernanceProofDirect(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns()
func (_CertenAccountV2 *CertenAccountV2Session) ExecuteGovernanceProofDirect(target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.ExecuteGovernanceProofDirect(&_CertenAccountV2.TransactOpts, target, value, data, proof)
}

// ExecuteGovernanceProofDirect is a paid mutator transaction binding the contract method for direct validator execution.
// Does NOT require EntryPoint - security is enforced via BLS validator signatures in proof.
//
// Solidity: function executeGovernanceProofDirect(address target, uint256 value, bytes data, (string,bytes32,bytes32[],bytes,bytes,bytes,uint256,uint256,bytes,uint256,uint8) proof) returns()
func (_CertenAccountV2 *CertenAccountV2TransactorSession) ExecuteGovernanceProofDirect(target common.Address, value *big.Int, data []byte, proof AccountProof) (*types.Transaction, error) {
	return _CertenAccountV2.Contract.ExecuteGovernanceProofDirect(&_CertenAccountV2.TransactOpts, target, value, data, proof)
}
