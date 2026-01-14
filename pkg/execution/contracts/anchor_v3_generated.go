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

// CertenAnchorV3BLSProofData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV3BLSProofData struct {
	AggregateSignature []byte
	ValidatorAddresses []common.Address
	VotingPowers       []*big.Int
	TotalVotingPower   *big.Int
	SignedVotingPower  *big.Int
	ThresholdMet       bool
	MessageHash        [32]byte
}

// CertenAnchorV3CertenProof is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV3CertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof CertenAnchorV3GovernanceProofData
	BlsProof        CertenAnchorV3BLSProofData
	Commitments     CertenAnchorV3CommitmentData
	ExpirationTime  *big.Int
	Metadata        []byte
}

// CertenAnchorV3CommitmentData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV3CommitmentData struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	SourceChain          string
	SourceBlockHeight    *big.Int
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        common.Address
}

// CertenAnchorV3GovernanceProofData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV3GovernanceProofData struct {
	KeyBookURL         string
	KeyBookRoot        [32]byte
	KeyPageProofs      [][32]byte
	AuthorityAddress   common.Address
	AuthorityLevel     uint8
	Nonce              *big.Int
	RequiredSignatures *big.Int
	ProvidedSignatures *big.Int
	ThresholdMet       bool
}

// CertenAnchorV3MetaData contains all meta data concerning the CertenAnchorV3 contract.
var CertenAnchorV3MetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"EnforcedPause\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ExpectedPause\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"bundleId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"}],\"name\":\"AnchorCreated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"zkEnabled\",\"type\":\"bool\"}],\"name\":\"BLSVerificationModeUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"oldVerifier\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newVerifier\",\"type\":\"address\"}],\"name\":\"BLSVerifierUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"target\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"}],\"name\":\"GovernanceExecuted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"oldVerifier\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newVerifier\",\"type\":\"address\"}],\"name\":\"GovernanceVerifierUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"merkleVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"blsVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"governanceVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"}],\"name\":\"ProofExecuted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"merkleVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"blsVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"governanceVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"bool\",\"name\":\"commitmentVerified\",\"type\":\"bool\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"reason\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"}],\"name\":\"ProofVerificationFailed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldThreshold\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newThreshold\",\"type\":\"uint256\"}],\"name\":\"ThresholdUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"votingPower\",\"type\":\"uint256\"}],\"name\":\"ValidatorRegistered\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"}],\"name\":\"ValidatorRemoved\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"operator\",\"type\":\"address\"}],\"name\":\"addOperator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"}],\"name\":\"anchorExists\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"anchorIds\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"anchors\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"bundleId\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"valid\",\"type\":\"bool\"},{\"internalType\":\"bool\",\"name\":\"proofExecuted\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blsThresholdDenominator\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blsThresholdNumerator\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blsZKVerificationEnabled\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blsZKVerifier\",\"outputs\":[{\"internalType\":\"contractIBLSZKVerifier\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"bundleId\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\"}],\"name\":\"createAnchor\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"proofHashes\",\"type\":\"bytes32[]\"},{\"internalType\":\"bytes32\",\"name\":\"leafHash\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"keyBookURL\",\"type\":\"string\"},{\"internalType\":\"bytes32\",\"name\":\"keyBookRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"keyPageProofs\",\"type\":\"bytes32[]\"},{\"internalType\":\"address\",\"name\":\"authorityAddress\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"authorityLevel\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"requiredSignatures\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providedSignatures\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"}],\"internalType\":\"structCertenAnchorV3.GovernanceProofData\",\"name\":\"governanceProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes\",\"name\":\"aggregateSignature\",\"type\":\"bytes\"},{\"internalType\":\"address[]\",\"name\":\"validatorAddresses\",\"type\":\"address[]\"},{\"internalType\":\"uint256[]\",\"name\":\"votingPowers\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"totalVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"signedVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"internalType\":\"structCertenAnchorV3.BLSProofData\",\"name\":\"blsProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"sourceChain\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"sourceBlockHeight\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"sourceTxHash\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"targetChain\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"targetAddress\",\"type\":\"address\"}],\"internalType\":\"structCertenAnchorV3.CommitmentData\",\"name\":\"commitments\",\"type\":\"tuple\"},{\"internalType\":\"uint256\",\"name\":\"expirationTime\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"metadata\",\"type\":\"bytes\"}],\"internalType\":\"structCertenAnchorV3.CertenProof\",\"name\":\"proof\",\"type\":\"tuple\"}],\"name\":\"executeComprehensiveProof\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"target\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"executeWithGovernance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"}],\"name\":\"getAnchor\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"bundleId\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"},{\"internalType\":\"bool\",\"name\":\"valid\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getAnchorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBLSThresholdInfo\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"}],\"name\":\"getBLSValidatorInfo\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBLSZKVerificationStatus\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"configured\",\"type\":\"bool\"},{\"internalType\":\"bool\",\"name\":\"enabled\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getGovernanceVerifierStatus\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"verifierSet\",\"type\":\"bool\"},{\"internalType\":\"bool\",\"name\":\"verifierInitialized\",\"type\":\"bool\"},{\"internalType\":\"uint8\",\"name\":\"minLevel\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"}],\"name\":\"getValidatorAnchorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getValidatorCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"}],\"name\":\"getVerificationStats\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"governanceVerifier\",\"outputs\":[{\"internalType\":\"contractIGovernanceVerifier\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"}],\"name\":\"invalidateAnchor\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"commitmentHash\",\"type\":\"bytes32\"}],\"name\":\"isCommitmentUsed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"authority\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"}],\"name\":\"isNonceUsed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"minimumGovernanceLevel\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"operators\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"votingPower\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"blsPublicKey\",\"type\":\"bytes\"}],\"name\":\"registerValidator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"operator\",\"type\":\"address\"}],\"name\":\"removeOperator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"validator\",\"type\":\"address\"}],\"name\":\"removeValidator\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bool\",\"name\":\"enabled\",\"type\":\"bool\"}],\"name\":\"setBLSZKVerificationEnabled\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"verifier\",\"type\":\"address\"}],\"name\":\"setBLSZKVerifier\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"verifier\",\"type\":\"address\"}],\"name\":\"setGovernanceVerifier\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"level\",\"type\":\"uint8\"}],\"name\":\"setMinimumGovernanceLevel\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"numerator\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"denominator\",\"type\":\"uint256\"}],\"name\":\"setThreshold\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalAnchors\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalProofsExecuted\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalVotingPower\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"usedCommitments\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"usedNonces\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"validatorAnchorCounts\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"validatorList\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"validators\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"registered\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"votingPower\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"blsPublicKey\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"registeredAt\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"name\":\"verifyBLSSignature\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"proofHashes\",\"type\":\"bytes32[]\"},{\"internalType\":\"bytes32\",\"name\":\"leafHash\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"keyBookURL\",\"type\":\"string\"},{\"internalType\":\"bytes32\",\"name\":\"keyBookRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"keyPageProofs\",\"type\":\"bytes32[]\"},{\"internalType\":\"address\",\"name\":\"authorityAddress\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"authorityLevel\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"requiredSignatures\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providedSignatures\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"}],\"internalType\":\"structCertenAnchorV3.GovernanceProofData\",\"name\":\"governanceProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes\",\"name\":\"aggregateSignature\",\"type\":\"bytes\"},{\"internalType\":\"address[]\",\"name\":\"validatorAddresses\",\"type\":\"address[]\"},{\"internalType\":\"uint256[]\",\"name\":\"votingPowers\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"totalVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"signedVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"internalType\":\"structCertenAnchorV3.BLSProofData\",\"name\":\"blsProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"sourceChain\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"sourceBlockHeight\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"sourceTxHash\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"targetChain\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"targetAddress\",\"type\":\"address\"}],\"internalType\":\"structCertenAnchorV3.CommitmentData\",\"name\":\"commitments\",\"type\":\"tuple\"},{\"internalType\":\"uint256\",\"name\":\"expirationTime\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"metadata\",\"type\":\"bytes\"}],\"internalType\":\"structCertenAnchorV3.CertenProof\",\"name\":\"proof\",\"type\":\"tuple\"}],\"name\":\"verifyCertenProof\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"anchorId\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"transactionHash\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"merkleRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"proofHashes\",\"type\":\"bytes32[]\"},{\"internalType\":\"bytes32\",\"name\":\"leafHash\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"keyBookURL\",\"type\":\"string\"},{\"internalType\":\"bytes32\",\"name\":\"keyBookRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"keyPageProofs\",\"type\":\"bytes32[]\"},{\"internalType\":\"address\",\"name\":\"authorityAddress\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"authorityLevel\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"requiredSignatures\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"providedSignatures\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"}],\"internalType\":\"structCertenAnchorV3.GovernanceProofData\",\"name\":\"governanceProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes\",\"name\":\"aggregateSignature\",\"type\":\"bytes\"},{\"internalType\":\"address[]\",\"name\":\"validatorAddresses\",\"type\":\"address[]\"},{\"internalType\":\"uint256[]\",\"name\":\"votingPowers\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"totalVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"signedVotingPower\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"thresholdMet\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"messageHash\",\"type\":\"bytes32\"}],\"internalType\":\"structCertenAnchorV3.BLSProofData\",\"name\":\"blsProof\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"operationCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"crossChainCommitment\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"governanceRoot\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"sourceChain\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"sourceBlockHeight\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"sourceTxHash\",\"type\":\"bytes32\"},{\"internalType\":\"string\",\"name\":\"targetChain\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"targetAddress\",\"type\":\"address\"}],\"internalType\":\"structCertenAnchorV3.CommitmentData\",\"name\":\"commitments\",\"type\":\"tuple\"},{\"internalType\":\"uint256\",\"name\":\"expirationTime\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"metadata\",\"type\":\"bytes\"}],\"internalType\":\"structCertenAnchorV3.CertenProof\",\"name\":\"proof\",\"type\":\"tuple\"}],\"name\":\"verifyCertenProofDetailed\",\"outputs\":[{\"internalType\":\"bool[6]\",\"name\":\"\",\"type\":\"bool[6]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"stateMutability\":\"payable\",\"type\":\"receive\"}]",
	Bin: "0x608080604052346100615760026006556003600755600f805460ff60a01b1916600160a01b179055600d80546001600160a01b031916339081179091556000908152600e60205260409020805460ff19166001179055612ac090816100678239f35b600080fdfe608060409080825260049081361015610023575b505050361561002157600080fd5b005b60009160e08335811c9283630219b98314611d57575082631074f19114611d1d5782631166c38914611cf257826313e7c9d814611cb45782631d2a4ad014611c135782632897eb5514611a755782633197fec514611a565782633e83a283146117625782633f4ba83a146116ec57826340a141ff146114be57826346882a501461115f5782635817562b146110fe5782635c975abb146110dc578263671b3793146110bd57826369c9fd90146109035782636a8a6894146108bc5782637071688a1461109e5782637574f7581461104d5782637caeac00146110245782637ee832a314610ff45782637feb51d914610f675782638456cb5914610f015782638da5cb5b14610ed85782638dd58e5914610e5d5782639140203914610b84578263981e2d9b14610e3e5782639870d7fe14610df15782639ffb463514610dd2578263ac8a584a14610d88578263af9cedbb14610d54578263b01b6d5314610cb9578263b048e05614610c78578263b07ccf1a14610c53578263b259ddc514610bb2578263b61b395c14610b84578263b6202f3a14610b5b578263b855002f14610b34578263b9c36209146109fe578263c6609a8a1461093b578263c7f0bacb14610903578263cab7e8eb146108bc578263cd2b226e1461060a57508163d3182bed146105eb578163d400939f146105cc578163d68ac7fc14610524578163d8ca9380146104dd578163f2fde38b1461045457508063f46c2d0a146103e0578063f66fc3141461036c5763fa52c7d81461025b5780610013565b346103695760209182600319360112610365576001600160a01b0361027e611dfd565b1682526003835280822060ff8154169160019081830154926002810187835194888354936102ab85611f55565b8089529483811690811561033f5750600114610302575b838a8a6102f88b8f8c60038d6102dc856080950386611ee2565b0154948151978897151588528701528501526080840190611f8f565b9060608301520390f35b908094939a50528883205b82841061032c575050508301909501946003876102dc856102f86102c2565b80548785018b015292890192810161030d565b60ff1916858a01525050505090151560051b84010195506003876102dc856102f86102c2565b5080fd5b80fd5b503461036957602036600319011261036957610386611dfd565b600d546001600160a01b039061039f90821633146122ca565b80600f54921691826001600160601b0360a01b821617600f55167f22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e084078380a380f35b5034610369576020366003190112610369576103fa611dfd565b600d546001600160a01b039061041390821633146122ca565b80601054921691826001600160601b0360a01b821617601055167f9952183108d9133ea2fc010fc77d2dae1427eea28a56037e6e2333a7c45330eb8380a380f35b839150346104d95760203660031901126104d957610470611dfd565b600d5491906001600160a01b039061048b33838616146122ca565b169283156104a65750506001600160a01b03191617600d5580f35b906020606492519162461bcd60e51b8352820152600d60248201526c24b73b30b634b21037bbb732b960991b6044820152fd5b8280fd5b828434610365576020366003190112610365579081906001600160a01b03610503611dfd565b168152600360205220600160ff825416910154825191151582526020820152f35b839150346104d95760203660031901126104d95780359160ff83168084036105c85760029061055e60018060a01b03600d541633146122ca565b11610585575050600f805460ff60a01b191660a09290921b60ff60a01b1691909117905580f35b906020606492519162461bcd60e51b8352820152601860248201527f496e76616c696420676f7665726e616e6365206c6576656c00000000000000006044820152fd5b8480fd5b8284346103655781600319360112610365576020906006549051908152f35b828434610365578160031936011261036557602090600b549051908152f35b915083346108b85760a03660031901126108b857813591602491823594604435906064359360843595338a526020926003845260ff868c2054161561087757610651611ff4565b888b526001845260ff6007878d20015460a01c1661083e578551908482018b815286888401528860608401526060835260808301916001600160401b03918484108385111761082c57838a5284519020916101c085019081118482101761082c578b8f918f8f95908c918f938f90978e9b9a98825289895260a08b0192835260c08b019384528a019384526101008a019485526101208a019586526101408a01964288526101608b019b338d526101808c019b60018d526101a0019a828c528252600190522096518755516001870155516002860155516003850155518884015551600583015551600682015560070192600160a01b6001900390511683549260ff60a01b9051151560a01b169160ff60a81b9051151560a81b169269ffffffffffffffffffff60b01b16171717905560025491600160401b83101561081b5750508060016107a39201600255611d79565b81549060031b9088821b91600019901b1916179055338852600a81528288206107cc8154611fcf565b90556107d9600b54611fcf565b600b55825196875286015284015260608301524260808301527fc866200572526163e672bf703698fdca409ba4f3f75f57768a36849a43dd7ecf60a03393a380f35b634e487b7160e01b8b526041905289fd5b634e487b7160e01b8f5260418752858ffd5b5060159060649386519362461bcd60e51b855284015282015274416e63686f7220616c72656164792065786973747360581b6044820152fd5b5060199060649386519362461bcd60e51b85528401528201527f4f6e6c7920726567697374657265642076616c696461746f72000000000000006044820152fd5b8380fd5b83853461036557806003193601126103655760209160ff9082906001600160a01b036108e6611dfd565b168152600985528181206024358252855220541690519015158152f35b8385346103655760203660031901126103655760209181906001600160a01b0361092b611dfd565b168152600a845220549051908152f35b838286346104d957826003193601126104d957600f546060936001600160a01b0382168015159460ff93929182919087610989575b50505083519485521515602085015260a01c1690820152f35b91925090803b156109f75760209086519283809263392e53cd60e01b82525afa8291816109c7575b506109c057505b868080610970565b90506109b8565b6109e991925060203d81116109f0575b6109e18183611ee2565b810190612132565b90886109b1565b503d6109d7565b50506109b8565b508284346103655780600319360112610365578235602435610a2b60018060a01b03600d541633146122ca565b8015610afb57808211610ac457600654606481029080820460641490151715610ab157600754610a5a9161231a565b918060065581600755606481029080820460641490151715610ab1577fb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b939291610aa39161231a565b82519182526020820152a180f35b634e487b7160e01b855260118652602485fd5b825162461bcd60e51b81526020818701526011602482015270125b9d985b1a59081d1a1c995cda1bdb19607a1b6044820152606490fd5b825162461bcd60e51b8152602081870152601360248201527224b73b30b634b2103232b737b6b4b730ba37b960691b6044820152606490fd5b83853461036557816003193601126103655760209060ff60105460a01c1690519015158152f35b838534610365578160031936011261036557600f5490516001600160a01b039091168152602090f35b838583346104d95760203660031901126104d9578160209360ff923581526008855220541690519015158152f35b8385346103655790610bdc610bc636611e45565b9060c08551610bd481611e7b565b3690376123e1565b825192610be884611e7b565b81511515845260a060209283810151151584870152828101511515838701526060810151151560608701526080810151151560808701520151151560a08501525192839092905b60068210610c3c5760c085f35b828060019286511515815201940191019092610c2f565b83853461036557602090610c6f610c6936611e45565b90612090565b90519015158152f35b5083833461036957602036600319011261036957823592548310156103695750610ca3602092611dc6565b905491519160018060a01b039160031b1c168152f35b849250346108b85760203660031901126108b8579060ff9183610140958335815260016020522080549460018201549360028301549060038401549084015491600585015493600760068701549601549781519a8b5260208b01528901526060880152608087015260a086015260c085015260018060a01b03821690840152818160a01c16151561010084015260a81c161515610120820152f35b838583346104d95760203660031901126104d95760078260209460ff933581526001865220015460a01c1690519015158152f35b83853461036557602036600319011261036557610da3611dfd565b600d546001600160a01b039190610dbd90831633146122ca565b168252600e6020528120805460ff1916905580f35b838534610365578160031936011261036557602090600b549051908152f35b83853461036557602036600319011261036557610e0c611dfd565b600d546001600160a01b039190610e2690831633146122ca565b168252600e6020528120805460ff1916600117905580f35b838534610365578160031936011261036557602090600c549051908152f35b838583346104d95760203660031901126104d95735908115158092036104d9577f80426a93f1720f7a443e949b3f8f08844cbb1973685e5cf2db0e00811801b6a891602091610eb760018060a01b03600d541633146122ca565b6010805460ff60a01b191660a084901b60ff60a01b1617905551908152a180f35b838534610365578160031936011261036557600d5490516001600160a01b039091168152602090f35b83853461036557816003193601126103655760207f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a25891610f4c60018060a01b03600d541633146122ca565b610f54611ff4565b835460ff1916600117845551338152a180f35b849250346108b85760203660031901126108b8579060ff9183610120958335815260016020522080549460018201549360028301549060038401549084015491600585015493600760068701549601549781519a8b5260208b01528901526060880152608087015260a086015260c085015260018060a01b0382169084015260a01c161515610100820152f35b83853461036557816003193601126103655760609060065490600754906005549181519384526020840152820152f35b83853461036557816003193601126103655760105490516001600160a01b039091168152602090f35b508383346103695781600319360112610369578235906001600160401b03821161036957366023830112156103695750611095602093826024610c6f94369301359101611f1e565b6024359061214a565b838583346104d957826003193601126104d95760209250549051908152f35b8385346103655781600319360112610365576020906005549051908152f35b83853461036557816003193601126103655760ff602092541690519015158152f35b838286346104d95760203660031901126104d9576007913561112b60018060a01b03600d541633146122ca565b808452600160205261114760ff84848720015460a01c16612012565b83526001602052822001805460ff60a01b1916905580f35b849250346108b85761117036611e45565b91909261117b611ff4565b8386526020956001875285812091600783019260ff84546111a0828260a01c16612012565b60a81c166114825784860135421161144f576001015488860135036113fd576111c985876123e1565b9384511515908180926113f1575b806113e5575b806113d8575b806113cb575b806113be575b156113045750505091839160a09361122b60c07faafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d970185612051565b358152600889528781209060ff1991600183825416179055886080860191600180891b0392836112666060611260848c612066565b0161207c565b166112c5575b5050835460ff60a81b1916600160a81b179093555050600c5461128f9150611fcf565b600c5580511515908787820151151591015115159187519335845288840152868301526060820152426080820152a25160018152f35b6001936112d76060611260848c612066565b16825260098d52886112ec848420928a612066565b013582528c522091825416179055888088818061126c565b8989897f54897191894573dfd69a2c60cbaf791db5b8dde5264694c39dddfe11479d4c466064958b6113788c8a988782015115159189810151151561134f606083015115159261289c565b938a519788973588528c8801528a870152606086015260808501528060a0850152830190611f8f565b4260c08301520390a25162461bcd60e51b815291820152601960248201527f50726f6f6620766572696669636174696f6e206661696c6564000000000000006044820152fd5b5060a086015115156111ef565b50608086015115156111e9565b50606086015115156111e3565b508886015115156111dd565b508986015115156111d7565b865162461bcd60e51b8152908101889052602660248201527f50726f6f66206d65726b6c65526f6f7420646f6573206e6f74206d617463682060448201526530b731b437b960d11b6064820152608490fd5b875162461bcd60e51b81528083018a9052600d60248201526c141c9bdbd988195e1c1a5c9959609a1b6044820152606490fd5b875162461bcd60e51b81528083018a90526016602482015275141c9bdbd988185b1c9958591e48195e1958dd5d195960521b6044820152606490fd5b838583346104d9576020806003193601126108b8576114db611dfd565b600d546001600160a01b03939184916114f790831633146122ca565b169283865260039283815260ff8688205416156116b9578487528381526001958681892001546005549081039081116116a657918886928194600555888252838352812091818355818a84015560028301906115538254611f55565b9081611668575b50505050015585855b611591575b86857fe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f18280a280f35b8254808210156116625785836115a684611dc6565b905490881b1c16146115c257506115bc90611fcf565b85611563565b9192939495506000199182810190811161164f57906115f4846115e761161394611dc6565b905490891b1c1691611dc6565b90919082549060031b9160018060a01b03809116831b921b1916179055565b8254801561163c57019261162684611dc6565b81939154921b1b19169055558083808080611568565b634e487b7160e01b875260318452602487fd5b634e487b7160e01b885260118552602488fd5b50611568565b8390601f831160011461168357505050555b828a808061155a565b838252812092909161169f90601f0160051c84018d8501612303565b555561167a565b634e487b7160e01b895260118552602489fd5b8260649187519162461bcd60e51b8352820152600e60248201526d139bdd081c9959da5cdd195c995960921b6044820152fd5b838583346104d957826003193601126104d95761171460018060a01b03600d541633146122ca565b82549060ff821615611754575060ff19168255513381527f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa90602090a180f35b8251638dfc202b60e01b8152fd5b509050346103655760603660031901126103655761177e611dfd565b90602493843590604435926001600160401b0393848111611a52576117a69036908301611e18565b959060018060a01b036117be81600d541633146122ca565b8216968789526020966003885260ff868b205416611a1b5786156119d95785519160808301838110838211176119c75787526118076001948585528a8501928a84523691611f1e565b87840190815260608401914283528b8d5260038b52888d209451151560ff8019875416911617855551858501556002840190519283519081116119b5578c8b6118508454611f55565b601f811161197b575b5050508a8d601f831160011461191857906003958361190d575b505060001982861b1c191690861b1790555b51910155825490600160401b8210156118fb57816115f4916118aa9493018555611dc6565b600554908382018092116118e957507fb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c9495965060055551908152a280f35b634e487b7160e01b8752601190528686fd5b634e487b7160e01b8952604184528989fd5b015190503880611873565b8381528c81208893929091601f198416908f5b82821061196457505096836003981061194c575b505050811b019055611885565b015160001983881b60f8161c1916905538808061193f565b838a015185558b969094019392830192018f61192b565b8183866119a395522090601f850160051c82019285106119ab575b601f0160051c0190612303565b8c8b38611859565b9091508190611996565b634e487b7160e01b8d52604188528d8dfd5b634e487b7160e01b8c52604187528c8cfd5b855162461bcd60e51b8152808601899052601d818d01527f566f74696e6720706f776572206d75737420626520706f7369746976650000006044820152606490fd5b855162461bcd60e51b81528086018990526012818d015271105b1c9958591e481c9959da5cdd195c995960721b6044820152606490fd5b8680fd5b8385346103655781600319360112610365576020906007549051908152f35b838286346104d95760803660031901126104d9576001600160a01b03926024358481169184359183810361036557604435956064356001600160401b0381116108b857611ac59036908301611e18565b91338552602099600e8b5260ff8987205416908115611c05575b5015611bd257611aed611ff4565b85855260018a5260ff60078987200154611b0b828260a01c16612012565b60a81c1615611b9657509280606093838a7f360cff1b16f1fa5b481c344aa6535e4e085f4ba2d1a5774a786f03e0bfc03b7e9784968c519384928337810185815203925af1903d15611b90573d90611b6282611f03565b91611b6f89519384611ee2565b8252893d92013e5b855196875215159586888201524286820152a351908152f35b50611b77565b875162461bcd60e51b81529081018a90526016602482015275141c9bdbd9881b9bdd081e595d08195e1958dd5d195960521b6044820152606490fd5b875162461bcd60e51b81529081018a9052600d60248201526c27b7363c9037b832b930ba37b960991b6044820152606490fd5b9050600d541633148b611adf565b848285346103695780600319360112610369576010546001600160a01b038116801515939192919084611c5a575b5050835192151583525060a01c60ff1615156020820152f35b60ff939450602090865192838092635e16ef7d60e01b82525afa829181611c94575b50611c8c5750915b908480611c41565b905091611c84565b611cad91925060203d81116109f0576109e18183611ee2565b9086611c7c565b8385346103655760203660031901126103655760209160ff9082906001600160a01b03611cdf611dfd565b168152600e855220541690519015158152f35b848285346103695760203660031901126103695750611d11903561233a565b82519182526020820152f35b838583346104d95760203660031901126104d95735916002548310156103695750611d49602092611d79565b91905490519160031b1c8152f35b84903461036557816003193601126103655760209060ff600f5460a01c168152f35b600254811015611db05760026000527f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace0190600090565b634e487b7160e01b600052603260045260246000fd5b600454811015611db05760046000527f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b0190600090565b600435906001600160a01b0382168203611e1357565b600080fd5b9181601f84011215611e13578235916001600160401b038311611e135760208381860195010111611e1357565b90600319604081840112611e135760043592602435916001600160401b038311611e13578261012092030112611e135760040190565b60c081019081106001600160401b03821117611e9657604052565b634e487b7160e01b600052604160045260246000fd5b606081019081106001600160401b03821117611e9657604052565b604081019081106001600160401b03821117611e9657604052565b90601f801991011681019081106001600160401b03821117611e9657604052565b6001600160401b038111611e9657601f01601f191660200190565b929192611f2a82611f03565b91611f386040519384611ee2565b829481845281830111611e13578281602093846000960137010152565b90600182811c92168015611f85575b6020831014611f6f57565b634e487b7160e01b600052602260045260246000fd5b91607f1691611f64565b919082519283825260005b848110611fbb575050826000602080949584010152601f8019910116010190565b602081830181015184830182015201611f9a565b6000198114611fde5760010190565b634e487b7160e01b600052601160045260246000fd5b60ff6000541661200057565b60405163d93c066560e01b8152600490fd5b1561201957565b60405162461bcd60e51b815260206004820152601060248201526f105b98da1bdc881b9bdd08199bdd5b9960821b6044820152606490fd5b90359060fe1981360301821215611e13570190565b90359061011e1981360301821215611e13570190565b356001600160a01b0381168103611e135790565b9081600052600160205260ff60076040600020015460a01c161561212b5760e0810135421161212b576120c2916123e1565b80511515908161211d575b8161210f575b81612101575b816120f3575b816120e8575090565b60a091500151151590565b6080810151151591506120df565b6060810151151591506120d9565b6040810151151591506120d3565b6020810151151591506120cd565b5050600090565b90816020910312611e1357518015158103611e135790565b80511561212b57811561212b5760105460ff8160a01c1615612285576001600160a01b0316801561224057604051635e16ef7d60e01b8152602092908381600481865afa60009181612221575b506121a6575050505050600090565b156122185782916121d591604051809681948293630eae9eeb60e31b8452604060048501526044840190611f8f565b90602483015203915afa9182916000936121f9575b50506121f65750600090565b90565b612210929350803d106109f0576109e18183611ee2565b9038806121ea565b50505050600090565b612239919250853d87116109f0576109e18183611ee2565b9038612197565b60405162461bcd60e51b815260206004820152601e60248201527f424c53205a4b207665726966696572206e6f7420636f6e6669677572656400006044820152606490fd5b60405162461bcd60e51b815260206004820152601f60248201527f424c53205a4b20766572696669636174696f6e206e6f7420656e61626c6564006044820152606490fd5b156122d157565b60405162461bcd60e51b815260206004820152600a60248201526927b7363c9037bbb732b960b11b6044820152606490fd5b81811061230e575050565b60008155600101612303565b8115612324570490565b634e487b7160e01b600052601260045260246000fd5b600052600160205260076040600020015460ff8160a01c16156123715760a81c60ff1615612369576001908190565b600190600090565b50600090600090565b6040519061238782611e7b565b8160a06000918281528260208201528260408201528260608201528260808201520152565b903590601e1981360301821215611e1357018035906001600160401b038211611e1357602001918160051b36038313611e1357565b906123ea61237a565b506123f361237a565b9161241661240460408401846123ac565b906060850135916020860135916124f6565b15158352608082019061243161242c8385612066565b612579565b1515602085015260a08301359060de1984360301821215611e135761245a612474928501612784565b1515604086015261246e60c0850185612051565b90612814565b1515606084015260e0820135421115608084015260018060a01b038061249f60606112608587612066565b16156124e957816124cf916124bb606061126060a09688612066565b166000526009602052604060002093612066565b013560005260205260ff604060002054161560a082015290565b505050600160a082015290565b909192916000915b81831061250c575050501490565b909192612548908460051b83013580821060001461254f5760408051916020830193845281830152815261253f81611eac565b51902093611fcf565b91906124fe565b9060408051916020830193845281830152815261253f81611eac565b3560ff81168103611e135790565b60e08101359060c08101359081831061266e5760ff608082019361259c8561256b565b93600f5494838660a01c169384911610612779576001600160a01b03948516806126c45750505060408201906125d282846123ac565b90501515806126b7575b15612676575061262f906126246125f56060850161207c565b60405160208101916001600160601b03199060601b1682526014815261261a81611ec7565b51902091846123ac565b6020850135916124f6565b1561266e576060612640910161207c565b16159081612658575b5061265357600190565b600090565b60ff91506126659061256b565b16151538612649565b505050600090565b6001111561268b575b50606061264091611260565b60208201351590816126a3575b5061266e573861267f565b6126ae9150826123ac565b90501538612698565b50602083013515156125dc565b9250929450926126d760408601866123ac565b6126e36060880161207c565b60405163c419ab0160e01b815260209890980135600489015260a0602489015260a48801829052916001600160fb1b038211611e13576020968896879560c495879560051b8095888801371660448501526064840152608483015281010301915afa60009181612759575b506121f65750600090565b61277291925060203d81116109f0576109e18183611ee2565b903861274e565b505050505050600090565b60a0810135801590811503611e135761280e576006546060820135818102918115918304141715611fde576007546127bb9161231a565b60808201351061280e578035601e1982360301811215611e135781018035906001600160401b038211611e1357602001918136038313611e13576121f69260c0612809920135923691611f1e565b61214a565b50600090565b9060009182526001602052604082208135808452600860205260ff6040852054166128965760028201548061288a575b5050600381015480612875575b50600401549081612865575b505050600190565b60400135036121f657808061285d565b6020830135036128855738612851565b505090565b03612885573880612844565b50505090565b805115612a505760408082015115612a0d5760209182810151156129c957606081015115612991576080810151156129595760a001511561290e577f556e6b6e6f776e20766572696669636174696f6e206661696c7572650000000090519161290483611ec7565b601c835282015290565b807f4e6f6e636520616c7265616479207573656420287265706c61792061747461636b6b2070726576656e7465642960a01b92519361294c85611eac565b602c855284015282015290565b507f50726f6f662074696d657374616d70206578706972656400000000000000000090519161298783611ec7565b6017835282015290565b507f436f6d6d69746d656e7420766572696669636174696f6e206661696c656400009051916129bf83611ec7565b601e835282015290565b50807f476f7665726e616e63652070726f6f6620766572696669636174696f6e206661631a5b195960e21b925193612a0085611eac565b6024855284015282015290565b9050601960fa1b815191612a2083611eac565b602183527f424c53207369676e617475726520766572696669636174696f6e206661696c65602084015282015290565b50604051612a5d81611ec7565b602081527f4d65726b6c652070726f6f6620766572696669636174696f6e206661696c656460208201529056fea26469706673582212201b2f8994883f5c21dd55ce51509116ca0d097bf3a7a10e8debcf42a43010e15364736f6c63430008140033",
}

// CertenAnchorV3ABI is the input ABI used to generate the binding from.
// Deprecated: Use CertenAnchorV3MetaData.ABI instead.
var CertenAnchorV3ABI = CertenAnchorV3MetaData.ABI

// CertenAnchorV3Bin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use CertenAnchorV3MetaData.Bin instead.
var CertenAnchorV3Bin = CertenAnchorV3MetaData.Bin

// DeployCertenAnchorV3 deploys a new Ethereum contract, binding an instance of CertenAnchorV3 to it.
func DeployCertenAnchorV3(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *CertenAnchorV3, error) {
	parsed, err := CertenAnchorV3MetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(CertenAnchorV3Bin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &CertenAnchorV3{CertenAnchorV3Caller: CertenAnchorV3Caller{contract: contract}, CertenAnchorV3Transactor: CertenAnchorV3Transactor{contract: contract}, CertenAnchorV3Filterer: CertenAnchorV3Filterer{contract: contract}}, nil
}

// CertenAnchorV3 is an auto generated Go binding around an Ethereum contract.
type CertenAnchorV3 struct {
	CertenAnchorV3Caller     // Read-only binding to the contract
	CertenAnchorV3Transactor // Write-only binding to the contract
	CertenAnchorV3Filterer   // Log filterer for contract events
}

// CertenAnchorV3Caller is an auto generated read-only Go binding around an Ethereum contract.
type CertenAnchorV3Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV3Transactor is an auto generated write-only Go binding around an Ethereum contract.
type CertenAnchorV3Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV3Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type CertenAnchorV3Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV3Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type CertenAnchorV3Session struct {
	Contract     *CertenAnchorV3   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// CertenAnchorV3CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type CertenAnchorV3CallerSession struct {
	Contract *CertenAnchorV3Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// CertenAnchorV3TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type CertenAnchorV3TransactorSession struct {
	Contract     *CertenAnchorV3Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// CertenAnchorV3Raw is an auto generated low-level Go binding around an Ethereum contract.
type CertenAnchorV3Raw struct {
	Contract *CertenAnchorV3 // Generic contract binding to access the raw methods on
}

// CertenAnchorV3CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type CertenAnchorV3CallerRaw struct {
	Contract *CertenAnchorV3Caller // Generic read-only contract binding to access the raw methods on
}

// CertenAnchorV3TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type CertenAnchorV3TransactorRaw struct {
	Contract *CertenAnchorV3Transactor // Generic write-only contract binding to access the raw methods on
}

// NewCertenAnchorV3 creates a new instance of CertenAnchorV3, bound to a specific deployed contract.
func NewCertenAnchorV3(address common.Address, backend bind.ContractBackend) (*CertenAnchorV3, error) {
	contract, err := bindCertenAnchorV3(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3{CertenAnchorV3Caller: CertenAnchorV3Caller{contract: contract}, CertenAnchorV3Transactor: CertenAnchorV3Transactor{contract: contract}, CertenAnchorV3Filterer: CertenAnchorV3Filterer{contract: contract}}, nil
}

// NewCertenAnchorV3Caller creates a new read-only instance of CertenAnchorV3, bound to a specific deployed contract.
func NewCertenAnchorV3Caller(address common.Address, caller bind.ContractCaller) (*CertenAnchorV3Caller, error) {
	contract, err := bindCertenAnchorV3(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3Caller{contract: contract}, nil
}

// NewCertenAnchorV3Transactor creates a new write-only instance of CertenAnchorV3, bound to a specific deployed contract.
func NewCertenAnchorV3Transactor(address common.Address, transactor bind.ContractTransactor) (*CertenAnchorV3Transactor, error) {
	contract, err := bindCertenAnchorV3(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3Transactor{contract: contract}, nil
}

// NewCertenAnchorV3Filterer creates a new log filterer instance of CertenAnchorV3, bound to a specific deployed contract.
func NewCertenAnchorV3Filterer(address common.Address, filterer bind.ContractFilterer) (*CertenAnchorV3Filterer, error) {
	contract, err := bindCertenAnchorV3(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3Filterer{contract: contract}, nil
}

// bindCertenAnchorV3 binds a generic wrapper to an already deployed contract.
func bindCertenAnchorV3(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := CertenAnchorV3MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV3 *CertenAnchorV3Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV3.Contract.CertenAnchorV3Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV3 *CertenAnchorV3Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.CertenAnchorV3Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV3 *CertenAnchorV3Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.CertenAnchorV3Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV3 *CertenAnchorV3CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV3.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV3 *CertenAnchorV3TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV3 *CertenAnchorV3TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.contract.Transact(opts, method, params...)
}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) AnchorExists(opts *bind.CallOpts, anchorId [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "anchorExists", anchorId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) AnchorExists(anchorId [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.AnchorExists(&_CertenAnchorV3.CallOpts, anchorId)
}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) AnchorExists(anchorId [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.AnchorExists(&_CertenAnchorV3.CallOpts, anchorId)
}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV3 *CertenAnchorV3Caller) AnchorIds(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "anchorIds", arg0)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV3 *CertenAnchorV3Session) AnchorIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV3.Contract.AnchorIds(&_CertenAnchorV3.CallOpts, arg0)
}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) AnchorIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV3.Contract.AnchorIds(&_CertenAnchorV3.CallOpts, arg0)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV3 *CertenAnchorV3Caller) Anchors(opts *bind.CallOpts, arg0 [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
	ProofExecuted         bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "anchors", arg0)

	outstruct := new(struct {
		BundleId              [32]byte
		MerkleRoot            [32]byte
		OperationCommitment   [32]byte
		CrossChainCommitment  [32]byte
		GovernanceRoot        [32]byte
		AccumulateBlockHeight *big.Int
		Timestamp             *big.Int
		Validator             common.Address
		Valid                 bool
		ProofExecuted         bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BundleId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.MerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.OperationCommitment = *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	outstruct.CrossChainCommitment = *abi.ConvertType(out[3], new([32]byte)).(*[32]byte)
	outstruct.GovernanceRoot = *abi.ConvertType(out[4], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[7], new(common.Address)).(*common.Address)
	outstruct.Valid = *abi.ConvertType(out[8], new(bool)).(*bool)
	outstruct.ProofExecuted = *abi.ConvertType(out[9], new(bool)).(*bool)

	return *outstruct, err

}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV3 *CertenAnchorV3Session) Anchors(arg0 [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
	ProofExecuted         bool
}, error) {
	return _CertenAnchorV3.Contract.Anchors(&_CertenAnchorV3.CallOpts, arg0)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) Anchors(arg0 [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
	ProofExecuted         bool
}, error) {
	return _CertenAnchorV3.Contract.Anchors(&_CertenAnchorV3.CallOpts, arg0)
}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) BlsThresholdDenominator(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "blsThresholdDenominator")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) BlsThresholdDenominator() (*big.Int, error) {
	return _CertenAnchorV3.Contract.BlsThresholdDenominator(&_CertenAnchorV3.CallOpts)
}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) BlsThresholdDenominator() (*big.Int, error) {
	return _CertenAnchorV3.Contract.BlsThresholdDenominator(&_CertenAnchorV3.CallOpts)
}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) BlsThresholdNumerator(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "blsThresholdNumerator")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) BlsThresholdNumerator() (*big.Int, error) {
	return _CertenAnchorV3.Contract.BlsThresholdNumerator(&_CertenAnchorV3.CallOpts)
}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) BlsThresholdNumerator() (*big.Int, error) {
	return _CertenAnchorV3.Contract.BlsThresholdNumerator(&_CertenAnchorV3.CallOpts)
}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) BlsZKVerificationEnabled(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "blsZKVerificationEnabled")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) BlsZKVerificationEnabled() (bool, error) {
	return _CertenAnchorV3.Contract.BlsZKVerificationEnabled(&_CertenAnchorV3.CallOpts)
}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) BlsZKVerificationEnabled() (bool, error) {
	return _CertenAnchorV3.Contract.BlsZKVerificationEnabled(&_CertenAnchorV3.CallOpts)
}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Caller) BlsZKVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "blsZKVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Session) BlsZKVerifier() (common.Address, error) {
	return _CertenAnchorV3.Contract.BlsZKVerifier(&_CertenAnchorV3.CallOpts)
}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) BlsZKVerifier() (common.Address, error) {
	return _CertenAnchorV3.Contract.BlsZKVerifier(&_CertenAnchorV3.CallOpts)
}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetAnchor(opts *bind.CallOpts, anchorId [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getAnchor", anchorId)

	outstruct := new(struct {
		BundleId              [32]byte
		MerkleRoot            [32]byte
		OperationCommitment   [32]byte
		CrossChainCommitment  [32]byte
		GovernanceRoot        [32]byte
		AccumulateBlockHeight *big.Int
		Timestamp             *big.Int
		Validator             common.Address
		Valid                 bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BundleId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.MerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.OperationCommitment = *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	outstruct.CrossChainCommitment = *abi.ConvertType(out[3], new([32]byte)).(*[32]byte)
	outstruct.GovernanceRoot = *abi.ConvertType(out[4], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[7], new(common.Address)).(*common.Address)
	outstruct.Valid = *abi.ConvertType(out[8], new(bool)).(*bool)

	return *outstruct, err

}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetAnchor(anchorId [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
}, error) {
	return _CertenAnchorV3.Contract.GetAnchor(&_CertenAnchorV3.CallOpts, anchorId)
}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetAnchor(anchorId [32]byte) (struct {
	BundleId              [32]byte
	MerkleRoot            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
}, error) {
	return _CertenAnchorV3.Contract.GetAnchor(&_CertenAnchorV3.CallOpts, anchorId)
}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetAnchorCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getAnchorCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetAnchorCount() (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetAnchorCount(&_CertenAnchorV3.CallOpts)
}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetAnchorCount() (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetAnchorCount(&_CertenAnchorV3.CallOpts)
}

// GetBLSThresholdInfo is a free data retrieval call binding the contract method 0x7ee832a3.
//
// Solidity: function getBLSThresholdInfo() view returns(uint256, uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetBLSThresholdInfo(opts *bind.CallOpts) (*big.Int, *big.Int, *big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getBLSThresholdInfo")

	if err != nil {
		return *new(*big.Int), *new(*big.Int), *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	out2 := *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)

	return out0, out1, out2, err

}

// GetBLSThresholdInfo is a free data retrieval call binding the contract method 0x7ee832a3.
//
// Solidity: function getBLSThresholdInfo() view returns(uint256, uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetBLSThresholdInfo() (*big.Int, *big.Int, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetBLSThresholdInfo(&_CertenAnchorV3.CallOpts)
}

// GetBLSThresholdInfo is a free data retrieval call binding the contract method 0x7ee832a3.
//
// Solidity: function getBLSThresholdInfo() view returns(uint256, uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetBLSThresholdInfo() (*big.Int, *big.Int, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetBLSThresholdInfo(&_CertenAnchorV3.CallOpts)
}

// GetBLSValidatorInfo is a free data retrieval call binding the contract method 0xd8ca9380.
//
// Solidity: function getBLSValidatorInfo(address validator) view returns(bool, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetBLSValidatorInfo(opts *bind.CallOpts, validator common.Address) (bool, *big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getBLSValidatorInfo", validator)

	if err != nil {
		return *new(bool), *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return out0, out1, err

}

// GetBLSValidatorInfo is a free data retrieval call binding the contract method 0xd8ca9380.
//
// Solidity: function getBLSValidatorInfo(address validator) view returns(bool, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetBLSValidatorInfo(validator common.Address) (bool, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetBLSValidatorInfo(&_CertenAnchorV3.CallOpts, validator)
}

// GetBLSValidatorInfo is a free data retrieval call binding the contract method 0xd8ca9380.
//
// Solidity: function getBLSValidatorInfo(address validator) view returns(bool, uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetBLSValidatorInfo(validator common.Address) (bool, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetBLSValidatorInfo(&_CertenAnchorV3.CallOpts, validator)
}

// GetBLSZKVerificationStatus is a free data retrieval call binding the contract method 0x1d2a4ad0.
//
// Solidity: function getBLSZKVerificationStatus() view returns(bool configured, bool enabled)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetBLSZKVerificationStatus(opts *bind.CallOpts) (struct {
	Configured bool
	Enabled    bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getBLSZKVerificationStatus")

	outstruct := new(struct {
		Configured bool
		Enabled    bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Configured = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.Enabled = *abi.ConvertType(out[1], new(bool)).(*bool)

	return *outstruct, err

}

// GetBLSZKVerificationStatus is a free data retrieval call binding the contract method 0x1d2a4ad0.
//
// Solidity: function getBLSZKVerificationStatus() view returns(bool configured, bool enabled)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetBLSZKVerificationStatus() (struct {
	Configured bool
	Enabled    bool
}, error) {
	return _CertenAnchorV3.Contract.GetBLSZKVerificationStatus(&_CertenAnchorV3.CallOpts)
}

// GetBLSZKVerificationStatus is a free data retrieval call binding the contract method 0x1d2a4ad0.
//
// Solidity: function getBLSZKVerificationStatus() view returns(bool configured, bool enabled)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetBLSZKVerificationStatus() (struct {
	Configured bool
	Enabled    bool
}, error) {
	return _CertenAnchorV3.Contract.GetBLSZKVerificationStatus(&_CertenAnchorV3.CallOpts)
}

// GetGovernanceVerifierStatus is a free data retrieval call binding the contract method 0xc6609a8a.
//
// Solidity: function getGovernanceVerifierStatus() view returns(bool verifierSet, bool verifierInitialized, uint8 minLevel)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetGovernanceVerifierStatus(opts *bind.CallOpts) (struct {
	VerifierSet         bool
	VerifierInitialized bool
	MinLevel            uint8
}, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getGovernanceVerifierStatus")

	outstruct := new(struct {
		VerifierSet         bool
		VerifierInitialized bool
		MinLevel            uint8
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.VerifierSet = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.VerifierInitialized = *abi.ConvertType(out[1], new(bool)).(*bool)
	outstruct.MinLevel = *abi.ConvertType(out[2], new(uint8)).(*uint8)

	return *outstruct, err

}

// GetGovernanceVerifierStatus is a free data retrieval call binding the contract method 0xc6609a8a.
//
// Solidity: function getGovernanceVerifierStatus() view returns(bool verifierSet, bool verifierInitialized, uint8 minLevel)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetGovernanceVerifierStatus() (struct {
	VerifierSet         bool
	VerifierInitialized bool
	MinLevel            uint8
}, error) {
	return _CertenAnchorV3.Contract.GetGovernanceVerifierStatus(&_CertenAnchorV3.CallOpts)
}

// GetGovernanceVerifierStatus is a free data retrieval call binding the contract method 0xc6609a8a.
//
// Solidity: function getGovernanceVerifierStatus() view returns(bool verifierSet, bool verifierInitialized, uint8 minLevel)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetGovernanceVerifierStatus() (struct {
	VerifierSet         bool
	VerifierInitialized bool
	MinLevel            uint8
}, error) {
	return _CertenAnchorV3.Contract.GetGovernanceVerifierStatus(&_CertenAnchorV3.CallOpts)
}

// GetValidatorAnchorCount is a free data retrieval call binding the contract method 0xc7f0bacb.
//
// Solidity: function getValidatorAnchorCount(address validator) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetValidatorAnchorCount(opts *bind.CallOpts, validator common.Address) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getValidatorAnchorCount", validator)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetValidatorAnchorCount is a free data retrieval call binding the contract method 0xc7f0bacb.
//
// Solidity: function getValidatorAnchorCount(address validator) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetValidatorAnchorCount(validator common.Address) (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetValidatorAnchorCount(&_CertenAnchorV3.CallOpts, validator)
}

// GetValidatorAnchorCount is a free data retrieval call binding the contract method 0xc7f0bacb.
//
// Solidity: function getValidatorAnchorCount(address validator) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetValidatorAnchorCount(validator common.Address) (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetValidatorAnchorCount(&_CertenAnchorV3.CallOpts, validator)
}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetValidatorCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getValidatorCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetValidatorCount() (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetValidatorCount(&_CertenAnchorV3.CallOpts)
}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetValidatorCount() (*big.Int, error) {
	return _CertenAnchorV3.Contract.GetValidatorCount(&_CertenAnchorV3.CallOpts)
}

// GetVerificationStats is a free data retrieval call binding the contract method 0x1166c389.
//
// Solidity: function getVerificationStats(bytes32 anchorId) view returns(uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GetVerificationStats(opts *bind.CallOpts, anchorId [32]byte) (*big.Int, *big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "getVerificationStats", anchorId)

	if err != nil {
		return *new(*big.Int), *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	out1 := *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return out0, out1, err

}

// GetVerificationStats is a free data retrieval call binding the contract method 0x1166c389.
//
// Solidity: function getVerificationStats(bytes32 anchorId) view returns(uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) GetVerificationStats(anchorId [32]byte) (*big.Int, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetVerificationStats(&_CertenAnchorV3.CallOpts, anchorId)
}

// GetVerificationStats is a free data retrieval call binding the contract method 0x1166c389.
//
// Solidity: function getVerificationStats(bytes32 anchorId) view returns(uint256, uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GetVerificationStats(anchorId [32]byte) (*big.Int, *big.Int, error) {
	return _CertenAnchorV3.Contract.GetVerificationStats(&_CertenAnchorV3.CallOpts, anchorId)
}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Caller) GovernanceVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "governanceVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Session) GovernanceVerifier() (common.Address, error) {
	return _CertenAnchorV3.Contract.GovernanceVerifier(&_CertenAnchorV3.CallOpts)
}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) GovernanceVerifier() (common.Address, error) {
	return _CertenAnchorV3.Contract.GovernanceVerifier(&_CertenAnchorV3.CallOpts)
}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) IsCommitmentUsed(opts *bind.CallOpts, commitmentHash [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "isCommitmentUsed", commitmentHash)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) IsCommitmentUsed(commitmentHash [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.IsCommitmentUsed(&_CertenAnchorV3.CallOpts, commitmentHash)
}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) IsCommitmentUsed(commitmentHash [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.IsCommitmentUsed(&_CertenAnchorV3.CallOpts, commitmentHash)
}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) IsNonceUsed(opts *bind.CallOpts, authority common.Address, nonce *big.Int) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "isNonceUsed", authority, nonce)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) IsNonceUsed(authority common.Address, nonce *big.Int) (bool, error) {
	return _CertenAnchorV3.Contract.IsNonceUsed(&_CertenAnchorV3.CallOpts, authority, nonce)
}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) IsNonceUsed(authority common.Address, nonce *big.Int) (bool, error) {
	return _CertenAnchorV3.Contract.IsNonceUsed(&_CertenAnchorV3.CallOpts, authority, nonce)
}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV3 *CertenAnchorV3Caller) MinimumGovernanceLevel(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "minimumGovernanceLevel")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV3 *CertenAnchorV3Session) MinimumGovernanceLevel() (uint8, error) {
	return _CertenAnchorV3.Contract.MinimumGovernanceLevel(&_CertenAnchorV3.CallOpts)
}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) MinimumGovernanceLevel() (uint8, error) {
	return _CertenAnchorV3.Contract.MinimumGovernanceLevel(&_CertenAnchorV3.CallOpts)
}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) Operators(opts *bind.CallOpts, arg0 common.Address) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "operators", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) Operators(arg0 common.Address) (bool, error) {
	return _CertenAnchorV3.Contract.Operators(&_CertenAnchorV3.CallOpts, arg0)
}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) Operators(arg0 common.Address) (bool, error) {
	return _CertenAnchorV3.Contract.Operators(&_CertenAnchorV3.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Caller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Session) Owner() (common.Address, error) {
	return _CertenAnchorV3.Contract.Owner(&_CertenAnchorV3.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) Owner() (common.Address, error) {
	return _CertenAnchorV3.Contract.Owner(&_CertenAnchorV3.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) Paused() (bool, error) {
	return _CertenAnchorV3.Contract.Paused(&_CertenAnchorV3.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) Paused() (bool, error) {
	return _CertenAnchorV3.Contract.Paused(&_CertenAnchorV3.CallOpts)
}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) TotalAnchors(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "totalAnchors")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) TotalAnchors() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalAnchors(&_CertenAnchorV3.CallOpts)
}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) TotalAnchors() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalAnchors(&_CertenAnchorV3.CallOpts)
}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) TotalProofsExecuted(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "totalProofsExecuted")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) TotalProofsExecuted() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalProofsExecuted(&_CertenAnchorV3.CallOpts)
}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) TotalProofsExecuted() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalProofsExecuted(&_CertenAnchorV3.CallOpts)
}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) TotalVotingPower(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "totalVotingPower")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) TotalVotingPower() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalVotingPower(&_CertenAnchorV3.CallOpts)
}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) TotalVotingPower() (*big.Int, error) {
	return _CertenAnchorV3.Contract.TotalVotingPower(&_CertenAnchorV3.CallOpts)
}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) UsedCommitments(opts *bind.CallOpts, arg0 [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "usedCommitments", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) UsedCommitments(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.UsedCommitments(&_CertenAnchorV3.CallOpts, arg0)
}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) UsedCommitments(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.UsedCommitments(&_CertenAnchorV3.CallOpts, arg0)
}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) UsedNonces(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "usedNonces", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) UsedNonces(arg0 common.Address, arg1 *big.Int) (bool, error) {
	return _CertenAnchorV3.Contract.UsedNonces(&_CertenAnchorV3.CallOpts, arg0, arg1)
}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) UsedNonces(arg0 common.Address, arg1 *big.Int) (bool, error) {
	return _CertenAnchorV3.Contract.UsedNonces(&_CertenAnchorV3.CallOpts, arg0, arg1)
}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Caller) ValidatorAnchorCounts(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "validatorAnchorCounts", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3Session) ValidatorAnchorCounts(arg0 common.Address) (*big.Int, error) {
	return _CertenAnchorV3.Contract.ValidatorAnchorCounts(&_CertenAnchorV3.CallOpts, arg0)
}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) ValidatorAnchorCounts(arg0 common.Address) (*big.Int, error) {
	return _CertenAnchorV3.Contract.ValidatorAnchorCounts(&_CertenAnchorV3.CallOpts, arg0)
}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Caller) ValidatorList(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "validatorList", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3Session) ValidatorList(arg0 *big.Int) (common.Address, error) {
	return _CertenAnchorV3.Contract.ValidatorList(&_CertenAnchorV3.CallOpts, arg0)
}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) ValidatorList(arg0 *big.Int) (common.Address, error) {
	return _CertenAnchorV3.Contract.ValidatorList(&_CertenAnchorV3.CallOpts, arg0)
}

// Validators is a free data retrieval call binding the contract method 0xfa52c7d8.
//
// Solidity: function validators(address ) view returns(bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)
func (_CertenAnchorV3 *CertenAnchorV3Caller) Validators(opts *bind.CallOpts, arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "validators", arg0)

	outstruct := new(struct {
		Registered   bool
		VotingPower  *big.Int
		BlsPublicKey []byte
		RegisteredAt *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Registered = *abi.ConvertType(out[0], new(bool)).(*bool)
	outstruct.VotingPower = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.BlsPublicKey = *abi.ConvertType(out[2], new([]byte)).(*[]byte)
	outstruct.RegisteredAt = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Validators is a free data retrieval call binding the contract method 0xfa52c7d8.
//
// Solidity: function validators(address ) view returns(bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)
func (_CertenAnchorV3 *CertenAnchorV3Session) Validators(arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	return _CertenAnchorV3.Contract.Validators(&_CertenAnchorV3.CallOpts, arg0)
}

// Validators is a free data retrieval call binding the contract method 0xfa52c7d8.
//
// Solidity: function validators(address ) view returns(bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) Validators(arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	return _CertenAnchorV3.Contract.Validators(&_CertenAnchorV3.CallOpts, arg0)
}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) VerifyBLSSignature(opts *bind.CallOpts, signature []byte, messageHash [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "verifyBLSSignature", signature, messageHash)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) VerifyBLSSignature(signature []byte, messageHash [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.VerifyBLSSignature(&_CertenAnchorV3.CallOpts, signature, messageHash)
}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) VerifyBLSSignature(signature []byte, messageHash [32]byte) (bool, error) {
	return _CertenAnchorV3.Contract.VerifyBLSSignature(&_CertenAnchorV3.CallOpts, signature, messageHash)
}

// VerifyCertenProof is a free data retrieval call binding the contract method 0xb07ccf1a.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Caller) VerifyCertenProof(opts *bind.CallOpts, anchorId [32]byte, proof CertenAnchorV3CertenProof) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "verifyCertenProof", anchorId, proof)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyCertenProof is a free data retrieval call binding the contract method 0xb07ccf1a.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) VerifyCertenProof(anchorId [32]byte, proof CertenAnchorV3CertenProof) (bool, error) {
	return _CertenAnchorV3.Contract.VerifyCertenProof(&_CertenAnchorV3.CallOpts, anchorId, proof)
}

// VerifyCertenProof is a free data retrieval call binding the contract method 0xb07ccf1a.
//
// Solidity: function verifyCertenProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) VerifyCertenProof(anchorId [32]byte, proof CertenAnchorV3CertenProof) (bool, error) {
	return _CertenAnchorV3.Contract.VerifyCertenProof(&_CertenAnchorV3.CallOpts, anchorId, proof)
}

// VerifyCertenProofDetailed is a free data retrieval call binding the contract method 0xb259ddc5.
//
// Solidity: function verifyCertenProofDetailed(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool[6])
func (_CertenAnchorV3 *CertenAnchorV3Caller) VerifyCertenProofDetailed(opts *bind.CallOpts, anchorId [32]byte, proof CertenAnchorV3CertenProof) ([6]bool, error) {
	var out []interface{}
	err := _CertenAnchorV3.contract.Call(opts, &out, "verifyCertenProofDetailed", anchorId, proof)

	if err != nil {
		return *new([6]bool), err
	}

	out0 := *abi.ConvertType(out[0], new([6]bool)).(*[6]bool)

	return out0, err

}

// VerifyCertenProofDetailed is a free data retrieval call binding the contract method 0xb259ddc5.
//
// Solidity: function verifyCertenProofDetailed(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool[6])
func (_CertenAnchorV3 *CertenAnchorV3Session) VerifyCertenProofDetailed(anchorId [32]byte, proof CertenAnchorV3CertenProof) ([6]bool, error) {
	return _CertenAnchorV3.Contract.VerifyCertenProofDetailed(&_CertenAnchorV3.CallOpts, anchorId, proof)
}

// VerifyCertenProofDetailed is a free data retrieval call binding the contract method 0xb259ddc5.
//
// Solidity: function verifyCertenProofDetailed(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) view returns(bool[6])
func (_CertenAnchorV3 *CertenAnchorV3CallerSession) VerifyCertenProofDetailed(anchorId [32]byte, proof CertenAnchorV3CertenProof) ([6]bool, error) {
	return _CertenAnchorV3.Contract.VerifyCertenProofDetailed(&_CertenAnchorV3.CallOpts, anchorId, proof)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) AddOperator(opts *bind.TransactOpts, operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "addOperator", operator)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) AddOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.AddOperator(&_CertenAnchorV3.TransactOpts, operator)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) AddOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.AddOperator(&_CertenAnchorV3.TransactOpts, operator)
}

// CreateAnchor is a paid mutator transaction binding the contract method 0xcd2b226e.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) CreateAnchor(opts *bind.TransactOpts, bundleId [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "createAnchor", bundleId, operationCommitment, crossChainCommitment, governanceRoot, accumulateBlockHeight)
}

// CreateAnchor is a paid mutator transaction binding the contract method 0xcd2b226e.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) CreateAnchor(bundleId [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.CreateAnchor(&_CertenAnchorV3.TransactOpts, bundleId, operationCommitment, crossChainCommitment, governanceRoot, accumulateBlockHeight)
}

// CreateAnchor is a paid mutator transaction binding the contract method 0xcd2b226e.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) CreateAnchor(bundleId [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.CreateAnchor(&_CertenAnchorV3.TransactOpts, bundleId, operationCommitment, crossChainCommitment, governanceRoot, accumulateBlockHeight)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Transactor) ExecuteComprehensiveProof(opts *bind.TransactOpts, anchorId [32]byte, proof CertenAnchorV3CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "executeComprehensiveProof", anchorId, proof)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) ExecuteComprehensiveProof(anchorId [32]byte, proof CertenAnchorV3CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.ExecuteComprehensiveProof(&_CertenAnchorV3.TransactOpts, anchorId, proof)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) ExecuteComprehensiveProof(anchorId [32]byte, proof CertenAnchorV3CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.ExecuteComprehensiveProof(&_CertenAnchorV3.TransactOpts, anchorId, proof)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Transactor) ExecuteWithGovernance(opts *bind.TransactOpts, anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "executeWithGovernance", anchorId, target, value, data)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3Session) ExecuteWithGovernance(anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.ExecuteWithGovernance(&_CertenAnchorV3.TransactOpts, anchorId, target, value, data)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) ExecuteWithGovernance(anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.ExecuteWithGovernance(&_CertenAnchorV3.TransactOpts, anchorId, target, value, data)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) InvalidateAnchor(opts *bind.TransactOpts, anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "invalidateAnchor", anchorId)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) InvalidateAnchor(anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.InvalidateAnchor(&_CertenAnchorV3.TransactOpts, anchorId)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) InvalidateAnchor(anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.InvalidateAnchor(&_CertenAnchorV3.TransactOpts, anchorId)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) Pause() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Pause(&_CertenAnchorV3.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) Pause() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Pause(&_CertenAnchorV3.TransactOpts)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) RegisterValidator(opts *bind.TransactOpts, validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "registerValidator", validator, votingPower, blsPublicKey)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) RegisterValidator(validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RegisterValidator(&_CertenAnchorV3.TransactOpts, validator, votingPower, blsPublicKey)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) RegisterValidator(validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RegisterValidator(&_CertenAnchorV3.TransactOpts, validator, votingPower, blsPublicKey)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) RemoveOperator(opts *bind.TransactOpts, operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "removeOperator", operator)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) RemoveOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RemoveOperator(&_CertenAnchorV3.TransactOpts, operator)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) RemoveOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RemoveOperator(&_CertenAnchorV3.TransactOpts, operator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) RemoveValidator(opts *bind.TransactOpts, validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "removeValidator", validator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) RemoveValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RemoveValidator(&_CertenAnchorV3.TransactOpts, validator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) RemoveValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.RemoveValidator(&_CertenAnchorV3.TransactOpts, validator)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) SetBLSZKVerificationEnabled(opts *bind.TransactOpts, enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "setBLSZKVerificationEnabled", enabled)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) SetBLSZKVerificationEnabled(enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetBLSZKVerificationEnabled(&_CertenAnchorV3.TransactOpts, enabled)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) SetBLSZKVerificationEnabled(enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetBLSZKVerificationEnabled(&_CertenAnchorV3.TransactOpts, enabled)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) SetBLSZKVerifier(opts *bind.TransactOpts, verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "setBLSZKVerifier", verifier)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) SetBLSZKVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetBLSZKVerifier(&_CertenAnchorV3.TransactOpts, verifier)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) SetBLSZKVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetBLSZKVerifier(&_CertenAnchorV3.TransactOpts, verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) SetGovernanceVerifier(opts *bind.TransactOpts, verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "setGovernanceVerifier", verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) SetGovernanceVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetGovernanceVerifier(&_CertenAnchorV3.TransactOpts, verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) SetGovernanceVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetGovernanceVerifier(&_CertenAnchorV3.TransactOpts, verifier)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) SetMinimumGovernanceLevel(opts *bind.TransactOpts, level uint8) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "setMinimumGovernanceLevel", level)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) SetMinimumGovernanceLevel(level uint8) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetMinimumGovernanceLevel(&_CertenAnchorV3.TransactOpts, level)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) SetMinimumGovernanceLevel(level uint8) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetMinimumGovernanceLevel(&_CertenAnchorV3.TransactOpts, level)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) SetThreshold(opts *bind.TransactOpts, numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "setThreshold", numerator, denominator)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) SetThreshold(numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetThreshold(&_CertenAnchorV3.TransactOpts, numerator, denominator)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) SetThreshold(numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.SetThreshold(&_CertenAnchorV3.TransactOpts, numerator, denominator)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.TransferOwnership(&_CertenAnchorV3.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.TransferOwnership(&_CertenAnchorV3.TransactOpts, newOwner)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) Unpause() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Unpause(&_CertenAnchorV3.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) Unpause() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Unpause(&_CertenAnchorV3.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV3 *CertenAnchorV3Transactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV3.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV3 *CertenAnchorV3Session) Receive() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Receive(&_CertenAnchorV3.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV3 *CertenAnchorV3TransactorSession) Receive() (*types.Transaction, error) {
	return _CertenAnchorV3.Contract.Receive(&_CertenAnchorV3.TransactOpts)
}

// CertenAnchorV3AnchorCreatedIterator is returned from FilterAnchorCreated and is used to iterate over the raw logs and unpacked data for AnchorCreated events raised by the CertenAnchorV3 contract.
type CertenAnchorV3AnchorCreatedIterator struct {
	Event *CertenAnchorV3AnchorCreated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3AnchorCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3AnchorCreated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3AnchorCreated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3AnchorCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3AnchorCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3AnchorCreated represents a AnchorCreated event raised by the CertenAnchorV3 contract.
type CertenAnchorV3AnchorCreated struct {
	BundleId              [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Validator             common.Address
	Timestamp             *big.Int
	Raw                   types.Log // Blockchain specific contextual infos
}

// FilterAnchorCreated is a free log retrieval operation binding the contract event 0xc866200572526163e672bf703698fdca409ba4f3f75f57768a36849a43dd7ecf.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterAnchorCreated(opts *bind.FilterOpts, bundleId [][32]byte, validator []common.Address) (*CertenAnchorV3AnchorCreatedIterator, error) {

	var bundleIdRule []interface{}
	for _, bundleIdItem := range bundleId {
		bundleIdRule = append(bundleIdRule, bundleIdItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "AnchorCreated", bundleIdRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3AnchorCreatedIterator{contract: _CertenAnchorV3.contract, event: "AnchorCreated", logs: logs, sub: sub}, nil
}

// WatchAnchorCreated is a free log subscription operation binding the contract event 0xc866200572526163e672bf703698fdca409ba4f3f75f57768a36849a43dd7ecf.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchAnchorCreated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3AnchorCreated, bundleId [][32]byte, validator []common.Address) (event.Subscription, error) {

	var bundleIdRule []interface{}
	for _, bundleIdItem := range bundleId {
		bundleIdRule = append(bundleIdRule, bundleIdItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "AnchorCreated", bundleIdRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3AnchorCreated)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "AnchorCreated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAnchorCreated is a log parse operation binding the contract event 0xc866200572526163e672bf703698fdca409ba4f3f75f57768a36849a43dd7ecf.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseAnchorCreated(log types.Log) (*CertenAnchorV3AnchorCreated, error) {
	event := new(CertenAnchorV3AnchorCreated)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "AnchorCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3BLSVerificationModeUpdatedIterator is returned from FilterBLSVerificationModeUpdated and is used to iterate over the raw logs and unpacked data for BLSVerificationModeUpdated events raised by the CertenAnchorV3 contract.
type CertenAnchorV3BLSVerificationModeUpdatedIterator struct {
	Event *CertenAnchorV3BLSVerificationModeUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3BLSVerificationModeUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3BLSVerificationModeUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3BLSVerificationModeUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3BLSVerificationModeUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3BLSVerificationModeUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3BLSVerificationModeUpdated represents a BLSVerificationModeUpdated event raised by the CertenAnchorV3 contract.
type CertenAnchorV3BLSVerificationModeUpdated struct {
	ZkEnabled bool
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterBLSVerificationModeUpdated is a free log retrieval operation binding the contract event 0x80426a93f1720f7a443e949b3f8f08844cbb1973685e5cf2db0e00811801b6a8.
//
// Solidity: event BLSVerificationModeUpdated(bool zkEnabled)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterBLSVerificationModeUpdated(opts *bind.FilterOpts) (*CertenAnchorV3BLSVerificationModeUpdatedIterator, error) {

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "BLSVerificationModeUpdated")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3BLSVerificationModeUpdatedIterator{contract: _CertenAnchorV3.contract, event: "BLSVerificationModeUpdated", logs: logs, sub: sub}, nil
}

// WatchBLSVerificationModeUpdated is a free log subscription operation binding the contract event 0x80426a93f1720f7a443e949b3f8f08844cbb1973685e5cf2db0e00811801b6a8.
//
// Solidity: event BLSVerificationModeUpdated(bool zkEnabled)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchBLSVerificationModeUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3BLSVerificationModeUpdated) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "BLSVerificationModeUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3BLSVerificationModeUpdated)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "BLSVerificationModeUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBLSVerificationModeUpdated is a log parse operation binding the contract event 0x80426a93f1720f7a443e949b3f8f08844cbb1973685e5cf2db0e00811801b6a8.
//
// Solidity: event BLSVerificationModeUpdated(bool zkEnabled)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseBLSVerificationModeUpdated(log types.Log) (*CertenAnchorV3BLSVerificationModeUpdated, error) {
	event := new(CertenAnchorV3BLSVerificationModeUpdated)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "BLSVerificationModeUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3BLSVerifierUpdatedIterator is returned from FilterBLSVerifierUpdated and is used to iterate over the raw logs and unpacked data for BLSVerifierUpdated events raised by the CertenAnchorV3 contract.
type CertenAnchorV3BLSVerifierUpdatedIterator struct {
	Event *CertenAnchorV3BLSVerifierUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3BLSVerifierUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3BLSVerifierUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3BLSVerifierUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3BLSVerifierUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3BLSVerifierUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3BLSVerifierUpdated represents a BLSVerifierUpdated event raised by the CertenAnchorV3 contract.
type CertenAnchorV3BLSVerifierUpdated struct {
	OldVerifier common.Address
	NewVerifier common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterBLSVerifierUpdated is a free log retrieval operation binding the contract event 0x9952183108d9133ea2fc010fc77d2dae1427eea28a56037e6e2333a7c45330eb.
//
// Solidity: event BLSVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterBLSVerifierUpdated(opts *bind.FilterOpts, oldVerifier []common.Address, newVerifier []common.Address) (*CertenAnchorV3BLSVerifierUpdatedIterator, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "BLSVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3BLSVerifierUpdatedIterator{contract: _CertenAnchorV3.contract, event: "BLSVerifierUpdated", logs: logs, sub: sub}, nil
}

// WatchBLSVerifierUpdated is a free log subscription operation binding the contract event 0x9952183108d9133ea2fc010fc77d2dae1427eea28a56037e6e2333a7c45330eb.
//
// Solidity: event BLSVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchBLSVerifierUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3BLSVerifierUpdated, oldVerifier []common.Address, newVerifier []common.Address) (event.Subscription, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "BLSVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3BLSVerifierUpdated)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "BLSVerifierUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseBLSVerifierUpdated is a log parse operation binding the contract event 0x9952183108d9133ea2fc010fc77d2dae1427eea28a56037e6e2333a7c45330eb.
//
// Solidity: event BLSVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseBLSVerifierUpdated(log types.Log) (*CertenAnchorV3BLSVerifierUpdated, error) {
	event := new(CertenAnchorV3BLSVerifierUpdated)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "BLSVerifierUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3GovernanceExecutedIterator is returned from FilterGovernanceExecuted and is used to iterate over the raw logs and unpacked data for GovernanceExecuted events raised by the CertenAnchorV3 contract.
type CertenAnchorV3GovernanceExecutedIterator struct {
	Event *CertenAnchorV3GovernanceExecuted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3GovernanceExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3GovernanceExecuted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3GovernanceExecuted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3GovernanceExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3GovernanceExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3GovernanceExecuted represents a GovernanceExecuted event raised by the CertenAnchorV3 contract.
type CertenAnchorV3GovernanceExecuted struct {
	AnchorId  [32]byte
	Target    common.Address
	Value     *big.Int
	Success   bool
	Timestamp *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterGovernanceExecuted is a free log retrieval operation binding the contract event 0x360cff1b16f1fa5b481c344aa6535e4e085f4ba2d1a5774a786f03e0bfc03b7e.
//
// Solidity: event GovernanceExecuted(bytes32 indexed anchorId, address indexed target, uint256 value, bool success, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterGovernanceExecuted(opts *bind.FilterOpts, anchorId [][32]byte, target []common.Address) (*CertenAnchorV3GovernanceExecutedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}
	var targetRule []interface{}
	for _, targetItem := range target {
		targetRule = append(targetRule, targetItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "GovernanceExecuted", anchorIdRule, targetRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3GovernanceExecutedIterator{contract: _CertenAnchorV3.contract, event: "GovernanceExecuted", logs: logs, sub: sub}, nil
}

// WatchGovernanceExecuted is a free log subscription operation binding the contract event 0x360cff1b16f1fa5b481c344aa6535e4e085f4ba2d1a5774a786f03e0bfc03b7e.
//
// Solidity: event GovernanceExecuted(bytes32 indexed anchorId, address indexed target, uint256 value, bool success, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchGovernanceExecuted(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3GovernanceExecuted, anchorId [][32]byte, target []common.Address) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}
	var targetRule []interface{}
	for _, targetItem := range target {
		targetRule = append(targetRule, targetItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "GovernanceExecuted", anchorIdRule, targetRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3GovernanceExecuted)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "GovernanceExecuted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseGovernanceExecuted is a log parse operation binding the contract event 0x360cff1b16f1fa5b481c344aa6535e4e085f4ba2d1a5774a786f03e0bfc03b7e.
//
// Solidity: event GovernanceExecuted(bytes32 indexed anchorId, address indexed target, uint256 value, bool success, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseGovernanceExecuted(log types.Log) (*CertenAnchorV3GovernanceExecuted, error) {
	event := new(CertenAnchorV3GovernanceExecuted)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "GovernanceExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3GovernanceVerifierUpdatedIterator is returned from FilterGovernanceVerifierUpdated and is used to iterate over the raw logs and unpacked data for GovernanceVerifierUpdated events raised by the CertenAnchorV3 contract.
type CertenAnchorV3GovernanceVerifierUpdatedIterator struct {
	Event *CertenAnchorV3GovernanceVerifierUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3GovernanceVerifierUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3GovernanceVerifierUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3GovernanceVerifierUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3GovernanceVerifierUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3GovernanceVerifierUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3GovernanceVerifierUpdated represents a GovernanceVerifierUpdated event raised by the CertenAnchorV3 contract.
type CertenAnchorV3GovernanceVerifierUpdated struct {
	OldVerifier common.Address
	NewVerifier common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterGovernanceVerifierUpdated is a free log retrieval operation binding the contract event 0x22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e08407.
//
// Solidity: event GovernanceVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterGovernanceVerifierUpdated(opts *bind.FilterOpts, oldVerifier []common.Address, newVerifier []common.Address) (*CertenAnchorV3GovernanceVerifierUpdatedIterator, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "GovernanceVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3GovernanceVerifierUpdatedIterator{contract: _CertenAnchorV3.contract, event: "GovernanceVerifierUpdated", logs: logs, sub: sub}, nil
}

// WatchGovernanceVerifierUpdated is a free log subscription operation binding the contract event 0x22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e08407.
//
// Solidity: event GovernanceVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchGovernanceVerifierUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3GovernanceVerifierUpdated, oldVerifier []common.Address, newVerifier []common.Address) (event.Subscription, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "GovernanceVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3GovernanceVerifierUpdated)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "GovernanceVerifierUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseGovernanceVerifierUpdated is a log parse operation binding the contract event 0x22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e08407.
//
// Solidity: event GovernanceVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseGovernanceVerifierUpdated(log types.Log) (*CertenAnchorV3GovernanceVerifierUpdated, error) {
	event := new(CertenAnchorV3GovernanceVerifierUpdated)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "GovernanceVerifierUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3PausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the CertenAnchorV3 contract.
type CertenAnchorV3PausedIterator struct {
	Event *CertenAnchorV3Paused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3PausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3Paused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3Paused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3PausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3PausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3Paused represents a Paused event raised by the CertenAnchorV3 contract.
type CertenAnchorV3Paused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterPaused(opts *bind.FilterOpts) (*CertenAnchorV3PausedIterator, error) {

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3PausedIterator{contract: _CertenAnchorV3.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3Paused) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3Paused)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParsePaused(log types.Log) (*CertenAnchorV3Paused, error) {
	event := new(CertenAnchorV3Paused)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3ProofExecutedIterator is returned from FilterProofExecuted and is used to iterate over the raw logs and unpacked data for ProofExecuted events raised by the CertenAnchorV3 contract.
type CertenAnchorV3ProofExecutedIterator struct {
	Event *CertenAnchorV3ProofExecuted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3ProofExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3ProofExecuted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3ProofExecuted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3ProofExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3ProofExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3ProofExecuted represents a ProofExecuted event raised by the CertenAnchorV3 contract.
type CertenAnchorV3ProofExecuted struct {
	AnchorId           [32]byte
	TransactionHash    [32]byte
	MerkleVerified     bool
	BlsVerified        bool
	GovernanceVerified bool
	Timestamp          *big.Int
	Raw                types.Log // Blockchain specific contextual infos
}

// FilterProofExecuted is a free log retrieval operation binding the contract event 0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d.
//
// Solidity: event ProofExecuted(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterProofExecuted(opts *bind.FilterOpts, anchorId [][32]byte) (*CertenAnchorV3ProofExecutedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "ProofExecuted", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3ProofExecutedIterator{contract: _CertenAnchorV3.contract, event: "ProofExecuted", logs: logs, sub: sub}, nil
}

// WatchProofExecuted is a free log subscription operation binding the contract event 0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d.
//
// Solidity: event ProofExecuted(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchProofExecuted(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3ProofExecuted, anchorId [][32]byte) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "ProofExecuted", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3ProofExecuted)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "ProofExecuted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseProofExecuted is a log parse operation binding the contract event 0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d.
//
// Solidity: event ProofExecuted(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseProofExecuted(log types.Log) (*CertenAnchorV3ProofExecuted, error) {
	event := new(CertenAnchorV3ProofExecuted)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "ProofExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3ProofVerificationFailedIterator is returned from FilterProofVerificationFailed and is used to iterate over the raw logs and unpacked data for ProofVerificationFailed events raised by the CertenAnchorV3 contract.
type CertenAnchorV3ProofVerificationFailedIterator struct {
	Event *CertenAnchorV3ProofVerificationFailed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3ProofVerificationFailedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3ProofVerificationFailed)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3ProofVerificationFailed)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3ProofVerificationFailedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3ProofVerificationFailedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3ProofVerificationFailed represents a ProofVerificationFailed event raised by the CertenAnchorV3 contract.
type CertenAnchorV3ProofVerificationFailed struct {
	AnchorId           [32]byte
	TransactionHash    [32]byte
	MerkleVerified     bool
	BlsVerified        bool
	GovernanceVerified bool
	CommitmentVerified bool
	Reason             string
	Timestamp          *big.Int
	Raw                types.Log // Blockchain specific contextual infos
}

// FilterProofVerificationFailed is a free log retrieval operation binding the contract event 0x54897191894573dfd69a2c60cbaf791db5b8dde5264694c39dddfe11479d4c46.
//
// Solidity: event ProofVerificationFailed(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, bool commitmentVerified, string reason, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterProofVerificationFailed(opts *bind.FilterOpts, anchorId [][32]byte) (*CertenAnchorV3ProofVerificationFailedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "ProofVerificationFailed", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3ProofVerificationFailedIterator{contract: _CertenAnchorV3.contract, event: "ProofVerificationFailed", logs: logs, sub: sub}, nil
}

// WatchProofVerificationFailed is a free log subscription operation binding the contract event 0x54897191894573dfd69a2c60cbaf791db5b8dde5264694c39dddfe11479d4c46.
//
// Solidity: event ProofVerificationFailed(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, bool commitmentVerified, string reason, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchProofVerificationFailed(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3ProofVerificationFailed, anchorId [][32]byte) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "ProofVerificationFailed", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3ProofVerificationFailed)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "ProofVerificationFailed", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseProofVerificationFailed is a log parse operation binding the contract event 0x54897191894573dfd69a2c60cbaf791db5b8dde5264694c39dddfe11479d4c46.
//
// Solidity: event ProofVerificationFailed(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, bool commitmentVerified, string reason, uint256 timestamp)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseProofVerificationFailed(log types.Log) (*CertenAnchorV3ProofVerificationFailed, error) {
	event := new(CertenAnchorV3ProofVerificationFailed)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "ProofVerificationFailed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3ThresholdUpdatedIterator is returned from FilterThresholdUpdated and is used to iterate over the raw logs and unpacked data for ThresholdUpdated events raised by the CertenAnchorV3 contract.
type CertenAnchorV3ThresholdUpdatedIterator struct {
	Event *CertenAnchorV3ThresholdUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3ThresholdUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3ThresholdUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3ThresholdUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3ThresholdUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3ThresholdUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3ThresholdUpdated represents a ThresholdUpdated event raised by the CertenAnchorV3 contract.
type CertenAnchorV3ThresholdUpdated struct {
	OldThreshold *big.Int
	NewThreshold *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterThresholdUpdated is a free log retrieval operation binding the contract event 0xb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b.
//
// Solidity: event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterThresholdUpdated(opts *bind.FilterOpts) (*CertenAnchorV3ThresholdUpdatedIterator, error) {

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "ThresholdUpdated")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3ThresholdUpdatedIterator{contract: _CertenAnchorV3.contract, event: "ThresholdUpdated", logs: logs, sub: sub}, nil
}

// WatchThresholdUpdated is a free log subscription operation binding the contract event 0xb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b.
//
// Solidity: event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchThresholdUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3ThresholdUpdated) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "ThresholdUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3ThresholdUpdated)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "ThresholdUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseThresholdUpdated is a log parse operation binding the contract event 0xb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b.
//
// Solidity: event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseThresholdUpdated(log types.Log) (*CertenAnchorV3ThresholdUpdated, error) {
	event := new(CertenAnchorV3ThresholdUpdated)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "ThresholdUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3UnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the CertenAnchorV3 contract.
type CertenAnchorV3UnpausedIterator struct {
	Event *CertenAnchorV3Unpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3UnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3Unpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3Unpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3UnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3UnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3Unpaused represents a Unpaused event raised by the CertenAnchorV3 contract.
type CertenAnchorV3Unpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterUnpaused(opts *bind.FilterOpts) (*CertenAnchorV3UnpausedIterator, error) {

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3UnpausedIterator{contract: _CertenAnchorV3.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3Unpaused) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3Unpaused)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseUnpaused(log types.Log) (*CertenAnchorV3Unpaused, error) {
	event := new(CertenAnchorV3Unpaused)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3ValidatorRegisteredIterator is returned from FilterValidatorRegistered and is used to iterate over the raw logs and unpacked data for ValidatorRegistered events raised by the CertenAnchorV3 contract.
type CertenAnchorV3ValidatorRegisteredIterator struct {
	Event *CertenAnchorV3ValidatorRegistered // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3ValidatorRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3ValidatorRegistered)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3ValidatorRegistered)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3ValidatorRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3ValidatorRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3ValidatorRegistered represents a ValidatorRegistered event raised by the CertenAnchorV3 contract.
type CertenAnchorV3ValidatorRegistered struct {
	Validator   common.Address
	VotingPower *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterValidatorRegistered is a free log retrieval operation binding the contract event 0xb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c.
//
// Solidity: event ValidatorRegistered(address indexed validator, uint256 votingPower)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterValidatorRegistered(opts *bind.FilterOpts, validator []common.Address) (*CertenAnchorV3ValidatorRegisteredIterator, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "ValidatorRegistered", validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3ValidatorRegisteredIterator{contract: _CertenAnchorV3.contract, event: "ValidatorRegistered", logs: logs, sub: sub}, nil
}

// WatchValidatorRegistered is a free log subscription operation binding the contract event 0xb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c.
//
// Solidity: event ValidatorRegistered(address indexed validator, uint256 votingPower)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchValidatorRegistered(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3ValidatorRegistered, validator []common.Address) (event.Subscription, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "ValidatorRegistered", validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3ValidatorRegistered)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "ValidatorRegistered", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseValidatorRegistered is a log parse operation binding the contract event 0xb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c.
//
// Solidity: event ValidatorRegistered(address indexed validator, uint256 votingPower)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseValidatorRegistered(log types.Log) (*CertenAnchorV3ValidatorRegistered, error) {
	event := new(CertenAnchorV3ValidatorRegistered)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "ValidatorRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV3ValidatorRemovedIterator is returned from FilterValidatorRemoved and is used to iterate over the raw logs and unpacked data for ValidatorRemoved events raised by the CertenAnchorV3 contract.
type CertenAnchorV3ValidatorRemovedIterator struct {
	Event *CertenAnchorV3ValidatorRemoved // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *CertenAnchorV3ValidatorRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV3ValidatorRemoved)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(CertenAnchorV3ValidatorRemoved)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *CertenAnchorV3ValidatorRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV3ValidatorRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV3ValidatorRemoved represents a ValidatorRemoved event raised by the CertenAnchorV3 contract.
type CertenAnchorV3ValidatorRemoved struct {
	Validator common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterValidatorRemoved is a free log retrieval operation binding the contract event 0xe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f1.
//
// Solidity: event ValidatorRemoved(address indexed validator)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) FilterValidatorRemoved(opts *bind.FilterOpts, validator []common.Address) (*CertenAnchorV3ValidatorRemovedIterator, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.FilterLogs(opts, "ValidatorRemoved", validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV3ValidatorRemovedIterator{contract: _CertenAnchorV3.contract, event: "ValidatorRemoved", logs: logs, sub: sub}, nil
}

// WatchValidatorRemoved is a free log subscription operation binding the contract event 0xe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f1.
//
// Solidity: event ValidatorRemoved(address indexed validator)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) WatchValidatorRemoved(opts *bind.WatchOpts, sink chan<- *CertenAnchorV3ValidatorRemoved, validator []common.Address) (event.Subscription, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV3.contract.WatchLogs(opts, "ValidatorRemoved", validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV3ValidatorRemoved)
				if err := _CertenAnchorV3.contract.UnpackLog(event, "ValidatorRemoved", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseValidatorRemoved is a log parse operation binding the contract event 0xe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f1.
//
// Solidity: event ValidatorRemoved(address indexed validator)
func (_CertenAnchorV3 *CertenAnchorV3Filterer) ParseValidatorRemoved(log types.Log) (*CertenAnchorV3ValidatorRemoved, error) {
	event := new(CertenAnchorV3ValidatorRemoved)
	if err := _CertenAnchorV3.contract.UnpackLog(event, "ValidatorRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
