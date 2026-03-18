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

// CertenAnchorV4BLSProofData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4BLSProofData struct {
	AggregateSignature []byte
	ValidatorAddresses []common.Address
	VotingPowers       []*big.Int
	TotalVotingPower   *big.Int
	SignedVotingPower  *big.Int
	ThresholdMet       bool
	MessageHash        [32]byte
}

// CertenAnchorV4CertenProof is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4CertenProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof CertenAnchorV4GovernanceProofData
	BlsProof        CertenAnchorV4BLSProofData
	Commitments     CertenAnchorV4CommitmentData
	ExpirationTime  *big.Int
	Metadata        []byte
}

// CertenAnchorV4CommitmentData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4CommitmentData struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	SourceChain          string
	SourceBlockHeight    *big.Int
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        common.Address
}

// CertenAnchorV4CreateMultiLegAnchorParams is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4CreateMultiLegAnchorParams struct {
	IntentId              [32]byte
	OperationId           [32]byte
	ProofRoot             [32]byte
	TotalLegsInIntent     uint8
	AccumulateBlockHeight *big.Int
	Legs                  []CertenAnchorV4LegData
}

// CertenAnchorV4GovernanceProofData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4GovernanceProofData struct {
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

// CertenAnchorV4LegData is an auto generated low-level Go binding around an user-defined struct.
type CertenAnchorV4LegData struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}

// CertenAnchorV4MetaData contains all meta data concerning the CertenAnchorV4 contract.
var CertenAnchorV4MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"addOperator\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"anchorExists\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"anchorIds\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"anchors\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"bundleId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"adiURLHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"crossChainCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"governanceRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"valid\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"proofExecuted\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsThresholdDenominator\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsThresholdNumerator\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsZKVerificationEnabled\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"blsZKVerifier\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIBLSZKVerifier\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"createAnchor\",\"inputs\":[{\"name\":\"bundleId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"adiURLHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"crossChainCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"governanceRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"createAnchorWithLegs\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proofRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"totalLegsInIntent\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"legs\",\"type\":\"tuple[]\",\"internalType\":\"structCertenAnchorV4.LegData[]\",\"components\":[{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fromAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"toAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"assetId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"createAnchorsWithLegsBatch\",\"inputs\":[{\"name\":\"params\",\"type\":\"tuple[]\",\"internalType\":\"structCertenAnchorV4.CreateMultiLegAnchorParams[]\",\"components\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proofRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"totalLegsInIntent\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"legs\",\"type\":\"tuple[]\",\"internalType\":\"structCertenAnchorV4.LegData[]\",\"components\":[{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fromAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"toAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"assetId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}]}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeComprehensiveProof\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"tuple\",\"internalType\":\"structCertenAnchorV4.CertenProof\",\"components\":[{\"name\":\"transactionHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proofHashes\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"leafHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"governanceProof\",\"type\":\"tuple\",\"internalType\":\"structCertenAnchorV4.GovernanceProofData\",\"components\":[{\"name\":\"keyBookURL\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"keyBookRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"keyPageProofs\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"authorityAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"authorityLevel\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"requiredSignatures\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"providedSignatures\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"thresholdMet\",\"type\":\"bool\",\"internalType\":\"bool\"}]},{\"name\":\"blsProof\",\"type\":\"tuple\",\"internalType\":\"structCertenAnchorV4.BLSProofData\",\"components\":[{\"name\":\"aggregateSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"validatorAddresses\",\"type\":\"address[]\",\"internalType\":\"address[]\"},{\"name\":\"votingPowers\",\"type\":\"uint256[]\",\"internalType\":\"uint256[]\"},{\"name\":\"totalVotingPower\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"signedVotingPower\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"thresholdMet\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"messageHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"name\":\"commitments\",\"type\":\"tuple\",\"internalType\":\"structCertenAnchorV4.CommitmentData\",\"components\":[{\"name\":\"operationCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"crossChainCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"governanceRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"sourceChain\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"sourceBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"sourceTxHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"targetChain\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"targetAddress\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"name\":\"expirationTime\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"metadata\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeLegs\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleProof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"blsSignature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeSingleLeg\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeWithGovernance\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getAnchor\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"bundleId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"adiURLHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"crossChainCommitment\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"governanceRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"valid\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAnchorCount\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getBLSThresholdInfo\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getBLSValidatorInfo\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getIntentAnchor\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"operationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"totalLegsInIntent\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"legsOnThisChain\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"proofRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"verified\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getIntentCount\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getIntentLeg\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fromAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"toAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"assetId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getIntentLegCount\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getIntentLegs\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple[]\",\"internalType\":\"structCertenAnchorV4.LegData[]\",\"components\":[{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fromAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"toAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"assetId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getMerkleProofForAdiURL\",\"inputs\":[{\"name\":\"bundleId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getTotalLegsAnchored\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getValidatorCount\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"governanceVerifier\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIGovernanceVerifier\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"intentAnchors\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"operationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"totalLegsInIntent\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"legsOnThisChain\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"proofRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"verified\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"intentExists\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"intentIds\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"intentLegs\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fromAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"toAddress\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"assetId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"executed\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"invalidateAnchor\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"invalidateIntent\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"isCommitmentUsed\",\"inputs\":[{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isLegExecuted\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"legId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isNonceUsed\",\"inputs\":[{\"name\":\"authority\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"legExecuted\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"minimumGovernanceLevel\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"operators\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"pause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"paused\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registerValidator\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"votingPower\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"blsPublicKey\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeOperator\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeValidator\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setBLSZKVerificationEnabled\",\"inputs\":[{\"name\":\"enabled\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setBLSZKVerifier\",\"inputs\":[{\"name\":\"verifier\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setGovernanceVerifier\",\"inputs\":[{\"name\":\"verifier\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setMinimumGovernanceLevel\",\"inputs\":[{\"name\":\"level\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setThreshold\",\"inputs\":[{\"name\":\"numerator\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"denominator\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"totalAnchors\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalIntentAnchors\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalLegsAnchored\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalProofsExecuted\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalVotingPower\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"unpause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"usedCommitments\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"usedNonces\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"usedOperationIds\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"validatorAnchorCounts\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"validatorList\",\"inputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"validators\",\"inputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"registered\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"votingPower\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"blsPublicKey\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"registeredAt\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyBLSSignature\",\"inputs\":[{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"messageHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"verifyProof\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"merkleProof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"leaf\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"AnchorCreated\",\"inputs\":[{\"name\":\"bundleId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"adiURLHash\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"operationCommitment\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"crossChainCommitment\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"governanceRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"accumulateBlockHeight\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"validator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"GovernanceExecuted\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"target\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"success\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"GovernanceVerifierUpdated\",\"inputs\":[{\"name\":\"oldVerifier\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newVerifier\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"LegAnchored\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"legId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"legIndex\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"toAddress\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"MultiLegAnchorCreated\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"operationId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"totalLegsInIntent\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"legsOnThisChain\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"proofRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"validator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"MultiLegProofExecuted\",\"inputs\":[{\"name\":\"intentId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"legsExecuted\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"verified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Paused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ProofExecuted\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"transactionHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"merkleVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"blsVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"governanceVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ProofVerificationFailed\",\"inputs\":[{\"name\":\"anchorId\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"transactionHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"merkleVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"blsVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"governanceVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"commitmentVerified\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"},{\"name\":\"reason\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"},{\"name\":\"timestamp\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ThresholdUpdated\",\"inputs\":[{\"name\":\"oldThreshold\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"newThreshold\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Unpaused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ValidatorRegistered\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"votingPower\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"ValidatorRemoved\",\"inputs\":[{\"name\":\"validator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"EnforcedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ExpectedPause\",\"inputs\":[]}]",
}

// CertenAnchorV4ABI is the input ABI used to generate the binding from.
// Deprecated: Use CertenAnchorV4MetaData.ABI instead.
var CertenAnchorV4ABI = CertenAnchorV4MetaData.ABI

// CertenAnchorV4 is an auto generated Go binding around an Ethereum contract.
type CertenAnchorV4 struct {
	CertenAnchorV4Caller     // Read-only binding to the contract
	CertenAnchorV4Transactor // Write-only binding to the contract
	CertenAnchorV4Filterer   // Log filterer for contract events
}

// CertenAnchorV4Caller is an auto generated read-only Go binding around an Ethereum contract.
type CertenAnchorV4Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV4Transactor is an auto generated write-only Go binding around an Ethereum contract.
type CertenAnchorV4Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV4Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type CertenAnchorV4Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// CertenAnchorV4Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type CertenAnchorV4Session struct {
	Contract     *CertenAnchorV4   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// CertenAnchorV4CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type CertenAnchorV4CallerSession struct {
	Contract *CertenAnchorV4Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// CertenAnchorV4TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type CertenAnchorV4TransactorSession struct {
	Contract     *CertenAnchorV4Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// CertenAnchorV4Raw is an auto generated low-level Go binding around an Ethereum contract.
type CertenAnchorV4Raw struct {
	Contract *CertenAnchorV4 // Generic contract binding to access the raw methods on
}

// CertenAnchorV4CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type CertenAnchorV4CallerRaw struct {
	Contract *CertenAnchorV4Caller // Generic read-only contract binding to access the raw methods on
}

// CertenAnchorV4TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type CertenAnchorV4TransactorRaw struct {
	Contract *CertenAnchorV4Transactor // Generic write-only contract binding to access the raw methods on
}

// NewCertenAnchorV4 creates a new instance of CertenAnchorV4, bound to a specific deployed contract.
func NewCertenAnchorV4(address common.Address, backend bind.ContractBackend) (*CertenAnchorV4, error) {
	contract, err := bindCertenAnchorV4(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4{CertenAnchorV4Caller: CertenAnchorV4Caller{contract: contract}, CertenAnchorV4Transactor: CertenAnchorV4Transactor{contract: contract}, CertenAnchorV4Filterer: CertenAnchorV4Filterer{contract: contract}}, nil
}

// NewCertenAnchorV4Caller creates a new read-only instance of CertenAnchorV4, bound to a specific deployed contract.
func NewCertenAnchorV4Caller(address common.Address, caller bind.ContractCaller) (*CertenAnchorV4Caller, error) {
	contract, err := bindCertenAnchorV4(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4Caller{contract: contract}, nil
}

// NewCertenAnchorV4Transactor creates a new write-only instance of CertenAnchorV4, bound to a specific deployed contract.
func NewCertenAnchorV4Transactor(address common.Address, transactor bind.ContractTransactor) (*CertenAnchorV4Transactor, error) {
	contract, err := bindCertenAnchorV4(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4Transactor{contract: contract}, nil
}

// NewCertenAnchorV4Filterer creates a new log filterer instance of CertenAnchorV4, bound to a specific deployed contract.
func NewCertenAnchorV4Filterer(address common.Address, filterer bind.ContractFilterer) (*CertenAnchorV4Filterer, error) {
	contract, err := bindCertenAnchorV4(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4Filterer{contract: contract}, nil
}

// bindCertenAnchorV4 binds a generic wrapper to an already deployed contract.
func bindCertenAnchorV4(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV4 *CertenAnchorV4Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV4.Contract.CertenAnchorV4Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV4 *CertenAnchorV4Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CertenAnchorV4Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV4 *CertenAnchorV4Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CertenAnchorV4Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_CertenAnchorV4 *CertenAnchorV4CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _CertenAnchorV4.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_CertenAnchorV4 *CertenAnchorV4TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_CertenAnchorV4 *CertenAnchorV4TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.contract.Transact(opts, method, params...)
}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) AnchorExists(opts *bind.CallOpts, anchorId [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "anchorExists", anchorId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) AnchorExists(anchorId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.AnchorExists(&_CertenAnchorV4.CallOpts, anchorId)
}

// AnchorExists is a free data retrieval call binding the contract method 0xaf9cedbb.
//
// Solidity: function anchorExists(bytes32 anchorId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) AnchorExists(anchorId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.AnchorExists(&_CertenAnchorV4.CallOpts, anchorId)
}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4Caller) AnchorIds(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "anchorIds", arg0)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4Session) AnchorIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV4.Contract.AnchorIds(&_CertenAnchorV4.CallOpts, arg0)
}

// AnchorIds is a free data retrieval call binding the contract method 0x1074f191.
//
// Solidity: function anchorIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) AnchorIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV4.Contract.AnchorIds(&_CertenAnchorV4.CallOpts, arg0)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV4 *CertenAnchorV4Caller) Anchors(opts *bind.CallOpts, arg0 [32]byte) (struct {
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
	ProofExecuted         bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "anchors", arg0)

	outstruct := new(struct {
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
		ProofExecuted         bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BundleId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.MerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.AdiURLHash = *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	outstruct.OperationCommitment = *abi.ConvertType(out[3], new([32]byte)).(*[32]byte)
	outstruct.CrossChainCommitment = *abi.ConvertType(out[4], new([32]byte)).(*[32]byte)
	outstruct.GovernanceRoot = *abi.ConvertType(out[5], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[7], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[8], new(common.Address)).(*common.Address)
	outstruct.Valid = *abi.ConvertType(out[9], new(bool)).(*bool)
	outstruct.ProofExecuted = *abi.ConvertType(out[10], new(bool)).(*bool)

	return *outstruct, err

}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV4 *CertenAnchorV4Session) Anchors(arg0 [32]byte) (struct {
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
	ProofExecuted         bool
}, error) {
	return _CertenAnchorV4.Contract.Anchors(&_CertenAnchorV4.CallOpts, arg0)
}

// Anchors is a free data retrieval call binding the contract method 0xb01b6d53.
//
// Solidity: function anchors(bytes32 ) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid, bool proofExecuted)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) Anchors(arg0 [32]byte) (struct {
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
	ProofExecuted         bool
}, error) {
	return _CertenAnchorV4.Contract.Anchors(&_CertenAnchorV4.CallOpts, arg0)
}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) BlsThresholdDenominator(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "blsThresholdDenominator")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) BlsThresholdDenominator() (*big.Int, error) {
	return _CertenAnchorV4.Contract.BlsThresholdDenominator(&_CertenAnchorV4.CallOpts)
}

// BlsThresholdDenominator is a free data retrieval call binding the contract method 0x3197fec5.
//
// Solidity: function blsThresholdDenominator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) BlsThresholdDenominator() (*big.Int, error) {
	return _CertenAnchorV4.Contract.BlsThresholdDenominator(&_CertenAnchorV4.CallOpts)
}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) BlsThresholdNumerator(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "blsThresholdNumerator")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) BlsThresholdNumerator() (*big.Int, error) {
	return _CertenAnchorV4.Contract.BlsThresholdNumerator(&_CertenAnchorV4.CallOpts)
}

// BlsThresholdNumerator is a free data retrieval call binding the contract method 0xd400939f.
//
// Solidity: function blsThresholdNumerator() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) BlsThresholdNumerator() (*big.Int, error) {
	return _CertenAnchorV4.Contract.BlsThresholdNumerator(&_CertenAnchorV4.CallOpts)
}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) BlsZKVerificationEnabled(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "blsZKVerificationEnabled")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) BlsZKVerificationEnabled() (bool, error) {
	return _CertenAnchorV4.Contract.BlsZKVerificationEnabled(&_CertenAnchorV4.CallOpts)
}

// BlsZKVerificationEnabled is a free data retrieval call binding the contract method 0xb855002f.
//
// Solidity: function blsZKVerificationEnabled() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) BlsZKVerificationEnabled() (bool, error) {
	return _CertenAnchorV4.Contract.BlsZKVerificationEnabled(&_CertenAnchorV4.CallOpts)
}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Caller) BlsZKVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "blsZKVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Session) BlsZKVerifier() (common.Address, error) {
	return _CertenAnchorV4.Contract.BlsZKVerifier(&_CertenAnchorV4.CallOpts)
}

// BlsZKVerifier is a free data retrieval call binding the contract method 0x7caeac00.
//
// Solidity: function blsZKVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) BlsZKVerifier() (common.Address, error) {
	return _CertenAnchorV4.Contract.BlsZKVerifier(&_CertenAnchorV4.CallOpts)
}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetAnchor(opts *bind.CallOpts, anchorId [32]byte) (struct {
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
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getAnchor", anchorId)

	outstruct := new(struct {
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
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BundleId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.MerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.AdiURLHash = *abi.ConvertType(out[2], new([32]byte)).(*[32]byte)
	outstruct.OperationCommitment = *abi.ConvertType(out[3], new([32]byte)).(*[32]byte)
	outstruct.CrossChainCommitment = *abi.ConvertType(out[4], new([32]byte)).(*[32]byte)
	outstruct.GovernanceRoot = *abi.ConvertType(out[5], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[7], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[8], new(common.Address)).(*common.Address)
	outstruct.Valid = *abi.ConvertType(out[9], new(bool)).(*bool)

	return *outstruct, err

}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetAnchor(anchorId [32]byte) (struct {
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
}, error) {
	return _CertenAnchorV4.Contract.GetAnchor(&_CertenAnchorV4.CallOpts, anchorId)
}

// GetAnchor is a free data retrieval call binding the contract method 0x7feb51d9.
//
// Solidity: function getAnchor(bytes32 anchorId) view returns(bytes32 bundleId, bytes32 merkleRoot, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool valid)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetAnchor(anchorId [32]byte) (struct {
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
}, error) {
	return _CertenAnchorV4.Contract.GetAnchor(&_CertenAnchorV4.CallOpts, anchorId)
}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetAnchorCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getAnchorCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetAnchorCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetAnchorCount(&_CertenAnchorV4.CallOpts)
}

// GetAnchorCount is a free data retrieval call binding the contract method 0xd3182bed.
//
// Solidity: function getAnchorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetAnchorCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetAnchorCount(&_CertenAnchorV4.CallOpts)
}

// GetBLSThresholdInfo is a free data retrieval call binding the contract method 0x7ee832a3.
//
// Solidity: function getBLSThresholdInfo() view returns(uint256, uint256, uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetBLSThresholdInfo(opts *bind.CallOpts) (*big.Int, *big.Int, *big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getBLSThresholdInfo")

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
func (_CertenAnchorV4 *CertenAnchorV4Session) GetBLSThresholdInfo() (*big.Int, *big.Int, *big.Int, error) {
	return _CertenAnchorV4.Contract.GetBLSThresholdInfo(&_CertenAnchorV4.CallOpts)
}

// GetBLSThresholdInfo is a free data retrieval call binding the contract method 0x7ee832a3.
//
// Solidity: function getBLSThresholdInfo() view returns(uint256, uint256, uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetBLSThresholdInfo() (*big.Int, *big.Int, *big.Int, error) {
	return _CertenAnchorV4.Contract.GetBLSThresholdInfo(&_CertenAnchorV4.CallOpts)
}

// GetBLSValidatorInfo is a free data retrieval call binding the contract method 0xd8ca9380.
//
// Solidity: function getBLSValidatorInfo(address validator) view returns(bool, uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetBLSValidatorInfo(opts *bind.CallOpts, validator common.Address) (bool, *big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getBLSValidatorInfo", validator)

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
func (_CertenAnchorV4 *CertenAnchorV4Session) GetBLSValidatorInfo(validator common.Address) (bool, *big.Int, error) {
	return _CertenAnchorV4.Contract.GetBLSValidatorInfo(&_CertenAnchorV4.CallOpts, validator)
}

// GetBLSValidatorInfo is a free data retrieval call binding the contract method 0xd8ca9380.
//
// Solidity: function getBLSValidatorInfo(address validator) view returns(bool, uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetBLSValidatorInfo(validator common.Address) (bool, *big.Int, error) {
	return _CertenAnchorV4.Contract.GetBLSValidatorInfo(&_CertenAnchorV4.CallOpts, validator)
}

// GetIntentAnchor is a free data retrieval call binding the contract method 0x53139139.
//
// Solidity: function getIntentAnchor(bytes32 intentId) view returns(bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetIntentAnchor(opts *bind.CallOpts, intentId [32]byte) (struct {
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getIntentAnchor", intentId)

	outstruct := new(struct {
		OperationId           [32]byte
		TotalLegsInIntent     uint8
		LegsOnThisChain       uint8
		ProofRoot             [32]byte
		AccumulateBlockHeight *big.Int
		Timestamp             *big.Int
		Validator             common.Address
		Verified              bool
		Executed              bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.OperationId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.TotalLegsInIntent = *abi.ConvertType(out[1], new(uint8)).(*uint8)
	outstruct.LegsOnThisChain = *abi.ConvertType(out[2], new(uint8)).(*uint8)
	outstruct.ProofRoot = *abi.ConvertType(out[3], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[6], new(common.Address)).(*common.Address)
	outstruct.Verified = *abi.ConvertType(out[7], new(bool)).(*bool)
	outstruct.Executed = *abi.ConvertType(out[8], new(bool)).(*bool)

	return *outstruct, err

}

// GetIntentAnchor is a free data retrieval call binding the contract method 0x53139139.
//
// Solidity: function getIntentAnchor(bytes32 intentId) view returns(bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetIntentAnchor(intentId [32]byte) (struct {
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	return _CertenAnchorV4.Contract.GetIntentAnchor(&_CertenAnchorV4.CallOpts, intentId)
}

// GetIntentAnchor is a free data retrieval call binding the contract method 0x53139139.
//
// Solidity: function getIntentAnchor(bytes32 intentId) view returns(bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetIntentAnchor(intentId [32]byte) (struct {
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	return _CertenAnchorV4.Contract.GetIntentAnchor(&_CertenAnchorV4.CallOpts, intentId)
}

// GetIntentCount is a free data retrieval call binding the contract method 0x0e1f4b89.
//
// Solidity: function getIntentCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetIntentCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getIntentCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetIntentCount is a free data retrieval call binding the contract method 0x0e1f4b89.
//
// Solidity: function getIntentCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetIntentCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetIntentCount(&_CertenAnchorV4.CallOpts)
}

// GetIntentCount is a free data retrieval call binding the contract method 0x0e1f4b89.
//
// Solidity: function getIntentCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetIntentCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetIntentCount(&_CertenAnchorV4.CallOpts)
}

// GetIntentLeg is a free data retrieval call binding the contract method 0xe343c263.
//
// Solidity: function getIntentLeg(bytes32 intentId, uint256 index) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetIntentLeg(opts *bind.CallOpts, intentId [32]byte, index *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getIntentLeg", intentId, index)

	outstruct := new(struct {
		LegId       [32]byte
		LegIndex    uint8
		FromAddress common.Address
		ToAddress   common.Address
		Amount      *big.Int
		AssetId     [32]byte
		Executed    bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.LegId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.LegIndex = *abi.ConvertType(out[1], new(uint8)).(*uint8)
	outstruct.FromAddress = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.ToAddress = *abi.ConvertType(out[3], new(common.Address)).(*common.Address)
	outstruct.Amount = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)
	outstruct.AssetId = *abi.ConvertType(out[5], new([32]byte)).(*[32]byte)
	outstruct.Executed = *abi.ConvertType(out[6], new(bool)).(*bool)

	return *outstruct, err

}

// GetIntentLeg is a free data retrieval call binding the contract method 0xe343c263.
//
// Solidity: function getIntentLeg(bytes32 intentId, uint256 index) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetIntentLeg(intentId [32]byte, index *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	return _CertenAnchorV4.Contract.GetIntentLeg(&_CertenAnchorV4.CallOpts, intentId, index)
}

// GetIntentLeg is a free data retrieval call binding the contract method 0xe343c263.
//
// Solidity: function getIntentLeg(bytes32 intentId, uint256 index) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetIntentLeg(intentId [32]byte, index *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	return _CertenAnchorV4.Contract.GetIntentLeg(&_CertenAnchorV4.CallOpts, intentId, index)
}

// GetIntentLegCount is a free data retrieval call binding the contract method 0xd5d66e84.
//
// Solidity: function getIntentLegCount(bytes32 intentId) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetIntentLegCount(opts *bind.CallOpts, intentId [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getIntentLegCount", intentId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetIntentLegCount is a free data retrieval call binding the contract method 0xd5d66e84.
//
// Solidity: function getIntentLegCount(bytes32 intentId) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetIntentLegCount(intentId [32]byte) (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetIntentLegCount(&_CertenAnchorV4.CallOpts, intentId)
}

// GetIntentLegCount is a free data retrieval call binding the contract method 0xd5d66e84.
//
// Solidity: function getIntentLegCount(bytes32 intentId) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetIntentLegCount(intentId [32]byte) (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetIntentLegCount(&_CertenAnchorV4.CallOpts, intentId)
}

// GetIntentLegs is a free data retrieval call binding the contract method 0xf2287ff3.
//
// Solidity: function getIntentLegs(bytes32 intentId) view returns((bytes32,uint8,address,address,uint256,bytes32,bool)[])
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetIntentLegs(opts *bind.CallOpts, intentId [32]byte) ([]CertenAnchorV4LegData, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getIntentLegs", intentId)

	if err != nil {
		return *new([]CertenAnchorV4LegData), err
	}

	out0 := *abi.ConvertType(out[0], new([]CertenAnchorV4LegData)).(*[]CertenAnchorV4LegData)

	return out0, err

}

// GetIntentLegs is a free data retrieval call binding the contract method 0xf2287ff3.
//
// Solidity: function getIntentLegs(bytes32 intentId) view returns((bytes32,uint8,address,address,uint256,bytes32,bool)[])
func (_CertenAnchorV4 *CertenAnchorV4Session) GetIntentLegs(intentId [32]byte) ([]CertenAnchorV4LegData, error) {
	return _CertenAnchorV4.Contract.GetIntentLegs(&_CertenAnchorV4.CallOpts, intentId)
}

// GetIntentLegs is a free data retrieval call binding the contract method 0xf2287ff3.
//
// Solidity: function getIntentLegs(bytes32 intentId) view returns((bytes32,uint8,address,address,uint256,bytes32,bool)[])
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetIntentLegs(intentId [32]byte) ([]CertenAnchorV4LegData, error) {
	return _CertenAnchorV4.Contract.GetIntentLegs(&_CertenAnchorV4.CallOpts, intentId)
}

// GetMerkleProofForAdiURL is a free data retrieval call binding the contract method 0x0355f9a8.
//
// Solidity: function getMerkleProofForAdiURL(bytes32 bundleId) view returns(bytes32[])
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetMerkleProofForAdiURL(opts *bind.CallOpts, bundleId [32]byte) ([][32]byte, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getMerkleProofForAdiURL", bundleId)

	if err != nil {
		return *new([][32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([][32]byte)).(*[][32]byte)

	return out0, err

}

// GetMerkleProofForAdiURL is a free data retrieval call binding the contract method 0x0355f9a8.
//
// Solidity: function getMerkleProofForAdiURL(bytes32 bundleId) view returns(bytes32[])
func (_CertenAnchorV4 *CertenAnchorV4Session) GetMerkleProofForAdiURL(bundleId [32]byte) ([][32]byte, error) {
	return _CertenAnchorV4.Contract.GetMerkleProofForAdiURL(&_CertenAnchorV4.CallOpts, bundleId)
}

// GetMerkleProofForAdiURL is a free data retrieval call binding the contract method 0x0355f9a8.
//
// Solidity: function getMerkleProofForAdiURL(bytes32 bundleId) view returns(bytes32[])
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetMerkleProofForAdiURL(bundleId [32]byte) ([][32]byte, error) {
	return _CertenAnchorV4.Contract.GetMerkleProofForAdiURL(&_CertenAnchorV4.CallOpts, bundleId)
}

// GetTotalLegsAnchored is a free data retrieval call binding the contract method 0xbe03ded3.
//
// Solidity: function getTotalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetTotalLegsAnchored(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getTotalLegsAnchored")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetTotalLegsAnchored is a free data retrieval call binding the contract method 0xbe03ded3.
//
// Solidity: function getTotalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetTotalLegsAnchored() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetTotalLegsAnchored(&_CertenAnchorV4.CallOpts)
}

// GetTotalLegsAnchored is a free data retrieval call binding the contract method 0xbe03ded3.
//
// Solidity: function getTotalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetTotalLegsAnchored() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetTotalLegsAnchored(&_CertenAnchorV4.CallOpts)
}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GetValidatorCount(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "getValidatorCount")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) GetValidatorCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetValidatorCount(&_CertenAnchorV4.CallOpts)
}

// GetValidatorCount is a free data retrieval call binding the contract method 0x7071688a.
//
// Solidity: function getValidatorCount() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GetValidatorCount() (*big.Int, error) {
	return _CertenAnchorV4.Contract.GetValidatorCount(&_CertenAnchorV4.CallOpts)
}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Caller) GovernanceVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "governanceVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Session) GovernanceVerifier() (common.Address, error) {
	return _CertenAnchorV4.Contract.GovernanceVerifier(&_CertenAnchorV4.CallOpts)
}

// GovernanceVerifier is a free data retrieval call binding the contract method 0xb6202f3a.
//
// Solidity: function governanceVerifier() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) GovernanceVerifier() (common.Address, error) {
	return _CertenAnchorV4.Contract.GovernanceVerifier(&_CertenAnchorV4.CallOpts)
}

// IntentAnchors is a free data retrieval call binding the contract method 0xc70dd3cd.
//
// Solidity: function intentAnchors(bytes32 ) view returns(bytes32 intentId, bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IntentAnchors(opts *bind.CallOpts, arg0 [32]byte) (struct {
	IntentId              [32]byte
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "intentAnchors", arg0)

	outstruct := new(struct {
		IntentId              [32]byte
		OperationId           [32]byte
		TotalLegsInIntent     uint8
		LegsOnThisChain       uint8
		ProofRoot             [32]byte
		AccumulateBlockHeight *big.Int
		Timestamp             *big.Int
		Validator             common.Address
		Verified              bool
		Executed              bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.IntentId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.OperationId = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.TotalLegsInIntent = *abi.ConvertType(out[2], new(uint8)).(*uint8)
	outstruct.LegsOnThisChain = *abi.ConvertType(out[3], new(uint8)).(*uint8)
	outstruct.ProofRoot = *abi.ConvertType(out[4], new([32]byte)).(*[32]byte)
	outstruct.AccumulateBlockHeight = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.Timestamp = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.Validator = *abi.ConvertType(out[7], new(common.Address)).(*common.Address)
	outstruct.Verified = *abi.ConvertType(out[8], new(bool)).(*bool)
	outstruct.Executed = *abi.ConvertType(out[9], new(bool)).(*bool)

	return *outstruct, err

}

// IntentAnchors is a free data retrieval call binding the contract method 0xc70dd3cd.
//
// Solidity: function intentAnchors(bytes32 ) view returns(bytes32 intentId, bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Session) IntentAnchors(arg0 [32]byte) (struct {
	IntentId              [32]byte
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	return _CertenAnchorV4.Contract.IntentAnchors(&_CertenAnchorV4.CallOpts, arg0)
}

// IntentAnchors is a free data retrieval call binding the contract method 0xc70dd3cd.
//
// Solidity: function intentAnchors(bytes32 ) view returns(bytes32 intentId, bytes32 operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, uint256 accumulateBlockHeight, uint256 timestamp, address validator, bool verified, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IntentAnchors(arg0 [32]byte) (struct {
	IntentId              [32]byte
	OperationId           [32]byte
	TotalLegsInIntent     uint8
	LegsOnThisChain       uint8
	ProofRoot             [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Verified              bool
	Executed              bool
}, error) {
	return _CertenAnchorV4.Contract.IntentAnchors(&_CertenAnchorV4.CallOpts, arg0)
}

// IntentExists is a free data retrieval call binding the contract method 0x9e028794.
//
// Solidity: function intentExists(bytes32 intentId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IntentExists(opts *bind.CallOpts, intentId [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "intentExists", intentId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IntentExists is a free data retrieval call binding the contract method 0x9e028794.
//
// Solidity: function intentExists(bytes32 intentId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) IntentExists(intentId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IntentExists(&_CertenAnchorV4.CallOpts, intentId)
}

// IntentExists is a free data retrieval call binding the contract method 0x9e028794.
//
// Solidity: function intentExists(bytes32 intentId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IntentExists(intentId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IntentExists(&_CertenAnchorV4.CallOpts, intentId)
}

// IntentIds is a free data retrieval call binding the contract method 0x2bd5d26e.
//
// Solidity: function intentIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IntentIds(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "intentIds", arg0)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// IntentIds is a free data retrieval call binding the contract method 0x2bd5d26e.
//
// Solidity: function intentIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4Session) IntentIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV4.Contract.IntentIds(&_CertenAnchorV4.CallOpts, arg0)
}

// IntentIds is a free data retrieval call binding the contract method 0x2bd5d26e.
//
// Solidity: function intentIds(uint256 ) view returns(bytes32)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IntentIds(arg0 *big.Int) ([32]byte, error) {
	return _CertenAnchorV4.Contract.IntentIds(&_CertenAnchorV4.CallOpts, arg0)
}

// IntentLegs is a free data retrieval call binding the contract method 0x05e69f4d.
//
// Solidity: function intentLegs(bytes32 , uint256 ) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IntentLegs(opts *bind.CallOpts, arg0 [32]byte, arg1 *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "intentLegs", arg0, arg1)

	outstruct := new(struct {
		LegId       [32]byte
		LegIndex    uint8
		FromAddress common.Address
		ToAddress   common.Address
		Amount      *big.Int
		AssetId     [32]byte
		Executed    bool
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.LegId = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.LegIndex = *abi.ConvertType(out[1], new(uint8)).(*uint8)
	outstruct.FromAddress = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.ToAddress = *abi.ConvertType(out[3], new(common.Address)).(*common.Address)
	outstruct.Amount = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)
	outstruct.AssetId = *abi.ConvertType(out[5], new([32]byte)).(*[32]byte)
	outstruct.Executed = *abi.ConvertType(out[6], new(bool)).(*bool)

	return *outstruct, err

}

// IntentLegs is a free data retrieval call binding the contract method 0x05e69f4d.
//
// Solidity: function intentLegs(bytes32 , uint256 ) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4Session) IntentLegs(arg0 [32]byte, arg1 *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	return _CertenAnchorV4.Contract.IntentLegs(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// IntentLegs is a free data retrieval call binding the contract method 0x05e69f4d.
//
// Solidity: function intentLegs(bytes32 , uint256 ) view returns(bytes32 legId, uint8 legIndex, address fromAddress, address toAddress, uint256 amount, bytes32 assetId, bool executed)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IntentLegs(arg0 [32]byte, arg1 *big.Int) (struct {
	LegId       [32]byte
	LegIndex    uint8
	FromAddress common.Address
	ToAddress   common.Address
	Amount      *big.Int
	AssetId     [32]byte
	Executed    bool
}, error) {
	return _CertenAnchorV4.Contract.IntentLegs(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IsCommitmentUsed(opts *bind.CallOpts, commitmentHash [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "isCommitmentUsed", commitmentHash)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) IsCommitmentUsed(commitmentHash [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IsCommitmentUsed(&_CertenAnchorV4.CallOpts, commitmentHash)
}

// IsCommitmentUsed is a free data retrieval call binding the contract method 0xb61b395c.
//
// Solidity: function isCommitmentUsed(bytes32 commitmentHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IsCommitmentUsed(commitmentHash [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IsCommitmentUsed(&_CertenAnchorV4.CallOpts, commitmentHash)
}

// IsLegExecuted is a free data retrieval call binding the contract method 0xb9939f4a.
//
// Solidity: function isLegExecuted(bytes32 intentId, bytes32 legId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IsLegExecuted(opts *bind.CallOpts, intentId [32]byte, legId [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "isLegExecuted", intentId, legId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsLegExecuted is a free data retrieval call binding the contract method 0xb9939f4a.
//
// Solidity: function isLegExecuted(bytes32 intentId, bytes32 legId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) IsLegExecuted(intentId [32]byte, legId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IsLegExecuted(&_CertenAnchorV4.CallOpts, intentId, legId)
}

// IsLegExecuted is a free data retrieval call binding the contract method 0xb9939f4a.
//
// Solidity: function isLegExecuted(bytes32 intentId, bytes32 legId) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IsLegExecuted(intentId [32]byte, legId [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.IsLegExecuted(&_CertenAnchorV4.CallOpts, intentId, legId)
}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) IsNonceUsed(opts *bind.CallOpts, authority common.Address, nonce *big.Int) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "isNonceUsed", authority, nonce)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) IsNonceUsed(authority common.Address, nonce *big.Int) (bool, error) {
	return _CertenAnchorV4.Contract.IsNonceUsed(&_CertenAnchorV4.CallOpts, authority, nonce)
}

// IsNonceUsed is a free data retrieval call binding the contract method 0xcab7e8eb.
//
// Solidity: function isNonceUsed(address authority, uint256 nonce) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) IsNonceUsed(authority common.Address, nonce *big.Int) (bool, error) {
	return _CertenAnchorV4.Contract.IsNonceUsed(&_CertenAnchorV4.CallOpts, authority, nonce)
}

// LegExecuted is a free data retrieval call binding the contract method 0x3e944576.
//
// Solidity: function legExecuted(bytes32 , bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) LegExecuted(opts *bind.CallOpts, arg0 [32]byte, arg1 [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "legExecuted", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// LegExecuted is a free data retrieval call binding the contract method 0x3e944576.
//
// Solidity: function legExecuted(bytes32 , bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) LegExecuted(arg0 [32]byte, arg1 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.LegExecuted(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// LegExecuted is a free data retrieval call binding the contract method 0x3e944576.
//
// Solidity: function legExecuted(bytes32 , bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) LegExecuted(arg0 [32]byte, arg1 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.LegExecuted(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV4 *CertenAnchorV4Caller) MinimumGovernanceLevel(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "minimumGovernanceLevel")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV4 *CertenAnchorV4Session) MinimumGovernanceLevel() (uint8, error) {
	return _CertenAnchorV4.Contract.MinimumGovernanceLevel(&_CertenAnchorV4.CallOpts)
}

// MinimumGovernanceLevel is a free data retrieval call binding the contract method 0x0219b983.
//
// Solidity: function minimumGovernanceLevel() view returns(uint8)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) MinimumGovernanceLevel() (uint8, error) {
	return _CertenAnchorV4.Contract.MinimumGovernanceLevel(&_CertenAnchorV4.CallOpts)
}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) Operators(opts *bind.CallOpts, arg0 common.Address) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "operators", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) Operators(arg0 common.Address) (bool, error) {
	return _CertenAnchorV4.Contract.Operators(&_CertenAnchorV4.CallOpts, arg0)
}

// Operators is a free data retrieval call binding the contract method 0x13e7c9d8.
//
// Solidity: function operators(address ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) Operators(arg0 common.Address) (bool, error) {
	return _CertenAnchorV4.Contract.Operators(&_CertenAnchorV4.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Caller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Session) Owner() (common.Address, error) {
	return _CertenAnchorV4.Contract.Owner(&_CertenAnchorV4.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) Owner() (common.Address, error) {
	return _CertenAnchorV4.Contract.Owner(&_CertenAnchorV4.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) Paused() (bool, error) {
	return _CertenAnchorV4.Contract.Paused(&_CertenAnchorV4.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) Paused() (bool, error) {
	return _CertenAnchorV4.Contract.Paused(&_CertenAnchorV4.CallOpts)
}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) TotalAnchors(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "totalAnchors")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) TotalAnchors() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalAnchors(&_CertenAnchorV4.CallOpts)
}

// TotalAnchors is a free data retrieval call binding the contract method 0x9ffb4635.
//
// Solidity: function totalAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) TotalAnchors() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalAnchors(&_CertenAnchorV4.CallOpts)
}

// TotalIntentAnchors is a free data retrieval call binding the contract method 0x7e18b89d.
//
// Solidity: function totalIntentAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) TotalIntentAnchors(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "totalIntentAnchors")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalIntentAnchors is a free data retrieval call binding the contract method 0x7e18b89d.
//
// Solidity: function totalIntentAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) TotalIntentAnchors() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalIntentAnchors(&_CertenAnchorV4.CallOpts)
}

// TotalIntentAnchors is a free data retrieval call binding the contract method 0x7e18b89d.
//
// Solidity: function totalIntentAnchors() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) TotalIntentAnchors() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalIntentAnchors(&_CertenAnchorV4.CallOpts)
}

// TotalLegsAnchored is a free data retrieval call binding the contract method 0x53432b91.
//
// Solidity: function totalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) TotalLegsAnchored(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "totalLegsAnchored")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalLegsAnchored is a free data retrieval call binding the contract method 0x53432b91.
//
// Solidity: function totalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) TotalLegsAnchored() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalLegsAnchored(&_CertenAnchorV4.CallOpts)
}

// TotalLegsAnchored is a free data retrieval call binding the contract method 0x53432b91.
//
// Solidity: function totalLegsAnchored() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) TotalLegsAnchored() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalLegsAnchored(&_CertenAnchorV4.CallOpts)
}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) TotalProofsExecuted(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "totalProofsExecuted")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) TotalProofsExecuted() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalProofsExecuted(&_CertenAnchorV4.CallOpts)
}

// TotalProofsExecuted is a free data retrieval call binding the contract method 0x981e2d9b.
//
// Solidity: function totalProofsExecuted() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) TotalProofsExecuted() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalProofsExecuted(&_CertenAnchorV4.CallOpts)
}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) TotalVotingPower(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "totalVotingPower")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) TotalVotingPower() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalVotingPower(&_CertenAnchorV4.CallOpts)
}

// TotalVotingPower is a free data retrieval call binding the contract method 0x671b3793.
//
// Solidity: function totalVotingPower() view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) TotalVotingPower() (*big.Int, error) {
	return _CertenAnchorV4.Contract.TotalVotingPower(&_CertenAnchorV4.CallOpts)
}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) UsedCommitments(opts *bind.CallOpts, arg0 [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "usedCommitments", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) UsedCommitments(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.UsedCommitments(&_CertenAnchorV4.CallOpts, arg0)
}

// UsedCommitments is a free data retrieval call binding the contract method 0x91402039.
//
// Solidity: function usedCommitments(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) UsedCommitments(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.UsedCommitments(&_CertenAnchorV4.CallOpts, arg0)
}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) UsedNonces(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "usedNonces", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) UsedNonces(arg0 common.Address, arg1 *big.Int) (bool, error) {
	return _CertenAnchorV4.Contract.UsedNonces(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// UsedNonces is a free data retrieval call binding the contract method 0x6a8a6894.
//
// Solidity: function usedNonces(address , uint256 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) UsedNonces(arg0 common.Address, arg1 *big.Int) (bool, error) {
	return _CertenAnchorV4.Contract.UsedNonces(&_CertenAnchorV4.CallOpts, arg0, arg1)
}

// UsedOperationIds is a free data retrieval call binding the contract method 0x3ffeea08.
//
// Solidity: function usedOperationIds(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) UsedOperationIds(opts *bind.CallOpts, arg0 [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "usedOperationIds", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// UsedOperationIds is a free data retrieval call binding the contract method 0x3ffeea08.
//
// Solidity: function usedOperationIds(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) UsedOperationIds(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.UsedOperationIds(&_CertenAnchorV4.CallOpts, arg0)
}

// UsedOperationIds is a free data retrieval call binding the contract method 0x3ffeea08.
//
// Solidity: function usedOperationIds(bytes32 ) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) UsedOperationIds(arg0 [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.UsedOperationIds(&_CertenAnchorV4.CallOpts, arg0)
}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Caller) ValidatorAnchorCounts(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "validatorAnchorCounts", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4Session) ValidatorAnchorCounts(arg0 common.Address) (*big.Int, error) {
	return _CertenAnchorV4.Contract.ValidatorAnchorCounts(&_CertenAnchorV4.CallOpts, arg0)
}

// ValidatorAnchorCounts is a free data retrieval call binding the contract method 0x69c9fd90.
//
// Solidity: function validatorAnchorCounts(address ) view returns(uint256)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) ValidatorAnchorCounts(arg0 common.Address) (*big.Int, error) {
	return _CertenAnchorV4.Contract.ValidatorAnchorCounts(&_CertenAnchorV4.CallOpts, arg0)
}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Caller) ValidatorList(opts *bind.CallOpts, arg0 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "validatorList", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4Session) ValidatorList(arg0 *big.Int) (common.Address, error) {
	return _CertenAnchorV4.Contract.ValidatorList(&_CertenAnchorV4.CallOpts, arg0)
}

// ValidatorList is a free data retrieval call binding the contract method 0xb048e056.
//
// Solidity: function validatorList(uint256 ) view returns(address)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) ValidatorList(arg0 *big.Int) (common.Address, error) {
	return _CertenAnchorV4.Contract.ValidatorList(&_CertenAnchorV4.CallOpts, arg0)
}

// Validators is a free data retrieval call binding the contract method 0xfa52c7d8.
//
// Solidity: function validators(address ) view returns(bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)
func (_CertenAnchorV4 *CertenAnchorV4Caller) Validators(opts *bind.CallOpts, arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "validators", arg0)

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
func (_CertenAnchorV4 *CertenAnchorV4Session) Validators(arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	return _CertenAnchorV4.Contract.Validators(&_CertenAnchorV4.CallOpts, arg0)
}

// Validators is a free data retrieval call binding the contract method 0xfa52c7d8.
//
// Solidity: function validators(address ) view returns(bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) Validators(arg0 common.Address) (struct {
	Registered   bool
	VotingPower  *big.Int
	BlsPublicKey []byte
	RegisteredAt *big.Int
}, error) {
	return _CertenAnchorV4.Contract.Validators(&_CertenAnchorV4.CallOpts, arg0)
}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) VerifyBLSSignature(opts *bind.CallOpts, signature []byte, messageHash [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "verifyBLSSignature", signature, messageHash)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) VerifyBLSSignature(signature []byte, messageHash [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.VerifyBLSSignature(&_CertenAnchorV4.CallOpts, signature, messageHash)
}

// VerifyBLSSignature is a free data retrieval call binding the contract method 0x7574f758.
//
// Solidity: function verifyBLSSignature(bytes signature, bytes32 messageHash) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) VerifyBLSSignature(signature []byte, messageHash [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.VerifyBLSSignature(&_CertenAnchorV4.CallOpts, signature, messageHash)
}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 anchorId, bytes32[] merkleProof, bytes32 leaf) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Caller) VerifyProof(opts *bind.CallOpts, anchorId [32]byte, merkleProof [][32]byte, leaf [32]byte) (bool, error) {
	var out []interface{}
	err := _CertenAnchorV4.contract.Call(opts, &out, "verifyProof", anchorId, merkleProof, leaf)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 anchorId, bytes32[] merkleProof, bytes32 leaf) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) VerifyProof(anchorId [32]byte, merkleProof [][32]byte, leaf [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.VerifyProof(&_CertenAnchorV4.CallOpts, anchorId, merkleProof, leaf)
}

// VerifyProof is a free data retrieval call binding the contract method 0x58161a42.
//
// Solidity: function verifyProof(bytes32 anchorId, bytes32[] merkleProof, bytes32 leaf) view returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4CallerSession) VerifyProof(anchorId [32]byte, merkleProof [][32]byte, leaf [32]byte) (bool, error) {
	return _CertenAnchorV4.Contract.VerifyProof(&_CertenAnchorV4.CallOpts, anchorId, merkleProof, leaf)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) AddOperator(opts *bind.TransactOpts, operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "addOperator", operator)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) AddOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.AddOperator(&_CertenAnchorV4.TransactOpts, operator)
}

// AddOperator is a paid mutator transaction binding the contract method 0x9870d7fe.
//
// Solidity: function addOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) AddOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.AddOperator(&_CertenAnchorV4.TransactOpts, operator)
}

// CreateAnchor is a paid mutator transaction binding the contract method.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, bytes32 executionCommitment, uint256 accumulateBlockHeight) returns()
// CRITICAL-001: Added executionCommitment parameter for runtime payload binding
func (_CertenAnchorV4 *CertenAnchorV4Transactor) CreateAnchor(opts *bind.TransactOpts, bundleId [32]byte, adiURLHash [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, executionCommitment [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "createAnchor", bundleId, adiURLHash, operationCommitment, crossChainCommitment, governanceRoot, executionCommitment, accumulateBlockHeight)
}

// CreateAnchor is a paid mutator transaction binding the contract method.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, bytes32 executionCommitment, uint256 accumulateBlockHeight) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) CreateAnchor(bundleId [32]byte, adiURLHash [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, executionCommitment [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchor(&_CertenAnchorV4.TransactOpts, bundleId, adiURLHash, operationCommitment, crossChainCommitment, governanceRoot, executionCommitment, accumulateBlockHeight)
}

// CreateAnchor is a paid mutator transaction binding the contract method.
//
// Solidity: function createAnchor(bytes32 bundleId, bytes32 adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, bytes32 executionCommitment, uint256 accumulateBlockHeight) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) CreateAnchor(bundleId [32]byte, adiURLHash [32]byte, operationCommitment [32]byte, crossChainCommitment [32]byte, governanceRoot [32]byte, executionCommitment [32]byte, accumulateBlockHeight *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchor(&_CertenAnchorV4.TransactOpts, bundleId, adiURLHash, operationCommitment, crossChainCommitment, governanceRoot, executionCommitment, accumulateBlockHeight)
}

// CreateAnchorWithLegs is a paid mutator transaction binding the contract method 0x4de02c79.
//
// Solidity: function createAnchorWithLegs(bytes32 intentId, bytes32 operationId, bytes32 proofRoot, uint8 totalLegsInIntent, uint256 accumulateBlockHeight, (bytes32,uint8,address,address,uint256,bytes32,bool)[] legs) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) CreateAnchorWithLegs(opts *bind.TransactOpts, intentId [32]byte, operationId [32]byte, proofRoot [32]byte, totalLegsInIntent uint8, accumulateBlockHeight *big.Int, legs []CertenAnchorV4LegData) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "createAnchorWithLegs", intentId, operationId, proofRoot, totalLegsInIntent, accumulateBlockHeight, legs)
}

// CreateAnchorWithLegs is a paid mutator transaction binding the contract method 0x4de02c79.
//
// Solidity: function createAnchorWithLegs(bytes32 intentId, bytes32 operationId, bytes32 proofRoot, uint8 totalLegsInIntent, uint256 accumulateBlockHeight, (bytes32,uint8,address,address,uint256,bytes32,bool)[] legs) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) CreateAnchorWithLegs(intentId [32]byte, operationId [32]byte, proofRoot [32]byte, totalLegsInIntent uint8, accumulateBlockHeight *big.Int, legs []CertenAnchorV4LegData) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchorWithLegs(&_CertenAnchorV4.TransactOpts, intentId, operationId, proofRoot, totalLegsInIntent, accumulateBlockHeight, legs)
}

// CreateAnchorWithLegs is a paid mutator transaction binding the contract method 0x4de02c79.
//
// Solidity: function createAnchorWithLegs(bytes32 intentId, bytes32 operationId, bytes32 proofRoot, uint8 totalLegsInIntent, uint256 accumulateBlockHeight, (bytes32,uint8,address,address,uint256,bytes32,bool)[] legs) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) CreateAnchorWithLegs(intentId [32]byte, operationId [32]byte, proofRoot [32]byte, totalLegsInIntent uint8, accumulateBlockHeight *big.Int, legs []CertenAnchorV4LegData) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchorWithLegs(&_CertenAnchorV4.TransactOpts, intentId, operationId, proofRoot, totalLegsInIntent, accumulateBlockHeight, legs)
}

// CreateAnchorsWithLegsBatch is a paid mutator transaction binding the contract method 0x9cd5d3fc.
//
// Solidity: function createAnchorsWithLegsBatch((bytes32,bytes32,bytes32,uint8,uint256,(bytes32,uint8,address,address,uint256,bytes32,bool)[])[] params) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) CreateAnchorsWithLegsBatch(opts *bind.TransactOpts, params []CertenAnchorV4CreateMultiLegAnchorParams) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "createAnchorsWithLegsBatch", params)
}

// CreateAnchorsWithLegsBatch is a paid mutator transaction binding the contract method 0x9cd5d3fc.
//
// Solidity: function createAnchorsWithLegsBatch((bytes32,bytes32,bytes32,uint8,uint256,(bytes32,uint8,address,address,uint256,bytes32,bool)[])[] params) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) CreateAnchorsWithLegsBatch(params []CertenAnchorV4CreateMultiLegAnchorParams) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchorsWithLegsBatch(&_CertenAnchorV4.TransactOpts, params)
}

// CreateAnchorsWithLegsBatch is a paid mutator transaction binding the contract method 0x9cd5d3fc.
//
// Solidity: function createAnchorsWithLegsBatch((bytes32,bytes32,bytes32,uint8,uint256,(bytes32,uint8,address,address,uint256,bytes32,bool)[])[] params) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) CreateAnchorsWithLegsBatch(params []CertenAnchorV4CreateMultiLegAnchorParams) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.CreateAnchorsWithLegsBatch(&_CertenAnchorV4.TransactOpts, params)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Transactor) ExecuteComprehensiveProof(opts *bind.TransactOpts, anchorId [32]byte, proof CertenAnchorV4CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "executeComprehensiveProof", anchorId, proof)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) ExecuteComprehensiveProof(anchorId [32]byte, proof CertenAnchorV4CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteComprehensiveProof(&_CertenAnchorV4.TransactOpts, anchorId, proof)
}

// ExecuteComprehensiveProof is a paid mutator transaction binding the contract method 0x46882a50.
//
// Solidity: function executeComprehensiveProof(bytes32 anchorId, (bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes) proof) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) ExecuteComprehensiveProof(anchorId [32]byte, proof CertenAnchorV4CertenProof) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteComprehensiveProof(&_CertenAnchorV4.TransactOpts, anchorId, proof)
}

// ExecuteLegs is a paid mutator transaction binding the contract method 0xf8fe6dcc.
//
// Solidity: function executeLegs(bytes32 intentId, bytes32[] merkleProof, bytes blsSignature) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Transactor) ExecuteLegs(opts *bind.TransactOpts, intentId [32]byte, merkleProof [][32]byte, blsSignature []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "executeLegs", intentId, merkleProof, blsSignature)
}

// ExecuteLegs is a paid mutator transaction binding the contract method 0xf8fe6dcc.
//
// Solidity: function executeLegs(bytes32 intentId, bytes32[] merkleProof, bytes blsSignature) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) ExecuteLegs(intentId [32]byte, merkleProof [][32]byte, blsSignature []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteLegs(&_CertenAnchorV4.TransactOpts, intentId, merkleProof, blsSignature)
}

// ExecuteLegs is a paid mutator transaction binding the contract method 0xf8fe6dcc.
//
// Solidity: function executeLegs(bytes32 intentId, bytes32[] merkleProof, bytes blsSignature) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) ExecuteLegs(intentId [32]byte, merkleProof [][32]byte, blsSignature []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteLegs(&_CertenAnchorV4.TransactOpts, intentId, merkleProof, blsSignature)
}

// ExecuteSingleLeg is a paid mutator transaction binding the contract method 0xd1c605fc.
//
// Solidity: function executeSingleLeg(bytes32 intentId, bytes32 legId) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Transactor) ExecuteSingleLeg(opts *bind.TransactOpts, intentId [32]byte, legId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "executeSingleLeg", intentId, legId)
}

// ExecuteSingleLeg is a paid mutator transaction binding the contract method 0xd1c605fc.
//
// Solidity: function executeSingleLeg(bytes32 intentId, bytes32 legId) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) ExecuteSingleLeg(intentId [32]byte, legId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteSingleLeg(&_CertenAnchorV4.TransactOpts, intentId, legId)
}

// ExecuteSingleLeg is a paid mutator transaction binding the contract method 0xd1c605fc.
//
// Solidity: function executeSingleLeg(bytes32 intentId, bytes32 legId) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) ExecuteSingleLeg(intentId [32]byte, legId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteSingleLeg(&_CertenAnchorV4.TransactOpts, intentId, legId)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Transactor) ExecuteWithGovernance(opts *bind.TransactOpts, anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "executeWithGovernance", anchorId, target, value, data)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4Session) ExecuteWithGovernance(anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteWithGovernance(&_CertenAnchorV4.TransactOpts, anchorId, target, value, data)
}

// ExecuteWithGovernance is a paid mutator transaction binding the contract method 0x2897eb55.
//
// Solidity: function executeWithGovernance(bytes32 anchorId, address target, uint256 value, bytes data) returns(bool)
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) ExecuteWithGovernance(anchorId [32]byte, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.ExecuteWithGovernance(&_CertenAnchorV4.TransactOpts, anchorId, target, value, data)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) InvalidateAnchor(opts *bind.TransactOpts, anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "invalidateAnchor", anchorId)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) InvalidateAnchor(anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.InvalidateAnchor(&_CertenAnchorV4.TransactOpts, anchorId)
}

// InvalidateAnchor is a paid mutator transaction binding the contract method 0x5817562b.
//
// Solidity: function invalidateAnchor(bytes32 anchorId) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) InvalidateAnchor(anchorId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.InvalidateAnchor(&_CertenAnchorV4.TransactOpts, anchorId)
}

// InvalidateIntent is a paid mutator transaction binding the contract method 0x6d223efd.
//
// Solidity: function invalidateIntent(bytes32 intentId) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) InvalidateIntent(opts *bind.TransactOpts, intentId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "invalidateIntent", intentId)
}

// InvalidateIntent is a paid mutator transaction binding the contract method 0x6d223efd.
//
// Solidity: function invalidateIntent(bytes32 intentId) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) InvalidateIntent(intentId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.InvalidateIntent(&_CertenAnchorV4.TransactOpts, intentId)
}

// InvalidateIntent is a paid mutator transaction binding the contract method 0x6d223efd.
//
// Solidity: function invalidateIntent(bytes32 intentId) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) InvalidateIntent(intentId [32]byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.InvalidateIntent(&_CertenAnchorV4.TransactOpts, intentId)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) Pause() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Pause(&_CertenAnchorV4.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) Pause() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Pause(&_CertenAnchorV4.TransactOpts)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) RegisterValidator(opts *bind.TransactOpts, validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "registerValidator", validator, votingPower, blsPublicKey)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) RegisterValidator(validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RegisterValidator(&_CertenAnchorV4.TransactOpts, validator, votingPower, blsPublicKey)
}

// RegisterValidator is a paid mutator transaction binding the contract method 0x3e83a283.
//
// Solidity: function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) RegisterValidator(validator common.Address, votingPower *big.Int, blsPublicKey []byte) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RegisterValidator(&_CertenAnchorV4.TransactOpts, validator, votingPower, blsPublicKey)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) RemoveOperator(opts *bind.TransactOpts, operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "removeOperator", operator)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) RemoveOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RemoveOperator(&_CertenAnchorV4.TransactOpts, operator)
}

// RemoveOperator is a paid mutator transaction binding the contract method 0xac8a584a.
//
// Solidity: function removeOperator(address operator) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) RemoveOperator(operator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RemoveOperator(&_CertenAnchorV4.TransactOpts, operator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) RemoveValidator(opts *bind.TransactOpts, validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "removeValidator", validator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) RemoveValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RemoveValidator(&_CertenAnchorV4.TransactOpts, validator)
}

// RemoveValidator is a paid mutator transaction binding the contract method 0x40a141ff.
//
// Solidity: function removeValidator(address validator) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) RemoveValidator(validator common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.RemoveValidator(&_CertenAnchorV4.TransactOpts, validator)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) SetBLSZKVerificationEnabled(opts *bind.TransactOpts, enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "setBLSZKVerificationEnabled", enabled)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) SetBLSZKVerificationEnabled(enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetBLSZKVerificationEnabled(&_CertenAnchorV4.TransactOpts, enabled)
}

// SetBLSZKVerificationEnabled is a paid mutator transaction binding the contract method 0x8dd58e59.
//
// Solidity: function setBLSZKVerificationEnabled(bool enabled) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) SetBLSZKVerificationEnabled(enabled bool) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetBLSZKVerificationEnabled(&_CertenAnchorV4.TransactOpts, enabled)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) SetBLSZKVerifier(opts *bind.TransactOpts, verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "setBLSZKVerifier", verifier)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) SetBLSZKVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetBLSZKVerifier(&_CertenAnchorV4.TransactOpts, verifier)
}

// SetBLSZKVerifier is a paid mutator transaction binding the contract method 0xf46c2d0a.
//
// Solidity: function setBLSZKVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) SetBLSZKVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetBLSZKVerifier(&_CertenAnchorV4.TransactOpts, verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) SetGovernanceVerifier(opts *bind.TransactOpts, verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "setGovernanceVerifier", verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) SetGovernanceVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetGovernanceVerifier(&_CertenAnchorV4.TransactOpts, verifier)
}

// SetGovernanceVerifier is a paid mutator transaction binding the contract method 0xf66fc314.
//
// Solidity: function setGovernanceVerifier(address verifier) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) SetGovernanceVerifier(verifier common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetGovernanceVerifier(&_CertenAnchorV4.TransactOpts, verifier)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) SetMinimumGovernanceLevel(opts *bind.TransactOpts, level uint8) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "setMinimumGovernanceLevel", level)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) SetMinimumGovernanceLevel(level uint8) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetMinimumGovernanceLevel(&_CertenAnchorV4.TransactOpts, level)
}

// SetMinimumGovernanceLevel is a paid mutator transaction binding the contract method 0xd68ac7fc.
//
// Solidity: function setMinimumGovernanceLevel(uint8 level) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) SetMinimumGovernanceLevel(level uint8) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetMinimumGovernanceLevel(&_CertenAnchorV4.TransactOpts, level)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) SetThreshold(opts *bind.TransactOpts, numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "setThreshold", numerator, denominator)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) SetThreshold(numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetThreshold(&_CertenAnchorV4.TransactOpts, numerator, denominator)
}

// SetThreshold is a paid mutator transaction binding the contract method 0xb9c36209.
//
// Solidity: function setThreshold(uint256 numerator, uint256 denominator) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) SetThreshold(numerator *big.Int, denominator *big.Int) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.SetThreshold(&_CertenAnchorV4.TransactOpts, numerator, denominator)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.TransferOwnership(&_CertenAnchorV4.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.TransferOwnership(&_CertenAnchorV4.TransactOpts, newOwner)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) Unpause() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Unpause(&_CertenAnchorV4.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) Unpause() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Unpause(&_CertenAnchorV4.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV4 *CertenAnchorV4Transactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _CertenAnchorV4.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV4 *CertenAnchorV4Session) Receive() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Receive(&_CertenAnchorV4.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_CertenAnchorV4 *CertenAnchorV4TransactorSession) Receive() (*types.Transaction, error) {
	return _CertenAnchorV4.Contract.Receive(&_CertenAnchorV4.TransactOpts)
}

// CertenAnchorV4AnchorCreatedIterator is returned from FilterAnchorCreated and is used to iterate over the raw logs and unpacked data for AnchorCreated events raised by the CertenAnchorV4 contract.
type CertenAnchorV4AnchorCreatedIterator struct {
	Event *CertenAnchorV4AnchorCreated // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4AnchorCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4AnchorCreated)
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
		it.Event = new(CertenAnchorV4AnchorCreated)
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
func (it *CertenAnchorV4AnchorCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4AnchorCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4AnchorCreated represents a AnchorCreated event raised by the CertenAnchorV4 contract.
type CertenAnchorV4AnchorCreated struct {
	BundleId              [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	AccumulateBlockHeight *big.Int
	Validator             common.Address
	Timestamp             *big.Int
	Raw                   types.Log // Blockchain specific contextual infos
}

// FilterAnchorCreated is a free log retrieval operation binding the contract event 0x46487f77044b5e5bfff1a083e910ca498562341d3190e3ef79530c95da62bc5e.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 indexed adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterAnchorCreated(opts *bind.FilterOpts, bundleId [][32]byte, adiURLHash [][32]byte, validator []common.Address) (*CertenAnchorV4AnchorCreatedIterator, error) {

	var bundleIdRule []interface{}
	for _, bundleIdItem := range bundleId {
		bundleIdRule = append(bundleIdRule, bundleIdItem)
	}
	var adiURLHashRule []interface{}
	for _, adiURLHashItem := range adiURLHash {
		adiURLHashRule = append(adiURLHashRule, adiURLHashItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "AnchorCreated", bundleIdRule, adiURLHashRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4AnchorCreatedIterator{contract: _CertenAnchorV4.contract, event: "AnchorCreated", logs: logs, sub: sub}, nil
}

// WatchAnchorCreated is a free log subscription operation binding the contract event 0x46487f77044b5e5bfff1a083e910ca498562341d3190e3ef79530c95da62bc5e.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 indexed adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchAnchorCreated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4AnchorCreated, bundleId [][32]byte, adiURLHash [][32]byte, validator []common.Address) (event.Subscription, error) {

	var bundleIdRule []interface{}
	for _, bundleIdItem := range bundleId {
		bundleIdRule = append(bundleIdRule, bundleIdItem)
	}
	var adiURLHashRule []interface{}
	for _, adiURLHashItem := range adiURLHash {
		adiURLHashRule = append(adiURLHashRule, adiURLHashItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "AnchorCreated", bundleIdRule, adiURLHashRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4AnchorCreated)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "AnchorCreated", log); err != nil {
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

// ParseAnchorCreated is a log parse operation binding the contract event 0x46487f77044b5e5bfff1a083e910ca498562341d3190e3ef79530c95da62bc5e.
//
// Solidity: event AnchorCreated(bytes32 indexed bundleId, bytes32 indexed adiURLHash, bytes32 operationCommitment, bytes32 crossChainCommitment, bytes32 governanceRoot, uint256 accumulateBlockHeight, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseAnchorCreated(log types.Log) (*CertenAnchorV4AnchorCreated, error) {
	event := new(CertenAnchorV4AnchorCreated)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "AnchorCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4GovernanceExecutedIterator is returned from FilterGovernanceExecuted and is used to iterate over the raw logs and unpacked data for GovernanceExecuted events raised by the CertenAnchorV4 contract.
type CertenAnchorV4GovernanceExecutedIterator struct {
	Event *CertenAnchorV4GovernanceExecuted // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4GovernanceExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4GovernanceExecuted)
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
		it.Event = new(CertenAnchorV4GovernanceExecuted)
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
func (it *CertenAnchorV4GovernanceExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4GovernanceExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4GovernanceExecuted represents a GovernanceExecuted event raised by the CertenAnchorV4 contract.
type CertenAnchorV4GovernanceExecuted struct {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterGovernanceExecuted(opts *bind.FilterOpts, anchorId [][32]byte, target []common.Address) (*CertenAnchorV4GovernanceExecutedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}
	var targetRule []interface{}
	for _, targetItem := range target {
		targetRule = append(targetRule, targetItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "GovernanceExecuted", anchorIdRule, targetRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4GovernanceExecutedIterator{contract: _CertenAnchorV4.contract, event: "GovernanceExecuted", logs: logs, sub: sub}, nil
}

// WatchGovernanceExecuted is a free log subscription operation binding the contract event 0x360cff1b16f1fa5b481c344aa6535e4e085f4ba2d1a5774a786f03e0bfc03b7e.
//
// Solidity: event GovernanceExecuted(bytes32 indexed anchorId, address indexed target, uint256 value, bool success, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchGovernanceExecuted(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4GovernanceExecuted, anchorId [][32]byte, target []common.Address) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}
	var targetRule []interface{}
	for _, targetItem := range target {
		targetRule = append(targetRule, targetItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "GovernanceExecuted", anchorIdRule, targetRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4GovernanceExecuted)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "GovernanceExecuted", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseGovernanceExecuted(log types.Log) (*CertenAnchorV4GovernanceExecuted, error) {
	event := new(CertenAnchorV4GovernanceExecuted)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "GovernanceExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4GovernanceVerifierUpdatedIterator is returned from FilterGovernanceVerifierUpdated and is used to iterate over the raw logs and unpacked data for GovernanceVerifierUpdated events raised by the CertenAnchorV4 contract.
type CertenAnchorV4GovernanceVerifierUpdatedIterator struct {
	Event *CertenAnchorV4GovernanceVerifierUpdated // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4GovernanceVerifierUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4GovernanceVerifierUpdated)
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
		it.Event = new(CertenAnchorV4GovernanceVerifierUpdated)
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
func (it *CertenAnchorV4GovernanceVerifierUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4GovernanceVerifierUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4GovernanceVerifierUpdated represents a GovernanceVerifierUpdated event raised by the CertenAnchorV4 contract.
type CertenAnchorV4GovernanceVerifierUpdated struct {
	OldVerifier common.Address
	NewVerifier common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterGovernanceVerifierUpdated is a free log retrieval operation binding the contract event 0x22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e08407.
//
// Solidity: event GovernanceVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterGovernanceVerifierUpdated(opts *bind.FilterOpts, oldVerifier []common.Address, newVerifier []common.Address) (*CertenAnchorV4GovernanceVerifierUpdatedIterator, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "GovernanceVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4GovernanceVerifierUpdatedIterator{contract: _CertenAnchorV4.contract, event: "GovernanceVerifierUpdated", logs: logs, sub: sub}, nil
}

// WatchGovernanceVerifierUpdated is a free log subscription operation binding the contract event 0x22f0af8e812b6db4e042632ece0645ffed2e3ed7c201b496637e6f9217e08407.
//
// Solidity: event GovernanceVerifierUpdated(address indexed oldVerifier, address indexed newVerifier)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchGovernanceVerifierUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4GovernanceVerifierUpdated, oldVerifier []common.Address, newVerifier []common.Address) (event.Subscription, error) {

	var oldVerifierRule []interface{}
	for _, oldVerifierItem := range oldVerifier {
		oldVerifierRule = append(oldVerifierRule, oldVerifierItem)
	}
	var newVerifierRule []interface{}
	for _, newVerifierItem := range newVerifier {
		newVerifierRule = append(newVerifierRule, newVerifierItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "GovernanceVerifierUpdated", oldVerifierRule, newVerifierRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4GovernanceVerifierUpdated)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "GovernanceVerifierUpdated", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseGovernanceVerifierUpdated(log types.Log) (*CertenAnchorV4GovernanceVerifierUpdated, error) {
	event := new(CertenAnchorV4GovernanceVerifierUpdated)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "GovernanceVerifierUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4LegAnchoredIterator is returned from FilterLegAnchored and is used to iterate over the raw logs and unpacked data for LegAnchored events raised by the CertenAnchorV4 contract.
type CertenAnchorV4LegAnchoredIterator struct {
	Event *CertenAnchorV4LegAnchored // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4LegAnchoredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4LegAnchored)
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
		it.Event = new(CertenAnchorV4LegAnchored)
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
func (it *CertenAnchorV4LegAnchoredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4LegAnchoredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4LegAnchored represents a LegAnchored event raised by the CertenAnchorV4 contract.
type CertenAnchorV4LegAnchored struct {
	IntentId  [32]byte
	LegId     [32]byte
	LegIndex  uint8
	ToAddress common.Address
	Amount    *big.Int
	Timestamp *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterLegAnchored is a free log retrieval operation binding the contract event 0x8c38e138d6525f44c6034fbe84f4aac489ad760bf8991b266d65a250def0397e.
//
// Solidity: event LegAnchored(bytes32 indexed intentId, bytes32 indexed legId, uint8 legIndex, address toAddress, uint256 amount, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterLegAnchored(opts *bind.FilterOpts, intentId [][32]byte, legId [][32]byte) (*CertenAnchorV4LegAnchoredIterator, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}
	var legIdRule []interface{}
	for _, legIdItem := range legId {
		legIdRule = append(legIdRule, legIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "LegAnchored", intentIdRule, legIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4LegAnchoredIterator{contract: _CertenAnchorV4.contract, event: "LegAnchored", logs: logs, sub: sub}, nil
}

// WatchLegAnchored is a free log subscription operation binding the contract event 0x8c38e138d6525f44c6034fbe84f4aac489ad760bf8991b266d65a250def0397e.
//
// Solidity: event LegAnchored(bytes32 indexed intentId, bytes32 indexed legId, uint8 legIndex, address toAddress, uint256 amount, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchLegAnchored(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4LegAnchored, intentId [][32]byte, legId [][32]byte) (event.Subscription, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}
	var legIdRule []interface{}
	for _, legIdItem := range legId {
		legIdRule = append(legIdRule, legIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "LegAnchored", intentIdRule, legIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4LegAnchored)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "LegAnchored", log); err != nil {
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

// ParseLegAnchored is a log parse operation binding the contract event 0x8c38e138d6525f44c6034fbe84f4aac489ad760bf8991b266d65a250def0397e.
//
// Solidity: event LegAnchored(bytes32 indexed intentId, bytes32 indexed legId, uint8 legIndex, address toAddress, uint256 amount, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseLegAnchored(log types.Log) (*CertenAnchorV4LegAnchored, error) {
	event := new(CertenAnchorV4LegAnchored)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "LegAnchored", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4MultiLegAnchorCreatedIterator is returned from FilterMultiLegAnchorCreated and is used to iterate over the raw logs and unpacked data for MultiLegAnchorCreated events raised by the CertenAnchorV4 contract.
type CertenAnchorV4MultiLegAnchorCreatedIterator struct {
	Event *CertenAnchorV4MultiLegAnchorCreated // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4MultiLegAnchorCreatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4MultiLegAnchorCreated)
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
		it.Event = new(CertenAnchorV4MultiLegAnchorCreated)
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
func (it *CertenAnchorV4MultiLegAnchorCreatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4MultiLegAnchorCreatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4MultiLegAnchorCreated represents a MultiLegAnchorCreated event raised by the CertenAnchorV4 contract.
type CertenAnchorV4MultiLegAnchorCreated struct {
	IntentId          [32]byte
	OperationId       [32]byte
	TotalLegsInIntent uint8
	LegsOnThisChain   uint8
	ProofRoot         [32]byte
	Validator         common.Address
	Timestamp         *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterMultiLegAnchorCreated is a free log retrieval operation binding the contract event 0x81bb03a90d87fa561adb0b1912ed84801ddfa59023e3532314bf6a6faafc8744.
//
// Solidity: event MultiLegAnchorCreated(bytes32 indexed intentId, bytes32 indexed operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterMultiLegAnchorCreated(opts *bind.FilterOpts, intentId [][32]byte, operationId [][32]byte, validator []common.Address) (*CertenAnchorV4MultiLegAnchorCreatedIterator, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}
	var operationIdRule []interface{}
	for _, operationIdItem := range operationId {
		operationIdRule = append(operationIdRule, operationIdItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "MultiLegAnchorCreated", intentIdRule, operationIdRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4MultiLegAnchorCreatedIterator{contract: _CertenAnchorV4.contract, event: "MultiLegAnchorCreated", logs: logs, sub: sub}, nil
}

// WatchMultiLegAnchorCreated is a free log subscription operation binding the contract event 0x81bb03a90d87fa561adb0b1912ed84801ddfa59023e3532314bf6a6faafc8744.
//
// Solidity: event MultiLegAnchorCreated(bytes32 indexed intentId, bytes32 indexed operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchMultiLegAnchorCreated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4MultiLegAnchorCreated, intentId [][32]byte, operationId [][32]byte, validator []common.Address) (event.Subscription, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}
	var operationIdRule []interface{}
	for _, operationIdItem := range operationId {
		operationIdRule = append(operationIdRule, operationIdItem)
	}

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "MultiLegAnchorCreated", intentIdRule, operationIdRule, validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4MultiLegAnchorCreated)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "MultiLegAnchorCreated", log); err != nil {
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

// ParseMultiLegAnchorCreated is a log parse operation binding the contract event 0x81bb03a90d87fa561adb0b1912ed84801ddfa59023e3532314bf6a6faafc8744.
//
// Solidity: event MultiLegAnchorCreated(bytes32 indexed intentId, bytes32 indexed operationId, uint8 totalLegsInIntent, uint8 legsOnThisChain, bytes32 proofRoot, address indexed validator, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseMultiLegAnchorCreated(log types.Log) (*CertenAnchorV4MultiLegAnchorCreated, error) {
	event := new(CertenAnchorV4MultiLegAnchorCreated)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "MultiLegAnchorCreated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4MultiLegProofExecutedIterator is returned from FilterMultiLegProofExecuted and is used to iterate over the raw logs and unpacked data for MultiLegProofExecuted events raised by the CertenAnchorV4 contract.
type CertenAnchorV4MultiLegProofExecutedIterator struct {
	Event *CertenAnchorV4MultiLegProofExecuted // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4MultiLegProofExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4MultiLegProofExecuted)
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
		it.Event = new(CertenAnchorV4MultiLegProofExecuted)
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
func (it *CertenAnchorV4MultiLegProofExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4MultiLegProofExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4MultiLegProofExecuted represents a MultiLegProofExecuted event raised by the CertenAnchorV4 contract.
type CertenAnchorV4MultiLegProofExecuted struct {
	IntentId     [32]byte
	LegsExecuted uint8
	Verified     bool
	Timestamp    *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterMultiLegProofExecuted is a free log retrieval operation binding the contract event 0x29b318310d8aa98b34fb20481095fd32bb1472cf2d8502817ee3b460af758d81.
//
// Solidity: event MultiLegProofExecuted(bytes32 indexed intentId, uint8 legsExecuted, bool verified, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterMultiLegProofExecuted(opts *bind.FilterOpts, intentId [][32]byte) (*CertenAnchorV4MultiLegProofExecutedIterator, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "MultiLegProofExecuted", intentIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4MultiLegProofExecutedIterator{contract: _CertenAnchorV4.contract, event: "MultiLegProofExecuted", logs: logs, sub: sub}, nil
}

// WatchMultiLegProofExecuted is a free log subscription operation binding the contract event 0x29b318310d8aa98b34fb20481095fd32bb1472cf2d8502817ee3b460af758d81.
//
// Solidity: event MultiLegProofExecuted(bytes32 indexed intentId, uint8 legsExecuted, bool verified, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchMultiLegProofExecuted(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4MultiLegProofExecuted, intentId [][32]byte) (event.Subscription, error) {

	var intentIdRule []interface{}
	for _, intentIdItem := range intentId {
		intentIdRule = append(intentIdRule, intentIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "MultiLegProofExecuted", intentIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4MultiLegProofExecuted)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "MultiLegProofExecuted", log); err != nil {
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

// ParseMultiLegProofExecuted is a log parse operation binding the contract event 0x29b318310d8aa98b34fb20481095fd32bb1472cf2d8502817ee3b460af758d81.
//
// Solidity: event MultiLegProofExecuted(bytes32 indexed intentId, uint8 legsExecuted, bool verified, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseMultiLegProofExecuted(log types.Log) (*CertenAnchorV4MultiLegProofExecuted, error) {
	event := new(CertenAnchorV4MultiLegProofExecuted)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "MultiLegProofExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4PausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the CertenAnchorV4 contract.
type CertenAnchorV4PausedIterator struct {
	Event *CertenAnchorV4Paused // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4PausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4Paused)
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
		it.Event = new(CertenAnchorV4Paused)
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
func (it *CertenAnchorV4PausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4PausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4Paused represents a Paused event raised by the CertenAnchorV4 contract.
type CertenAnchorV4Paused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterPaused(opts *bind.FilterOpts) (*CertenAnchorV4PausedIterator, error) {

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4PausedIterator{contract: _CertenAnchorV4.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4Paused) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4Paused)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "Paused", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParsePaused(log types.Log) (*CertenAnchorV4Paused, error) {
	event := new(CertenAnchorV4Paused)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4ProofExecutedIterator is returned from FilterProofExecuted and is used to iterate over the raw logs and unpacked data for ProofExecuted events raised by the CertenAnchorV4 contract.
type CertenAnchorV4ProofExecutedIterator struct {
	Event *CertenAnchorV4ProofExecuted // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4ProofExecutedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4ProofExecuted)
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
		it.Event = new(CertenAnchorV4ProofExecuted)
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
func (it *CertenAnchorV4ProofExecutedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4ProofExecutedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4ProofExecuted represents a ProofExecuted event raised by the CertenAnchorV4 contract.
type CertenAnchorV4ProofExecuted struct {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterProofExecuted(opts *bind.FilterOpts, anchorId [][32]byte) (*CertenAnchorV4ProofExecutedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "ProofExecuted", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4ProofExecutedIterator{contract: _CertenAnchorV4.contract, event: "ProofExecuted", logs: logs, sub: sub}, nil
}

// WatchProofExecuted is a free log subscription operation binding the contract event 0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d.
//
// Solidity: event ProofExecuted(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchProofExecuted(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4ProofExecuted, anchorId [][32]byte) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "ProofExecuted", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4ProofExecuted)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "ProofExecuted", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseProofExecuted(log types.Log) (*CertenAnchorV4ProofExecuted, error) {
	event := new(CertenAnchorV4ProofExecuted)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "ProofExecuted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4ProofVerificationFailedIterator is returned from FilterProofVerificationFailed and is used to iterate over the raw logs and unpacked data for ProofVerificationFailed events raised by the CertenAnchorV4 contract.
type CertenAnchorV4ProofVerificationFailedIterator struct {
	Event *CertenAnchorV4ProofVerificationFailed // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4ProofVerificationFailedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4ProofVerificationFailed)
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
		it.Event = new(CertenAnchorV4ProofVerificationFailed)
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
func (it *CertenAnchorV4ProofVerificationFailedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4ProofVerificationFailedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4ProofVerificationFailed represents a ProofVerificationFailed event raised by the CertenAnchorV4 contract.
type CertenAnchorV4ProofVerificationFailed struct {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterProofVerificationFailed(opts *bind.FilterOpts, anchorId [][32]byte) (*CertenAnchorV4ProofVerificationFailedIterator, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "ProofVerificationFailed", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4ProofVerificationFailedIterator{contract: _CertenAnchorV4.contract, event: "ProofVerificationFailed", logs: logs, sub: sub}, nil
}

// WatchProofVerificationFailed is a free log subscription operation binding the contract event 0x54897191894573dfd69a2c60cbaf791db5b8dde5264694c39dddfe11479d4c46.
//
// Solidity: event ProofVerificationFailed(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified, bool governanceVerified, bool commitmentVerified, string reason, uint256 timestamp)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchProofVerificationFailed(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4ProofVerificationFailed, anchorId [][32]byte) (event.Subscription, error) {

	var anchorIdRule []interface{}
	for _, anchorIdItem := range anchorId {
		anchorIdRule = append(anchorIdRule, anchorIdItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "ProofVerificationFailed", anchorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4ProofVerificationFailed)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "ProofVerificationFailed", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseProofVerificationFailed(log types.Log) (*CertenAnchorV4ProofVerificationFailed, error) {
	event := new(CertenAnchorV4ProofVerificationFailed)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "ProofVerificationFailed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4ThresholdUpdatedIterator is returned from FilterThresholdUpdated and is used to iterate over the raw logs and unpacked data for ThresholdUpdated events raised by the CertenAnchorV4 contract.
type CertenAnchorV4ThresholdUpdatedIterator struct {
	Event *CertenAnchorV4ThresholdUpdated // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4ThresholdUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4ThresholdUpdated)
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
		it.Event = new(CertenAnchorV4ThresholdUpdated)
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
func (it *CertenAnchorV4ThresholdUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4ThresholdUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4ThresholdUpdated represents a ThresholdUpdated event raised by the CertenAnchorV4 contract.
type CertenAnchorV4ThresholdUpdated struct {
	OldThreshold *big.Int
	NewThreshold *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterThresholdUpdated is a free log retrieval operation binding the contract event 0xb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b.
//
// Solidity: event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterThresholdUpdated(opts *bind.FilterOpts) (*CertenAnchorV4ThresholdUpdatedIterator, error) {

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "ThresholdUpdated")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4ThresholdUpdatedIterator{contract: _CertenAnchorV4.contract, event: "ThresholdUpdated", logs: logs, sub: sub}, nil
}

// WatchThresholdUpdated is a free log subscription operation binding the contract event 0xb06a54caabe58475c86c2bf9df3f2f06dd1213e9e10659c293117fe4893b274b.
//
// Solidity: event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchThresholdUpdated(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4ThresholdUpdated) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "ThresholdUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4ThresholdUpdated)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "ThresholdUpdated", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseThresholdUpdated(log types.Log) (*CertenAnchorV4ThresholdUpdated, error) {
	event := new(CertenAnchorV4ThresholdUpdated)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "ThresholdUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4UnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the CertenAnchorV4 contract.
type CertenAnchorV4UnpausedIterator struct {
	Event *CertenAnchorV4Unpaused // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4UnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4Unpaused)
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
		it.Event = new(CertenAnchorV4Unpaused)
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
func (it *CertenAnchorV4UnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4UnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4Unpaused represents a Unpaused event raised by the CertenAnchorV4 contract.
type CertenAnchorV4Unpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterUnpaused(opts *bind.FilterOpts) (*CertenAnchorV4UnpausedIterator, error) {

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4UnpausedIterator{contract: _CertenAnchorV4.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4Unpaused) (event.Subscription, error) {

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4Unpaused)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "Unpaused", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseUnpaused(log types.Log) (*CertenAnchorV4Unpaused, error) {
	event := new(CertenAnchorV4Unpaused)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4ValidatorRegisteredIterator is returned from FilterValidatorRegistered and is used to iterate over the raw logs and unpacked data for ValidatorRegistered events raised by the CertenAnchorV4 contract.
type CertenAnchorV4ValidatorRegisteredIterator struct {
	Event *CertenAnchorV4ValidatorRegistered // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4ValidatorRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4ValidatorRegistered)
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
		it.Event = new(CertenAnchorV4ValidatorRegistered)
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
func (it *CertenAnchorV4ValidatorRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4ValidatorRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4ValidatorRegistered represents a ValidatorRegistered event raised by the CertenAnchorV4 contract.
type CertenAnchorV4ValidatorRegistered struct {
	Validator   common.Address
	VotingPower *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterValidatorRegistered is a free log retrieval operation binding the contract event 0xb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c.
//
// Solidity: event ValidatorRegistered(address indexed validator, uint256 votingPower)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterValidatorRegistered(opts *bind.FilterOpts, validator []common.Address) (*CertenAnchorV4ValidatorRegisteredIterator, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "ValidatorRegistered", validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4ValidatorRegisteredIterator{contract: _CertenAnchorV4.contract, event: "ValidatorRegistered", logs: logs, sub: sub}, nil
}

// WatchValidatorRegistered is a free log subscription operation binding the contract event 0xb4a7f5c563a0e35593d156394ed681bdc9c39467d7d722749d23862c2e4b712c.
//
// Solidity: event ValidatorRegistered(address indexed validator, uint256 votingPower)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchValidatorRegistered(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4ValidatorRegistered, validator []common.Address) (event.Subscription, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "ValidatorRegistered", validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4ValidatorRegistered)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "ValidatorRegistered", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseValidatorRegistered(log types.Log) (*CertenAnchorV4ValidatorRegistered, error) {
	event := new(CertenAnchorV4ValidatorRegistered)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "ValidatorRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// CertenAnchorV4ValidatorRemovedIterator is returned from FilterValidatorRemoved and is used to iterate over the raw logs and unpacked data for ValidatorRemoved events raised by the CertenAnchorV4 contract.
type CertenAnchorV4ValidatorRemovedIterator struct {
	Event *CertenAnchorV4ValidatorRemoved // Event containing the contract specifics and raw log

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
func (it *CertenAnchorV4ValidatorRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(CertenAnchorV4ValidatorRemoved)
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
		it.Event = new(CertenAnchorV4ValidatorRemoved)
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
func (it *CertenAnchorV4ValidatorRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *CertenAnchorV4ValidatorRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// CertenAnchorV4ValidatorRemoved represents a ValidatorRemoved event raised by the CertenAnchorV4 contract.
type CertenAnchorV4ValidatorRemoved struct {
	Validator common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterValidatorRemoved is a free log retrieval operation binding the contract event 0xe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f1.
//
// Solidity: event ValidatorRemoved(address indexed validator)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) FilterValidatorRemoved(opts *bind.FilterOpts, validator []common.Address) (*CertenAnchorV4ValidatorRemovedIterator, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.FilterLogs(opts, "ValidatorRemoved", validatorRule)
	if err != nil {
		return nil, err
	}
	return &CertenAnchorV4ValidatorRemovedIterator{contract: _CertenAnchorV4.contract, event: "ValidatorRemoved", logs: logs, sub: sub}, nil
}

// WatchValidatorRemoved is a free log subscription operation binding the contract event 0xe1434e25d6611e0db941968fdc97811c982ac1602e951637d206f5fdda9dd8f1.
//
// Solidity: event ValidatorRemoved(address indexed validator)
func (_CertenAnchorV4 *CertenAnchorV4Filterer) WatchValidatorRemoved(opts *bind.WatchOpts, sink chan<- *CertenAnchorV4ValidatorRemoved, validator []common.Address) (event.Subscription, error) {

	var validatorRule []interface{}
	for _, validatorItem := range validator {
		validatorRule = append(validatorRule, validatorItem)
	}

	logs, sub, err := _CertenAnchorV4.contract.WatchLogs(opts, "ValidatorRemoved", validatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(CertenAnchorV4ValidatorRemoved)
				if err := _CertenAnchorV4.contract.UnpackLog(event, "ValidatorRemoved", log); err != nil {
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
func (_CertenAnchorV4 *CertenAnchorV4Filterer) ParseValidatorRemoved(log types.Log) (*CertenAnchorV4ValidatorRemoved, error) {
	event := new(CertenAnchorV4ValidatorRemoved)
	if err := _CertenAnchorV4.contract.UnpackLog(event, "ValidatorRemoved", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
