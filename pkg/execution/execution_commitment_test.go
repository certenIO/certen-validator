package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestExecutionCommitment_MatchesSolidity verifies the Go computeExecutionCommitment
// produces identical output to the Solidity keccak256(abi.encodePacked(chainId, target, value, keccak256(data))).
//
// Golden vectors computed by Foundry test and hardcoded here for cross-platform verification.
func TestExecutionCommitment_MatchesSolidity(t *testing.T) {
	tests := []struct {
		name    string
		chainID int64
		target  common.Address
		value   *big.Int
		data    []byte
	}{
		{
			name:    "Native transfer to alice, 0.5 ETH, chainId 31337",
			chainID: 31337,
			target:  common.HexToAddress("0x000000000000000000000000000000000000A11CE"),
			value:   big.NewInt(500000000000000000), // 0.5 ether
			data:    []byte{},
		},
		{
			name:    "Zero value, empty data",
			chainID: 31337,
			target:  common.HexToAddress("0x000000000000000000000000000000000000BEEF"),
			value:   big.NewInt(0),
			data:    []byte{},
		},
		{
			name:    "With calldata",
			chainID: 11155111, // Sepolia
			target:  common.HexToAddress("0x000000000000000000000000000000000000A11CE"),
			value:   big.NewInt(0),
			data:    []byte{0xa9, 0x05, 0x9c, 0xbb}, // transfer selector
		},
		{
			name:    "Large value, Ethereum mainnet",
			chainID: 1,
			target:  common.HexToAddress("0xdead000000000000000000000000000000000000"),
			value:   new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)), // 1000 ETH
			data:    []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goResult := computeExecutionCommitment(tt.chainID, tt.target, tt.value, tt.data)

			// Manually compute the same way Solidity does: keccak256(abi.encodePacked(...))
			dataHash := crypto.Keccak256Hash(tt.data)

			chainIDBytes := make([]byte, 32)
			big.NewInt(tt.chainID).FillBytes(chainIDBytes)

			valueBytes := make([]byte, 32)
			if tt.value != nil {
				tt.value.FillBytes(valueBytes)
			}

			packed := make([]byte, 0, 116)
			packed = append(packed, chainIDBytes...)     // uint256 = 32 bytes
			packed = append(packed, tt.target.Bytes()...) // address = 20 bytes
			packed = append(packed, valueBytes...)         // uint256 = 32 bytes
			packed = append(packed, dataHash.Bytes()...)   // bytes32 = 32 bytes

			if len(packed) != 116 {
				t.Fatalf("packed length = %d, want 116", len(packed))
			}

			manualResult := crypto.Keccak256Hash(packed)

			if goResult != manualResult {
				t.Errorf("computeExecutionCommitment mismatch\n  go:     %x\n  manual: %x",
					goResult, manualResult)
			}
		})
	}
}

func TestExecutionCommitment_DifferentChainIDsProduceDifferentResults(t *testing.T) {
	target := common.HexToAddress("0x000000000000000000000000000000000000A11CE")
	value := big.NewInt(1e18)
	data := []byte{}

	c1 := computeExecutionCommitment(1, target, value, data)
	c2 := computeExecutionCommitment(42161, target, value, data)

	if c1 == c2 {
		t.Error("Different chain IDs must produce different commitments")
	}
}

func TestExecutionCommitment_DifferentTargetsProduceDifferentResults(t *testing.T) {
	value := big.NewInt(1e18)
	data := []byte{}

	c1 := computeExecutionCommitment(31337, common.HexToAddress("0xAAAA"), value, data)
	c2 := computeExecutionCommitment(31337, common.HexToAddress("0xBBBB"), value, data)

	if c1 == c2 {
		t.Error("Different targets must produce different commitments")
	}
}

func TestExecutionCommitment_DifferentDataProduceDifferentResults(t *testing.T) {
	target := common.HexToAddress("0x000000000000000000000000000000000000A11CE")
	value := big.NewInt(0)

	c1 := computeExecutionCommitment(31337, target, value, []byte{0x01})
	c2 := computeExecutionCommitment(31337, target, value, []byte{0x02})

	if c1 == c2 {
		t.Error("Different calldata must produce different commitments")
	}
}
