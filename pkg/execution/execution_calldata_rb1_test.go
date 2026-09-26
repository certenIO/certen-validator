package execution

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB-1: end-to-end calldata binding tests.
//
// These assert the validator agrees byte-for-byte with the TS producer and Solidity
// contracts on (callData, dataHash, executionCommitment) via the shared vectors in
// certen-contracts/test/vectors/execution_commitment_test_vectors.json, and that the
// CRITICAL-003 gate binds the REAL calldata (not []byte{}).

type rb1Vector struct {
	Description string `json:"description"`
	ChainID     int64  `json:"chainId"`
	Leg         struct {
		ToAddress    string      `json:"toAddress"`
		AmountWei    string      `json:"amountWei"`
		TokenAddress interface{} `json:"tokenAddress"`
		ContractCall *struct {
			Target            string        `json:"target"`
			Value             string        `json:"value"`
			FunctionSignature string        `json:"functionSignature"`
			Args              []interface{} `json:"args"`
		} `json:"contractCall"`
	} `json:"leg"`
	Expected struct {
		Target              string `json:"target"`
		Value               string `json:"value"`
		CallData            string `json:"callData"`
		DataHash            string `json:"dataHash"`
		ExecutionCommitment string `json:"executionCommitment"`
	} `json:"expected"`
}

func loadRB1Vectors(t *testing.T) []rb1Vector {
	t.Helper()
	path := sharedVectorPath(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared vectors %s: %v", path, err)
	}
	var vs []rb1Vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vs
}

func sharedVectorPath(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("CERTEN_CONTRACTS_DIR"); root != "" {
		return filepath.Join(root, "test", "vectors", "execution_commitment_test_vectors.json")
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "certen-contracts", "test", "vectors", "execution_commitment_test_vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("shared execution vectors not found; set CERTEN_CONTRACTS_DIR to the certen-contracts checkout")
	return ""
}

// TestRB1_CommitmentMatchesSharedVectors asserts the Go computeExecutionCommitment
// reproduces the exact commitment the TS producer emitted for every case (native,
// ERC-20, and arbitrary contract calls), and that keccak256(callData)==dataHash.
func TestRB1_CommitmentMatchesSharedVectors(t *testing.T) {
	for _, v := range loadRB1Vectors(t) {
		t.Run(v.Description, func(t *testing.T) {
			callData, err := decodeHexBytes(v.Expected.CallData)
			if err != nil {
				t.Fatalf("decode callData: %v", err)
			}

			// keccak256(callData) must equal the published dataHash.
			gotDataHash := crypto.Keccak256Hash(callData)
			if gotDataHash != common.HexToHash(v.Expected.DataHash) {
				t.Errorf("dataHash mismatch: got %s want %s", gotDataHash.Hex(), v.Expected.DataHash)
			}

			value := new(big.Int)
			value.SetString(v.Expected.Value, 10)
			got := computeExecutionCommitment(v.ChainID, common.HexToAddress(v.Expected.Target), value, callData)
			if got != common.HexToHash(v.Expected.ExecutionCommitment) {
				t.Errorf("executionCommitment mismatch:\n got  %s\n want %s", common.Hash(got).Hex(), v.Expected.ExecutionCommitment)
			}

			// Negative: mutating any calldata byte must change the commitment.
			if len(callData) > 0 {
				mutated := make([]byte, len(callData))
				copy(mutated, callData)
				mutated[len(mutated)-1] ^= 0xFF
				if computeExecutionCommitment(v.ChainID, common.HexToAddress(v.Expected.Target), value, mutated) == got {
					t.Error("mutated calldata produced identical commitment (gate would not detect tampering)")
				}
			}
		})
	}
}
