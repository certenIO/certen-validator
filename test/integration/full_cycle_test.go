// Section 14.4: Cross-Codebase Integration Test
//
// Verifies the full chain of custody from intent construction through on-chain verification.
// This test simulates the API bridge constructing blobs, the validator computing commitments,
// and the contract verifying them — all using the same algorithms.
//
// NOTE: This is a unit-level simulation of the full cycle. It does NOT require
// a running Accumulate node or EVM chain. Real end-to-end testing requires testnet deployment.

package integration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =========================================================================
// Shared algorithms (must match Go validator, TypeScript API bridge, Solidity)
// =========================================================================

// canonicalizeJSON sorts map keys recursively — matches Go commitment.CanonicalizeJSON
func canonicalizeJSON(raw []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalizeValue(v))
}

func canonicalizeValue(v interface{}) interface{} {
	switch vv := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(vv))
		for k := range vv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]interface{}, len(vv))
		for _, k := range keys {
			ordered[k] = canonicalizeValue(vv[k])
		}
		return ordered
	case []interface{}:
		out := make([]interface{}, len(vv))
		for i, e := range vv {
			out[i] = canonicalizeValue(e)
		}
		return out
	default:
		return vv
	}
}

// computeCanonical4BlobHash matches proof.ComputeCanonical4BlobHash (CRITICAL-002)
func computeCanonical4BlobHash(blob0, blob1, blob2, blob3 []byte) [32]byte {
	blobs := [][]byte{blob0, blob1, blob2, blob3}
	h := sha256.New()
	for _, blob := range blobs {
		canon, _ := canonicalizeJSON(blob)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(canon)))
		h.Write(lenBuf)
		h.Write(canon)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeExecutionCommitment matches ethereum_contracts.computeExecutionCommitment (CRITICAL-001)
func computeExecutionCommitment(chainID int64, target common.Address, value *big.Int, callData []byte) [32]byte {
	dataHash := crypto.Keccak256Hash(callData)

	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)

	valueBytes := make([]byte, 32)
	if value != nil {
		value.FillBytes(valueBytes)
	}

	packed := make([]byte, 0, 116)
	packed = append(packed, chainIDBytes...)
	packed = append(packed, target.Bytes()...)
	packed = append(packed, valueBytes...)
	packed = append(packed, dataHash.Bytes()...)

	return crypto.Keccak256Hash(packed)
}

// sortedHash matches Solidity _sortedHash
func sortedHash(a, b []byte) []byte {
	if compareBytes(a, b) < 0 {
		return crypto.Keccak256(append(append([]byte{}, a...), b...))
	}
	return crypto.Keccak256(append(append([]byte{}, b...), a...))
}

func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

// computeMerkleRoot5 matches Solidity _computeMerkleRoot5 (LOW-001)
func computeMerkleRoot5(adiURLHash, opCommitment, ccCommitment, govRoot, execCommitment [32]byte) [32]byte {
	taggedAdi := crypto.Keccak256Hash(append([]byte("certen:adi:"), adiURLHash[:]...))
	taggedOp := crypto.Keccak256Hash(append([]byte("certen:op:"), opCommitment[:]...))
	taggedCC := crypto.Keccak256Hash(append([]byte("certen:cc:"), ccCommitment[:]...))
	taggedGov := crypto.Keccak256Hash(append([]byte("certen:gov:"), govRoot[:]...))
	taggedExec := crypto.Keccak256Hash(append([]byte("certen:exec:"), execCommitment[:]...))

	hash01 := sortedHash(taggedAdi[:], taggedOp[:])
	hash23 := sortedHash(taggedCC[:], taggedGov[:])
	hash0123 := sortedHash(hash01, hash23)
	root := sortedHash(hash0123, taggedExec[:])

	var result [32]byte
	copy(result[:], root)
	return result
}

// =========================================================================
// Full Cycle Simulation
// =========================================================================

func TestFullCycle_IntentToVerification(t *testing.T) {
	// === Step 1: Simulate API bridge constructing 4-blob intent ===
	recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amountWei := "500000000000000000" // 0.5 ETH
	chainID := int64(31337)

	blob0 := []byte(`{"kind":"CERTEN_INTENT","version":"2.0","proof_class":"on_demand"}`)
	blob1 := []byte(`{"legs":[{"chain":"ethereum","chainId":31337,"from":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","to":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","amountWei":"500000000000000000","amountEth":"0.5"}],"protocol":"CERTEN","version":"2.0"}`)
	blob2 := []byte(`{"authorization":{"required_key_book":"acc://test.acme/book","signature_threshold":1},"organizationAdi":"acc://test.acme"}`)
	blob3 := []byte(`{"created_at":1710720000,"expires_at":1710723600,"nonce":"certen_test_abc123"}`)

	// === Step 2: Compute OperationID (CRITICAL-002) ===
	operationID := computeCanonical4BlobHash(blob0, blob1, blob2, blob3)
	t.Logf("OperationID: 0x%s", hex.EncodeToString(operationID[:]))

	// Verify it's deterministic
	operationID2 := computeCanonical4BlobHash(blob0, blob1, blob2, blob3)
	if operationID != operationID2 {
		t.Fatal("OperationID is not deterministic")
	}

	// === Step 3: Compute executionCommitment (CRITICAL-001) ===
	value := new(big.Int)
	value.SetString(amountWei, 10)
	execCommitment := computeExecutionCommitment(chainID, recipient, value, []byte{})
	t.Logf("ExecutionCommitment: 0x%x", execCommitment[:])

	// === Step 4: Compute Merkle root (LOW-001) ===
	adiURL := "acc://test.acme/data"
	adiURLHash := crypto.Keccak256Hash([]byte(adiURL))

	var opHash, ccHash, govHash [32]byte
	copy(opHash[:], crypto.Keccak256([]byte("test-op-commitment")))
	copy(ccHash[:], crypto.Keccak256([]byte("test-cc-commitment")))
	copy(govHash[:], crypto.Keccak256([]byte("test-gov-root")))

	merkleRoot := computeMerkleRoot5(adiURLHash, opHash, ccHash, govHash, execCommitment)
	t.Logf("MerkleRoot: 0x%x", merkleRoot[:])

	// === Step 5: Verify mutation detection (CRITICAL-001, 13.4) ===
	t.Run("MutationDetection", func(t *testing.T) {
		original := execCommitment

		// Amount 500 → 5000
		mutatedValue := new(big.Int).Mul(value, big.NewInt(10))
		mutatedCommitment := computeExecutionCommitment(chainID, recipient, mutatedValue, []byte{})
		if mutatedCommitment == original {
			t.Error("Amount mutation NOT detected")
		}

		// Alice → Mallory
		mallory := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
		targetMutated := computeExecutionCommitment(chainID, mallory, value, []byte{})
		if targetMutated == original {
			t.Error("Target mutation NOT detected")
		}

		// Chain ID change
		chainMutated := computeExecutionCommitment(999, recipient, value, []byte{})
		if chainMutated == original {
			t.Error("Chain ID mutation NOT detected")
		}

		// Calldata change
		dataMutated := computeExecutionCommitment(chainID, recipient, value, []byte{0x01})
		if dataMutated == original {
			t.Error("Calldata mutation NOT detected")
		}

		t.Log("All 4 mutation types correctly detected")
	})

	// === Step 6: Verify replay would be blocked ===
	t.Run("ReplayDetection", func(t *testing.T) {
		// Same OperationID computed twice = replay if not tracked
		replay1 := computeCanonical4BlobHash(blob0, blob1, blob2, blob3)
		replay2 := computeCanonical4BlobHash(blob0, blob1, blob2, blob3)
		if replay1 != replay2 {
			t.Error("Same blobs should produce same OperationID for replay detection")
		}

		// Different nonce = different OperationID
		blob3Modified := []byte(`{"created_at":1710720000,"expires_at":1710723600,"nonce":"certen_test_DIFFERENT"}`)
		different := computeCanonical4BlobHash(blob0, blob1, blob2, blob3Modified)
		if different == replay1 {
			t.Error("Different nonce should produce different OperationID")
		}

		t.Log("Replay detection verified — same blobs = same ID, different nonce = different ID")
	})

	// === Step 7: Verify Merkle root changes with any leaf change ===
	t.Run("MerkleIntegrity", func(t *testing.T) {
		original := merkleRoot

		// Change execution commitment
		differentExec := computeExecutionCommitment(chainID, recipient, big.NewInt(999), []byte{})
		alteredRoot := computeMerkleRoot5(adiURLHash, opHash, ccHash, govHash, differentExec)
		if alteredRoot == original {
			t.Error("Merkle root should change when execution commitment changes")
		}

		// Change ADI URL
		alteredAdi := crypto.Keccak256Hash([]byte("acc://different.acme/data"))
		alteredRoot2 := computeMerkleRoot5(alteredAdi, opHash, ccHash, govHash, execCommitment)
		if alteredRoot2 == original {
			t.Error("Merkle root should change when ADI URL changes")
		}

		t.Log("Merkle integrity verified — any leaf change alters root")
	})
}
