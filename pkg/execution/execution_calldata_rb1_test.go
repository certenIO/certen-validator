package execution

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/intent"
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
	path := filepath.Join("..", "..", "..", "certen-contracts", "test", "vectors", "execution_commitment_test_vectors.json")
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

type rb1Logger struct{}

func (rb1Logger) Printf(string, ...interface{}) {}

// buildCrossChainDataJSON builds a single-leg crossChainData blob carrying an
// executionPayload with the given (chainId, target, value, callData, commitment).
func buildCrossChainDataJSON(chainID int64, target, value, callData, commitment string) []byte {
	leg := map[string]interface{}{
		"legId":     "leg-0",
		"from":      "0x1111111111111111111111111111111111111111",
		"to":        target,
		"amountWei": value,
		"chainId":   chainID,
		"chain":     "ethereum sepolia",
		"executionPayload": map[string]interface{}{
			"target":              target,
			"value":               value,
			"callData":            callData,
			"dataHash":            crypto.Keccak256Hash(common.FromHex(callData)).Hex(),
			"chainId":             chainID,
			"executionCommitment": commitment,
		},
	}
	blob := map[string]interface{}{
		"protocol": "CERTEN",
		"version":  "2.0",
		"legs":     []interface{}{leg},
	}
	b, _ := json.Marshal(blob)
	return b
}

// TestRB1_Critical003GateBindsRealCalldata drives extractAllLegsFromIntent with a leg
// whose executionPayload carries real calldata. The gate must pass when the stored
// commitment matches the real calldata, surface leg.Data == callData, and REJECT
// (return nil) when the executed calldata is mutated away from the committed one.
func TestRB1_Critical003GateBindsRealCalldata(t *testing.T) {
	vs := loadRB1Vectors(t)
	// Pick the arbitrary-call vector (non-empty calldata, target != recipient).
	var v *rb1Vector
	for i := range vs {
		if vs[i].Leg.ContractCall != nil {
			v = &vs[i]
			break
		}
	}
	if v == nil {
		t.Fatal("no contractCall vector present")
	}

	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true") // opt in to arbitrary calls for this test

	btce := NewBFTTargetChainExecutor(rb1Logger{})

	// (a) Correct calldata + matching commitment ⇒ accepted, Data carries the calldata.
	ccd := buildCrossChainDataJSON(v.ChainID, v.Expected.Target, v.Expected.Value, v.Expected.CallData, v.Expected.ExecutionCommitment)
	legs := btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "rb1-ok", CrossChainData: ccd})
	if len(legs) != 1 {
		t.Fatalf("expected 1 leg, got %d (gate wrongly rejected valid calldata)", len(legs))
	}
	wantData, _ := decodeHexBytes(v.Expected.CallData)
	if fmt.Sprintf("%x", legs[0].Data) != fmt.Sprintf("%x", wantData) {
		t.Errorf("leg.Data mismatch:\n got  0x%x\n want 0x%x", legs[0].Data, wantData)
	}

	// (b) Mutated calldata but the SAME (now-stale) committed commitment ⇒ rejected.
	mutatedCallData := "0x" + fmt.Sprintf("%x", append([]byte{0xde, 0xad, 0xbe, 0xef}, wantData[4:]...))
	ccdBad := buildCrossChainDataJSON(v.ChainID, v.Expected.Target, v.Expected.Value, mutatedCallData, v.Expected.ExecutionCommitment)
	legsBad := btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "rb1-bad", CrossChainData: ccdBad})
	if legsBad != nil {
		t.Errorf("gate accepted mutated calldata (expected nil rejection), got %d legs", len(legsBad))
	}
}

// TestFeatureGate_ContractCallsOffByDefault asserts arbitrary contract calls are refused
// unless CERTEN_ALLOW_CONTRACT_CALLS is enabled (fail-closed default).
func TestFeatureGate_ContractCallsOffByDefault(t *testing.T) {
	vs := loadRB1Vectors(t)
	var v *rb1Vector
	for i := range vs {
		if vs[i].Leg.ContractCall != nil {
			v = &vs[i]
			break
		}
	}
	if v == nil {
		t.Fatal("no contractCall vector present")
	}
	ccd := buildCrossChainDataJSON(v.ChainID, v.Expected.Target, v.Expected.Value, v.Expected.CallData, v.Expected.ExecutionCommitment)
	btce := NewBFTTargetChainExecutor(rb1Logger{})

	// Default (env unset): contract-call leg must be rejected.
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "")
	if legs := btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "gate-off", CrossChainData: ccd}); legs != nil {
		t.Errorf("contract call must be refused by default, got %d legs", len(legs))
	}

	// Enabled: same leg is accepted.
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	if legs := btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "gate-on", CrossChainData: ccd}); len(legs) != 1 {
		t.Errorf("contract call must be accepted when enabled, got %d legs", len(legs))
	}
}

// TestRB1_BuildFromIntentBindsCallDataHash asserts the commitment builder binds the
// real calldata into Step3.CallDataHash and FinalCallData (previously always zero).
func TestRB1_BuildFromIntentBindsCallDataHash(t *testing.T) {
	vs := loadRB1Vectors(t)
	var v *rb1Vector
	for i := range vs {
		if vs[i].Leg.ContractCall != nil {
			v = &vs[i]
			break
		}
	}
	if v == nil {
		t.Fatal("no contractCall vector present")
	}

	ccd := buildCrossChainDataJSON(v.ChainID, v.Expected.Target, v.Expected.Value, v.Expected.CallData, v.Expected.ExecutionCommitment)
	builder := NewExecutionCommitmentBuilder()
	var bundleID [32]byte
	commitment, err := builder.BuildFromIntent("rb1-intent", bundleID, ccd, v.Expected.Target)
	if err != nil {
		t.Fatalf("BuildFromIntent: %v", err)
	}

	wantData, _ := decodeHexBytes(v.Expected.CallData)
	if fmt.Sprintf("%x", commitment.FinalCallData) != fmt.Sprintf("%x", wantData) {
		t.Errorf("FinalCallData mismatch:\n got  0x%x\n want 0x%x", commitment.FinalCallData, wantData)
	}
	var wantHash [32]byte
	copy(wantHash[:], crypto.Keccak256(wantData))
	if commitment.ExecuteGovernanceCommitment.CallDataHash != wantHash {
		t.Errorf("Step3 CallDataHash mismatch:\n got  0x%x\n want 0x%x", commitment.ExecuteGovernanceCommitment.CallDataHash, wantHash)
	}
	var zero [32]byte
	if commitment.ExecuteGovernanceCommitment.CallDataHash == zero {
		t.Error("Step3 CallDataHash is zero — calldata not bound")
	}
}
