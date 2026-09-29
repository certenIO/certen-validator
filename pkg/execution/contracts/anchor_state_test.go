package contracts

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// A V8.1 record is V8.2's first fifteen fields; both decode, each to its own generation, and nothing else does.
func TestDecodeAnchorsReturn_BothGenerations(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV8_2BatchABI))
	if err != nil {
		t.Fatal(err)
	}
	outs := parsed.Methods["anchors"].Outputs
	acc, inc := [32]byte{0xac}, [32]byte{0x1c}
	vals := []interface{}{[32]byte{1}, [32]byte{2}, [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{2}, [32]byte{7},
		big.NewInt(42), big.NewInt(1790000000), common.HexToAddress("0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"), true, true, false, uint8(2)}
	v82, err := outs.Pack(append(append([]interface{}{}, vals...), acc, inc)...)
	if err != nil {
		t.Fatal(err)
	}
	v81, err := outs[:15].Pack(vals...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := DecodeAnchorsReturn(v82)
	if err != nil || s.Version != BatchAnchorV8_2 || s.AccumulateSetRoot != acc || s.Incarnation != inc || s.OperationID != ([32]byte{7}) || !s.ProofExecuted || s.GovernanceLevel != 2 {
		t.Fatalf("v8.2: %+v %v", s, err)
	}
	s, err = DecodeAnchorsReturn(v81)
	if err != nil || s.Version != BatchAnchorV8_1 || s.AccumulateSetRoot != ([32]byte{}) || s.OperationID != ([32]byte{7}) || s.AccumulateBlockHeight.Int64() != 42 {
		t.Fatalf("v8.1: %+v %v", s, err)
	}
	for _, bad := range [][]byte{nil, v81[:14*32], v82[:16*32], append(append([]byte{}, v82...), make([]byte, 32)...)} {
		if _, err := DecodeAnchorsReturn(bad); err == nil {
			t.Errorf("a %d-byte return was decoded", len(bad))
		}
	}
	if got := AnchorsCallData([32]byte{9}); len(got) != 36 || common.Bytes2Hex(got[:4]) != common.Bytes2Hex(parsed.Methods["anchors"].ID) {
		t.Fatalf("anchors calldata %x", got)
	}
}
