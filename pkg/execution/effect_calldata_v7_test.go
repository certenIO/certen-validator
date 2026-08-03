package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// v7Proof mirrors ADIGovernanceProof so the ABI packer can encode the tuple.
type v7Proof struct {
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
	RequiredLevel       uint8
}

func newV7Proof() v7Proof {
	return v7Proof{
		AdiURL:      "acc://certen-kermit-12.acme",
		MerkleProof: [][32]byte{},
		Timestamp:   big.NewInt(1), ExpiresAt: big.NewInt(2), Nonce: big.NewInt(3),
		KeyBookProof: []byte{}, RoleProof: []byte{}, ThresholdProof: []byte{}, ValidatorSignatures: []byte{},
		RequiredLevel: 3,
	}
}

// A V7 NATIVE transfer must decode to "no inner calldata".
//
// This is the case that broke attestation: the decoder only knew the V2 selector, missed the V7
// wrapper, and fell back to the outer input length — which is never zero — so every peer refused
// with "carries calldata but committed intent has no contract-call leg".
func TestV7NativeTransferHasNoInnerCalldata(t *testing.T) {
	if certenAccountV7ABIErr != nil {
		t.Fatalf("V7 ABI failed to parse: %v", certenAccountV7ABIErr)
	}
	input, err := certenAccountV7ABI.Pack("executeGovernanceProofDirect",
		common.HexToAddress("0xBE0043abB10E6Db56b8C6C5cb3f639BF7fe69251"),
		big.NewInt(1), []byte{}, newV7Proof())
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	inner, matched, err := decodeAbstractAccountEffectCalldata(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !matched {
		t.Fatal("V7 wrapper not recognised — peers would refuse to attest a native transfer")
	}
	if inner {
		t.Fatal("native transfer reported as carrying calldata")
	}
}

// A V7 contract call must still be detected, so the forgery gate keeps working.
func TestV7ContractCallHasInnerCalldata(t *testing.T) {
	input, err := certenAccountV7ABI.Pack("executeGovernanceProofDirect",
		common.HexToAddress("0xBE0043abB10E6Db56b8C6C5cb3f639BF7fe69251"),
		big.NewInt(0), []byte{0xa9, 0x05, 0x9c, 0xbb}, newV7Proof())
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	inner, matched, err := decodeAbstractAccountEffectCalldata(input)
	if err != nil || !matched {
		t.Fatalf("decode: matched=%v err=%v", matched, err)
	}
	if !inner {
		t.Fatal("contract call NOT detected — the forgery gate would be a no-op")
	}
}

// A batch is a contract call if ANY leg carries calldata.
func TestV7BatchDetectsAnyCallLeg(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
		data [][]byte
	}{
		{"all native", false, [][]byte{{}, {}}},
		{"one call leg", true, [][]byte{{}, {0xa9, 0x05, 0x9c, 0xbb}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addrs := []common.Address{{1}, {2}}
			vals := []*big.Int{big.NewInt(1), big.NewInt(1)}
			input, err := certenAccountV7ABI.Pack("batchExecuteGovernanceProofDirect", addrs, vals, tc.data, newV7Proof())
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			inner, matched, err := decodeAbstractAccountEffectCalldata(input)
			if err != nil || !matched {
				t.Fatalf("decode: matched=%v err=%v", matched, err)
			}
			if inner != tc.want {
				t.Fatalf("inner=%v want=%v", inner, tc.want)
			}
		})
	}
}
