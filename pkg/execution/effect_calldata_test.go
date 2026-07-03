package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// packExecuteGovernanceProofDirect builds real ABI-encoded calldata for the V6.1
// abstract-account wrapper with the given INNER data argument.
func packExecuteGovernanceProofDirect(t *testing.T, innerData []byte) []byte {
	t.Helper()
	proof := contracts.AccountProof{
		AdiURL:    "acc://certen-v5g-7fea0a.acme/data",
		Timestamp: big.NewInt(0),
		ExpiresAt: big.NewInt(0),
		Nonce:     big.NewInt(0),
	}
	packed, err := certenAccountABI.Pack(
		"executeGovernanceProofDirect",
		common.HexToAddress("0xBE0043abB10E6Db56b8C6C5cb3f639BF7fe69251"),
		big.NewInt(1),
		innerData,
		proof,
	)
	if err != nil {
		t.Fatalf("pack executeGovernanceProofDirect: %v", err)
	}
	return packed
}

// TestDecodeAbstractAccountEffectCalldata locks in the RB-SEC-1 Phase-8 fix: for the V6.1
// abstract-account wrapper the EFFECT's calldata is the INNER `data` arg, not the (always
// non-empty) outer tx input. A native transfer (empty inner data) must NOT be flagged as a
// contract call — that false positive was making every peer refuse to attest.
func TestDecodeAbstractAccountEffectCalldata(t *testing.T) {
	if certenAccountABI == nil {
		t.Fatal("CertenAccount ABI failed to parse")
	}

	// Native transfer: outer wrapper present, inner data empty → effect has NO calldata.
	inner, matched, err := decodeAbstractAccountEffectCalldata(packExecuteGovernanceProofDirect(t, []byte{}))
	if err != nil || !matched || inner {
		t.Fatalf("native transfer: inner=%v matched=%v err=%v; want inner=false matched=true err=nil", inner, matched, err)
	}

	// Contract call: inner data non-empty → effect HAS calldata (security preserved: still refused upstream).
	inner, matched, err = decodeAbstractAccountEffectCalldata(packExecuteGovernanceProofDirect(t, []byte{0xde, 0xad, 0xbe, 0xef}))
	if err != nil || !matched || !inner {
		t.Fatalf("contract call: inner=%v matched=%v err=%v; want inner=true matched=true err=nil", inner, matched, err)
	}

	// Not the wrapper (some other selector) → fall through to raw-input handling.
	if _, matched, err := decodeAbstractAccountEffectCalldata([]byte{0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0}); err != nil || matched {
		t.Fatalf("non-wrapper selector: matched=%v err=%v; want matched=false err=nil", matched, err)
	}

	// Too short to hold a selector → fall through.
	if _, matched, _ := decodeAbstractAccountEffectCalldata([]byte{0x01}); matched {
		t.Fatal("sub-4-byte input must not match the wrapper")
	}
}
