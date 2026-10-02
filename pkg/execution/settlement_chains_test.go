package execution

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB5-F33: the chains CERTEN settles on now are named, never defaulted, and only from those this build supports.
func TestSettlementChainsAreNamed(t *testing.T) {
	supported := []int64{11155111, 84532, 421614}
	t.Setenv(SettlementChainsEnv, "")
	if _, err := SettlementChainsFromEnv(supported); err == nil {
		t.Fatal("no settlement chains named, and the validator would start")
	}
	t.Setenv(SettlementChainsEnv, " 421614, 84532 ")
	if got, err := SettlementChainsFromEnv(supported); err != nil || len(got) != 2 || got[0] != 84532 || got[1] != 421614 {
		t.Fatalf("(%v, %v)", got, err)
	}
	for _, bad := range []string{"97", "84532,84532", "base", "84532,"} {
		t.Setenv(SettlementChainsEnv, bad)
		if got, err := SettlementChainsFromEnv(supported); err == nil {
			t.Fatalf("%q accepted as %v", bad, got)
		}
	}
}

// anchorsWords is an anchors() return of n 32-byte words: 15 is what a V8.1 anchor answers, 17 a V8.2.
type fakeGenerationChain struct {
	code    []byte
	words   int
	callErr error
}

func (f fakeGenerationChain) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return f.code, nil
}
func (f fakeGenerationChain) CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
	if f.callErr != nil {
		return nil, f.callErr
	}
	return make([]byte, 32*f.words), nil
}

// Every settlement chain's anchor must be a CertenAnchorV8_2: this build sends the V8.2 call, which an earlier anchor
// cannot take. An anchor that is a V8.1, has no code, or cannot be read stops the start.
func TestASettlementChainsAnchorMustBeAV8_2(t *testing.T) {
	a := common.HexToAddress("0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c")
	if err := verifyAnchorGeneration(context.Background(), fakeGenerationChain{code: []byte{1}, words: 17}, 84532, a); err != nil {
		t.Fatalf("a V8.2 anchor was refused: %v", err)
	}
	err := verifyAnchorGeneration(context.Background(), fakeGenerationChain{code: []byte{1}, words: 15}, 84532, a)
	if err == nil || !strings.Contains(err.Error(), "CertenAnchorV8.1") {
		t.Fatalf("a V8.1 anchor was accepted: %v", err)
	}
	for name, c := range map[string]fakeGenerationChain{
		"no code":     {words: 17},
		"unreadable":  {code: []byte{1}, callErr: errors.New("connection refused")},
		"not anchors": {code: []byte{1}, words: 3},
	} {
		if err := verifyAnchorGeneration(context.Background(), c, 84532, a); err == nil {
			t.Errorf("%s: the start went ahead", name)
		}
	}
}

// A chain outside the settlement set is answered as not settled - a refusal by name - never as an anchor to look for.
func TestAChainOutsideTheSetIsNotSettled(t *testing.T) {
	r, err := NewEVMChainResolver(&config.AnchorConfig{}, map[int64]common.Address{84532: common.HexToAddress("0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Endpoint(11155111); !errors.Is(err, consensus.ErrChainNotSettled) {
		t.Fatalf("Endpoint: %v", err)
	}
	if _, _, err := r.ManagerForChain(421614); !errors.Is(err, consensus.ErrChainNotSettled) {
		t.Fatalf("ManagerForChain: %v", err)
	}
}
