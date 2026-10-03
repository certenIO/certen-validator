package execution

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB5 D4: every settlement chain names its outcome registry, and the registry must be the one bound to that chain's
// anchor on that chain - a boot refusal by name otherwise.

func TestEverySettlementChainMustNameItsOutcomeRegistry(t *testing.T) {
	t.Setenv("CERTEN_OUTCOME_REGISTRY_11155111", "0xd479841a17770D89Dae94B5b41C95D2117414c21")
	t.Setenv("CERTEN_OUTCOME_REGISTRY_84532", "not-an-address")
	t.Setenv("CERTEN_OUTCOME_REGISTRY_421614", "")
	_, err := OutcomeRegistriesFromEnv([]int64{11155111, 84532, 421614})
	if err == nil {
		t.Fatal("a settlement chain without a usable outcome registry was accepted")
	}
	for _, name := range []string{"CERTEN_OUTCOME_REGISTRY_84532=", "CERTEN_OUTCOME_REGISTRY_421614 is not set"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s: %v", name, err)
		}
	}
	t.Setenv("CERTEN_OUTCOME_REGISTRY_84532", "0xd479841a17770D89Dae94B5b41C95D2117414c21")
	t.Setenv("CERTEN_OUTCOME_REGISTRY_421614", "0xbBa0a4aE0fDF5F7cFC7DE67358a32d1E82aFEE0e")
	got, err := OutcomeRegistriesFromEnv([]int64{11155111, 84532, 421614})
	if err != nil || got[421614] != common.HexToAddress("0xbBa0a4aE0fDF5F7cFC7DE67358a32d1E82aFEE0e") {
		t.Fatalf("(%v, %v)", got, err)
	}
	t.Setenv("CERTEN_OUTCOME_REGISTRY_84532", "0x0000000000000000000000000000000000000000")
	if _, err := OutcomeRegistriesFromEnv([]int64{84532}); err == nil {
		t.Fatal("the zero address was accepted as a registry")
	}
}

type fakeRegistryIdentity struct {
	anchor common.Address
	chain  *big.Int
	err    error
}

func (f fakeRegistryIdentity) RegistryIdentity(context.Context) (common.Address, *big.Int, error) {
	return f.anchor, f.chain, f.err
}

func TestARegistryNotBoundToTheChainsAnchorStopsTheStart(t *testing.T) {
	anchor := common.HexToAddress("0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c")
	reg := common.HexToAddress("0xd479841a17770D89Dae94B5b41C95D2117414c21")
	ctx := context.Background()
	if err := VerifyOutcomeRegistry(ctx, 84532, reg, anchor, fakeRegistryIdentity{anchor: anchor, chain: big.NewInt(84532)}); err != nil {
		t.Fatalf("the deployed binding was refused: %v", err)
	}
	for name, id := range map[string]fakeRegistryIdentity{
		"another anchor": {anchor: common.HexToAddress("0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6"), chain: big.NewInt(84532)},
		"another chain":  {anchor: anchor, chain: big.NewInt(11155111)},
		"unreadable":     {err: errors.New("providers disagree")},
	} {
		if err := VerifyOutcomeRegistry(ctx, 84532, reg, anchor, id); err == nil || !strings.Contains(err.Error(), "chain 84532") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
