package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// legChain is the target chain of the intent's one leg, resolved from -chain (RB10-F5). Nothing about it is typed here:
// the chain's name, id, network and native token are the validator's chain catalogue's (pkg/supportedchains), and its
// anchor is CERTEN_ANCHOR_V8_<chainId>, the variable every validator's batch path settles on (pkg/config, the anchors
// are not compiled in; consensus refuses a leg declaring any other anchor, RB4-F9).
type legChain struct {
	Name     string // the catalogue name: the leg's "chain", the legId and the chain_nonces key
	ChainID  int64
	Network  string
	Display  string
	Symbol   string // the native token the leg moves
	Decimals uint8
	Anchor   string // the CertenAnchorV8 the leg declares
}

// anchorEnvOf is the name of the variable holding chainID's anchor.
func anchorEnvOf(chainID int64) string { return fmt.Sprintf("CERTEN_ANCHOR_V8_%d", chainID) }

// resolveLegChain resolves -chain through the catalogue and the anchor through getenv. A chain the catalogue does not
// hold, or whose anchor is not set to an address, is refused by name.
func resolveLegChain(name string, getenv func(string) string) (legChain, error) {
	c, ok := supportedchains.LookupName(name)
	if !ok {
		return legChain{}, fmt.Errorf("-chain %q is not a supported chain (the catalogue holds %s)", name, catalogueNames())
	}
	key := anchorEnvOf(c.ID)
	a := strings.TrimSpace(getenv(key))
	if a == "" {
		return legChain{}, fmt.Errorf("%s is not set: the leg on %s (chain %d) must declare the anchor the validators settle it on", key, c.Name, c.ID)
	}
	if !common.IsHexAddress(a) || !strings.HasPrefix(a, "0x") {
		return legChain{}, fmt.Errorf("%s is not an address: %q", key, a)
	}
	return legChain{Name: c.Name, ChainID: c.ID, Network: c.Network, Display: c.DisplayName, Symbol: c.NativeSymbol,
		Decimals: c.NativeDecimals, Anchor: a}, nil
}

// legChainFromEnv resolves -chain against the process environment.
func legChainFromEnv(name string) (legChain, error) { return resolveLegChain(name, os.Getenv) }

func catalogueNames() string {
	var n []string
	for _, c := range supportedchains.All {
		n = append(n, c.Name)
	}
	return strings.Join(n, ", ")
}
