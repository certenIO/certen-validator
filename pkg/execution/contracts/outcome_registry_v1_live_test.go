//go:build live

package contracts

import (
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB5 D4, against the deployed contracts: each registry is bound to its chain's V8.2 anchor, and its outcomeMessage
// for a real attested batch anchor is exactly ComputeEvmMessageHashV8_2_Outcome over that anchor's committed values.
// The live build requires every input; nothing is skipped.
func TestDeployedOutcomeRegistriesSignTheGoOutcomeMessage(t *testing.T) {
	for _, c := range []struct {
		chain    int64
		env      string
		registry string
		anchor   string
		bundle   string // a V8.2 batch anchor whose proof executed (anchor_batches, 2026-10-03)
	}{
		{11155111, "CERTEN_LIVE_SEPOLIA_RPC", "0xd479841a17770D89Dae94B5b41C95D2117414c21", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c",
			"0x692571219ee830e0374679ac99f960fbfee00be2c2f1ecb24da15ccc0137d736"},
		{84532, "CERTEN_LIVE_BASE_SEPOLIA_RPC", "0xd479841a17770D89Dae94B5b41C95D2117414c21", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c",
			"0x4fb6a9d7b7e39f0727d96c184ee91d30cbf3cee98a1cba81b7e00584f67a4f36"},
		{421614, "CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", "0xbBa0a4aE0fDF5F7cFC7DE67358a32d1E82aFEE0e", "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6",
			"0xa7c028667ef5b1e6a91a1d086e8e91d9e46334fb7e8a1fc384397499791b87d1"},
	} {
		rpcURL := os.Getenv(c.env)
		if rpcURL == "" {
			t.Fatalf("the live build requires %s", c.env)
		}
		client, err := ethclient.Dial(rpcURL)
		if err != nil {
			t.Fatal(err)
		}
		reg, err := NewCertenOutcomeRegistryV1(common.HexToAddress(c.registry), client)
		if err != nil {
			t.Fatal(err)
		}
		anchorAddr, err := reg.Anchor(nil)
		if err != nil || anchorAddr != common.HexToAddress(c.anchor) {
			t.Fatalf("chain %d: the registry's anchor is %s (%v), want %s", c.chain, anchorAddr.Hex(), err, c.anchor)
		}
		if id, err := reg.DeploymentChainID(nil); err != nil || id.Int64() != c.chain {
			t.Fatalf("chain %d: the registry was deployed for chain %v (%v)", c.chain, id, err)
		}
		anchor, err := NewCertenAnchorV8_2Batch(anchorAddr, client)
		if err != nil {
			t.Fatal(err)
		}
		bundle := common.HexToHash(c.bundle)
		a, err := anchor.Anchors(nil, bundle)
		if err != nil || !a.Valid || !a.ProofExecuted {
			t.Fatalf("chain %d: bundle %s is not an attested V8.2 anchor: %+v (%v)", c.chain, bundle.Hex(), a, err)
		}
		setRoot, err := anchor.CurrentValidatorSetRoot(nil)
		if err != nil {
			t.Fatal(err)
		}
		root := common.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777")
		onChain, err := reg.OutcomeMessage(nil, bundle, root)
		if err != nil {
			t.Fatalf("chain %d: outcomeMessage: %v", c.chain, err)
		}
		if want := ComputeEvmMessageHashV8_2_Outcome(c.chain, bundle, root, setRoot, a.AccumulateValidatorSetRoot, a.AccumulateIncarnation); onChain != want {
			t.Fatalf("chain %d: the registry signs %x, Go computes %x", c.chain, onChain, want)
		}
	}
}
