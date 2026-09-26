package consensus

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// chainLeg is a leg whose leg-level and payload-level chain IDs can be set independently.
func chainLeg(legChain, payloadChain int64) map[string]interface{} {
	return map[string]interface{}{"legId": "l", "chain": "ethereum", "chainId": legChain,
		"from": pinAccount.Hex(),
		"executionPayload": map[string]interface{}{
			"target":  common.HexToAddress("0x1111111111111111111111111111111111111111").Hex(),
			"chainId": payloadChain,
		}}
}

// Only Ethereum Sepolia, Base Sepolia and Arbitrum Sepolia run CERTEN's current contracts. An intent
// naming anything else is refused on every validator, whatever the chain's name says.
func TestCheckIntentTargetChains_AcceptsExactlyTheThreeSupportedChains(t *testing.T) {
	for _, id := range []int64{11155111, 84532, 421614} {
		if err := CheckIntentTargetChains(pinIntent(t, chainLeg(id, id))); err != nil {
			t.Errorf("supported chain %d was refused: %v", id, err)
		}
		if err := CheckIntentTargetChains(pinIntent(t, chainLeg(id, 0))); err != nil {
			t.Errorf("supported chain %d with no payload chainId was refused: %v", id, err)
		}
	}
	// A cross-chain intent over supported chains only is fine.
	if err := CheckIntentTargetChains(pinIntent(t, chainLeg(11155111, 11155111), chainLeg(84532, 84532))); err != nil {
		t.Errorf("a two-supported-chain intent was refused: %v", err)
	}
}

func TestCheckIntentTargetChains_RefusesEveryOtherChain(t *testing.T) {
	retired := []int64{
		11155420,           // Optimism Sepolia
		80002,              // Polygon Amoy
		97,                 // BSC testnet
		1287,               // Moonbase Alpha
		296,                // Hedera testnet
		2494104990,         // TRON Shasta
		1, 10, 8453, 42161, // mainnets
		-3, // TON testnet as the envelope encodes it
		424242,
	}
	for _, id := range retired {
		err := CheckIntentTargetChains(pinIntent(t, chainLeg(id, id)))
		if !errors.Is(err, ErrUnsupportedTargetChain) {
			t.Errorf("chain %d was not refused as unsupported: %v", id, err)
		}
	}
}

func TestCheckIntentTargetChains_OneBadLegRefusesTheWholeIntent(t *testing.T) {
	err := CheckIntentTargetChains(pinIntent(t, chainLeg(84532, 84532), chainLeg(11155420, 11155420)))
	if !errors.Is(err, ErrUnsupportedTargetChain) {
		t.Fatalf("an intent with one unsupported leg was allowed: %v", err)
	}
}

func TestCheckIntentTargetChains_RefusesLegsItCannotPlace(t *testing.T) {
	cases := map[string]*CertenIntent{
		"no chainId":                         pinIntent(t, chainLeg(0, 84532)),
		"payload names a different chain":    pinIntent(t, chainLeg(84532, 11155111)),
		"payload names an unsupported chain": pinIntent(t, chainLeg(84532, 11155420)),
		"no legs":                            pinIntent(t),
		"unreadable envelope":                {IntentID: "bad", CrossChainData: []byte("{not json")},
		"no envelope":                        {IntentID: "empty"},
	}
	for name, ci := range cases {
		if err := CheckIntentTargetChains(ci); !errors.Is(err, ErrUnsupportedTargetChain) {
			t.Errorf("%s: not refused as unsupported: %v", name, err)
		}
	}
}

// The chain check, like the anchor pin, must run on every validator before the intent is queued for
// batching or anything is sent: after either, a signature or a transaction may already exist.
func TestSupportedChainCheckRunsBeforeAnythingIsQueuedOrSent(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	check := strings.Index(src, "CheckIntentTargetChains(certenIntent)")
	enqueue := strings.Index(src, "bv.enqueueForBatch(")
	if check < 0 || enqueue < 0 || check > enqueue {
		t.Fatalf("chain check at %d, enqueue at %d: the chain check must run first", check, enqueue)
	}
}
