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

// RB7 §4.3 / RB8 §0: admission admits the ENABLED chains, not every chain the build knows. A chain the build catalogues
// but CERTEN_SETTLEMENT_CHAINS does not name is refused here, on every validator, by name - before RB7 it passed
// admission and was refused only later, when no anchor could be named for it.
func TestCheckIntentTargetChains_RefusesACataloguedChainThatIsNotEnabled(t *testing.T) {
	t.Setenv("CERTEN_SETTLEMENT_CHAINS", "84532")
	err := CheckIntentTargetChains(pinIntent(t, chainLeg(11155111, 11155111)))
	if !errors.Is(err, ErrUnsupportedTargetChain) {
		t.Fatalf("a leg on Sepolia was admitted with only Base Sepolia enabled: %v", err)
	}
	if !strings.Contains(err.Error(), "ethereum-sepolia") || !strings.Contains(err.Error(), "not enabled") ||
		!strings.Contains(err.Error(), "CERTEN executes only on base-sepolia (84532)") {
		t.Fatalf("the refusal does not name the chain and the enabled set: %v", err)
	}
	if err := CheckIntentTargetChains(pinIntent(t, chainLeg(84532, 84532))); err != nil {
		t.Fatalf("the enabled chain was refused: %v", err)
	}
}

// Telcoin Adiri (2017) is disabled by default: with the live configuration a 2017 leg is refused by name.
func TestCheckIntentTargetChains_RefusesTelcoinAdiriUnlessEnabled(t *testing.T) {
	t.Setenv("CERTEN_SETTLEMENT_CHAINS", liveSettlementChains)
	err := CheckIntentTargetChains(pinIntent(t, chainLeg(2017, 2017)))
	if !errors.Is(err, ErrUnsupportedTargetChain) || !strings.Contains(err.Error(), "chain 2017 (telcoin-adiri), which is not enabled") {
		t.Fatalf("a 2017 leg was not refused by name: %v", err)
	}
}

// Enabled by configuration, a 2017 leg is admitted, alone and beside a live chain.
func TestCheckIntentTargetChains_AdmitsTelcoinAdiriWhenEnabled(t *testing.T) {
	t.Setenv("CERTEN_SETTLEMENT_CHAINS", liveSettlementChains+",2017")
	if err := CheckIntentTargetChains(pinIntent(t, chainLeg(2017, 2017))); err != nil {
		t.Fatalf("an enabled 2017 leg was refused: %v", err)
	}
	if err := CheckIntentTargetChains(pinIntent(t, chainLeg(84532, 84532), chainLeg(2017, 0))); err != nil {
		t.Fatalf("an intent over Base Sepolia and an enabled 2017 was refused: %v", err)
	}
	if !IsSupportedTargetChain(2017) {
		t.Fatal("2017 is not a target chain when enabled")
	}
}

// With the live configuration, the refusal of a chain outside the catalogue is byte-for-byte what it was before the
// catalogue gained an entry that is not enabled.
func TestCheckIntentTargetChains_TheLiveRefusalIsUnchanged(t *testing.T) {
	t.Setenv("CERTEN_SETTLEMENT_CHAINS", liveSettlementChains)
	err := CheckIntentTargetChains(pinIntent(t, chainLeg(84532, 84532), chainLeg(11155420, 11155420)))
	const want = "unsupported target chain: leg 1 targets chain 11155420; CERTEN executes only on " +
		"ethereum-sepolia (11155111), base-sepolia (84532), arbitrum-sepolia (421614)"
	if err == nil || err.Error() != want {
		t.Fatalf("refusal changed:\n got %v\nwant %s", err, want)
	}
	for _, id := range []int64{11155111, 84532, 421614} {
		if !IsSupportedTargetChain(id) {
			t.Fatalf("live chain %d is not a target chain", id)
		}
	}
}

// An enabled set that cannot be read admits nothing.
func TestCheckIntentTargetChains_AnUnreadableEnabledSetAdmitsNothing(t *testing.T) {
	for _, v := range []string{"", "84532,nope"} {
		t.Setenv("CERTEN_SETTLEMENT_CHAINS", v)
		if err := CheckIntentTargetChains(pinIntent(t, chainLeg(84532, 84532))); !errors.Is(err, ErrUnsupportedTargetChain) ||
			!strings.Contains(err.Error(), "CERTEN_SETTLEMENT_CHAINS") {
			t.Fatalf("%q: %v", v, err)
		}
	}
}
