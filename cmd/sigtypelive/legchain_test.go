package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// The live anchors of the four supported chains (docs/runbooks/rules-v14-ceiling-anchor-set.md, anchor set v1): test
// input standing in for each validator's CERTEN_ANCHOR_V8_<chainId>, the one place the tool reads them from.
var liveAnchorEnv = map[string]string{
	"CERTEN_ANCHOR_V8_11155111": "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c",
	"CERTEN_ANCHOR_V8_84532":    "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c",
	"CERTEN_ANCHOR_V8_421614":   "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6",
	"CERTEN_ANCHOR_V8_2017":     "0xEE381d01Dab7ffeA0F0006943F8337bA88B4070C",
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

type legBlob struct {
	Legs []struct {
		LegID   string `json:"legId"`
		Chain   string `json:"chain"`
		ChainID int64  `json:"chainId"`
		Network string `json:"network"`
		Asset   struct {
			Symbol   string `json:"symbol"`
			Decimals int    `json:"decimals"`
		} `json:"asset"`
		Anchor struct {
			Address string `json:"address"`
		} `json:"anchorContract"`
		Payload struct {
			ChainID    int64  `json:"chainId"`
			Commitment string `json:"executionCommitment"`
		} `json:"executionPayload"`
	} `json:"legs"`
}

// RB10-F5: the intent leg's chain, chainId, network, anchor and chain nonce come from -chain, for each of the four
// supported chains, through the catalogue (pkg/supportedchains) and the validators' own anchor variable.
func TestTheIntentLegFollowsTheChainFlag(t *testing.T) {
	for _, flag := range []string{"sepolia", "ethereum-sepolia", "base-sepolia", "arbitrum-sepolia", "adiri", "telcoin-adiri"} {
		t.Run(flag, func(t *testing.T) {
			cat, ok := supportedchains.LookupName(flag)
			if !ok {
				t.Fatalf("%s is not in the catalogue", flag)
			}
			leg, err := resolveLegChain(flag, envOf(liveAnchorEnv))
			if err != nil {
				t.Fatal(err)
			}
			anchorEnv := "CERTEN_ANCHOR_V8_" + strconv.FormatInt(cat.ID, 10)
			if leg.Name != cat.Name || leg.ChainID != cat.ID || leg.Network != cat.Network || leg.Anchor != liveAnchorEnv[anchorEnv] ||
				leg.Symbol != cat.NativeSymbol || leg.Display != cat.DisplayName {
				t.Fatalf("-chain %s resolves to %+v, the catalogue says %+v (anchor %s)", flag, leg, cat, liveAnchorEnv[anchorEnv])
			}
			blobs, err := buildIntent("acc://pv2-sig-1.acme", liveCases()[0], addrA, leg)
			if err != nil {
				t.Fatal(err)
			}
			var cc legBlob
			if err := json.Unmarshal(blobs.Blobs[1], &cc); err != nil || len(cc.Legs) != 1 {
				t.Fatalf("cross-chain blob: %v (%d legs)", err, len(cc.Legs))
			}
			l := cc.Legs[0]
			if l.Chain != cat.Name || l.ChainID != cat.ID || l.Network != cat.Network || l.Payload.ChainID != cat.ID ||
				l.Anchor.Address != liveAnchorEnv[anchorEnv] || l.LegID != "leg-"+cat.Name+"-"+strconv.FormatInt(cat.ID, 10)+"-1" ||
				l.Asset.Symbol != cat.NativeSymbol || l.Asset.Decimals != int(cat.NativeDecimals) {
				t.Fatalf("-chain %s: leg %+v", flag, l)
			}
			commit, _, err := executionCommitment(uint64(cat.ID), intentRecipient, 1)
			if err != nil || l.Payload.Commitment != "0x"+hex.EncodeToString(commit) {
				t.Fatalf("-chain %s: the execution commitment %s is not over chain %d (%v)", flag, l.Payload.Commitment, cat.ID, err)
			}
			var rp struct {
				Nonces map[string]string `json:"chain_nonces"`
			}
			if err := json.Unmarshal(blobs.Blobs[3], &rp); err != nil || len(rp.Nonces) != 2 || rp.Nonces[cat.Name] != "latest" || rp.Nonces["accumulated"] != "1" {
				t.Fatalf("-chain %s: chain_nonces %v (%v)", flag, rp.Nonces, err)
			}
			if !strings.Contains(string(blobs.Blobs[0]), cat.DisplayName) {
				t.Fatalf("-chain %s: the description does not name %s: %s", flag, cat.DisplayName, blobs.Blobs[0])
			}
		})
	}
}

// A chain the catalogue does not hold, or one whose anchor the environment does not name (or names badly), is refused by
// name: the tool never falls back to another chain or a compiled-in address.
func TestALegChainIsRefusedByName(t *testing.T) {
	for _, c := range []struct {
		chain string
		env   map[string]string
		want  string
	}{
		{"mainnet", liveAnchorEnv, `"mainnet" is not a supported chain`},
		{"", liveAnchorEnv, `"" is not a supported chain`},
		{"arbitrum-sepolia", map[string]string{}, "CERTEN_ANCHOR_V8_421614 is not set"},
		{"adiri", map[string]string{"CERTEN_ANCHOR_V8_2017": "0x1234"}, "CERTEN_ANCHOR_V8_2017 is not an address"},
	} {
		if leg, err := resolveLegChain(c.chain, envOf(c.env)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("-chain %q: %+v, %v; want an error naming %q", c.chain, leg, err, c.want)
		}
	}
}

// testLeg is -chain resolved against the live anchors.
func testLeg(t *testing.T, chain string) legChain {
	t.Helper()
	leg, err := resolveLegChain(chain, envOf(liveAnchorEnv))
	if err != nil {
		t.Fatal(err)
	}
	return leg
}
