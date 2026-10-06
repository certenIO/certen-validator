// Copyright 2026 Certen Protocol

// Package supportedchains is the validator's ONE chain catalogue, and the one reading of which of its chains are
// enabled.
//
// Two levels, never mixed (RB7 §4.1, RB8 §0):
//
//   - The catalogue (All) is what this build CAN settle on: each chain's identity (id, names, slugs), the key its RPC
//     providers are configured under, its gas defaults and ceilings, its explorer, its native token and the properties of
//     its execution layer. It is code, and a chain in it does nothing by being there.
//   - The enabled set is what this network DOES settle on now: CERTEN_SETTLEMENT_CHAINS (EnabledEnv), required, no
//     default, identical on every validator. A chain is admitted at consensus, observed, anchored and settled only when
//     it is named there - and naming it requires its configuration (RPC providers, anchor, outcome registry, leaf version,
//     gas ceiling), each refused at boot by name when missing.
//
// Consensus, the strategy registry, the configuration and the evidence repairs each kept their own copy of the chain
// list (RB3-F26); a copy that drifts is a chain one part accepts and another does not. Every table that states a
// per-chain fact reads it here.
//
// API for the tables that derive from the catalogue (RB7 Task 4 groups V-2 and V-3):
//
//	Lookup(id) (Chain, bool)            the chain with that id
//	LookupName(name) (Chain, bool)      the chain its Name, Network, RPCKey or an alias names (case, " ", "_" ignored)
//	Chain.Name                          canonical slug ("ethereum-sepolia", "telcoin-adiri"): refusals, network names
//	Chain.Network                       short label ("sepolia", "base-sepolia"): strategy network name, anchor-row label
//	Chain.Aliases                       further slugs naming the chain ("eth-sepolia", "adiri")
//	Chain.Family                        fee-model family the chain reduces to ("ethereum", "base", "arbitrum", "telcoin")
//	Chain.NativeSymbol, NativeDecimals  the gas token ("ETH"/18, "TEL"/18)
//	Chain.ContractBlockIsParent         a contract's block.number is the parent chain's (Arbitrum: an L1 block number)
//	Chain.DisplayName, ExplorerURL      for people
//	Chain.BlocksOnlyWithTraffic         its time stops while it is idle: the per-chain clock may send a heartbeat (RB7 §1.1)
//	Chain.GenesisHash, PinnedGenesis()  the incarnation of the chain this build settles on: its block 0 hash (RB7 D8)
//	Chain.EnvPrefix() and the *Env()    the environment variables the chain is configured under
//	EnabledFromEnv(), Enabled()         the enabled set, read from CERTEN_SETTLEMENT_CHAINS
//	IsEnabled(id), DescribeIDs(ids)     admission and its messages
package supportedchains

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Chain is one catalogued chain: what CERTEN must know to settle on it. Nothing here enables it.
type Chain struct {
	ID int64
	// Name is the chain's canonical slug, in refusals and network names ("base-sepolia").
	Name string
	// Network is the chain's short network label: the strategy registry's network name and the anchor rows' target_chain
	// label ("sepolia" for Ethereum Sepolia).
	Network string
	// Aliases are further lower-case slugs that name the chain.
	Aliases []string
	// Family is the fee-model family the chain belongs to ("ethereum", "base", "arbitrum", "telcoin").
	Family string
	// DisplayName is the chain's name for people ("Ethereum Sepolia").
	DisplayName string
	// Testnet is true for a test network.
	Testnet bool

	// RPCKey is the key its RPC providers are configured under (ethrpc.ChainKeyForID): <PREFIX>_RPC_URL,
	// <PREFIX>_URL_FALLBACKS, INFURA_<PREFIX>_URL, ALCHEMY_<PREFIX>_URL and <PREFIX>_WS_URL, with PREFIX = EnvPrefix().
	RPCKey string
	// LegacyRPCEnv is an older name its primary RPC is still read under when <PREFIX>_RPC_URL is unset ("" for none).
	LegacyRPCEnv string
	// GasEnvPrefix prefixes its gas settings: <G>_MAX_GAS_PRICE_GWEI, <G>_MAX_PRIORITY_FEE_GWEI, <G>_GAS_LIMIT_ANCHOR.
	GasEnvPrefix string

	// DefaultMaxGasPriceGwei is the gas price ceiling, in gwei of the native token, when <G>_MAX_GAS_PRICE_GWEI is unset.
	// 0 means no default is compiled in: the ceiling must be configured before the chain can be enabled (a ceiling is a
	// fact of the chain's fee market, measured, never copied from another chain).
	DefaultMaxGasPriceGwei int64
	// DefaultMaxPriorityFeeGwei is the priority fee cap when <G>_MAX_PRIORITY_FEE_GWEI is unset.
	DefaultMaxPriorityFeeGwei int64
	// DefaultGasLimitAnchor is the anchor gas limit when <G>_GAS_LIMIT_ANCHOR is unset. 0: it must be configured.
	DefaultGasLimitAnchor int64

	// ExplorerURL is the chain's block explorer.
	ExplorerURL string
	// NativeSymbol and NativeDecimals are the chain's gas token.
	NativeSymbol   string
	NativeDecimals uint8
	// ContractBlockIsParent: a contract's block.number on this chain is its parent chain's block number, not the chain's
	// own (Arbitrum Nitro, whose recordedInBlock is an L1 block number).
	ContractBlockIsParent bool

	// BlocksOnlyWithTraffic: the chain produces a block only when a transaction lands (or when its protocol closes a
	// period), so its time - the time of its latest finalized block - stops while it is idle. Every rule that waits for
	// a finalized block past a horizon (a deadline plus its margin, a settlement window's fence) would wait for traffic
	// that may never come; on such a chain, and only on such a chain, the per-chain clock may send a heartbeat
	// transaction to produce the block (pkg/execution chain_heartbeat.go). The block decides; the heartbeat only makes
	// one exist. A chain whose blocks never stop (Ethereum, the OP stack, Arbitrum) never heartbeats.
	BlocksOnlyWithTraffic bool

	// GenesisHash is the hash of the chain's block 0 this build settles on ("" for a chain not pinned). A testnet that
	// is reset keeps its chain id and starts again from a new genesis, erasing every CERTEN contract and settlement on
	// it; like an Accumulate incarnation, the genesis names WHICH chain of that id this is. A pinned chain whose
	// providers serve another genesis is refused by name, at boot and on every read (pkg/ethrpc genesis.go), never
	// treated as the same chain. GenesisEnv overrides it - the one way to re-enable a chain after a reset (see
	// PinnedGenesis).
	GenesisHash string
}

// All is the catalogue, in a fixed order: the order chains are listed in messages.
var All = []Chain{
	{
		ID: 11155111, Name: "ethereum-sepolia", Network: "sepolia", Aliases: []string{"eth-sepolia"},
		Family: "ethereum", DisplayName: "Ethereum Sepolia", Testnet: true,
		RPCKey: "ethereum-sepolia", LegacyRPCEnv: "ETHEREUM_URL", GasEnvPrefix: "SEPOLIA",
		DefaultMaxGasPriceGwei: 100, DefaultMaxPriorityFeeGwei: 2, DefaultGasLimitAnchor: 500000,
		ExplorerURL: "https://sepolia.etherscan.io", NativeSymbol: "ETH", NativeDecimals: 18,
	},
	{
		ID: 84532, Name: "base-sepolia", Network: "base-sepolia",
		Family: "base", DisplayName: "Base Sepolia", Testnet: true,
		RPCKey: "base-sepolia", GasEnvPrefix: "BASE",
		DefaultMaxGasPriceGwei: 1, DefaultMaxPriorityFeeGwei: 0, DefaultGasLimitAnchor: 2000000,
		ExplorerURL: "https://sepolia.basescan.org", NativeSymbol: "ETH", NativeDecimals: 18,
	},
	{
		ID: 421614, Name: "arbitrum-sepolia", Network: "arbitrum-sepolia",
		Family: "arbitrum", DisplayName: "Arbitrum Sepolia", Testnet: true,
		RPCKey: "arbitrum-sepolia", GasEnvPrefix: "ARBITRUM",
		DefaultMaxGasPriceGwei: 1, DefaultMaxPriorityFeeGwei: 0, DefaultGasLimitAnchor: 2000000,
		ExplorerURL: "https://sepolia.arbiscan.io", NativeSymbol: "ETH", NativeDecimals: 18,
		ContractBlockIsParent: true,
	},
	// Telcoin Network's Adiri testnet (RB7 Task 4): a reth-derived execution layer under Narwhal/Bullshark consensus, gas
	// paid in TEL. Catalogued, not enabled: it is inert until CERTEN_SETTLEMENT_CHAINS names 2017 together with its RPC
	// providers (TELCOIN_ADIRI_RPC_URL and TELCOIN_ADIRI_URL_FALLBACKS), CERTEN_ANCHOR_V8_2017,
	// CERTEN_OUTCOME_REGISTRY_2017, a 2017 entry in CERTEN_ACCOUNT_LEAF_VERSIONS, TELCOIN_ADIRI_MAX_GAS_PRICE_GWEI and
	// TELCOIN_ADIRI_GAS_LIMIT_ANCHOR - none of which has a compiled default. "telcoin" alone is not an alias: it would
	// name Telcoin's mainnet.
	{
		ID: 2017, Name: "telcoin-adiri", Network: "telcoin-adiri", Aliases: []string{"adiri", "tel-adiri"},
		Family: "telcoin", DisplayName: "Telcoin Adiri", Testnet: true,
		RPCKey: "telcoin-adiri", GasEnvPrefix: "TELCOIN_ADIRI",
		DefaultMaxGasPriceGwei: 0, DefaultMaxPriorityFeeGwei: 0, DefaultGasLimitAnchor: 0,
		ExplorerURL: "https://scan.telcoin.network", NativeSymbol: "TEL", NativeDecimals: 18,
		// An Adiri block exists only when a consensus commit carries transactions, or closes an epoch (every 21600 s):
		// telcoin-network@5736cc30 crates/engine/src/payload_builder.rs:114-127 skips an empty output (RB7 Phase A
		// F-BLK-1, F-BLK-2).
		BlocksOnlyWithTraffic: true,
		// Block 0 of the Adiri incarnation launched 2026-05-07 19:57:27 UTC (timestamp 0x69fceea7). Read 2026-10-05 from
		// all six public endpoints (rpc.telcoin.network, adiri.tel, node1-4.telcoin.network: identical), and recomputed
		// with go-ethereum v1.17.0 core.Genesis.ToBlock from the published telcoin-network@5736cc30
		// chain-configs/testnet/genesis.yaml: the same hash, state root 0x0eecd289...a224. The chain id has had an
		// earlier incarnation (Phase A F-FIN-5); a reset is refused by name until the pin is changed.
		GenesisHash: "0x3577ee7223cf0d9a1da1293fd12a47e0e45bb97afcd0427bccd4954cb704baef",
	},
}

// IDs are the catalogued chain IDs, in All's order.
func IDs() []int64 {
	out := make([]int64, 0, len(All))
	for _, c := range All {
		out = append(out, c.ID)
	}
	return out
}

// Lookup returns the catalogued chain with the given ID.
func Lookup(id int64) (Chain, bool) {
	for _, c := range All {
		if c.ID == id {
			return c, true
		}
	}
	return Chain{}, false
}

// normalizeName lower-cases a chain name and writes its separators as "-".
func normalizeName(name string) string {
	return strings.NewReplacer(" ", "-", "_", "-").Replace(strings.ToLower(strings.TrimSpace(name)))
}

// LookupName returns the catalogued chain a name names: its Name, Network, RPCKey or one of its Aliases, ignoring case
// and writing " " and "_" as "-". Anything else is not a catalogued chain - never the nearest match.
func LookupName(name string) (Chain, bool) {
	n := normalizeName(name)
	if n == "" {
		return Chain{}, false
	}
	for _, c := range All {
		if n == c.Name || n == c.Network || n == c.RPCKey {
			return c, true
		}
		for _, a := range c.Aliases {
			if n == a {
				return c, true
			}
		}
	}
	return Chain{}, false
}

// IsSupported reports whether the chain is in the catalogue: this build can settle on it. Whether this network settles
// on it now is IsEnabled.
func IsSupported(id int64) bool {
	_, ok := Lookup(id)
	return ok
}

// Describe renders the whole catalogue for messages: "ethereum-sepolia (11155111), ...".
func Describe() string {
	return DescribeIDs(IDs())
}

// DescribeIDs renders the chains among ids for messages, catalogued ones first in catalogue order
// ("ethereum-sepolia (11155111), base-sepolia (84532)"), then any id not in the catalogue as its number alone.
func DescribeIDs(ids []int64) string {
	want := map[int64]bool{}
	for _, id := range ids {
		want[id] = true
	}
	parts := make([]string, 0, len(want))
	for _, c := range All {
		if want[c.ID] {
			parts = append(parts, c.Name+" ("+strconv.FormatInt(c.ID, 10)+")")
			delete(want, c.ID)
		}
	}
	rest := make([]int64, 0, len(want))
	for id := range want {
		rest = append(rest, id)
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	for _, id := range rest {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ", ")
}

// EnvPrefix is the prefix of the chain's RPC variables: its RPCKey upper-cased with " ", "-" and "." written as "_"
// (the same rule as ethrpc.ChainEnvPrefix).
func (c Chain) EnvPrefix() string {
	return strings.NewReplacer(" ", "_", "-", "_", ".", "_").Replace(strings.ToUpper(strings.TrimSpace(c.RPCKey)))
}

// RPCURLEnv is the variable holding the chain's primary RPC.
func (c Chain) RPCURLEnv() string { return c.EnvPrefix() + "_RPC_URL" }

// WSURLEnv is the variable holding the chain's websocket RPC.
func (c Chain) WSURLEnv() string { return c.EnvPrefix() + "_WS_URL" }

// URLFallbacksEnv is the variable holding the chain's further RPC providers, comma-separated.
func (c Chain) URLFallbacksEnv() string { return c.EnvPrefix() + "_URL_FALLBACKS" }

// MaxGasPriceEnv is the variable holding the chain's gas price ceiling in gwei.
func (c Chain) MaxGasPriceEnv() string { return c.GasEnvPrefix + "_MAX_GAS_PRICE_GWEI" }

// MaxPriorityFeeEnv is the variable holding the chain's priority fee cap in gwei.
func (c Chain) MaxPriorityFeeEnv() string { return c.GasEnvPrefix + "_MAX_PRIORITY_FEE_GWEI" }

// GasLimitAnchorEnv is the variable holding the chain's anchor gas limit.
func (c Chain) GasLimitAnchorEnv() string { return c.GasEnvPrefix + "_GAS_LIMIT_ANCHOR" }

// GenesisEnv is the variable that pins the chain's genesis, overriding the catalogue's GenesisHash:
// CERTEN_CHAIN_GENESIS_<id>.
func (c Chain) GenesisEnv() string { return GenesisEnvFor(c.ID) }

// GenesisEnvFor is the genesis pin variable of chain id.
func GenesisEnvFor(id int64) string { return "CERTEN_CHAIN_GENESIS_" + strconv.FormatInt(id, 10) }

// PinnedGenesis is the genesis the chain is pinned to, as lower-case 0x-hex of 32 bytes, and whether it is pinned at
// all: GenesisEnv when it is set, the catalogue's GenesisHash otherwise.
//
// Re-enabling a chain after a reset. A reset chain is refused by name until its pin names the new genesis: set
// CERTEN_CHAIN_GENESIS_<id> to the new block 0 hash in the SHARED environment, so that all seven validators carry the
// same value, and restart them together - exactly as CERTEN_SETTLEMENT_CHAINS is changed. The reset erased every
// CERTEN contract on the chain, so the chain's anchor, outcome registry and account factory are redeployed and their
// variables changed in the same window. A validator left on the old pin refuses the chain and attests nothing on it:
// it fails closed, it never reads the new chain as the old one.
//
// A set but malformed value is refused by name: a pin that cannot be read pins nothing, and is not taken as "unpinned".
func (c Chain) PinnedGenesis() (string, bool, error) {
	if raw, set := os.LookupEnv(c.GenesisEnv()); set {
		h, err := parseGenesisHash(raw)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", c.GenesisEnv(), err)
		}
		return h, true, nil
	}
	if c.GenesisHash == "" {
		return "", false, nil
	}
	h, err := parseGenesisHash(c.GenesisHash)
	if err != nil {
		return "", false, fmt.Errorf("the catalogue's genesis of chain %d: %w", c.ID, err)
	}
	return h, true, nil
}

// PinnedGenesisOf is PinnedGenesis of a catalogued chain; a chain not in the catalogue is not pinned.
func PinnedGenesisOf(id int64) (string, bool, error) {
	c, ok := Lookup(id)
	if !ok {
		if raw, set := os.LookupEnv(GenesisEnvFor(id)); set {
			return "", false, fmt.Errorf("%s=%q pins chain %d, which is not in the catalogue", GenesisEnvFor(id), raw, id)
		}
		return "", false, nil
	}
	return c.PinnedGenesis()
}

func parseGenesisHash(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(s, "0x") || len(s) != 66 {
		return "", fmt.Errorf("%q is not a 0x-prefixed 32-byte block hash", raw)
	}
	zero := true
	for _, r := range s[2:] {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return "", fmt.Errorf("%q is not a 0x-prefixed 32-byte block hash", raw)
		}
		if r != '0' {
			zero = false
		}
	}
	if zero {
		return "", fmt.Errorf("%q is all zeroes, which is no block's hash", raw)
	}
	return s, nil
}

// =============================================================================
// The enabled set
// =============================================================================

// EnabledEnv names the chains CERTEN settles on NOW, by chain id ("84532" or "11155111,84532,421614"). It is required -
// there is no default - and every validator must carry the same value (it is read from the shared environment): a leg on
// a chain not named is refused by name at consensus, so validators that disagreed would decide the same intent
// differently. Each named chain must be in the catalogue and fully configured. A rollout brings chains up one at a time
// by naming them (RB5-F33).
const EnabledEnv = "CERTEN_SETTLEMENT_CHAINS"

// ParseEnabled reads an EnabledEnv value against the chains a caller supports, ascending. An empty value, and an entry
// that is not a chain id, is not supported, or is repeated, is refused by name.
func ParseEnabled(raw string, supported []int64) ([]int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is not set: name the chains CERTEN settles on now (of %v)", EnabledEnv, supported)
	}
	ok := map[int64]bool{}
	for _, id := range supported {
		ok[id] = true
	}
	seen := map[int64]bool{}
	var out []int64
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a chain id", EnabledEnv, part)
		}
		if !ok[id] {
			return nil, fmt.Errorf("%s names chain %d, which this build does not settle on (it supports %v)",
				EnabledEnv, id, supported)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s names chain %d twice", EnabledEnv, id)
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// EnabledFromEnv reads the enabled set from EnabledEnv against the catalogue, ascending. It is read on every call: the
// environment is fixed for the life of the process, and reading it here rather than from a copy taken at boot means the
// admission check and the boot can never disagree.
func EnabledFromEnv() ([]int64, error) {
	return ParseEnabled(os.Getenv(EnabledEnv), IDs())
}

// Enabled returns the enabled chains' catalogue entries, in catalogue order.
func Enabled() ([]Chain, error) {
	ids, err := EnabledFromEnv()
	if err != nil {
		return nil, err
	}
	on := map[int64]bool{}
	for _, id := range ids {
		on[id] = true
	}
	out := make([]Chain, 0, len(ids))
	for _, c := range All {
		if on[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

// IsEnabled reports whether the chain is in the catalogue and named in EnabledEnv. An unreadable EnabledEnv enables
// nothing (and the validator does not start with one: the batch path refuses it at boot).
func IsEnabled(id int64) bool {
	ids, err := EnabledFromEnv()
	if err != nil {
		return false
	}
	for _, e := range ids {
		if e == id {
			return true
		}
	}
	return false
}
