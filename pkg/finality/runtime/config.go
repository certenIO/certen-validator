// Copyright 2026 Certen Protocol

// Package runtime is the production wiring of the staged-finality builders (RB11, PROOF_V2 S7, certen:finality:v1): from the
// validator's existing configuration surface (the ethrpc per-chain provider variables, the supported-chain catalogue) plus a
// small set of CERTEN_FINALITY_* variables it builds, for every live chain and kind, the Prover and the Capturer the kind
// packages define, the light-client source, the durable capture store with its byte budgets, the rate-limited provider
// transport and the pins; and it registers them into a finality.Registry that finality.Launch starts.
//
// Rules this package keeps (V2_SPEC_S7 2.7, 2.8, 8.3):
//   - A provider that is not configured is a NAMED, LOGGED state (finality_upgrader_disabled, its reason naming the missing
//     setting), logged once per chain and counted; the chain's legs keep the level they were stored at. Nothing is skipped
//     silently and nothing panics.
//   - Providers are availability only, never evidence: every byte they serve is verified by the kind's own verifier before it
//     is stored.
//   - Provider text reaches logs, states and status rows only through pkg/ethrpc RedactText / RedactError.
//   - Nothing here runs on the settlement, attestation or write-back path.
package runtime

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// The CERTEN_FINALITY_* variables this package reads (the switches CERTEN_FINALITY_UPGRADER_ENABLED and
// CERTEN_FINALITY_CHAIN_<id>_ENABLED belong to pkg/finality).
const (
	EnvL1RPCURLs      = "CERTEN_FINALITY_L1_RPC_URLS"
	EnvL1ProofURLs    = "CERTEN_FINALITY_L1_PROOF_URLS"
	EnvArchiveURLs    = "CERTEN_FINALITY_ARCHIVE_URLS"
	EnvLCURLs         = "CERTEN_FINALITY_LC_URLS"
	EnvBeaconURLs     = "CERTEN_FINALITY_BEACON_URLS"
	EnvAdiriURLs      = "CERTEN_FINALITY_ADIRI_PUBLIC_URLS"
	EnvPinsFile       = "CERTEN_FINALITY_PINS_FILE"
	EnvRateRPS        = "CERTEN_FINALITY_RATE_LIMIT_RPS"
	EnvRateBurst      = "CERTEN_FINALITY_RATE_BURST"
	EnvMaxBatch       = "CERTEN_FINALITY_MAX_BATCH"
	EnvBackoffRetries = "CERTEN_FINALITY_BACKOFF_RETRIES"
	EnvBackoffMax     = "CERTEN_FINALITY_BACKOFF_MAX_SECONDS"
	EnvCaptureEvery   = "CERTEN_FINALITY_CAPTURE_INTERVAL_SECONDS"
	EnvCaptureBytes   = "CERTEN_FINALITY_MAX_CAPTURE_BYTES_PER_LEG"
	EnvCaptureBlocks  = "CERTEN_FINALITY_CAPTURE_MAX_BLOCKS_PER_TICK"
	EnvConcurrency    = "CERTEN_FINALITY_UPGRADER_CONCURRENCY"
	EnvInterval       = "CERTEN_FINALITY_UPGRADER_INTERVAL_SECONDS"
	EnvBuildTimeout   = "CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS"
)

// Defaults of the public providers the kind packages' live sources and recorders were measured against (V2_SPEC_S7 8.1; the
// proof providers hold eth_getProof only near the head: Tenderly about 8 blocks, the others at most 100).
var (
	DefaultL1RPCURLs   = []string{"https://ethereum-sepolia-rpc.publicnode.com"}
	DefaultL1ProofURLs = []string{"https://0xrpc.io/sep", "https://api.zan.top/eth-sepolia", "https://1rpc.io/sepolia", "https://sepolia.gateway.tenderly.co"}
	DefaultLCURLs      = []string{"https://lodestar-sepolia.chainsafe.io"}
	DefaultBeaconURLs  = []string{"https://ethereum-sepolia-beacon-api.publicnode.com", "https://lodestar-sepolia.chainsafe.io"}
	DefaultAdiriURLs   = []string{"https://rpc.telcoin.network"}
)

// Limits and cadences.
const (
	// DefaultMaxCaptureBytesPerLeg is the V2_SPEC_S7 2.8 per-leg capture bound (4 MiB).
	DefaultMaxCaptureBytesPerLeg int64 = 4 << 20
	// DefaultMaxBatch is the largest JSON-RPC batch sent to a provider: Arbitrum's public RPC answers 429 to 100-request batches.
	DefaultMaxBatch = 40
	// DefaultRateRPS is the per-provider request rate (requests per second, per host).
	DefaultRateRPS = 5.0
)

// Config is everything the wiring needs. It carries URLs, which may hold credentials: Describe is the only secret-free view.
type Config struct {
	L1RPC   []string // Ethereum Sepolia execution endpoints (blocks, headers, logs, receipts)
	L1Proof []string // near-head eth_getProof providers
	Archive []string // OD4: a provider that serves proofs beyond the near-head window; tried after L1Proof
	LC      []string // Lodestar-compatible light-client endpoints, in order
	Beacon  []string // beacon blob API bases
	BaseL2  []string // Base Sepolia endpoints
	ArbL2   []string // Arbitrum Sepolia endpoints
	Adiri   []string // public Adiri endpoints (self-authenticating epoch records)
	AdiriPF []string // Adiri endpoints that may serve eth_getProof at an epoch seal (CERTEN's own node)

	PinsFile string

	RateRPS        float64
	RateBurst      int
	MaxBatch       int
	BackoffRetries int
	BackoffMax     time.Duration

	CaptureEvery    time.Duration
	CaptureBytes    int64
	CaptureBlocks   int // L1 blocks one Base capture tick scans at most
	Concurrency     int
	Interval        time.Duration
	BuildTimeout    time.Duration
	ArchiveOrigin   string // "set" or "unset": whether OD4 is configured (reported, never the URL)
	ProviderSources map[string]string
}

// urlSeparators are the separators of a provider list the validator has always accepted (ethrpc.ParseEndpoints).
func urlSeparator(r rune) bool {
	return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// checkURLEntries refuses an entry that is not an http(s) URL with a host. The refusal names the variable (or provider list) and the
// INDEX of the entry among the non-blank entries, never the entry: a provider URL may hold a credential.
func checkURLEntries(what string, entries []string) error {
	for i, e := range entries {
		u, err := url.Parse(e)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("%s: entry %d is not an http(s) URL with a host (the entry is not printed: it may hold a credential)", what, i)
		}
	}
	return nil
}

// parseURLList splits and validates one URL-list variable. A value that holds no entry at all (",,,") is a refusal: it must not
// become an empty list that silently overrides the default.
func parseURLList(env, value string) ([]string, error) {
	entries := strings.FieldsFunc(value, urlSeparator)
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s is set but holds no entry (an empty list would override the default; unset the variable to use it)", env)
	}
	if err := checkURLEntries(env, entries); err != nil {
		return nil, err
	}
	return ethrpc.ParseEndpoints(entries...), nil
}

func listFromEnv(key string, def []string) ([]string, string, error) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		l, err := parseURLList(key, v)
		return l, key, err
	}
	return append([]string(nil), def...), "default", nil
}

// chainListFromEnv is the validated provider list the validator already uses for a chain (<PREFIX>_RPC_URL, <PREFIX>_URL_FALLBACKS,
// INFURA_<PREFIX>_URL, ALCHEMY_<PREFIX>_URL): the finality providers speak HTTP JSON-RPC, so an entry that is not an http(s) URL with
// a host is refused here by chain and index.
func chainListFromEnv(chainKey string) ([]string, error) {
	l := ethrpc.EndpointsForChain(chainKey)
	if err := checkURLEntries(chainKey+" provider list ("+ethrpc.ChainEnvPrefix(chainKey)+"_RPC_URL, "+ethrpc.ChainEnvPrefix(chainKey)+"_URL_FALLBACKS, INFURA_/ALCHEMY_"+ethrpc.ChainEnvPrefix(chainKey)+"_URL)", l); err != nil {
		return nil, err
	}
	return l, nil
}

// ConfigFromEnv reads the configuration. A numeric variable that is not a number in range refuses startup by name (the
// envvar package's rule); a list variable that is empty takes its default, and one that is set must hold at least one entry and every
// entry must be an http(s) URL with a host (the refusal names the variable and the entry index, never the value); the per-chain
// provider lists are the ones the validator already uses (<PREFIX>_RPC_URL, <PREFIX>_URL_FALLBACKS, INFURA_/ALCHEMY_<PREFIX>_URL).
func ConfigFromEnv() (Config, error) {
	var c Config
	c.ProviderSources = map[string]string{}
	var src string
	var err error

	// Ethereum Sepolia: the validator's own provider list first, then the public default, so the capture follows the same node
	// the observers use when it is configured.
	own, err := chainListFromEnv("ethereum-sepolia")
	if err != nil {
		return Config{}, err
	}
	l1, src, err := listFromEnv(EnvL1RPCURLs, nil)
	if err != nil {
		return Config{}, err
	}
	if src == "default" {
		l1 = ethrpc.ParseEndpoints(append(append([]string(nil), own...), DefaultL1RPCURLs...)...)
		if len(own) > 0 {
			src = "ethrpc:ethereum-sepolia+default"
		}
	}
	c.L1RPC, c.ProviderSources["l1_rpc"] = l1, src
	if c.L1Proof, c.ProviderSources["l1_proof"], err = listFromEnv(EnvL1ProofURLs, DefaultL1ProofURLs); err != nil {
		return Config{}, err
	}
	if c.Archive, src, err = listFromEnv(EnvArchiveURLs, nil); err != nil {
		return Config{}, err
	}
	c.ProviderSources["archive"] = src
	c.ArchiveOrigin = "unset"
	if len(c.Archive) > 0 {
		c.ArchiveOrigin = "set"
	}
	if c.LC, c.ProviderSources["lc"], err = listFromEnv(EnvLCURLs, DefaultLCURLs); err != nil {
		return Config{}, err
	}
	if c.Beacon, c.ProviderSources["beacon"], err = listFromEnv(EnvBeaconURLs, DefaultBeaconURLs); err != nil {
		return Config{}, err
	}

	if c.BaseL2, err = chainListFromEnv("base-sepolia"); err != nil {
		return Config{}, err
	}
	c.ProviderSources["base_l2"] = "ethrpc:base-sepolia"
	if c.ArbL2, err = chainListFromEnv("arbitrum-sepolia"); err != nil {
		return Config{}, err
	}
	c.ProviderSources["arb_l2"] = "ethrpc:arbitrum-sepolia"
	if c.AdiriPF, err = chainListFromEnv("telcoin-adiri"); err != nil {
		return Config{}, err
	}
	c.ProviderSources["adiri_proof"] = "ethrpc:telcoin-adiri"
	pub, src, err := listFromEnv(EnvAdiriURLs, DefaultAdiriURLs)
	if err != nil {
		return Config{}, err
	}
	c.Adiri = ethrpc.ParseEndpoints(append(append([]string(nil), pub...), c.AdiriPF...)...)
	c.ProviderSources["adiri_public"] = src

	c.PinsFile = strings.TrimSpace(os.Getenv(EnvPinsFile))

	rd := []func() error{
		func() (e error) { c.RateRPS, e = envvar.Float(EnvRateRPS, DefaultRateRPS, 0.1); return },
		func() (e error) { c.RateBurst, e = envvar.Int(EnvRateBurst, 5, 1); return },
		func() (e error) { c.MaxBatch, e = envvar.Int(EnvMaxBatch, DefaultMaxBatch, 1); return },
		func() (e error) { c.BackoffRetries, e = envvar.Int(EnvBackoffRetries, 5, 0); return },
		func() (e error) { c.BackoffMax, e = envvar.Seconds(EnvBackoffMax, time.Minute, 1); return },
		func() (e error) { c.CaptureEvery, e = envvar.Seconds(EnvCaptureEvery, 12*time.Second, 1); return },
		func() (e error) {
			c.CaptureBytes, e = envvar.Int64(EnvCaptureBytes, DefaultMaxCaptureBytesPerLeg, 1<<16)
			return
		},
		func() (e error) { c.CaptureBlocks, e = envvar.Int(EnvCaptureBlocks, 64, 1); return },
		func() (e error) { c.Concurrency, e = envvar.Int(EnvConcurrency, 4, 1); return },
		func() (e error) { c.Interval, e = envvar.Seconds(EnvInterval, 60*time.Second, 1); return },
		func() (e error) { c.BuildTimeout, e = envvar.Seconds(EnvBuildTimeout, 5*time.Minute, 1); return },
	}
	if err = envvar.Check(rd...); err != nil {
		return Config{}, err
	}
	if c.MaxBatch > 100 {
		return Config{}, fmt.Errorf("%s=%d: public providers answer 429 to 100-request batches; the largest accepted value is 100", EnvMaxBatch, c.MaxBatch)
	}
	return c, nil
}

// RegisterRedaction tells pkg/ethrpc every configured URL so no provider text carrying a credential reaches a log.
func (c Config) RegisterRedaction() {
	for _, l := range [][]string{c.L1RPC, c.L1Proof, c.Archive, c.LC, c.Beacon, c.BaseL2, c.ArbL2, c.Adiri, c.AdiriPF} {
		ethrpc.RegisterProviderURLs(l...)
	}
}

// proofURLs is the near-head proof providers followed by the OD4 archive provider.
func (c Config) proofURLs() []string {
	return ethrpc.ParseEndpoints(append(append([]string(nil), c.L1Proof...), c.Archive...)...)
}

// Describe is the secret-free view of the configuration for logs and the health endpoint: counts and host labels only.
func (c Config) Describe() map[string]any {
	n := func(l []string) int { return len(l) }
	return map[string]any{
		"l1_rpc_providers": n(c.L1RPC), "l1_proof_providers": n(c.L1Proof), "archive_provider": c.ArchiveOrigin,
		"lc_endpoints": Hosts(c.LC), "beacon_endpoints": Hosts(c.Beacon), "base_l2_providers": n(c.BaseL2), "arb_l2_providers": n(c.ArbL2),
		"adiri_providers": n(c.Adiri), "adiri_proof_providers": n(c.AdiriPF), "pins_file": c.PinsFile != "",
		"rate_rps": c.RateRPS, "max_batch": c.MaxBatch, "max_capture_bytes_per_leg": c.CaptureBytes,
		"capture_interval": c.CaptureEvery.String(), "concurrency": c.Concurrency, "interval": c.Interval.String(),
	}
}

// Missing returns, for each chain, the settings whose absence makes the chain's builders impossible (no provider at all). A chain
// that is not listed has everything it needs configured. The effect text of the logged state names the first one.
func (c Config) Missing() map[uint64][]string {
	out := map[uint64][]string{}
	add := func(chain uint64, env string) { out[chain] = append(out[chain], env) }
	if len(c.BaseL2) == 0 {
		add(finality.ChainBaseSepolia, "BASE_SEPOLIA_RPC_URL")
	}
	if len(c.ArbL2) == 0 {
		add(finality.ChainArbitrumSepolia, "ARBITRUM_SEPOLIA_RPC_URL")
	}
	if len(c.L1RPC) == 0 && len(c.L1Proof) == 0 {
		add(finality.ChainBaseSepolia, EnvL1RPCURLs)
		add(finality.ChainArbitrumSepolia, EnvL1RPCURLs)
	}
	if len(c.LC) == 0 {
		add(finality.ChainBaseSepolia, EnvLCURLs)
		add(finality.ChainArbitrumSepolia, EnvLCURLs)
	}
	if len(c.LC) == 0 {
		add(finality.ChainSepolia, EnvLCURLs)
	}
	if len(c.L1RPC) == 0 {
		add(finality.ChainSepolia, EnvL1RPCURLs)
	}
	if len(c.Adiri) == 0 {
		add(finality.ChainAdiri, EnvAdiriURLs)
	}
	return out
}
