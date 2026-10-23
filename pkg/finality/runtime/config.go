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
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// The CERTEN_FINALITY_* variables this package reads (the switches CERTEN_FINALITY_UPGRADER_ENABLED and
// CERTEN_FINALITY_CHAIN_<id>_ENABLED belong to pkg/finality).
const (
	EnvL1RPCURLs       = "CERTEN_FINALITY_L1_RPC_URLS"
	EnvL1ProofURLs     = "CERTEN_FINALITY_L1_PROOF_URLS"
	EnvArchiveURLs     = "CERTEN_FINALITY_ARCHIVE_URLS"
	EnvLCURLs          = "CERTEN_FINALITY_LC_URLS"
	EnvBeaconURLs      = "CERTEN_FINALITY_BEACON_URLS"
	EnvAdiriURLs       = "CERTEN_FINALITY_ADIRI_PUBLIC_URLS"
	EnvPinsFile        = "CERTEN_FINALITY_PINS_FILE"
	EnvRateRPS         = "CERTEN_FINALITY_RATE_LIMIT_RPS"
	EnvRateBurst       = "CERTEN_FINALITY_RATE_BURST"
	EnvMaxBatch        = "CERTEN_FINALITY_MAX_BATCH"
	EnvBackoffRetries  = "CERTEN_FINALITY_BACKOFF_RETRIES"
	EnvBackoffMax      = "CERTEN_FINALITY_BACKOFF_MAX_SECONDS"
	EnvCaptureEvery    = "CERTEN_FINALITY_CAPTURE_INTERVAL_SECONDS"
	EnvCaptureBytes    = "CERTEN_FINALITY_MAX_CAPTURE_BYTES_PER_LEG"
	EnvCaptureBlocks   = "CERTEN_FINALITY_CAPTURE_MAX_BLOCKS_PER_TICK"
	EnvConcurrency     = "CERTEN_FINALITY_UPGRADER_CONCURRENCY"
	EnvInterval        = "CERTEN_FINALITY_UPGRADER_INTERVAL_SECONDS"
	EnvBuildTimeout    = "CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS"
	EnvGapBlocks       = "CERTEN_FINALITY_GAPFILL_BLOCKS_PER_TICK"
	EnvGapAuditSpacing = "CERTEN_FINALITY_GAP_AUDIT_SPACING"
	// EnvBaseIndex switches the Base capture index (RB12-INDEX-A) on (default) or off. Off: the Base builder reads and decompresses
	// the leg's window of the capture as before and nothing is indexed.
	EnvBaseIndex = "CERTEN_FINALITY_BASE_INDEX"
	// EnvArbIndex switches the Arbitrum batch index (RB12-INDEX-B) on (default) or off. Off: the Arbitrum builder reads every captured batch and
	// decodes every batch of the leg's window as before, and nothing is indexed. EnvArbIndexGeneration starts a new generation.
	EnvArbIndex           = "CERTEN_FINALITY_ARB_INDEX"
	EnvArbIndexGeneration = "CERTEN_FINALITY_ARB_INDEX_GENERATION"
	EnvIndexBlocks        = "CERTEN_FINALITY_INDEX_BLOCKS_PER_STEP"
	EnvIndexStepSecond    = "CERTEN_FINALITY_INDEX_STEP_SECONDS"
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

	CaptureEvery       time.Duration
	CaptureBytes       int64
	CaptureBlocks      int // L1 blocks one Base capture tick scans at most
	GapBlocks          int // L1 blocks one gap-backfill tick captures at most (concurrency is one block at a time)
	GapAuditSpacing    int // a run of more than this many blocks between two captured inbox blocks is recorded as an unproven gap
	Concurrency        int
	Interval           time.Duration
	BuildTimeout       time.Duration
	MemoryBudget       int64                // bytes of in-flight builder working set per process (finality.EnvMemoryBudget)
	BaseIndex          bool                 // the Base capture index is built and used (EnvBaseIndex)
	IndexDisabled      *finality.StateError // set when a bad index setting switched the index off: finality_index_disabled{chain, key, reason}
	IndexGeneration    uint32               // the index generation (finality.EnvIndexGeneration); a new one rebuilds
	ArbIndex           bool                 // the Arbitrum batch index is built and used (EnvArbIndex)
	ArbIndexDisabled   *finality.StateError // set when a bad setting switched the Arbitrum index off: finality_index_disabled{chain=421614, ...}
	ArbIndexGeneration uint32               // the Arbitrum index generation (EnvArbIndexGeneration)
	IndexBlocks        int                  // captured blocks one index step digests at most
	IndexStep          time.Duration        // wall time after which an index step stops
	ArchiveOrigin      string               // "set" or "unset": whether OD4 is configured (reported, never the URL)
	ProviderSources    map[string]string
}

// urlSeparators are the separators of a provider list the validator has always accepted (ethrpc.ParseEndpoints).
func urlSeparator(r rune) bool {
	return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// The classes of a refused provider entry. They name the kind of defect and never carry a byte of the value.
const (
	ClassNoEntry          = "no_entry"          // the variable is set but holds no entry at all
	ClassNoScheme         = "no_scheme"         // no scheme (a bare host, a path, words)
	ClassOtherScheme      = "other_scheme"      // a scheme that is not http or https (ws, wss, ftp, postgres, ...)
	ClassNoHost           = "no_host"           // http(s) with an empty host
	ClassBadEscape        = "bad_escape"        // a percent escape url.Parse rejects
	ClassBadPort          = "bad_port"          // a port that is not a number
	ClassBadUserinfo      = "bad_userinfo"      // a character url.Parse does not allow in user information
	ClassBadHost          = "bad_host"          // a host url.Parse rejects
	ClassControlCharacter = "control_character" // a control character
	ClassUnparseable      = "unparseable"       // url.Parse rejects it for another reason
)

// ConfigError is the refusal of one provider URL entry: the variable that holds it, its position among that variable's non-blank
// entries (-1: the variable is set but holds none), the chain key for a per-chain variable and the class of the defect. It carries
// no part of the value, which may hold a credential, so it can be logged, counted and shown as it is.
type ConfigError struct {
	Variable string
	Chain    string
	Entry    int
	Class    string
}

func (e *ConfigError) Error() string {
	if e.Class == ClassNoEntry {
		return fmt.Sprintf("%s is set but holds no entry (an empty list would override the default; unset the variable to use it)", e.Variable)
	}
	where := e.Variable
	if e.Chain != "" {
		where = e.Chain + " provider list (" + e.Variable + ")"
	}
	return fmt.Sprintf("%s: entry %d is not an http(s) URL with a host [%s] (the entry is not printed: it may hold a credential)", where, e.Entry, e.Class)
}

// entryClass judges one provider entry by the rule of the code that uses it: url.Parse must accept it, its scheme must be http or
// https and it must name a host. It returns "" for an accepted entry and otherwise the class of the defect; it never returns, nor
// builds a message from, the text of the parse error (that text can quote the value).
func entryClass(e string) string {
	u, err := url.Parse(e)
	if err != nil {
		msg := err.Error()
		var ue *url.Error
		if errors.As(err, &ue) {
			msg = ue.Err.Error()
		}
		return parseErrorClass(msg)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Hostname() == "" {
			return ClassNoHost
		}
		return ""
	case "":
		return ClassNoScheme
	}
	return ClassOtherScheme
}

// parseErrorClass names the kind of defect a url.Parse error message reports; a message it does not know is ClassUnparseable (still a
// refusal). The message is read here and nowhere else, and is never returned.
func parseErrorClass(msg string) string {
	switch {
	case strings.Contains(msg, "invalid control character"):
		return ClassControlCharacter
	case strings.Contains(msg, "invalid URL escape"):
		return ClassBadEscape
	case strings.Contains(msg, "invalid port"):
		return ClassBadPort
	case strings.Contains(msg, "invalid userinfo"):
		return ClassBadUserinfo
	case strings.Contains(msg, "missing protocol scheme"), strings.Contains(msg, "first path segment in URL cannot contain colon"):
		return ClassNoScheme
	case strings.Contains(msg, "host"): // "invalid character ... in host name", "missing ']' in host"
		return ClassBadHost
	}
	return ClassUnparseable
}

// refusedEntries judges every entry of one variable and returns each refusal (the position is the index among the non-blank entries).
func refusedEntries(variable, chain string, entries []string) []ConfigError {
	var out []ConfigError
	for i, e := range entries {
		if class := entryClass(e); class != "" {
			out = append(out, ConfigError{Variable: variable, Chain: chain, Entry: i, Class: class})
		}
	}
	return out
}

// checkURLEntries refuses an entry that is not an http(s) URL with a host. The refusal is a *ConfigError: it names the variable and
// the INDEX of the entry among the non-blank entries, never the entry (a provider URL may hold a credential).
func checkURLEntries(variable, chain string, entries []string) error {
	if refused := refusedEntries(variable, chain, entries); len(refused) > 0 {
		return &refused[0]
	}
	return nil
}

// parseURLList splits and validates one URL-list variable. A value that holds no entry at all (",,,") is a refusal: it must not
// become an empty list that silently overrides the default.
func parseURLList(env, value string) ([]string, error) {
	entries := strings.FieldsFunc(value, urlSeparator)
	if len(entries) == 0 {
		return nil, &ConfigError{Variable: env, Entry: -1, Class: ClassNoEntry}
	}
	if err := checkURLEntries(env, "", entries); err != nil {
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

// chainListFromEnv is the validated provider list the validator already uses for a chain (every variable of
// ethrpc.EndpointVariablesForChain: <PREFIX>_RPC_URL, <PREFIX>_URL_FALLBACKS, INFURA_<PREFIX>_URL, ALCHEMY_<PREFIX>_URL and, for
// Ethereum Sepolia, its legacy ETHEREUM_* variables): the finality providers speak HTTP JSON-RPC, so an entry that is not an http(s)
// URL with a host is refused here by chain, variable and index.
func chainListFromEnv(chainKey string) ([]string, error) {
	for _, name := range ethrpc.EndpointVariablesForChain(chainKey) {
		if err := checkURLEntries(name, chainKey, strings.FieldsFunc(os.Getenv(name), urlSeparator)); err != nil {
			return nil, err
		}
	}
	return ethrpc.EndpointsForChain(chainKey), nil
}

// ProviderVariable is one environment variable ConfigFromEnv parses as a list of provider URLs; Chain is the chain key of a
// per-chain provider variable and empty for a CERTEN_FINALITY_* list.
type ProviderVariable struct {
	Name  string
	Chain string
}

// providerChains are the chain keys whose provider lists ConfigFromEnv reads.
var providerChains = []string{"ethereum-sepolia", "base-sepolia", "arbitrum-sepolia", "telcoin-adiri"}

// ProviderVariables lists, in the order ConfigFromEnv reads them, every environment variable it parses as a list of provider URLs.
// It is the table the startup validation and the read-only deploy check share, so neither can name a variable the other does not.
func ProviderVariables() []ProviderVariable {
	var out []ProviderVariable
	chain := func(key string) {
		for _, n := range ethrpc.EndpointVariablesForChain(key) {
			out = append(out, ProviderVariable{Name: n, Chain: key})
		}
	}
	chain(providerChains[0])
	for _, n := range []string{EnvL1RPCURLs, EnvL1ProofURLs, EnvArchiveURLs, EnvLCURLs, EnvBeaconURLs} {
		out = append(out, ProviderVariable{Name: n})
	}
	chain(providerChains[1])
	chain(providerChains[2])
	chain(providerChains[3])
	out = append(out, ProviderVariable{Name: EnvAdiriURLs})
	return out
}

// ProviderEntryCount is the number of non-blank entries a provider variable holds (the positions ConfigError.Entry counts).
func ProviderEntryCount(raw string) int { return len(strings.FieldsFunc(raw, urlSeparator)) }

// CheckProviderEnvironment judges every provider variable of the environment by the rule ConfigFromEnv applies and returns each
// refusal (all of them, in ProviderVariables order), without reading anything else. It holds no value: see ConfigError.
func CheckProviderEnvironment() []ConfigError {
	var out []ConfigError
	for _, v := range ProviderVariables() {
		raw := os.Getenv(v.Name)
		entries := strings.FieldsFunc(raw, urlSeparator)
		if v.Chain == "" && strings.TrimSpace(raw) != "" && len(entries) == 0 {
			out = append(out, ConfigError{Variable: v.Name, Entry: -1, Class: ClassNoEntry})
			continue
		}
		out = append(out, refusedEntries(v.Name, v.Chain, entries)...)
	}
	return out
}

// ConfigFromEnv reads the configuration. A numeric variable that is not a number in range is refused by name (the
// envvar package's rule: a *envvar.Refusal, announced by the process as finality_upgrader_disabled{reason=setting_invalid}); a list variable that is empty takes its default, and one that is set must hold at least one entry and every
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

	if err = readSettings(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// readSettings reads every number, duration and size setting into c and returns EVERY refusal (a joined error of *envvar.Refusal, in
// the order the settings are read), including the bound of the batch size that is checked after its reader accepted it.
func readSettings(c *Config) error {
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
		func() (e error) { c.GapBlocks, e = envvar.Int(EnvGapBlocks, DefaultGapBlocksPerTick, 1); return },
		func() (e error) {
			c.GapAuditSpacing, e = envvar.Int(EnvGapAuditSpacing, DefaultGapAuditSpacing, 2)
			return
		},
		func() (e error) { c.Concurrency, e = envvar.Int(EnvConcurrency, 4, 1); return },
		func() (e error) { c.Interval, e = envvar.Seconds(EnvInterval, 60*time.Second, 1); return },
		func() (e error) { c.BuildTimeout, e = envvar.Seconds(EnvBuildTimeout, 5*time.Minute, 1); return },
		func() (e error) { c.MemoryBudget, e = finality.MemoryBudgetFromEnv(); return },
	}
	var errs []error
	if err := envvar.Check(rd...); err != nil {
		errs = append(errs, err)
	}
	// the capture index settings are NOT checked with the rest: a bad one never stops a consensus node (RB12-INDEX-FIX D2)
	c.readIndexSettings()
	if c.MaxBatch > 100 {
		errs = append(errs, envvar.Refuse(EnvMaxBatch, strconv.Itoa(c.MaxBatch), "an integer from 1 to 100 (public providers answer 429 to 100-request batches)"))
	}
	return errors.Join(errs...)
}

// RefusedSettings judges every number, duration and size setting of the environment by the rule ConfigFromEnv applies and returns each
// refusal (all of them), without reading anything else. A refusal holds the name of the variable and what it must be, never its value.
func RefusedSettings() []*envvar.Refusal {
	var c Config
	return envvar.Refusals(readSettings(&c))
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
	out := map[string]any{
		"l1_rpc_providers": n(c.L1RPC), "l1_proof_providers": n(c.L1Proof), "archive_provider": c.ArchiveOrigin,
		"lc_endpoints": Hosts(c.LC), "beacon_endpoints": Hosts(c.Beacon), "base_l2_providers": n(c.BaseL2), "arb_l2_providers": n(c.ArbL2),
		"adiri_providers": n(c.Adiri), "adiri_proof_providers": n(c.AdiriPF), "pins_file": c.PinsFile != "",
		"rate_rps": c.RateRPS, "max_batch": c.MaxBatch, "max_capture_bytes_per_leg": c.CaptureBytes,
		"capture_interval": c.CaptureEvery.String(), "concurrency": c.Concurrency, "interval": c.Interval.String(),
		"memory_budget_bytes": c.MemoryBudget, "memory_gate_bytes": finality.HeapGate(c.MemoryBudget),
		"gap_blocks_per_tick": c.GapBlocks, "gap_audit_spacing": c.GapAuditSpacing,
		"base_index": c.BaseIndex, "index_generation": c.IndexGeneration, "index_blocks_per_step": c.IndexBlocks,
		"arb_index": c.ArbIndex, "arb_index_generation": c.ArbIndexGeneration,
	}
	if c.IndexDisabled != nil {
		out["index_disabled"] = c.IndexDisabled.Error()
	}
	if c.ArbIndexDisabled != nil {
		out["arb_index_disabled"] = c.ArbIndexDisabled.Error()
	}
	return out
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

// readIndexSettings reads the four capture index settings. A setting that is not what it must be switches the index OFF by the registered
// named state finality_index_disabled{chain, key, reason} (announced at wiring: log, metric, /health/detailed) and the validator runs on
// with the window reader: finality is not an input of consensus and the settings are shared by all seven validators, so a refusal that ended
// the process would take them all down at one roll. The state names the setting and the class of the fault, never the value.
func (c *Config) readIndexSettings() {
	c.BaseIndex, c.IndexGeneration, c.IndexBlocks, c.IndexStep = true, finality.DefaultIndexGeneration, 128, 15*time.Second
	c.IndexDisabled = nil
	c.ArbIndex, c.ArbIndexGeneration, c.ArbIndexDisabled = true, finality.DefaultIndexGeneration, nil
	// a setting of one chain switches that chain's index off; a setting both share (the step bounds) switches both off, each with its own state
	offBase := func(variable, reason, refused string) {
		c.BaseIndex = false
		if c.IndexDisabled == nil {
			c.IndexDisabled = finality.IndexDisabledState(finality.ChainBaseSepolia, variable, reason, refused)
		}
	}
	offArb := func(variable, reason, refused string) {
		c.ArbIndex = false
		if c.ArbIndexDisabled == nil {
			c.ArbIndexDisabled = finality.IndexDisabledState(finality.ChainArbitrumSepolia, variable, reason, refused)
		}
	}
	off := func(variable, reason, refused string) {
		offBase(variable, reason, refused)
		offArb(variable, reason, refused)
	}
	on, err := envvar.Bool(EnvBaseIndex, true)
	if err != nil {
		offBase(EnvBaseIndex, finality.IndexSettingSwitchInvalid, "")
	} else {
		c.BaseIndex = on
	}
	if v, refused := indexInt(finality.EnvIndexGeneration, int64(finality.DefaultIndexGeneration), 1, math.MaxUint32); refused != "" {
		offBase(finality.EnvIndexGeneration, finality.IndexSettingInvalid, refused)
	} else {
		c.IndexGeneration = uint32(v)
	}
	onArb, err := envvar.Bool(EnvArbIndex, true)
	if err != nil {
		offArb(EnvArbIndex, finality.IndexSettingSwitchInvalid, "")
	} else {
		c.ArbIndex = c.ArbIndex && onArb
	}
	if v, refused := indexInt(EnvArbIndexGeneration, int64(finality.DefaultIndexGeneration), 1, math.MaxUint32); refused != "" {
		offArb(EnvArbIndexGeneration, finality.IndexSettingInvalid, refused)
	} else {
		c.ArbIndexGeneration = uint32(v)
	}
	if v, refused := indexInt(EnvIndexBlocks, 128, 1, math.MaxInt32); refused != "" {
		off(EnvIndexBlocks, finality.IndexSettingInvalid, refused)
	} else {
		c.IndexBlocks = int(v)
	}
	if v, refused := indexInt(EnvIndexStepSecond, 15, 1, 86400); refused != "" {
		off(EnvIndexStepSecond, finality.IndexSettingInvalid, refused)
	} else {
		c.IndexStep = time.Duration(v) * time.Second
	}
}

// indexInt reads an integer setting in [lo, hi]; the second result is empty when it is, else which way it is refused (never the value).
func indexInt(key string, def, lo, hi int64) (int64, string) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, ""
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def, finality.IndexRefusedNotInteger
	}
	if v < lo || v > hi {
		return def, finality.IndexRefusedOutOfRange
	}
	return v, ""
}
