// Copyright 2026 Certen Protocol

package runtime

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// rtClearEnv empties every variable ConfigFromEnv reads, so a test sees only what it sets (t.Setenv restores them).
func rtClearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EnvL1RPCURLs, EnvL1ProofURLs, EnvArchiveURLs, EnvLCURLs, EnvBeaconURLs, EnvAdiriURLs, EnvPinsFile, EnvRateRPS, EnvRateBurst,
		EnvMaxBatch, EnvBackoffRetries, EnvBackoffMax, EnvCaptureEvery, EnvCaptureBytes, EnvCaptureBlocks, EnvConcurrency, EnvInterval,
		EnvBuildTimeout,
		"ETHEREUM_URL", "ETHEREUM_SEPOLIA_RPC_URL", "ETHEREUM_URL_FALLBACKS", "ETHEREUM_SEPOLIA_URL_FALLBACKS", "INFURA_SEPOLIA_URL",
		"ALCHEMY_SEPOLIA_URL", "SEPOLIA_RPC_URL",
		"BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_URL_FALLBACKS", "INFURA_BASE_SEPOLIA_URL", "ALCHEMY_BASE_SEPOLIA_URL",
		"ARBITRUM_SEPOLIA_RPC_URL", "ARBITRUM_SEPOLIA_URL_FALLBACKS", "INFURA_ARBITRUM_SEPOLIA_URL", "ALCHEMY_ARBITRUM_SEPOLIA_URL",
		"TELCOIN_ADIRI_RPC_URL", "TELCOIN_ADIRI_URL_FALLBACKS", "INFURA_TELCOIN_ADIRI_URL", "ALCHEMY_TELCOIN_ADIRI_URL",
	} {
		t.Setenv(k, "")
	}
}

func TestRTConfigDefaults(t *testing.T) {
	rtClearEnv(t)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ got, want []string }{
		"l1 proof": {c.L1Proof, DefaultL1ProofURLs}, "light client": {c.LC, DefaultLCURLs}, "beacon": {c.Beacon, DefaultBeaconURLs},
		"l1 rpc": {c.L1RPC, DefaultL1RPCURLs}, "adiri public": {c.Adiri, DefaultAdiriURLs},
	} {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s: %v, want the default %v", name, tc.got, tc.want)
		}
	}
	if c.CaptureBytes != 4<<20 {
		t.Errorf("capture bytes %d, want 4 MiB", c.CaptureBytes)
	}
	if c.MaxBatch != 40 || c.RateRPS != DefaultRateRPS || c.BackoffRetries != 5 || c.BackoffMax != time.Minute {
		t.Errorf("limits: batch %d rps %v retries %d backoff max %v", c.MaxBatch, c.RateRPS, c.BackoffRetries, c.BackoffMax)
	}
	if c.CaptureEvery != 12*time.Second || c.Concurrency != 4 || c.Interval != 60*time.Second || c.BuildTimeout != 5*time.Minute {
		t.Errorf("cadences: capture %v concurrency %d interval %v build %v", c.CaptureEvery, c.Concurrency, c.Interval, c.BuildTimeout)
	}
	if c.ArchiveOrigin != "unset" || len(c.Archive) != 0 || c.PinsFile != "" {
		t.Errorf("archive %q %v, pins file %q: want unset, none, none", c.ArchiveOrigin, c.Archive, c.PinsFile)
	}
	if c.ProviderSources["lc"] != "default" {
		t.Errorf("lc source %q, want default", c.ProviderSources["lc"])
	}
}

func TestRTConfigLCListKeepsTheOrderAndDropsDuplicatesAndBlanks(t *testing.T) {
	rtClearEnv(t)
	t.Setenv(EnvLCURLs, "http://certen-sepolia-beacon:9596, https://lodestar-sepolia.chainsafe.io ;http://certen-sepolia-beacon:9596,,")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://certen-sepolia-beacon:9596", "https://lodestar-sepolia.chainsafe.io"}
	if !reflect.DeepEqual(c.LC, want) {
		t.Fatalf("LC %v, want %v: order is the preference, duplicates and blanks are dropped", c.LC, want)
	}
	if c.ProviderSources["lc"] != EnvLCURLs {
		t.Fatalf("lc source %q, want %s", c.ProviderSources["lc"], EnvLCURLs)
	}
}

func TestRTConfigABadValueRefusesStartupNamingTheVariable(t *testing.T) {
	for _, tc := range []struct{ env, val string }{
		{EnvRateRPS, "abc"},
		{EnvRateRPS, "0"},
		{EnvMaxBatch, "101"},
		{EnvMaxBatch, "0"},
		{EnvMaxBatch, "forty"},
		{EnvCaptureBytes, "1024"},
		{EnvCaptureEvery, "0"},
		{EnvBackoffRetries, "-1"},
		{EnvConcurrency, "0"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			rtClearEnv(t)
			t.Setenv(tc.env, tc.val)
			_, err := ConfigFromEnv()
			if err == nil {
				t.Fatalf("%s=%s was accepted", tc.env, tc.val)
			}
			if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("the refusal %q does not name %s", err, tc.env)
			}
		})
	}
	// two bad values: both are named, not just the first
	rtClearEnv(t)
	t.Setenv(EnvRateRPS, "abc")
	t.Setenv(EnvConcurrency, "0")
	_, err := ConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), EnvRateRPS) || !strings.Contains(err.Error(), EnvConcurrency) {
		t.Fatalf("error %v, want both variables named", err)
	}
}

func TestRTConfigTheValidatorsProviderVariablesFeedTheChains(t *testing.T) {
	rtClearEnv(t)
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://base.example/k1")
	t.Setenv("BASE_SEPOLIA_URL_FALLBACKS", "https://base2.example/k2, https://base.example/k1")
	t.Setenv("ARBITRUM_SEPOLIA_RPC_URL", "https://arb.example/k3")
	t.Setenv("TELCOIN_ADIRI_RPC_URL", "https://adiri-own.example/k4")
	t.Setenv("ETHEREUM_URL", "https://eth.example/k5")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://base.example/k1", "https://base2.example/k2"}; !reflect.DeepEqual(c.BaseL2, want) {
		t.Errorf("BaseL2 %v, want %v", c.BaseL2, want)
	}
	if want := []string{"https://arb.example/k3"}; !reflect.DeepEqual(c.ArbL2, want) {
		t.Errorf("ArbL2 %v, want %v", c.ArbL2, want)
	}
	if want := []string{"https://adiri-own.example/k4"}; !reflect.DeepEqual(c.AdiriPF, want) {
		t.Errorf("AdiriPF %v, want %v", c.AdiriPF, want)
	}
	// the public Adiri endpoint stays first, the own node follows (it is asked only for eth_getProof by the prover)
	if want := []string{DefaultAdiriURLs[0], "https://adiri-own.example/k4"}; !reflect.DeepEqual(c.Adiri, want) {
		t.Errorf("Adiri %v, want %v", c.Adiri, want)
	}
	// the validator's own Sepolia node comes before the public default
	if len(c.L1RPC) < 2 || c.L1RPC[0] != "https://eth.example/k5" || c.L1RPC[len(c.L1RPC)-1] != DefaultL1RPCURLs[0] {
		t.Errorf("L1RPC %v, want the configured node first and the public default last", c.L1RPC)
	}
	// an explicit finality list replaces both
	t.Setenv(EnvL1RPCURLs, "https://only.example/z")
	c, err = ConfigFromEnv()
	if err != nil || !reflect.DeepEqual(c.L1RPC, []string{"https://only.example/z"}) {
		t.Errorf("explicit %s: %v %v", EnvL1RPCURLs, c.L1RPC, err)
	}
}

func TestRTConfigMissingNamesTheUnsetProviderSettingPerChain(t *testing.T) {
	rtClearEnv(t)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	m := c.Missing()
	if got := m[finality.ChainBaseSepolia]; !reflect.DeepEqual(got, []string{"BASE_SEPOLIA_RPC_URL"}) {
		t.Errorf("Base missing %v, want [BASE_SEPOLIA_RPC_URL]", got)
	}
	if got := m[finality.ChainArbitrumSepolia]; !reflect.DeepEqual(got, []string{"ARBITRUM_SEPOLIA_RPC_URL"}) {
		t.Errorf("Arbitrum missing %v, want [ARBITRUM_SEPOLIA_RPC_URL]", got)
	}
	if _, bad := m[finality.ChainAdiri]; bad {
		t.Errorf("Adiri has a default public endpoint and must not be reported missing: %v", m[finality.ChainAdiri])
	}
	if _, bad := m[finality.ChainSepolia]; bad {
		t.Errorf("Sepolia is not reported by Missing (its seam has its own state): %v", m[finality.ChainSepolia])
	}

	// only Base configured: only Arbitrum is missing, by its own variable
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://base.example/k1")
	c, _ = ConfigFromEnv()
	m = c.Missing()
	if _, bad := m[finality.ChainBaseSepolia]; bad {
		t.Errorf("Base is configured but reported missing: %v", m[finality.ChainBaseSepolia])
	}
	if got := m[finality.ChainArbitrumSepolia]; !reflect.DeepEqual(got, []string{"ARBITRUM_SEPOLIA_RPC_URL"}) {
		t.Errorf("Arbitrum missing %v, want [ARBITRUM_SEPOLIA_RPC_URL]", got)
	}

	// only Arbitrum configured: only Base is missing
	t.Setenv("BASE_SEPOLIA_RPC_URL", "")
	t.Setenv("ARBITRUM_SEPOLIA_RPC_URL", "https://arb.example/k3")
	c, _ = ConfigFromEnv()
	m = c.Missing()
	if got := m[finality.ChainBaseSepolia]; !reflect.DeepEqual(got, []string{"BASE_SEPOLIA_RPC_URL"}) {
		t.Errorf("Base missing %v, want [BASE_SEPOLIA_RPC_URL]", got)
	}
	if _, bad := m[finality.ChainArbitrumSepolia]; bad {
		t.Errorf("Arbitrum is configured but reported missing: %v", m[finality.ChainArbitrumSepolia])
	}

	// both configured: nothing is missing
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://base.example/k1")
	c, _ = ConfigFromEnv()
	if m = c.Missing(); len(m) != 0 {
		t.Errorf("everything configured, Missing() = %v", m)
	}
}

func TestRTConfigDescribeCarriesNoUserinfoPathOrQuery(t *testing.T) {
	rtClearEnv(t)
	t.Setenv(EnvLCURLs, "https://u:pw@lodestar.example/v1/tok-0123456789abcdef?apikey=SECRETKEY")
	t.Setenv(EnvBeaconURLs, "https://beacon.example/path/tok-beacon-0123456789")
	t.Setenv(EnvArchiveURLs, "https://archive.example/archive-token-0123456789")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://base.example/base-token-0123456789")
	t.Setenv(EnvPinsFile, "/secret/dir/pins.json")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c.Describe())
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, leak := range []string{"tok-0123456789abcdef", "SECRETKEY", "pw", "tok-beacon", "archive-token", "base-token", "/v1", "/path", "/secret/dir"} {
		if strings.Contains(out, leak) {
			t.Fatalf("Describe() leaks %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "https://lodestar.example") || !strings.Contains(out, "https://beacon.example") {
		t.Fatalf("Describe() lost the host labels: %s", out)
	}
	if !strings.Contains(out, `"archive_provider":"set"`) {
		t.Fatalf("Describe() does not report the archive provider as set: %s", out)
	}
}

func TestRTConfigTheArchiveProviderFollowsTheNearHeadProofProviders(t *testing.T) {
	rtClearEnv(t)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ArchiveOrigin != "unset" || !reflect.DeepEqual(c.proofURLs(), DefaultL1ProofURLs) {
		t.Fatalf("no archive: origin %q proof urls %v, want unset and the near-head list only", c.ArchiveOrigin, c.proofURLs())
	}
	t.Setenv(EnvArchiveURLs, "https://archive.example/key")
	c, err = ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ArchiveOrigin != "set" {
		t.Fatalf("archive origin %q, want set", c.ArchiveOrigin)
	}
	p := c.proofURLs()
	if len(p) != len(DefaultL1ProofURLs)+1 || p[len(p)-1] != "https://archive.example/key" || !reflect.DeepEqual(p[:len(p)-1], DefaultL1ProofURLs) {
		t.Fatalf("proof urls %v: the archive provider must come AFTER the near-head providers", p)
	}
	// an archive URL that is also a near-head URL is not asked twice
	t.Setenv(EnvArchiveURLs, DefaultL1ProofURLs[0])
	c, _ = ConfigFromEnv()
	if p = c.proofURLs(); !reflect.DeepEqual(p, DefaultL1ProofURLs) {
		t.Fatalf("proof urls %v: duplicates must be dropped", p)
	}
}
