// Copyright 2026 Certen Protocol

package runtime

import (
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-TRAIN3-INT, V-INT3b LOW (b): a bad prefix (archive backfill) setting switches the PREFIX feature off, by the named state
// finality_prefix_disabled{chain, variable, reason, refused}. It never stops the validator, never disables the upgrader and never touches the
// other finality work of the process (the same isolation the index settings have).

type prefixSettingCase struct {
	env    string
	chains []uint64    // the chains whose prefix work this setting governs
	bad    [][2]string // value, refused class
	good   []string    // accepted values at and just inside the bounds
}

func prefixSettingCases() []prefixSettingCase {
	both := []uint64{finality.ChainBaseSepolia, finality.ChainArbitrumSepolia}
	baseOnly := []uint64{finality.ChainBaseSepolia}
	arbOnly := []uint64{finality.ChainArbitrumSepolia}
	junk := [][2]string{{"abc", "not_an_integer"}, {"1.5", "not_an_integer"}, {"0x10", "not_an_integer"}, {"1e3", "not_an_integer"},
		{"12 34", "not_an_integer"}, {"99999999999999999999999999", "out_of_range"}, {"-1", "out_of_range"}, {"-99999999999999999999999999", "out_of_range"}}
	with := func(extra ...[2]string) [][2]string { return append(append([][2]string(nil), junk...), extra...) }
	return []prefixSettingCase{
		{EnvPrefixMax, both, with([2]string{"18446744073709551616", "out_of_range"}), []string{"0", "1", "18446744073709551615", " 7 "}},
		{EnvPrefixFloor, both, with([2]string{"18446744073709551616", "out_of_range"}), []string{"0", "11842420", "18446744073709551615"}},
		{EnvPrefixLease, both, with([2]string{"0", "out_of_range"}, [2]string{"59", "out_of_range"}, [2]string{"86401", "out_of_range"}), []string{"60", "600", "86400"}},
		{EnvPrefixChunk, baseOnly, with([2]string{"0", "out_of_range"}, [2]string{"1025", "out_of_range"}), []string{"1", "8", "1024"}},
		{EnvPrefixReprobe, baseOnly, with([2]string{"0", "out_of_range"}, [2]string{"3599", "out_of_range"}, [2]string{"2592001", "out_of_range"}), []string{"3600", "86400", "2592000"}},
		{EnvPrefixArbScan, arbOnly, with([2]string{"0", "out_of_range"}, [2]string{"2001", "out_of_range"}), []string{"1", "400", "2000"}},
	}
}

func allPrefixEnvs() []string {
	return []string{EnvPrefixMax, EnvPrefixFloor, EnvPrefixLease, EnvPrefixChunk, EnvPrefixReprobe, EnvPrefixArbScan}
}

func clearPrefixEnv(t *testing.T) {
	t.Helper()
	rtClearEnv(t)
	for _, n := range allPrefixEnvs() {
		t.Setenv(n, "")
	}
}

// Every setting, every kind of bad value: ConfigFromEnv returns no error, and the state names the variable, the closed reason and the way it
// was refused, once per chain the setting governs; it never carries the value.
func TestRTBadPrefixSettingsAreANamedPrefixOnlyStateAndNeverAConfigError(t *testing.T) {
	for _, c := range prefixSettingCases() {
		for _, b := range c.bad {
			t.Run(c.env+"="+b[0], func(t *testing.T) {
				clearPrefixEnv(t)
				t.Setenv(c.env, b[0])
				cfg, err := ConfigFromEnv()
				if err != nil {
					t.Fatalf("a bad prefix setting must not stop the validator: ConfigFromEnv returned %v", err)
				}
				if len(cfg.PrefixDisabled) != len(c.chains) {
					t.Fatalf("one state per chain the setting governs (%v), got %v", c.chains, cfg.PrefixDisabled)
				}
				for i, st := range cfg.PrefixDisabled {
					if st.Code != finality.CodePrefixDisabled || st.Fields["variable"] != c.env || st.Fields["reason"] != finality.DisabledSettingInvalid ||
						st.Fields["refused"] != b[1] || st.Fields["chain"] != c.chains[i] {
						t.Fatalf("want finality_prefix_disabled{chain %d, %s, setting_invalid, %s}, got %v", c.chains[i], c.env, b[1], st)
					}
					if strings.Contains(st.Error(), b[0]) && len(b[0]) > 3 {
						t.Fatalf("the state must not echo the value: %v", st)
					}
				}
				d, _ := cfg.Describe()["prefix_disabled"].([]string)
				if len(d) != len(c.chains) {
					t.Fatalf("the secret-free description names the states: %v", cfg.Describe()["prefix_disabled"])
				}
				// the shared table still names the refusal (the deploy check and the log of a startup that fails for another setting)
				if r := RefusedSettings(); len(r) != 1 || r[0].Key != c.env {
					t.Fatalf("RefusedSettings names the variable: %v", r)
				}
			})
		}
	}
}

// Empty, blank and at-the-bound values are the default or the value: no state.
func TestRTPrefixSettingsThatAreEmptyBlankOrInsideTheirBoundsAreNotRefused(t *testing.T) {
	for _, c := range prefixSettingCases() {
		for _, v := range append([]string{"", "   "}, c.good...) {
			t.Run(c.env+"="+v, func(t *testing.T) {
				clearPrefixEnv(t)
				t.Setenv(c.env, v)
				cfg, err := ConfigFromEnv()
				if err != nil || len(cfg.PrefixDisabled) != 0 {
					t.Fatalf("%q: %v %v", v, err, cfg.PrefixDisabled)
				}
				if r := RefusedSettings(); len(r) != 0 {
					t.Fatalf("%q: %v", v, r)
				}
			})
		}
	}
	clearPrefixEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil || len(cfg.PrefixDisabled) != 0 || cfg.PrefixMax != 100_000 || cfg.PrefixArbScan != 400 || cfg.PrefixChunk != 8 {
		t.Fatalf("the defaults: %+v %v", cfg, err)
	}
	if _, ok := cfg.Describe()["prefix_disabled"]; ok {
		t.Fatalf("no state while nothing is refused: %v", cfg.Describe())
	}
}

// Several bad settings are ALL named (one state per chain and variable), in the order the settings are read.
func TestRTSeveralBadPrefixSettingsAreAllNamed(t *testing.T) {
	clearPrefixEnv(t)
	t.Setenv(EnvPrefixChunk, "0")   // Base only
	t.Setenv(EnvPrefixArbScan, "0") // Arbitrum only
	t.Setenv(EnvPrefixMax, "lots")  // both
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, st := range cfg.PrefixDisabled {
		got = append(got, fmt.Sprintf("%d:%v", st.Fields["chain"], st.Fields["variable"]))
	}
	want := []string{"84532:" + EnvPrefixMax, "421614:" + EnvPrefixMax, "84532:" + EnvPrefixChunk, "421614:" + EnvPrefixArbScan}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("\n got %v\nwant %v", got, want)
	}
}

// A setting that IS fatal keeps its F14 state, and the log of that failure still names the refused prefix setting beside it.
func TestRTAFatalSettingStillDisablesTheUpgraderByF14AndTheLogNamesThePrefixSettingToo(t *testing.T) {
	clearPrefixEnv(t)
	t.Setenv(EnvMaxBatch, "500")
	t.Setenv(EnvPrefixArbScan, "lots")
	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatal("a bad non-prefix numeric setting is still refused")
	}
	var logged []string
	st := StartFailure(func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }, err)
	if st.Code != finality.CodeUpgraderDisabled || st.Fields["variable"] != EnvMaxBatch {
		t.Fatalf("%v", st)
	}
	if j := strings.Join(logged, "\n"); !strings.Contains(j, EnvPrefixArbScan) || !strings.Contains(j, EnvMaxBatch) {
		t.Fatalf("every refused setting is logged by name:\n%s", j)
	}
}

// Wiring: the process starts, nothing is disabled, every loop and prover is registered as it is without the bad setting, the prefix work
// of exactly the governed chains is OFF (no policy, no scan, no backfill of windows), the other chain keeps its configured prefix, and the
// state is announced in the log, the gauge, /health/detailed and the description.
func TestRTBadPrefixSettingWiresNoPrefixWorkOnItsChainsAndEverythingElseRuns(t *testing.T) {
	clearPrefixEnv(t)
	rtProviderEnv(t)
	t.Setenv(EnvPrefixMax, "7000")
	t.Setenv(EnvPrefixFloor, "11000000")
	_, refReg, _ := rtWire(t)
	refLoops, refProvers := len(refReg.Capturers()), len(refReg.Provers(finality.ChainBaseSepolia))+len(refReg.Provers(finality.ChainArbitrumSepolia))
	metrics.RegisterMetrics()
	for _, c := range prefixSettingCases() {
		t.Run(c.env, func(t *testing.T) {
			clearPrefixEnv(t)
			rtProviderEnv(t)
			t.Setenv(EnvPrefixMax, "7000")
			t.Setenv(EnvPrefixFloor, "11000000")
			t.Setenv(c.env, c.bad[0][0])
			w, reg, logs := rtWire(t)
			for chain, st := range w.Disabled {
				t.Fatalf("a bad prefix setting disables no chain: %d %v", chain, st)
			}
			if n := len(reg.Capturers()); n != refLoops {
				t.Fatalf("every capture loop is still registered: %d, want %d", n, refLoops)
			}
			if n := len(reg.Provers(finality.ChainBaseSepolia)) + len(reg.Provers(finality.ChainArbitrumSepolia)); n != refProvers {
				t.Fatalf("every prover is still registered: %d, want %d", n, refProvers)
			}
			governs := map[uint64]bool{}
			for _, ch := range c.chains {
				governs[ch] = true
			}
			configured := finality.PrefixPolicy{MaxBlocks: 7000, Floor: 11000000}
			for _, p := range reg.Provers(finality.ChainBaseSepolia) {
				if b, ok := p.(*baseposted.Builder); ok {
					if want := (finality.PrefixPolicy{}); governs[finality.ChainBaseSepolia] && b.Prefix != want || !governs[finality.ChainBaseSepolia] && b.Prefix != configured {
						t.Errorf("Base builder prefix policy %+v (governed %v)", b.Prefix, governs[finality.ChainBaseSepolia])
					}
				}
			}
			for _, p := range reg.Provers(finality.ChainArbitrumSepolia) {
				if b, ok := p.(*arbposted.Builder); ok {
					if want := (finality.PrefixPolicy{}); governs[finality.ChainArbitrumSepolia] && b.Prefix != want || !governs[finality.ChainArbitrumSepolia] && b.Prefix != configured {
						t.Errorf("Arbitrum builder prefix policy %+v (governed %v)", b.Prefix, governs[finality.ChainArbitrumSepolia])
					}
				}
			}
			var sawBase, sawArb bool
			for _, cp := range reg.Capturers() {
				switch l := cp.(type) {
				case *GapBackfillLoop:
					sawBase = true
					if l.Backfill.NoPrefix != governs[finality.ChainBaseSepolia] {
						t.Errorf("the Base backfill takes prefix windows: NoPrefix=%v, governed %v", l.Backfill.NoPrefix, governs[finality.ChainBaseSepolia])
					}
				case *ArbPostedLoop:
					sawArb = true
					if (l.Cap.Prefix == nil) != governs[finality.ChainArbitrumSepolia] {
						t.Errorf("the Arbitrum capturer scans the prefix: %v, governed %v", l.Cap.Prefix != nil, governs[finality.ChainArbitrumSepolia])
					}
				}
			}
			if !sawBase || !sawArb {
				t.Fatalf("the Base backfill loop (%v) and the Arbitrum capture loop (%v) run", sawBase, sawArb)
			}
			for _, ch := range c.chains {
				if !strings.Contains(logs.String(), "finality_prefix_disabled") || !strings.Contains(logs.String(), c.env) {
					t.Fatalf("the state is logged by name: %s", logs.String())
				}
				if v, ok := gauge(t, "certen_finality_prefix_disabled", map[string]string{"chain": fmt.Sprint(ch), "key": c.env, "reason": "setting_invalid"}); !ok || v != 1 {
					t.Errorf("certen_finality_prefix_disabled{chain=%d,key=%s} = %v (%v)", ch, c.env, v, ok)
				}
				chains, _ := metrics.FinalityHealth()["chains"].(map[string]any)
				m, _ := chains[fmt.Sprint(ch)].(map[string]any)
				if r, _ := m["prefix_disabled_reason"].(string); !strings.Contains(r, "finality_prefix_disabled") || !strings.Contains(r, c.env) {
					t.Errorf("/health/detailed names the disabled prefix of chain %d: %v", ch, m)
				}
			}
		})
	}
}

// The default and every valid configuration announce nothing and wire the prefix on both chains.
func TestRTValidPrefixSettingsWirePrefixWorkOnBothChainsAndAnnounceNothing(t *testing.T) {
	clearPrefixEnv(t)
	rtProviderEnv(t)
	t.Setenv(EnvPrefixMax, "7000")
	_, reg, logs := rtWire(t)
	if strings.Contains(logs.String(), "finality_prefix_disabled") {
		t.Fatalf("nothing to announce: %s", logs.String())
	}
	var base, arb bool
	for _, cp := range reg.Capturers() {
		switch l := cp.(type) {
		case *GapBackfillLoop:
			base = !l.Backfill.NoPrefix
		case *ArbPostedLoop:
			arb = l.Cap.Prefix != nil
		}
	}
	if !base || !arb {
		t.Fatalf("prefix work on: base %v arb %v", base, arb)
	}
}

// The index settings classify a refusal the way the prefix settings do (one closed vocabulary): a number too large to read is out of range,
// not "not an integer"; a negative number is out of range; empty and blank are the default.
func TestRTIndexSettingsRefuseHugeAndNegativeNumbersAsOutOfRangeAndEmptyIsTheDefault(t *testing.T) {
	numeric := []struct {
		env    string
		chains []uint64
	}{
		{finality.EnvIndexGeneration, []uint64{finality.ChainBaseSepolia}},
		{EnvArbIndexGeneration, []uint64{finality.ChainArbitrumSepolia}},
		{EnvIndexBlocks, []uint64{finality.ChainBaseSepolia, finality.ChainArbitrumSepolia}},
		{EnvIndexStepSecond, []uint64{finality.ChainBaseSepolia, finality.ChainArbitrumSepolia}},
	}
	for _, s := range numeric {
		for _, b := range [][2]string{{"99999999999999999999999", "out_of_range"}, {"-99999999999999999999999", "out_of_range"}, {"-1", "out_of_range"}, {"abc", "not_an_integer"}, {"1.5", "not_an_integer"}} {
			t.Run(s.env+"="+b[0], func(t *testing.T) {
				clearPrefixEnv(t)
				t.Setenv(s.env, b[0])
				cfg, err := ConfigFromEnv()
				if err != nil {
					t.Fatalf("a bad index setting must not stop the validator: %v", err)
				}
				var got []*finality.StateError
				if cfg.IndexDisabled != nil {
					got = append(got, cfg.IndexDisabled)
				}
				if cfg.ArbIndexDisabled != nil {
					got = append(got, cfg.ArbIndexDisabled)
				}
				if len(got) != len(s.chains) {
					t.Fatalf("one state per index the setting governs (%v), got %v", s.chains, got)
				}
				for _, st := range got {
					if st.Code != finality.CodeIndexDisabled || st.Fields["variable"] != s.env || st.Fields["reason"] != finality.IndexSettingInvalid || st.Fields["refused"] != b[1] {
						t.Fatalf("want finality_index_disabled{%s, setting_invalid, %s}, got %v", s.env, b[1], st)
					}
					if strings.Contains(st.Error(), b[0]) && len(b[0]) > 3 {
						t.Fatalf("the state must not echo the value: %v", st)
					}
				}
			})
		}
		for _, v := range []string{"", "   "} {
			clearPrefixEnv(t)
			t.Setenv(s.env, v)
			if cfg, err := ConfigFromEnv(); err != nil || cfg.IndexDisabled != nil || cfg.ArbIndexDisabled != nil || !cfg.BaseIndex || !cfg.ArbIndex {
				t.Fatalf("%s=%q is the default: %v %v %v", s.env, v, err, cfg.IndexDisabled, cfg.ArbIndexDisabled)
			}
		}
	}
}
