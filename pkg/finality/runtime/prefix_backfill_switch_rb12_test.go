// Copyright 2026 Certen Protocol

package runtime

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2 (finding F-3): CERTEN_FINALITY_PREFIX_BACKFILL is the operator's switch for the FETCHES of the prefix work. Off stops the Base
// backfill and the Arbitrum scan on both chains and keeps the requests; MAX_BLOCKS=0 stops only new requests; a refused value is a named
// refusal of both chains.

func TestRB12PrefixBackfillSwitchOffStopsTheFetchesAndKeepsTheRequests(t *testing.T) {
	for _, v := range []string{"off", "OFF", "false", "0", "no", "n", "f"} {
		rtClearEnv(t)
		t.Setenv(EnvPrefixBackfill, v)
		var c Config
		refused := c.readPrefixSettings()
		if len(refused) != 0 || len(c.PrefixDisabled) != 0 || c.PrefixBackfill {
			t.Fatalf("%q: refused %v, states %v, PrefixBackfill %v: a valid off is an operator mode", v, refused, c.PrefixDisabled, c.PrefixBackfill)
		}
		for _, chain := range []uint64{finality.ChainBaseSepolia, finality.ChainArbitrumSepolia} {
			if !c.backfillOff(chain) {
				t.Errorf("%q: chain %d fetches are still on", v, chain)
			}
			if p := c.prefixPolicy(chain); p.MaxBlocks != c.PrefixMax || p.MaxBlocks == 0 {
				t.Errorf("%q: chain %d: the switch stopped the requests too: %+v", v, chain, p)
			}
		}
	}
}

func TestRB12PrefixBackfillSwitchDefaultsToOnAndOnIsOn(t *testing.T) {
	for _, v := range []string{"", "  ", "on", "true", "1", "yes", "y", "t"} {
		rtClearEnv(t)
		t.Setenv(EnvPrefixBackfill, v)
		var c Config
		refused := c.readPrefixSettings()
		if len(refused) != 0 || len(c.PrefixDisabled) != 0 || !c.PrefixBackfill || c.backfillOff(finality.ChainBaseSepolia) || c.backfillOff(finality.ChainArbitrumSepolia) {
			t.Fatalf("%q: refused %v, states %v, PrefixBackfill %v", v, refused, c.PrefixDisabled, c.PrefixBackfill)
		}
	}
}

func TestRB12PrefixBackfillSwitchThatIsNotASwitchIsANamedRefusalOfBothChains(t *testing.T) {
	for _, v := range []string{"maybe", "2", "enabled", "of", "-1"} {
		rtClearEnv(t)
		t.Setenv(EnvPrefixBackfill, v)
		var c Config
		refused := c.readPrefixSettings()
		if len(refused) != 1 || refused[0].Refusal.Key != EnvPrefixBackfill || refused[0].Refused != finality.PrefixRefusedNotASwitch {
			t.Fatalf("%q: refused %+v", v, refused)
		}
		if len(c.PrefixDisabled) != 2 {
			t.Fatalf("%q: %d states, want one per chain", v, len(c.PrefixDisabled))
		}
		for _, st := range c.PrefixDisabled {
			if st.Code != finality.CodePrefixDisabled || st.Fields["variable"] != EnvPrefixBackfill || st.Fields["refused"] != finality.PrefixRefusedNotASwitch {
				t.Errorf("%q: state %v", v, st)
			}
			if strings.Contains(st.Error(), v) && len(v) > 2 { // the state names the variable and the class of the fault, never the value
				t.Errorf("%q: the state echoes the value: %s", v, st.Error())
			}
		}
		for _, chain := range []uint64{finality.ChainBaseSepolia, finality.ChainArbitrumSepolia} {
			if !c.prefixOff(chain) || !c.backfillOff(chain) || c.prefixPolicy(chain).MaxBlocks != 0 {
				t.Errorf("%q: chain %d is not wholly off", v, chain)
			}
		}
	}
}

// The announcement of the operator's switch: a log line, and nothing for a chain whose prefix work a refused setting already switched off.
func TestRB12PrefixBackfillOffIsAnnouncedOnceAndARefusedSettingIsNotAnnouncedTwice(t *testing.T) {
	var lines []string
	logf := func(f string, a ...any) {
		lines = append(lines, strings.TrimSpace(strings.ReplaceAll(f, "%s", EnvPrefixBackfill)))
	}
	announcePrefixBackfillOff(Config{PrefixBackfill: true}, finality.ChainBaseSepolia, logf)
	if len(lines) != 0 {
		t.Fatalf("on is not announced: %v", lines)
	}
	announcePrefixBackfillOff(Config{PrefixBackfill: false}, finality.ChainBaseSepolia, logf)
	if len(lines) != 1 || !strings.Contains(lines[0], "prefix backfill OFF by CERTEN_FINALITY_PREFIX_BACKFILL") {
		t.Fatalf("off is announced once: %v", lines)
	}
	refused := Config{PrefixBackfill: false, PrefixDisabled: []*finality.StateError{finality.PrefixDisabledState(finality.ChainBaseSepolia, EnvPrefixBackfill, finality.PrefixRefusedNotASwitch)}}
	announcePrefixBackfillOff(refused, finality.ChainBaseSepolia, logf)
	if len(lines) != 1 {
		t.Fatalf("a refused setting is announced by AnnouncePrefixDisabled, not twice: %v", lines)
	}
}
