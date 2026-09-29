// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// RB3-F71 sweep: the validator refuses to boot on any runtime knob that does not parse, naming each.
func TestBootRefusesEveryUnreadableKnobByName(t *testing.T) {
	bad := map[string]string{
		"BATCH_PERIOD_BLOCKS":                "0",
		"CERTEN_BFT_TIMEOUT":                 "6 minutes",
		"CERTEN_BLOCK_RETENTION":             "all",
		"CERTEN_ALLOW_CONTRACT_CALLS":        "ture",
		"CERTEN_GAS_CEILING_ENFORCE":         "maybe",
		"CERTEN_NATIVE_USD":                  "$3000",
		"INTENT_REWIND_BLOCKS":               "-5",
		"BLOCK_WORKERS":                      "many",
		"CERTEN_DEFAULT_PROOF_CLASS":         "fast",
		"ETHEREUM_RPC_COOLDOWN_SECONDS":      "30s",
		"CERTEN_ENTITLEMENT_MAX_AGE_SEC":     "15m",
		"CERTEN_VALIDATOR_SET_THRESHOLD_NUM": "two",
		"MIGRATE_ON_START":                   "yes please",
	}
	for k, v := range bad {
		t.Setenv(k, v)
	}
	err := checkEnvironment()
	if err == nil {
		t.Fatal("the validator would boot on values it cannot read")
	}
	for k := range bad {
		if !strings.Contains(err.Error(), k+"=") {
			t.Errorf("the boot refusal does not name %s", k)
		}
	}
}

func TestBootAcceptsProductionsValues(t *testing.T) {
	// The values the seven production validators carry (read 2026-09-27).
	for k, v := range map[string]string{
		"BATCH_PERIOD_BLOCKS": "100", "CERTEN_ALLOW_CONTRACT_CALLS": "true", "CERTEN_BLOCK_RETENTION": "0",
		"CERTEN_ENTITLEMENT_REFRESH_SEC": "10", "ON_DEMAND_INTENT_KEYED": "true", "CHECKPOINT_ANCHOR_ENABLED": "false",
		"PROOF_CYCLE_WRITEBACK": "true", "ACCUMULATE_RESULTS_PRINCIPAL": "acc://certen-protocol.acme/proof-results",
		"ACCUMULATE_SIGNER_URL": "acc://certen-protocol.acme/book/1", "ACCUMULATE_WRITEBACK_PRIV_KEY": hex.EncodeToString(make([]byte, 64)),
	} {
		t.Setenv(k, v)
	}
	if err := checkEnvironment(); err != nil {
		t.Fatalf("production's values were refused: %v", err)
	}
}

// Enabled means configured, whole. Each missing piece used to be defaulted or to turn the anchor off.
func TestCheckpointAnchorIsConfiguredWholeOrRefused(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 64))
	set := func(writer, account, signer, cpKey, wbKey string) {
		t.Setenv("CHECKPOINT_WRITER_VALIDATOR", writer)
		t.Setenv("CHECKPOINT_DATA_ACCOUNT", account)
		t.Setenv("CHECKPOINT_SIGNER_URL", signer)
		t.Setenv("CHECKPOINT_WRITEBACK_PRIV_KEY", cpKey)
		t.Setenv("ACCUMULATE_WRITEBACK_PRIV_KEY", wbKey)
	}
	set("validator-1", "acc://x.acme/history", "acc://x.acme/book/1", "", key)
	cp, err := checkpointSettingsFromEnv()
	if err != nil || cp.writer != "validator-1" || len(cp.key) != 64 {
		t.Fatalf("a whole configuration was refused: %+v %v", cp, err)
	}
	for name, args := range map[string][5]string{
		"no writer":              {"", "acc://x.acme/history", "acc://x.acme/book/1", "", key},
		"no account":             {"validator-1", "", "acc://x.acme/book/1", "", key},
		"no signer":              {"validator-1", "acc://x.acme/history", "", "", key},
		"no write-back key":      {"validator-1", "acc://x.acme/history", "acc://x.acme/book/1", "", ""},
		"malformed override key": {"validator-1", "acc://x.acme/history", "acc://x.acme/book/1", "zz", key},
	} {
		set(args[0], args[1], args[2], args[3], args[4])
		if _, err := checkpointSettingsFromEnv(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), key) {
			t.Errorf("%s: the refusal printed the key", name)
		}
	}
	t.Setenv("CHECKPOINT_ANCHOR_ENABLED", "true")
	set("", "", "", "", "")
	if err := checkEnvironment(); err == nil || !strings.Contains(err.Error(), "CHECKPOINT_WRITER_VALIDATOR") {
		t.Fatalf("an enabled, unconfigured checkpoint anchor passed the boot check: %v", err)
	}
}

// RB4-F50: without ACCUMULATE_WRITEBACK_PRIV_KEY a validator signed its write-backs with its own key.
func TestWritebackIsConfiguredWholeOrRefused(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 64))
	set := func(principal, signer, wbKey string) {
		t.Setenv("ACCUMULATE_RESULTS_PRINCIPAL", principal)
		t.Setenv("ACCUMULATE_SIGNER_URL", signer)
		t.Setenv("ACCUMULATE_WRITEBACK_PRIV_KEY", wbKey)
	}
	set("acc://x.acme/results", "acc://x.acme/book/1", key)
	wb, err := writebackSettingsFromEnv()
	if err != nil || wb.signer != "acc://x.acme/book/1" || len(wb.key) != 64 {
		t.Fatalf("a whole configuration was refused: %+v %v", wb, err)
	}
	for name, args := range map[string][3]string{
		"no principal":      {"", "acc://x.acme/book/1", key},
		"no signer":         {"acc://x.acme/results", "", key},
		"no write-back key": {"acc://x.acme/results", "acc://x.acme/book/1", ""},
		"malformed key":     {"acc://x.acme/results", "acc://x.acme/book/1", "zz"},
		"short key":         {"acc://x.acme/results", "acc://x.acme/book/1", key[:64]},
	} {
		set(args[0], args[1], args[2])
		if _, err := writebackSettingsFromEnv(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), key[:64]) {
			t.Errorf("%s: the refusal printed the key", name)
		}
	}
	set("acc://x.acme/results", "acc://x.acme/book/1", "")
	if err := checkEnvironment(); err == nil || !strings.Contains(err.Error(), "ACCUMULATE_WRITEBACK_PRIV_KEY") {
		t.Fatalf("a validator without its write-back key passed the boot check: %v", err)
	}
}
