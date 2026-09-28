// Copyright 2026 Certen Protocol

package contracts

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

func configureRegisteredSet(t *testing.T) {
	t.Helper()
	for k, v := range testvalset.Settings {
		t.Setenv(k, v)
	}
	for _, k := range []string{legacyValidatorSetAddrs, legacyValidatorSetPowers, legacyValidatorSetThresholdNum, legacyValidatorSetThresholdDen} {
		t.Setenv(k, "")
	}
	ResetV6_1ValidatorSetRootCache()
	t.Cleanup(ResetV6_1ValidatorSetRootCache)
}

// RB3-F71 sweep, RB3-F21: the threshold committed into the validator-set root is the one configured, or
// none. An unreadable value used to become 2/3 silently - and so did an absent one.
func TestTheSetRootThresholdIsReadOrRefused(t *testing.T) {
	configureRegisteredSet(t)
	if n, d, err := resolveThreshold(); err != nil || n.Int64() != 2 || d.Int64() != 3 {
		t.Fatalf("configured 2/3: (%v, %v, %v)", n, d, err)
	}
	t.Setenv(envValidatorSetThresholdNum, "")
	if n, d, err := resolveThreshold(); err == nil {
		t.Fatalf("unset threshold committed as %v/%v", n, d)
	}
	for _, c := range [][2]string{{"two", "3"}, {"2", "0"}, {"4", "3"}, {"-1", "3"}} {
		t.Setenv(envValidatorSetThresholdNum, c[0])
		t.Setenv(envValidatorSetThresholdDen, c[1])
		if n, d, err := resolveThreshold(); err == nil {
			t.Errorf("%s/%s committed as %v/%v", c[0], c[1], n, d)
		}
	}
}

// RB3-F21: the set is configured, never compiled in. It equals the registered root; without it the node
// does not start; its former names still configure it, and disagree with the new ones only by refusal.
func TestTheValidatorSetIsConfiguredNeverAssumed(t *testing.T) {
	configureRegisteredSet(t)
	root, err := GetV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatal(err)
	}
	const registered = "a85a6911183f5085dedba666ab04b370550d8e0f1cd6b39dc0d716da7aa174e8"
	if got := strings.TrimPrefix(bytesHex(root[:]), "0x"); got != registered {
		t.Fatalf("root %s, want the registered %s", got, registered)
	}
	if err := CheckEnv(); err != nil {
		t.Fatalf("the registered set was refused at boot: %v", err)
	}

	t.Setenv(envValidatorSetAddrs, "")
	if err := CheckEnv(); err == nil || !strings.Contains(err.Error(), envValidatorSetAddrs) {
		t.Fatalf("no configured set: %v", err)
	}

	// Former names alone configure it.
	t.Setenv(legacyValidatorSetAddrs, testvalset.Settings[envValidatorSetAddrs])
	if err := CheckEnv(); err != nil {
		t.Fatalf("the former name was refused: %v", err)
	}
	// Both names, the same set (differently cased): accepted. Different sets: refused, naming both.
	t.Setenv(envValidatorSetAddrs, strings.ToLower(testvalset.Settings[envValidatorSetAddrs]))
	if err := CheckEnv(); err != nil {
		t.Fatalf("both names stating one set: %v", err)
	}
	t.Setenv(legacyValidatorSetAddrs, "0x0000000000000000000000000000000000000001")
	if err := CheckEnv(); err == nil || !strings.Contains(err.Error(), legacyValidatorSetAddrs) {
		t.Fatalf("disagreeing names accepted: %v", err)
	}

	// Powers are configured too: none, one short, or not positive is refused.
	t.Setenv(legacyValidatorSetAddrs, "")
	for _, p := range []string{"", "100,100", "100,100,100,100,100,100,0"} {
		t.Setenv(envValidatorSetPowers, p)
		if err := CheckEnv(); err == nil {
			t.Errorf("powers %q accepted", p)
		}
	}
}

func bytesHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
