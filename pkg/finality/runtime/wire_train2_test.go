// Copyright 2026 Certen Protocol

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/allkinds"
)

// RB12-GO-INT F14: every refusal the runtime makes of its start is TYPED, so the process names it (variable or stage) without parsing
// text and without echoing a value: a refused setting is an *envvar.Refusal, a failure of the wiring is a *WireError with a stage.

func rtWireErr(t *testing.T, mutate func(reg *finality.Registry), deps func(*Deps)) error {
	t.Helper()
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	reg := finality.NewRegistry()
	if mutate != nil {
		mutate(reg)
	}
	d := Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Logf: (&syncBuf{}).Logf}
	if deps != nil {
		deps(&d)
	}
	_, err = Wire(cfg, d)
	return err
}

func TestRTF14WireNamesTheStageOfEveryFailure(t *testing.T) {
	t.Run("the pins file cannot be read", func(t *testing.T) {
		rtClearEnv(t)
		t.Setenv(EnvPinsFile, filepath.Join(t.TempDir(), "absent.json"))
		err := rtWireErr(t, nil, nil)
		var we *WireError
		if !errors.As(err, &we) || we.Stage != finality.StartStagePinsFile {
			t.Fatalf("%T %v", err, err)
		}
		if !strings.Contains(err.Error(), EnvPinsFile) {
			t.Fatalf("the text names the variable: %v", err)
		}
	})
	t.Run("the pins file is not a pins file", func(t *testing.T) {
		rtClearEnv(t)
		p := filepath.Join(t.TempDir(), "pins.json")
		if err := os.WriteFile(p, []byte(`{"not":"pins"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(EnvPinsFile, p)
		var we *WireError
		if err := rtWireErr(t, nil, nil); !errors.As(err, &we) || we.Stage != finality.StartStagePinsFile {
			t.Fatalf("%T %v", err, err)
		}
	})
	t.Run("a verifier kind is already registered", func(t *testing.T) {
		rtClearEnv(t)
		err := rtWireErr(t, func(reg *finality.Registry) {
			if e := allkinds.Register(reg); e != nil {
				t.Fatal(e)
			}
		}, nil)
		var we *WireError
		if !errors.As(err, &we) || we.Stage != finality.StartStageKinds {
			t.Fatalf("%T %v", err, err)
		}
	})
	t.Run("no registry", func(t *testing.T) {
		rtClearEnv(t)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		_, err = Wire(cfg, Deps{})
		var we *WireError
		if !errors.As(err, &we) || we.Stage != finality.StartStageArguments {
			t.Fatalf("%T %v", err, err)
		}
	})
	t.Run("a per-chain switch that is not a switch is a refusal of that variable, not a wiring failure", func(t *testing.T) {
		rtClearEnv(t)
		t.Setenv(finality.ChainEnv(finality.ChainBaseSepolia), "maybe")
		err := rtWireErr(t, nil, nil)
		rs := envvar.Refusals(err)
		var we *WireError
		if len(rs) != 1 || rs[0].Key != finality.ChainEnv(finality.ChainBaseSepolia) || errors.As(err, &we) {
			t.Fatalf("%T %v %v", err, err, rs)
		}
	})
}

func TestRTF14ConfigFromEnvRefusesEverySettingAsATypedRefusal(t *testing.T) {
	rtClearEnv(t)
	t.Setenv(EnvRateRPS, "fast")
	t.Setenv(EnvConcurrency, "0")
	t.Setenv(EnvMaxBatch, "250")
	_, err := ConfigFromEnv()
	var keys []string
	for _, r := range envvar.Refusals(err) {
		keys = append(keys, r.Key)
	}
	got := strings.Join(sortedStrings(keys), ",")
	want := strings.Join(sortedStrings([]string{EnvRateRPS, EnvConcurrency, EnvMaxBatch}), ",")
	if got != want {
		t.Fatalf("refused %s, want %s (%v)", got, want, err)
	}
	// RefusedSettings is the same judgement without a configuration: every refusal, never a value
	var named []string
	for _, r := range RefusedSettings() {
		named = append(named, r.Key)
		if r.Want == "" {
			t.Fatalf("a refusal says what the setting must be: %+v", r)
		}
	}
	if strings.Join(sortedStrings(named), ",") != want {
		t.Fatalf("RefusedSettings %v, want %s", named, want)
	}
	// alone, the batch bound is the same kind of refusal and states the bound
	rtClearEnv(t)
	t.Setenv(EnvMaxBatch, "250")
	_, err = ConfigFromEnv()
	rs := envvar.Refusals(err)
	if len(rs) != 1 || rs[0].Key != EnvMaxBatch || !strings.Contains(err.Error(), "100") {
		t.Fatalf("%v %v", rs, err)
	}
	// and a good environment refuses nothing
	rtClearEnv(t)
	if rs := RefusedSettings(); len(rs) != 0 {
		t.Fatalf("%v", rs)
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
