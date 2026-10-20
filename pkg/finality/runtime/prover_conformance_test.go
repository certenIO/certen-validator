// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// The upgrader asks EVERY prover of a chain about every stored level the leg lacks and keeps the LAST answer as the leg's status
// (upgrader.go, the "for _, p := range u.reg.Provers" loop). A prover that answers a level it does not serve with anything but
// "not mine" therefore overwrites the real pending or unavailable state of the sibling prover that does serve the level, and counts a
// failure on every pass. This conformance test pins the contract on the provers exactly as Wire registers them, for every kind
// registered by allkinds: asked, with a minimally valid request, for a level it does not serve, a prover returns (nil, nil, nil)
// and touches no provider. The one other legal answer is the chain profile's own level_not_applicable for a level the CHAIN does not
// offer (Sepolia and Adiri have no l1_posted); the upgrader never asks for such a level and special-cases the state, and the
// test pins its exact fields.

// servedLevels is the level each registered prover type builds. A prover registered by Wire that is missing here fails the test
// by name: a new prover must declare its level before it can be wired.
var servedLevels = map[string]finality.Level{
	"github.com/certen/independant-validator/pkg/finality/adiri.Prover":          finality.LevelFinalized,
	"github.com/certen/independant-validator/pkg/finality/ethsepolia.Prover":     finality.LevelFinalized,
	"github.com/certen/independant-validator/pkg/finality/baseposted.Builder":    finality.LevelL1Posted,
	"github.com/certen/independant-validator/pkg/finality/basefinal.Builder":     finality.LevelFinalized,
	"github.com/certen/independant-validator/pkg/finality/arbposted.Builder":     finality.LevelL1Posted,
	"github.com/certen/independant-validator/pkg/finality/arbfinal/build.Prover": finality.LevelFinalized,
}

func proverTypeName(p finality.Prover) string {
	t := reflect.TypeOf(p)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.PkgPath() + "." + t.Name()
}

type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, fmt.Errorf("conformance: a prover asked for a level it does not serve called %s", r.URL.Host)
}

func TestRTEveryProverAnswersNothingForALevelItDoesNotServe(t *testing.T) {
	rtProviderEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	tr := &countingTransport{}
	reg := finality.NewRegistry()
	w, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), HTTP: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Disabled) != 0 {
		t.Fatalf("every provider is configured, yet chains are off: %v", w.Disabled)
	}
	fixtureOf := map[uint64]string{}
	for fx, chain := range finalitytest.Blocks {
		fixtureOf[chain] = fx
	}

	asked := 0
	for _, chain := range reg.Chains() {
		profile, _ := reg.Profile(chain)
		provers := reg.Provers(chain)
		if len(provers) == 0 {
			t.Fatalf("chain %d has no prover after Wire", chain)
		}
		// the declared levels of the chain's provers cover exactly the stored levels the profile offers, each by one prover
		serves := map[finality.Level][]string{}
		for _, p := range provers {
			name := proverTypeName(p)
			lvl, ok := servedLevels[name]
			if !ok {
				t.Fatalf("chain %d: prover %s is registered by Wire but declares no level in servedLevels", chain, name)
			}
			serves[lvl] = append(serves[lvl], name)
		}
		for _, l := range profile.Levels {
			if l.Stored() && len(serves[l]) != 1 {
				t.Errorf("chain %d offers %s but %d provers serve it: %v", chain, l, len(serves[l]), serves[l])
			}
		}
		for l, names := range serves {
			if !profile.Offers(l) {
				t.Errorf("chain %d: %v serve %s, which the chain does not offer", chain, names, l)
			}
		}

		s := finalitytest.Settlement(t, fixtureOf[chain])
		for _, p := range provers {
			own := servedLevels[proverTypeName(p)]
			for _, l := range finality.Levels {
				if l == own {
					continue
				}
				for _, have := range []finality.LevelSet{0, finality.LevelSetOf(finality.LevelL1Posted, finality.LevelFinalized)} {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					before := tr.n.Load()
					add, pend, err := p.Build(ctx, s.Included, have, l)
					cancel()
					asked++
					who := fmt.Sprintf("chain %d prover %s level %s have %08b", chain, proverTypeName(p), l, uint8(have))
					if tr.n.Load() != before {
						t.Errorf("%s: a level the prover does not serve reached a provider", who)
					}
					if na, ok := profile.NotApplicableFor(l); ok {
						// the chain has no such level: the profile's own named state, nothing built, nothing pending
						if add != nil || pend != nil || err == nil || err.Error() != na.Error() {
							t.Errorf("%s: want exactly %s, got add=%v pending=%v err=%v", who, na.Error(), add, pend, err)
						}
						continue
					}
					if add != nil || pend != nil || err != nil {
						t.Errorf("%s: want (nil, nil, nil) for a level the prover does not serve, got add=%v pending=%v err=%v", who, add != nil, pend, err)
					}
				}
			}
		}
	}
	// 4 chains: Sepolia 1 prover x 2 levels, Base 2 x 2, Arbitrum 2 x 2, Adiri 1 x 2, each under two `have` sets
	if want := (2 + 4 + 4 + 2) * 2; asked != want {
		t.Fatalf("asked %d (prover, level, have) combinations, want %d", asked, want)
	}
	if got := reg.Chains(); len(got) != 4 {
		t.Fatalf("chains %v", got)
	}
}
