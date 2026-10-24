// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
)

// V-INDEX-B B3(c): the floor of the batches the capture did not scan itself is ONE function given to the reader's time search and to the indexer's
// rotating walk, by the wiring; without one (this branch) both have none. An explicit off is announced at wiring, not only a bad value.
func TestRTArbFloorIsWiredToTheReaderAndTheIndexerAndAnExplicitOffIsAnnounced(t *testing.T) {
	rtProviderEnv(t)
	floor := func(context.Context) (uint64, bool, error) { return 123, true, nil }
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	reg := finality.NewRegistry()
	if _, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Logf: (&syncBuf{}).Logf, ArbFloor: floor}); err != nil {
		t.Fatal(err)
	}
	var readers, indexers int
	for _, p := range reg.Provers(finality.ChainArbitrumSepolia) {
		if b, ok := p.(*arbposted.Builder); ok && b.Index != nil {
			readers++
			if b.Index.Floor == nil {
				t.Error("the reader has no floor")
			} else if f, ok, _ := b.Index.Floor(context.Background()); !ok || f != 123 {
				t.Errorf("the reader's floor is %d %v", f, ok)
			}
		}
	}
	for _, c := range reg.Capturers() {
		if l, ok := c.(*ArbIndexLoop); ok {
			indexers++
			ix := l.Index.(*arbposted.Indexer)
			if ix.Cfg.Floor == nil {
				t.Error("the indexer has no floor")
			} else if f, ok, _ := ix.Cfg.Floor(context.Background()); !ok || f != 123 {
				t.Errorf("the indexer's floor is %d %v", f, ok)
			}
		}
	}
	if readers != 1 || indexers != 1 {
		t.Fatalf("%d readers and %d indexers with a floor", readers, indexers)
	}
	// no floor given: none on either side, and no OFF line while the index is on
	_, reg2, logs := rtWire(t)
	for _, p := range reg2.Provers(finality.ChainArbitrumSepolia) {
		if b, ok := p.(*arbposted.Builder); ok && b.Index != nil && b.Index.Floor != nil {
			t.Error("a reader floor without a source")
		}
	}
	if strings.Contains(logs.String(), "arbitrum batch index OFF") {
		t.Error("the index is on, yet an OFF line was logged")
	}
	t.Setenv(EnvArbIndex, "off")
	_, _, logs = rtWire(t)
	if !strings.Contains(logs.String(), "arbitrum batch index OFF by "+EnvArbIndex) {
		t.Fatalf("an explicit off is not announced at wiring:\n%s", logs.String())
	}
}
