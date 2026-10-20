// Copyright 2026 Certen Protocol

//go:build adirilive

package adiri_test

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// One live read: the real settlement block 500980 (epoch 602) built from the public endpoint and verified end to end. Run with
// `go test -tags adirilive -run TestLiveRead ./pkg/finality/adiri`. The sibling fake-server tests of build_test.go pin the same
// code path offline in every normal run (TestBuilderLinkKind1ReproducesTheLiveEvidence).
func TestLiveReadBuildsAndVerifiesARealLeg(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	p := &adiri.Prover{Endpoints: []string{"https://rpc.telcoin.network"}, Pins: pins}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hs, err := p.ReadHeaders(ctx, 500980, 500980)
	if err != nil {
		t.Fatal(err)
	}
	h := finality.BlockRef{Chain: finality.ChainAdiri, Number: 500980, HeaderRLP: hs[0]}
	hf, err := finality.ReadHeader(hs[0])
	if err != nil {
		t.Fatal(err)
	}
	h.Hash = hf.Hash
	add, pend, err := p.BuildLeg(ctx, h)
	if err != nil || pend != nil {
		t.Fatalf("%v %v", err, pend)
	}
	v, err := adiri.NewVerifier().Verify(pins, h, add.Evidence)
	if err != nil || v.Fields["epoch"] != uint64(602) {
		t.Fatalf("%v %+v", err, v)
	}
	t.Logf("live build: %d B evidence, epoch %v, %v signers", len(add.Evidence), v.Fields["epoch"], v.Fields["signers"])
}
