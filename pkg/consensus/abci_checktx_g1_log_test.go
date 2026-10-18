package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
)

// A CheckTx that cannot read the cross-partition activation log keeps the v14 reading (the safe direction: FinalizeBlock, the
// authority, judges the block and stops the node on that log) - and says so, as the anchor-set read above it does, instead of
// silently taking one reading.
func TestCheckTxNamesAnActivationLogItCannotRead(t *testing.T) {
	f := newRotationFixture()
	cfg, ev := pricedFixture(t,
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000, PerLegMicroUSD: 500},
		entitlement.ChainCostBasis{ChainID: 421614})
	policy := *f.policy
	policy.Mode = string(EntitlementEnforce)
	policy.Keys = map[string]string{"k1": hex.EncodeToString(cfg.Keys["k1"])}
	pf := *f
	pf.policy = &policy

	kv := newMemKV()
	store := ledger.NewLedgerStore(kv)
	if err := store.SaveEntitlementPolicy(pf.policy); err != nil {
		t.Fatal(err)
	}
	app := newTestApp(t, store)
	app.validatorBlocks = map[string]*ValidatorBlock{}
	app.entitlement = EntitlementConfig{Mode: EntitlementOff}
	doc := &cmttypes.GenesisDoc{ChainID: rotChain}
	for i, k := range pf.validators {
		doc.Validators = append(doc.Validators, cmttypes.GenesisValidator{
			PubKey: cmted25519.PubKey(k.Public().(ed25519.PublicKey)), Power: 10, Name: string(rune('a' + i))})
	}
	if err := app.SetGenesis(doc); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	app.logger = log.New(&logged, "", 0)

	zero := []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum)}
	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", zero, ev))
	v14Step(t, app, 2, []uint32{0}, rotJSON(t, liveAnchorSet(&pf, 1, "ops-1", "ops-2")))
	logged.Reset()

	check := func(id string) *abcitypes.ResponseCheckTx {
		t.Helper()
		r, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: anchoredBlockJSON(t, id, "validator-1", zero, ev)})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := check("op-5"); r.Code != 0 {
		t.Fatalf("CheckTx refused the zero-basis block at v14 with a readable log: %d %s", r.Code, r.Log)
	}
	if strings.Contains(logged.String(), "G1-ACTIVATION") {
		t.Fatalf("a readable activation log produced a warning: %s", logged.String())
	}

	if err := kv.Set([]byte("abci:g1_activation"), []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if r := check("op-6"); r.Code != 0 {
		t.Fatalf("CheckTx must keep the v14 reading when the activation log is unreadable (FinalizeBlock decides): %d %s", r.Code, r.Log)
	}
	if out := logged.String(); !strings.Contains(out, "G1-ACTIVATION") || !strings.Contains(out, "could not read the cross-partition activation log") {
		t.Fatalf("an unreadable activation log was taken silently; log: %q", out)
	}
}
