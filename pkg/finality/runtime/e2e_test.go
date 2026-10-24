// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// secretToken stands for a provider credential configured in a URL path; it must never reach a log, a status row or a state.
const secretToken = "tok0123456789abcdef0123456789abcdef"

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Logf(f string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(&s.b, f+"\n", a...)
}
func (s *syncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fakeEL is a JSON-RPC execution endpoint (single and batch): a head, empty blocks, and refusals that carry a credential in their text.
type fakeEL struct{ calls sync.Map }

func (f *fakeEL) answer(method string, params []json.RawMessage) (any, map[string]any) {
	n, _ := f.calls.LoadOrStore(method, new(int))
	*(n.(*int))++
	switch method {
	case "eth_blockNumber":
		return "0x100", nil
	case "eth_getBlockByNumber", "eth_getBlockByHash":
		var num uint64 = 0x100
		if len(params) > 0 {
			var hx string
			if json.Unmarshal(params[0], &hx) == nil && strings.HasPrefix(hx, "0x") && len(hx) < 18 {
				fmt.Sscanf(hx, "0x%x", &num)
			}
		}
		h := &types.Header{Number: new(big.Int).SetUint64(num), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1_760_000_000 + num*12,
			BaseFee: big.NewInt(7), Extra: []byte{}, ParentHash: common.Hash{1}}
		raw, _ := json.Marshal(h)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		m["transactions"] = []any{}
		return m, nil
	}
	return nil, map[string]any{"code": -32601, "message": "method unavailable for key " + secretToken}
}

func (f *fakeEL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	type req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	one := func(q req) map[string]any {
		res, e := f.answer(q.Method, q.Params)
		out := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		if e != nil {
			out["error"] = e
		} else {
			out["result"] = res
		}
		return out
	}
	if t := bytes.TrimSpace(body); len(t) > 0 && t[0] == '[' {
		var qs []req
		_ = json.Unmarshal(body, &qs)
		outs := make([]map[string]any, 0, len(qs))
		for _, q := range qs {
			outs = append(outs, one(q))
		}
		_ = json.NewEncoder(w).Encode(outs)
		return
	}
	var q req
	_ = json.Unmarshal(body, &q)
	_ = json.NewEncoder(w).Encode(one(q))
}

// The wiring end to end, against PostgreSQL and fake providers: a settled leg of every live chain (real captured blocks with
// their L6 evidence) is loaded by the real leg source, handed to the provers the runtime wired from the environment, and every
// level the chain offers ends as a NAMED status row; the capture loops follow the fake heads and persist their cursors; no
// credential reaches a log or a stored state; nothing is stored that no Kind verified.
func TestRuntimeWiringEndToEndAgainstFakeProviders(t *testing.T) {
	url, err := testdb.PackageURL("finruntime")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(context.Background(), "finruntime-test"); err != nil {
		t.Fatal(err)
	}
	client := database.NewClientFromDB(db)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	el := httptest.NewServer(&fakeEL{})
	defer el.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream refuses key "+secretToken, http.StatusNotFound)
	}))
	defer dead.Close()
	withKey := func(base string) string { return base + "/v2/" + secretToken }

	for k, v := range map[string]string{
		"ETHEREUM_URL": withKey(el.URL), "BASE_SEPOLIA_RPC_URL": withKey(el.URL), "ARBITRUM_SEPOLIA_RPC_URL": withKey(el.URL),
		"TELCOIN_ADIRI_RPC_URL": withKey(el.URL), EnvL1ProofURLs: withKey(el.URL), EnvLCURLs: withKey(dead.URL), EnvBeaconURLs: withKey(dead.URL),
		EnvAdiriURLs: withKey(el.URL), EnvRateRPS: "1000", EnvRateBurst: "1000", EnvCaptureEvery: "1", EnvInterval: "1",
	} {
		t.Setenv(k, v)
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	legs := map[uint64]string{}
	levels := map[uint64][]finality.Level{
		finality.ChainSepolia:         {finality.LevelFinalized},
		finality.ChainBaseSepolia:     {finality.LevelL1Posted, finality.LevelFinalized},
		finality.ChainArbitrumSepolia: {finality.LevelL1Posted, finality.LevelFinalized},
		finality.ChainAdiri:           {finality.LevelFinalized},
	}
	for chain, fixture := range map[uint64]string{
		finality.ChainSepolia: "sepolia_11792612", finality.ChainBaseSepolia: "base_sepolia_47368146",
		finality.ChainArbitrumSepolia: "arbitrum_sepolia_312921216", finality.ChainAdiri: "telcoin_adiri_498759",
	} {
		s := finalitytest.Settlement(t, fixture)
		if s.Chain != chain {
			t.Fatalf("fixture %s settles on chain %d, not %d", fixture, s.Chain, chain)
		}
		legs[chain] = finalitytest.StoreProductionLeg(t, db, s)
	}

	logs := &syncBuf{}
	status := database.NewFinalityStatusRepository(client)
	repo := database.NewFinalityAddendaRepository(client)
	reg := finality.NewRegistry()
	w, err := Wire(cfg, Deps{Registry: reg, Store: database.NewFinalityCaptureStore(client), Status: status, Logf: logs.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Disabled) != 0 {
		t.Fatalf("every provider is configured, yet chains are switched off: %v", w.Disabled)
	}
	if w.PinsSource != finality.PinsSourceEmbedded || w.PinsSHA256 != finality.PinsSHA256 {
		t.Fatalf("pins source %s sha %s", w.PinsSource, w.PinsSHA256)
	}
	for chain := range levels {
		if len(reg.Provers(chain)) == 0 {
			t.Fatalf("chain %d has no prover after Wire", chain)
		}
	}
	if got := len(reg.Capturers()); got != 3 {
		t.Fatalf("%d capture loops registered, want the Base inbox loop, the Base gap backfill loop and the Arbitrum sequencer-inbox loop", got)
	}

	lctx, stop := context.WithCancel(ctx)
	if _, err := finality.Launch(lctx, true, repo, repo, w.Registry, w.Pins, w.Upgrader); err != nil {
		t.Fatal(err)
	}
	defer stop()

	// every (leg, level) the chain offers gets a status row that names its state
	deadline := time.Now().Add(150 * time.Second)
	missing := func() []string {
		var out []string
		for chain, ls := range levels {
			for _, l := range ls {
				if _, ok, err := status.GetStatus(ctx, legs[chain], l); err != nil || !ok {
					out = append(out, fmt.Sprintf("chain %d %s", chain, l))
				}
			}
		}
		return out
	}
	for len(missing()) > 0 && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
	if m := missing(); len(m) > 0 {
		t.Fatalf("no status row after the deadline for %v\nlogs:\n%s", m, logs.String())
	}
	logStates(t, status, ctx, legs, levels)
	for chain, ls := range levels {
		for _, l := range ls {
			v, _, _ := status.GetStatus(ctx, legs[chain], l)
			if v.Class == "" || (v.Class != finality.BuilderVerified && len(v.State) == 0) {
				t.Errorf("chain %d %s: the status names no state: %+v", chain, l, v)
			}
			if v.Class == finality.BuilderVerified {
				t.Errorf("chain %d %s is verified against providers that serve no evidence", chain, l)
			}
			// a prover that does not serve a level must not speak for it: the sibling prover's state is the leg's status
			// the embedded pins must load for every kind: a pin_mismatch here is a kind refusing the shipped pins file
			if code := stateCodeOf(v.State); code == "pin_mismatch" || code == finality.CodePinUnknown {
				t.Errorf("chain %d %s: the embedded pins are refused by a kind: %s", chain, l, code)
			}
			if code := stateCodeOf(v.State); code == finality.CodeEvidenceUnrecognised {
				t.Errorf("chain %d %s: the status is %s, a prover answered a level it does not serve", chain, l, code)
			}
		}
		if chain, err := repo.Chain(ctx, legs[chain]); err != nil || len(chain) != 0 {
			t.Errorf("an addendum was stored without a verifying Kind: %v %v", chain, err)
		}
	}

	// the capture loops followed the fake head and persisted their cursors
	capture := database.NewFinalityCaptureStore(client)
	for time.Now().Before(deadline) {
		cur, ok, _ := readCursor(ctx, capture, finality.ChainBaseSepolia)
		if ok && cur >= 0x100 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if cur, ok, err := readCursor(ctx, capture, finality.ChainBaseSepolia); err != nil || !ok || cur < 0x100 {
		t.Fatalf("the Base capture loop did not reach the fake head: cursor %d %v %v\nlogs:\n%s", cur, ok, err, logs.String())
	}

	stop()
	out := logs.String()
	if strings.Contains(out, secretToken) {
		t.Fatalf("a provider credential reached the logs:\n%s", out)
	}
	var stored string
	if err := db.QueryRow(`SELECT coalesce(string_agg(state::text, ' '), '') FROM proof_finality_status`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, secretToken) {
		t.Fatal("a provider credential reached a stored status row")
	}
	if !strings.Contains(out, "runtime wiring: pins_source=embedded") {
		t.Fatalf("the startup line does not report pins_source:\n%s", out)
	}
}

func logStates(t *testing.T, status finality.BuilderStatusStore, ctx context.Context, legs map[uint64]string, levels map[uint64][]finality.Level) {
	for chain, ls := range levels {
		for _, l := range ls {
			v, _, _ := status.GetStatus(ctx, legs[chain], l)
			code := ""
			var d struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(v.State, &d) == nil {
				code = d.Code
			}
			t.Logf("chain %d %s: class=%s state=%s", chain, l, v.Class, code)
		}
	}
}

func stateCodeOf(raw json.RawMessage) string {
	var d struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &d)
	return d.Code
}
