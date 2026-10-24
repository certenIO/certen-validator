// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/mr-tron/base58"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// replayAdiri is a JSON-RPC server that replays what the live Adiri endpoint answered when the adiri3 vector was recorded: the epoch
// records come from the recorded CFA1, the headers from its recorded spine. It answers batches, like the real endpoint.
type replayAdiri struct {
	cf      *adiri.CFA1
	headers map[uint64][]byte
	cur     uint64
	batches atomic.Int64
	biggest atomic.Int64
}

func (f *replayAdiri) record(e int) json.RawMessage {
	r := f.cf.Records[e]
	bs := func(keys [][]byte) []string {
		out := make([]string, len(keys))
		for i, k := range keys {
			out[i] = base58.Encode(k)
		}
		return out
	}
	digests, derr := f.cf.RecordDigests()
	if derr != nil {
		panic(derr) // a recorded chain names its tables
	}
	parent := make([]byte, 32)
	if e > 0 {
		parent = digests[e-1][:]
	}
	var signers []uint16
	for _, s := range r.Signers {
		signers = append(signers, uint16(s))
	}
	rec := map[string]any{
		"epoch": e, "committee": bs(f.cf.Tables[r.CommitteeIdx]), "next_committee": bs(f.cf.Tables[r.NextIdx]), "parent_hash": base58.Encode(parent),
		"final_state":     map[string]any{"number": r.FinalState.Number, "hash": "0x" + hex.EncodeToString(r.FinalState.Hash[:])},
		"final_consensus": map[string]any{"number": r.FinalConsensus.Number, "hash": base58.Encode(r.FinalConsensus.Hash[:])},
	}
	cert := map[string]any{"epoch_hash": base58.Encode(digests[e][:]), "signature": base58.Encode(r.Signature[:]), "signed_authorities": base58.Encode(adiri.EncodeRoaring(signers))}
	b, _ := json.Marshal([]any{rec, cert})
	return b
}

func (f *replayAdiri) block(n uint64) json.RawMessage {
	raw, ok := f.headers[n]
	if !ok {
		return json.RawMessage("null")
	}
	var h types.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		panic(err)
	}
	b, err := json.Marshal(&h)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *replayAdiri) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var reqs []struct {
		ID     int               `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &reqs); err != nil {
		http.Error(w, "not a batch", 400)
		return
	}
	f.batches.Add(1)
	if n := int64(len(reqs)); n > f.biggest.Load() {
		f.biggest.Store(n)
	}
	var out []map[string]any
	for _, q := range reqs {
		a := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		switch q.Method {
		case "tn_getCurrentEpoch":
			a["result"] = f.cur
		case "tn_epochRecord":
			var e int
			_ = json.Unmarshal(q.Params[0], &e)
			if e >= len(f.cf.Records) {
				a["error"] = map[string]any{"code": -32001, "message": "Not Found."}
			} else {
				a["result"] = f.record(e)
			}
		case "eth_getBlockByNumber":
			var hexN string
			_ = json.Unmarshal(q.Params[0], &hexN)
			var n uint64
			fmt.Sscanf(hexN, "0x%x", &n)
			a["result"] = f.block(n)
		default:
			a["error"] = map[string]any{"code": -32601, "message": "no such method"}
		}
		out = append(out, a)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// Adiri end to end through the production wiring: the prover Wire registered from the environment (public endpoint list, the
// rate-limited batch-splitting transport, the embedded pins) reads the recorded live answers of the published adiri3 vector over
// HTTP, builds the evidence, and the registry's Kind judges it as finalized for the recorded leg. Adiri is the one kind whose every
// provider answer is self-authenticating and replayable from the published sets; the L1-anchored kinds are covered by the DB wiring
// test and by their own builder tests (see the deploy notes).
func TestRuntimeAdiriWiredProverReplaysTheRecordedLiveAnswers(t *testing.T) {
	dir := filepath.Join("..", "adiri", "testdata", "finality_adiri3")
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Vectors []struct {
			Name string `json:"name"`
			Leg  struct {
				Chain     uint64 `json:"chain"`
				Number    uint64 `json:"number"`
				Hash      string `json:"hash"`
				HeaderHex string `json:"header_hex"`
			} `json:"leg"`
			Pins     json.RawMessage `json:"pins"`
			Evidence string          `json:"evidence"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	for _, v := range set.Vectors {
		if v.Name != "live-500749-epoch600" {
			continue
		}
		if string(v.Pins) != `"embedded"` {
			t.Fatalf("the recorded vector is judged under %s, not the embedded pins", v.Pins)
		}
		ev, err := os.ReadFile(filepath.Join(dir, "evidence", v.Evidence))
		if err != nil {
			t.Fatal(err)
		}
		c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		body, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
		if err != nil {
			t.Fatal(err)
		}
		cf, err := adiri.DecodeCFA1(body.CFA1, finality.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		fk := &replayAdiri{cf: cf, headers: map[uint64][]byte{}, cur: uint64(len(cf.Records))}
		fin := cf.Records[len(cf.Records)-1].FinalState.Number
		for i, h := range body.Spine {
			fk.headers[fin-uint64(i)] = h
		}
		srv := httptest.NewServer(fk)
		defer srv.Close()

		t.Setenv(EnvAdiriURLs, srv.URL+"/v2/"+secretToken)
		t.Setenv("TELCOIN_ADIRI_RPC_URL", "")
		t.Setenv(EnvRateRPS, "1000")
		t.Setenv(EnvRateBurst, "1000")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		logs := &syncBuf{}
		reg := finality.NewRegistry()
		w, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Logf: logs.Logf})
		if err != nil {
			t.Fatal(err)
		}
		if w.Disabled[finality.ChainAdiri] != nil {
			t.Fatalf("Adiri is configured yet switched off: %s", w.Disabled[finality.ChainAdiri].Error())
		}
		provers := reg.Provers(finality.ChainAdiri)
		if len(provers) != 1 {
			t.Fatalf("%d Adiri provers registered", len(provers))
		}
		hash, _ := hex.DecodeString(strings.TrimPrefix(v.Leg.Hash, "0x"))
		hdr, _ := hex.DecodeString(v.Leg.HeaderHex)
		leg := finality.BlockRef{Chain: v.Leg.Chain, Number: v.Leg.Number, Hash: [32]byte(hash), HeaderRLP: hdr}
		add, pend, err := provers[0].(interface {
			BuildLeg(context.Context, finality.BlockRef) (*finality.Addendum, *finality.PendingState, error)
		}).BuildLeg(context.Background(), leg)
		if err != nil || pend != nil || add == nil {
			t.Fatalf("build: %v %v", err, pend)
		}
		if string(add.Evidence) != string(ev) {
			t.Fatalf("the evidence built through the wiring (%d B) is not the recorded one (%d B)", len(add.Evidence), len(ev))
		}
		verdict, err := reg.JudgeAddendum(leg, *add, w.Pins)
		if err != nil || verdict.Level != finality.LevelFinalized || verdict.Kind != adiri.Name {
			t.Fatalf("the registry's Kind does not accept the built addendum: %v %+v", err, verdict)
		}
		// the transport bounded every JSON-RPC batch the prover sent (601 records and 61 headers need many requests)
		if got := fk.biggest.Load(); got > int64(cfg.MaxBatch) {
			t.Fatalf("a batch of %d requests reached the provider; the bound is %d", got, cfg.MaxBatch)
		}
		if fk.batches.Load() < 3 {
			t.Fatalf("only %d provider round trips: the build did not go through the wired transport", fk.batches.Load())
		}
		if strings.Contains(logs.String(), secretToken) {
			t.Fatalf("a credential reached the log:\n%s", logs.String())
		}
		return
	}
	t.Fatal("vector live-500749-epoch600 not found")
}
