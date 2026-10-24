// Copyright 2026 Certen Protocol

package adiri_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/mr-tron/base58"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// fakeAdiri is a JSON-RPC server answering what the builder asks (tn_getCurrentEpoch, tn_epochRecord, eth_getBlockByNumber,
// eth_getProof) from a decoded evidence file: the epoch records come from its CFA1, the headers from its spine or seal header.
type fakeAdiri struct {
	cf       *adiri.CFA1
	headers  map[uint64][]byte
	cur      uint64
	notFound map[uint64]bool // tn_epochRecord answers -32001
	proof    *adiri.Body     // eth_getProof is served from this linkKind 2 body (nil: refused)
	status   int             // non-zero: every request answers this HTTP status
	calls    atomic.Int64
	proofHit atomic.Int64
	secret   string
}

func (f *fakeAdiri) recordJSON(e int) json.RawMessage {
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

func (f *fakeAdiri) blockJSON(n uint64) json.RawMessage {
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

func (f *fakeAdiri) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if f.status != 0 {
		http.Error(w, "upstream says: bad key "+f.secret, f.status)
		return
	}
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
	var out []map[string]any
	for _, q := range reqs {
		a := map[string]any{"jsonrpc": "2.0", "id": q.ID}
		switch q.Method {
		case "tn_getCurrentEpoch":
			a["result"] = f.cur
		case "tn_epochRecord":
			var e int
			_ = json.Unmarshal(q.Params[0], &e)
			if f.notFound[uint64(e)] || e >= len(f.cf.Records) {
				a["error"] = map[string]any{"code": -32001, "message": "Not Found."}
			} else {
				a["result"] = f.recordJSON(e)
			}
		case "eth_getBlockByNumber":
			var hexN string
			_ = json.Unmarshal(q.Params[0], &hexN)
			var n uint64
			fmt.Sscanf(hexN, "0x%x", &n)
			a["result"] = f.blockJSON(n)
		case "eth_getProof":
			f.proofHit.Add(1)
			if f.proof == nil {
				a["error"] = map[string]any{"code": -32602, "message": "distance to target block exceeds maximum proof window"}
				break
			}
			var nodes []string
			for _, n := range f.proof.Nodes {
				nodes = append(nodes, "0x"+hex.EncodeToString(n))
			}
			a["result"] = map[string]any{"accountProof": nodes, "storageProof": []any{map[string]any{"proof": nodes}}}
		default:
			a["error"] = map[string]any{"code": -32601, "message": "no such method"}
		}
		out = append(out, a)
	}
	_ = json.NewEncoder(w).Encode(out)
}

func fakeFromVector(t *testing.T, name string) (*fakeAdiri, vVec, finality.BlockRef, *finality.Pins, []byte) {
	t.Helper()
	f := loadVectors(t)
	for _, v := range f.Vectors {
		if v.Name != name {
			continue
		}
		ev := evidenceOf(t, f, v)
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
		fk := &fakeAdiri{cf: cf, headers: map[uint64][]byte{}, cur: uint64(len(cf.Records)), notFound: map[uint64]bool{}}
		fin := cf.Records[len(cf.Records)-1].FinalState.Number
		if body.LinkKind == adiri.LinkSpine {
			for i, h := range body.Spine {
				fk.headers[fin-uint64(i)] = h
			}
		} else {
			fk.headers[fin] = body.FinalHeader
			fk.proof = body
		}
		return fk, v, legOf(t, v), pinsOf(t, v), ev
	}
	t.Fatalf("vector %s not found", name)
	return nil, vVec{}, finality.BlockRef{}, nil, nil
}

func newProver(pins *finality.Pins, urls ...string) *adiri.Prover {
	return &adiri.Prover{Endpoints: urls, Pins: pins, BatchSize: 200}
}

// The builder reads the epoch records and the headers from ONE endpoint, in batches, and the evidence it returns is the
// byte-identical evidence recorded from the live chain; it has already been through the verifier.
func TestBuilderLinkKind1ReproducesTheLiveEvidence(t *testing.T) {
	fk, _, leg, pins, want := fakeFromVector(t, "live-513643-epoch651")
	srv := httptest.NewServer(fk)
	defer srv.Close()
	p := newProver(pins, srv.URL)
	add, pend, err := p.BuildLeg(context.Background(), leg)
	if err != nil || pend != nil {
		t.Fatalf("%v %v", err, pend)
	}
	if string(add.Evidence) != string(want) || add.Kind != adiri.Name || add.Level != finality.LevelFinalized || add.Chain != finality.ChainAdiri {
		t.Fatalf("the built addendum is not the recorded evidence (%d vs %d B)", len(add.Evidence), len(want))
	}
	// 653 batched records need 4 round trips at 200 per batch, plus 1 for the current epoch and 1 for the 173 headers
	if c := fk.calls.Load(); c > 12 {
		t.Fatalf("%d HTTP calls: the reads are not batched", c)
	}
}

// Any one endpoint's answer is enough: the first endpoint fails, the second serves, and the first one's secret never reaches
// the result.
func TestBuilderNeedsNoAgreementAndRedactsEndpointErrors(t *testing.T) {
	fk, _, leg, pins, want := fakeFromVector(t, "live-500749-epoch600")
	good := httptest.NewServer(fk)
	defer good.Close()
	bad := httptest.NewServer(&fakeAdiri{status: 500, secret: "fakeprovidertoken-0123456789abcdef0123456789abcdef"})
	defer bad.Close()
	p := newProver(pins, bad.URL+"/v2/0123456789abcdef0123456789abcdef", good.URL)
	add, pend, err := p.BuildLeg(context.Background(), leg)
	if err != nil || pend != nil || string(add.Evidence) != string(want) {
		t.Fatalf("%v %v", err, pend)
	}
	// every endpoint failing is finality_source_unavailable with redacted notes
	p = newProver(pins, bad.URL+"/v2/0123456789abcdef0123456789abcdef?apikey=SECRETVALUE1234567890")
	_, _, err = p.BuildLeg(context.Background(), leg)
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != adiri.CodeSourceUnavailable {
		t.Fatalf("%v", err)
	}
	txt := string(s.Canonical())
	for _, secret := range []string{"0123456789abcdef0123456789abcdef", "SECRETVALUE1234567890", "fakeprovidertoken"} {
		if strings.Contains(txt, secret) {
			t.Fatalf("the state leaks %q: %s", secret, txt)
		}
	}
	if s.Fields["reason"] != adiri.SourceEpochRecord {
		t.Fatalf("%s", txt)
	}
}

// The pending states of the open and uncertified epochs.
func TestBuilderPendingStates(t *testing.T) {
	fk, _, leg, pins, _ := fakeFromVector(t, "live-513643-epoch651")
	srv := httptest.NewServer(fk)
	defer srv.Close()
	closeTS := func() time.Time {
		var h types.Header
		if err := rlp.DecodeBytes(fk.headers[513815], &h); err != nil {
			t.Fatal(err)
		}
		return time.Unix(int64(h.Time), 0).UTC()
	}()
	ctx := context.Background()

	// a block above the last sealed epoch's closing block: the epoch is open, eta = previous closing block + 21,600 s
	above := finality.BlockRef{Chain: finality.ChainAdiri, Number: 513816, Hash: [32]byte{1}}
	p := newProver(pins, srv.URL)
	p.Now = func() time.Time { return closeTS.Add(3600 * time.Second) }
	_, pend, err := p.BuildLeg(ctx, above)
	if err != nil || pend == nil {
		t.Fatalf("%v %v", err, pend)
	}
	st := pend.State()
	wantETA := closeTS.Add(adiri.EpochDuration)
	if st.Fields["reason"] != adiri.PendingEpochOpen || !pend.ETA.Equal(wantETA) || st.Fields["epoch"] != uint64(652) || pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelFinalized {
		t.Fatalf("%s eta=%v", st.Error(), pend.ETA)
	}
	// well past the eta + bound with the epoch still open: overdue
	p.Now = func() time.Time { return wantETA.Add(adiri.DefaultOverdueBound + time.Minute) }
	_, pend, err = p.BuildLeg(ctx, above)
	if err != nil || pend == nil || pend.Reason != adiri.PendingEpochOverdue || !pend.ETA.Equal(wantETA) {
		t.Fatalf("%v %v", err, pend)
	}
	// the last closed epoch has no certificate yet on any endpoint
	fk.notFound[651] = true
	_, pend, err = p.BuildLeg(ctx, leg)
	if err != nil || pend == nil || pend.Reason != adiri.PendingCertPending || pend.Judged["epoch"] != uint64(651) {
		t.Fatalf("%v %v", err, pend)
	}
	if pend.State().Fields["current_epoch"] != uint64(652) {
		t.Fatalf("%s", pend.State().Error())
	}
}

// A level the chain does not offer, and a level already held, are named states.
func TestBuilderTargetsAndTheLevelRule(t *testing.T) {
	fk, _, leg, pins, _ := fakeFromVector(t, "live-513643-epoch651")
	srv := httptest.NewServer(fk)
	defer srv.Close()
	p := newProver(pins, srv.URL)
	_, _, err := p.Build(context.Background(), nil, 0, finality.LevelL1Posted)
	if s, ok := finality.AsNamed(err); !ok || s.Code != finality.CodeNotApplicable || s.Fields["reason"] != finality.ReasonNoL1Settlment {
		t.Fatalf("%v", err)
	}
	_, _, err = p.Build(context.Background(), nil, finality.LevelSetOf(finality.LevelFinalized), finality.LevelFinalized)
	if s, ok := finality.AsNamed(err); !ok || s.Code != finality.CodeLevelAlreadyPresent {
		t.Fatalf("%v", err)
	}
	_ = leg
}

// linkKind 2 is chosen only when the builder holds eth_getProof at F; a refused window switches the encoding (linkKind 1), not
// the level.
func TestBuilderChoosesLinkKind2OnlyWithAProofAtF(t *testing.T) {
	fk, _, leg, pins, want := fakeFromVector(t, "syn-kind2")
	srv := httptest.NewServer(fk)
	defer srv.Close()
	p := newProver(pins, srv.URL)
	p.ProofEndpoints = []string{srv.URL}
	add, pend, err := p.BuildLeg(context.Background(), leg)
	if err != nil || pend != nil {
		t.Fatalf("%v %v", err, pend)
	}
	if string(add.Evidence) != string(want) {
		t.Fatal("the builder's linkKind 2 evidence differs from the recorded synthetic one")
	}
}

// A kind 1 build whose proof endpoint refuses the window keeps the level: it falls back to the spine.
func TestBuilderWindowRefusalSwitchesEncodingNotLevel(t *testing.T) {
	fk, _, leg, pins, want := fakeFromVector(t, "live-500980-epoch602")
	srv := httptest.NewServer(fk)
	defer srv.Close()
	p := newProver(pins, srv.URL)
	p.ProofEndpoints = []string{srv.URL} // serves no proof: "distance to target block exceeds maximum proof window"
	add, pend, err := p.BuildLeg(context.Background(), leg)
	if err != nil || pend != nil {
		t.Fatalf("%v %v", err, pend)
	}
	if string(add.Evidence) != string(want) {
		t.Fatal("the fallback evidence is not the linkKind 1 evidence")
	}
	if fk.proofHit.Load() == 0 {
		t.Fatal("the builder never asked the proof endpoint")
	}
}
