// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/build"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The recorded ethl1 v2 vector set (real Lodestar objects of 2026-10-20, period 1390) is the world the fake Lodestar replays.
const lctSet = "../ethl1/testdata/finality_ethl1_v2"

const (
	lctSecret  = "tok-0123456789abcdef"
	lctUserPw  = "u:pw@"
	lctFulu    = uint64(1378)
	lctLastPer = uint64(1390)
)

func lctRead(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(lctSet, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type lctCapture struct {
	BootRoot  string `json:"bootstrap_block_root"`
	SigSlot   uint64 `json:"final_signature_slot"`
	SigPeriod uint64 `json:"final_signature_period"`
	Exec      string `json:"final_finalized_exec_hash"`
}

func lctCap(t testing.TB) lctCapture {
	t.Helper()
	var c lctCapture
	if err := json.Unmarshal(lctRead(t, "raw/capture.json"), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// lctPins is the embedded pins file with eth_sepolia.anchors replaced by the v2 set's ledger (the way the arbfinal recorder does
// it); keep decides which entries keep their block_root.
func lctPins(t testing.TB, keepBlockRoot func(period uint64) bool) *finality.Pins {
	t.Helper()
	var led struct {
		Anchors []struct {
			Period        string  `json:"period"`
			CommitteeRoot string  `json:"committee_root"`
			BlockRoot     *string `json:"block_root"`
			WSPEpochs     string  `json:"wsp_epochs"`
		} `json:"anchors"`
	}
	if err := json.Unmarshal(lctRead(t, "pins/main.json"), &led); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	es := doc["eth_sepolia"].(map[string]any)
	var anchors []any
	for _, a := range led.Anchors {
		period, _ := strconv.ParseUint(a.Period, 10, 64)
		wsp, _ := strconv.ParseUint(a.WSPEpochs, 10, 64)
		sum := sha256.Sum256([]byte("lct-link-" + a.Period))
		m := map[string]any{"period": period, "committee_root": a.CommitteeRoot, "wsp_epochs": wsp,
			"link_sha256": hex.EncodeToString(sum[:]), "derived_by": []string{"runtime lc_test ledger of the ethl1 v2 vector set"}}
		if a.BlockRoot != nil && keepBlockRoot(period) {
			m["block_root"] = *a.BlockRoot
		}
		anchors = append(anchors, m)
	}
	es["anchors"] = anchors
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		t.Fatal(err)
	}
	p, err := finality.ParsePinsOverride(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// lctLodestar is a fake Lodestar beacon API replaying the recorded objects. Every request is counted and numbered in arrival
// order across all fakes sharing seq.
type lctLodestar struct {
	t         testing.TB
	bootstrap map[string][]byte // 0x<root> -> bytes
	seq       *atomic.Int64
	firstSeq  atomic.Int64
	status    int // non-zero: every request answers this status
	boots     atomic.Int64
	finals    atomic.Int64
	updates   atomic.Int64
	any       atomic.Int64
	secretLog atomic.Value // the last request line seen, to prove what reached the server
}

func lctNewLodestar(t testing.TB, seq *atomic.Int64) *lctLodestar {
	t.Helper()
	c := lctCap(t)
	return &lctLodestar{t: t, seq: seq, bootstrap: map[string][]byte{
		c.BootRoot: lctRead(t, "raw/bootstrap.ssz"),
		// the Fulu checkpoint of the ledger's first entry (period 1378)
		"0x5f71d7f650f9252b48749b5f062c0c234e01afd69f364ab600e2b6051494b20d": lctRead(t, "raw/bootstrap_fulu.ssz"),
	}}
}

func (f *lctLodestar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.any.Add(1)
	n := f.seq.Add(1)
	f.firstSeq.CompareAndSwap(0, n)
	f.secretLog.Store(r.URL.Path)
	if f.status != 0 {
		http.Error(w, "provider says tok-0123456789abcdef is wrong", f.status)
		return
	}
	p := r.URL.Path
	switch {
	case strings.Contains(p, "/eth/v1/beacon/light_client/finality_update"):
		f.finals.Add(1)
		_, _ = w.Write(lctRead(f.t, "raw/finality_update.ssz"))
	case strings.Contains(p, "/eth/v1/beacon/light_client/bootstrap/"):
		f.boots.Add(1)
		root := p[strings.LastIndex(p, "/")+1:]
		b, ok := f.bootstrap[root]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	case strings.Contains(p, "/eth/v1/beacon/light_client/updates"):
		f.updates.Add(1)
		start, _ := strconv.ParseUint(r.URL.Query().Get("start_period"), 10, 64)
		count, _ := strconv.ParseUint(r.URL.Query().Get("count"), 10, 64)
		var out []byte
		for per := start; per < start+count; per++ {
			u := lctRead(f.t, fmt.Sprintf("raw/updates/%d.ssz", per))
			var hdr [12]byte
			binary.LittleEndian.PutUint64(hdr[:8], uint64(4+len(u)))
			out = append(append(out, hdr[:]...), u...)
		}
		_, _ = w.Write(out)
	default:
		http.NotFound(w, r)
	}
}

type lctLogs struct {
	mu    sync.Mutex
	lines []string
}

func (l *lctLogs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *lctLogs) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func lctVerify(t testing.TB, pins *finality.Pins, lc ethl1.LC) ethl1.FinalizedHead {
	t.Helper()
	ep, err := l1adapt.PinsOf(pins)
	if err != nil {
		t.Fatal(err)
	}
	head, err := ethl1.VerifyFinalizedHead(ep, lc)
	if err != nil {
		t.Fatalf("ethl1 refused the LC the source assembled: %v", err)
	}
	return head
}

// (1) The LC the source assembles from a Lodestar replaying the recorded objects is accepted by ethl1 under the set's pins: the
// kind-2 anchor of the last ledger entry (period 1390) with no links, and the mixed-fork chain from the Fulu checkpoint (period
// 1378: Electra bootstrap, one Fulu link, eleven Gloas links) to the same finalized head.
func TestLCAssembledFromRecordedObjectsVerifiesUnderThePinnedLedger(t *testing.T) {
	c := lctCap(t)
	t.Run("anchor_is_the_last_block_root_entry_no_links", func(t *testing.T) {
		var seq atomic.Int64
		fake := lctNewLodestar(t, &seq)
		srv := httptest.NewServer(fake)
		defer srv.Close()
		pins := lctPins(t, func(uint64) bool { return true })
		src := &LC{URLs: []string{srv.URL}, Pins: pins}
		lc, err := src.LC(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if lc.AnchorKind != 2 || lc.AnchorPeriod != lctLastPer || len(lc.Links) != 0 || lc.AnchorBody.Layout != ethl1.LayoutGloas {
			t.Fatalf("anchor kind %d period %d links %d layout %v", lc.AnchorKind, lc.AnchorPeriod, len(lc.Links), lc.AnchorBody.Layout)
		}
		if got := "0x" + hex.EncodeToString(lc.AnchorRoot[:]); got != c.BootRoot {
			t.Fatalf("anchor root %s, ledger %s", got, c.BootRoot)
		}
		head := lctVerify(t, pins, lc)
		if got := "0x" + hex.EncodeToString(head.ExecHash[:]); got != c.Exec {
			t.Fatalf("exec hash %s, recorded %s", got, c.Exec)
		}
		if fake.updates.Load() != 0 {
			t.Fatal("no links are needed when the anchor period is the signature period, yet /updates was asked")
		}
	})
	t.Run("fulu_checkpoint_chain_to_gloas", func(t *testing.T) {
		var seq atomic.Int64
		fake := lctNewLodestar(t, &seq)
		srv := httptest.NewServer(fake)
		defer srv.Close()
		// only the first ledger entry keeps its block_root: the highest block_root entry is then period 1378
		pins := lctPins(t, func(p uint64) bool { return p == lctFulu })
		src := &LC{URLs: []string{srv.URL}, Pins: pins}
		lc, err := src.LC(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if lc.AnchorPeriod != lctFulu || lc.AnchorBody.Layout != ethl1.LayoutElectra || len(lc.Links) != int(c.SigPeriod-lctFulu) {
			t.Fatalf("anchor period %d layout %v links %d", lc.AnchorPeriod, lc.AnchorBody.Layout, len(lc.Links))
		}
		head := lctVerify(t, pins, lc)
		if got := "0x" + hex.EncodeToString(head.ExecHash[:]); got != c.Exec {
			t.Fatalf("exec hash %s, recorded %s", got, c.Exec)
		}
		if head.PeriodsCrossed != c.SigPeriod-lctFulu {
			t.Fatalf("periods crossed %d", head.PeriodsCrossed)
		}
	})
}

// (2) The endpoints are tried IN ORDER and an endpoint that answers ends the walk: the first (down) is asked before the second,
// the third is never asked; a credential in the configured URL reaches no log line and no error.
func TestLCEndpointOrderFailoverAndNoSecretLeak(t *testing.T) {
	var seq atomic.Int64
	down := lctNewLodestar(t, &seq)
	down.status = http.StatusInternalServerError
	good := lctNewLodestar(t, &seq)
	spare := lctNewLodestar(t, &seq)
	sd, sg, ss := httptest.NewServer(down), httptest.NewServer(good), httptest.NewServer(spare)
	defer sd.Close()
	defer sg.Close()
	defer ss.Close()
	secretURL := strings.Replace(sd.URL, "http://", "http://"+lctUserPw, 1) + "/v1/" + lctSecret
	var logs lctLogs
	src := &LC{URLs: []string{secretURL, sg.URL, ss.URL}, Pins: lctPins(t, func(uint64) bool { return true }), Logf: logs.logf}
	lc, err := src.LC(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lc.AnchorKind != 2 {
		t.Fatalf("anchor kind %d", lc.AnchorKind)
	}
	if down.any.Load() == 0 || good.any.Load() == 0 {
		t.Fatalf("down asked %d times, good %d", down.any.Load(), good.any.Load())
	}
	if down.firstSeq.Load() >= good.firstSeq.Load() {
		t.Fatalf("the failing first endpoint was asked at %d, the second at %d: order lost", down.firstSeq.Load(), good.firstSeq.Load())
	}
	if spare.any.Load() != 0 {
		t.Fatalf("the third endpoint was asked %d times although the second answered", spare.any.Load())
	}
	text := logs.text()
	if !strings.Contains(text, "light-client source") {
		t.Fatalf("a failed endpoint was not logged: %q", text)
	}
	for _, leak := range []string{lctSecret, "pw@", "u:pw"} {
		if strings.Contains(text, leak) {
			t.Fatalf("the log carries %q: %s", leak, text)
		}
	}
	if !strings.Contains(text, sd.URL) {
		t.Fatalf("the endpoint label (scheme and host) is missing from the log: %s", text)
	}
}

// (3) Every endpoint down: finality_lc_unavailable{endpoints} with scheme and host labels only, the redacted cause of each in
// Causes, and nothing of the URL's userinfo, path or token anywhere.
func TestLCAllEndpointsDownIsTheNamedStateWithHostLabelsOnly(t *testing.T) {
	var seq atomic.Int64
	down := lctNewLodestar(t, &seq)
	down.status = http.StatusBadGateway
	sd := httptest.NewServer(down)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close() // a refused connection: the transport error text carries the whole URL
	defer sd.Close()
	urls := []string{
		strings.Replace(sd.URL, "http://", "http://"+lctUserPw, 1) + "/v1/" + lctSecret + "?apikey=" + lctSecret,
		strings.Replace(closedURL, "http://", "http://"+lctUserPw, 1) + "/v1/" + lctSecret,
	}
	var logs lctLogs
	src := &LC{URLs: urls, Pins: lctPins(t, func(uint64) bool { return true }), Logf: logs.logf}
	_, err := src.LC(context.Background())
	if err == nil {
		t.Fatal("no endpoint answered, yet the source returned an LC")
	}
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != "finality_lc_unavailable" {
		t.Fatalf("not the named state: %v", err)
	}
	eps, _ := st.Fields["endpoints"].([]string)
	want := []string{sd.URL, closedURL}
	if len(eps) != 2 || eps[0] != want[0] || eps[1] != want[1] {
		t.Fatalf("endpoints %v, want scheme+host labels %v", eps, want)
	}
	var ue *LCUnavailableError
	if !errors.As(err, &ue) || len(ue.Causes) != 2 {
		t.Fatalf("causes: %+v", ue)
	}
	all := err.Error() + "\n" + strings.Join(ue.Causes, "\n") + "\n" + logs.text()
	for _, leak := range []string{lctSecret, "pw@", "u:pw", "apikey"} {
		if strings.Contains(all, leak) {
			t.Fatalf("the error, causes or log carry %q:\n%s", leak, all)
		}
	}
	if !strings.Contains(ue.Causes[0], "502") || !strings.HasPrefix(ue.Causes[0], want[0]+": ") || !strings.HasPrefix(ue.Causes[1], want[1]+": ") {
		t.Fatalf("each cause should name its endpoint label and its status: %v", ue.Causes)
	}
	if strings.Contains(all, "tok-0123456789abcdef is wrong") {
		t.Fatal("the provider's answer body was echoed")
	}
}

// (4) A ledger without a block_root anchor is finality_pin_unknown, and no endpoint is contacted for it.
func TestLCWithoutAKindTwoAnchorIsPinUnknownAndAsksNobody(t *testing.T) {
	cases := map[string]*finality.Pins{
		"no_block_root_in_any_entry": lctPins(t, func(uint64) bool { return false }),
		"nil_pins":                   nil,
	}
	for name, pins := range cases {
		t.Run(name, func(t *testing.T) {
			var seq atomic.Int64
			fake := lctNewLodestar(t, &seq)
			srv := httptest.NewServer(fake)
			defer srv.Close()
			var logs lctLogs
			_, err := (&LC{URLs: []string{srv.URL}, Pins: pins, Logf: logs.logf}).LC(context.Background())
			st, ok := finality.AsNamed(err)
			if !ok || st.Code != finality.CodePinUnknown {
				t.Fatalf("want finality_pin_unknown, got %v", err)
			}
			if st.Fields["chain"] != finality.ChainSepolia {
				t.Fatalf("chain field %v", st.Fields["chain"])
			}
			if fake.any.Load() != 0 {
				t.Fatalf("%d requests were made although the ledger fixes no anchor", fake.any.Load())
			}
		})
	}
}

// (5) The bootstrap is an immutable pinned object: two calls fetch it once; the finality update is fetched each call.
func TestLCBootstrapIsFetchedOnce(t *testing.T) {
	var seq atomic.Int64
	fake := lctNewLodestar(t, &seq)
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := &LC{URLs: []string{srv.URL}, Pins: lctPins(t, func(uint64) bool { return true })}
	for i := 0; i < 2; i++ {
		if _, err := src.LC(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if fake.boots.Load() != 1 || fake.finals.Load() != 2 {
		t.Fatalf("bootstrap fetched %d times, finality update %d (want 1 and 2)", fake.boots.Load(), fake.finals.Load())
	}
}

// A bootstrap that does not hash to the pinned checkpoint root is refused, is not cached, and the next endpoint is used.
func TestLCBootstrapNotHashingToThePinnedRootIsRefusedAndNotCached(t *testing.T) {
	var seq atomic.Int64
	bad := lctNewLodestar(t, &seq)
	c := lctCap(t)
	forged := append([]byte(nil), bad.bootstrap[c.BootRoot]...)
	forged[0] ^= 0x01 // slot of the beacon header: its root no longer equals the pinned root
	bad.bootstrap[c.BootRoot] = forged
	good := lctNewLodestar(t, &seq)
	sb, sg := httptest.NewServer(bad), httptest.NewServer(good)
	defer sb.Close()
	defer sg.Close()
	var logs lctLogs
	src := &LC{URLs: []string{sb.URL, sg.URL}, Pins: lctPins(t, func(uint64) bool { return true }), Logf: logs.logf}
	for i := 0; i < 2; i++ {
		if _, err := src.LC(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(logs.text(), "does not hash to the pinned checkpoint root") {
		t.Fatalf("the refusal is not logged: %s", logs.text())
	}
	if bad.boots.Load() != 1 || good.boots.Load() != 1 {
		t.Fatalf("first call: the forged bootstrap is refused once (%d) and the next endpoint's is fetched once (%d)", bad.boots.Load(), good.boots.Load())
	}
	// the cache holds the genuine bootstrap only: the second call is served the pinned object, whichever endpoint answers
	kept, ok := src.cached(lctRootOf(t, c.BootRoot))
	if !ok || !bytes.Equal(kept, lctRead(t, "raw/bootstrap.ssz")) {
		t.Fatal("the cache does not hold exactly the bootstrap that hashes to the pinned root")
	}
	if bad.boots.Load() != 1 {
		t.Fatalf("a cached bootstrap is not fetched again: the first endpoint was asked %d times", bad.boots.Load())
	}
}

func lctRootOf(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		t.Fatal(s)
	}
	return [32]byte(b)
}

// A cancelled context is the caller's cancellation, not "every endpoint is unavailable".
func TestLCCancelledContextIsNotTheUnavailableState(t *testing.T) {
	var seq atomic.Int64
	fake := lctNewLodestar(t, &seq)
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&LC{URLs: []string{srv.URL}, Pins: lctPins(t, func(uint64) bool { return true })}).LC(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, named := finality.AsNamed(err); named {
		t.Fatalf("a cancellation became a named state: %v", err)
	}
	if fake.any.Load() != 0 {
		t.Fatal("an endpoint was asked after cancellation")
	}
}

// The source is every LC source the kinds take, and FinalizedAt reports the slot the final update was signed at.
func TestLCSatisfiesTheKindsAndReportsTheObservedSlot(t *testing.T) {
	var _ baseposted.LCSource = (*LC)(nil)
	var _ basefinal.LCSource = LCWithSlot{}
	var _ build.LCSource = (*LC)(nil)
	var seq atomic.Int64
	fake := lctNewLodestar(t, &seq)
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := &LC{URLs: []string{srv.URL}, Pins: lctPins(t, func(uint64) bool { return true }),
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	lc, slot, err := (LCWithSlot{src}).Finalized(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := lctCap(t).SigSlot; slot != want {
		t.Fatalf("observed slot %d, the recorded signature slot is %d", slot, want)
	}
	if got, err := src.Finalized(context.Background()); err != nil || got.AnchorPeriod != lc.AnchorPeriod {
		t.Fatalf("Finalized: %v", err)
	}
	if finalUpdateSlot(nil) != 0 || finalUpdateSlot(make([]byte, 7)) != 0 {
		t.Fatal("a blob shorter than a slot has no slot")
	}
	if finalUpdateSlot([]byte{9, 9, 1, 0, 0, 0, 0, 0, 0, 0}) != 1 {
		t.Fatal("the slot is the last eight bytes, little-endian")
	}
}

func TestLCLabelsAreSchemeAndHostOnly(t *testing.T) {
	cases := map[string]string{
		"https://u:pw@host.example:8545/v1/tok-0123456789abcdef?apikey=k": "https://host.example:8545",
		"http://127.0.0.1:9596": "http://127.0.0.1:9596",
		"not a url":             "endpoint#3",
		"":                      "endpoint#3",
	}
	for in, want := range cases {
		if got := lcLabel(in, 3); got != want {
			t.Errorf("lcLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLCBootstrapCacheIsBounded(t *testing.T) {
	l := &LC{}
	for i := 0; i < lcBootstrapCacheMax+3; i++ {
		var r [32]byte
		r[0] = byte(i + 1)
		l.remember(r, []byte{byte(i)})
		l.remember(r, []byte{byte(i)}) // a second remember of the same root changes nothing
	}
	if len(l.boots) != lcBootstrapCacheMax || len(l.order) != lcBootstrapCacheMax {
		t.Fatalf("cache holds %d/%d entries, bound %d", len(l.boots), len(l.order), lcBootstrapCacheMax)
	}
	var oldest, newest [32]byte
	oldest[0], newest[0] = 1, byte(lcBootstrapCacheMax+3)
	if _, ok := l.cached(oldest); ok {
		t.Fatal("the oldest entry should have been evicted")
	}
	if _, ok := l.cached(newest); !ok {
		t.Fatal("the newest entry is missing")
	}
}

func TestLCBootstrapLayoutByLength(t *testing.T) {
	gloas := make([]byte, ethl1.LightClientBootstrapSize)
	if lay, hdr, ok := bootstrapLayout(gloas); !ok || lay != ethl1.LayoutGloas || len(hdr) != ethl1.BeaconBlockHeaderSize {
		t.Fatalf("gloas: %v %d %v", lay, len(hdr), ok)
	}
	electra := make([]byte, 24820+200)
	binary.LittleEndian.PutUint32(electra, 24820)
	if lay, hdr, ok := bootstrapLayout(electra); !ok || lay != ethl1.LayoutElectra || len(hdr) != ethl1.BeaconBlockHeaderSize {
		t.Fatalf("electra: %v %d %v", lay, len(hdr), ok)
	}
	for name, b := range map[string][]byte{"empty": nil, "three bytes": {1, 2, 3}, "offset below four": {2, 0, 0, 0, 0, 0}, "offset past the end": {0xff, 0, 0, 0, 1, 2, 3, 4}} {
		if _, _, ok := bootstrapLayout(b); ok {
			t.Errorf("%s accepted as a bootstrap", name)
		}
	}
}

// (4b) The embedded ledger carries the Sepolia root pin (period 1378 with its block_root): the source anchors there and asks the
// first endpoint for exactly that bootstrap, by that block root.
func TestLCEmbeddedRootPinIsTheAnchorOfTheFirstRequest(t *testing.T) {
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	e, err := embedded.Sepolia()
	if err != nil || len(e.Anchors) == 0 {
		t.Fatalf("the embedded ledger has no anchor: %v", err)
	}
	last := e.Anchors[len(e.Anchors)-1]
	if last.BlockRoot == "" {
		t.Fatalf("the embedded ledger's last entry has no block_root: %+v", last)
	}
	var first atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.CompareAndSwap(nil, r.URL.Path)
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer srv.Close()
	_, err = (&LC{URLs: []string{srv.URL}, Pins: embedded}).LC(context.Background())
	if st, ok := finality.AsNamed(err); !ok || st.Code != "finality_lc_unavailable" {
		t.Fatalf("a refusing endpoint must be finality_lc_unavailable, got %v", err)
	}
	if got, _ := first.Load().(string); got != "/eth/v1/beacon/light_client/bootstrap/"+last.BlockRoot {
		t.Fatalf("the first request was %q, want the bootstrap of the ledger's root pin %s", got, last.BlockRoot)
	}
}
