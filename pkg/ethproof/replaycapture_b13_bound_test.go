// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10-B13: the producer never emits S6 evidence its own verifier refuses. Honest evidence is under 1 MiB by
// construction except for the free text a provider serves (an HTML error page, a hostile body), and a provider's padding of
// a proof with nodes the walk does not use; both are bounded here, and a last guard replaces whatever is still longer than
// the 4 MiB the format allows by a named state.

var truncatedSuffix = regexp.MustCompile(`…\(truncated ([0-9]+) bytes\)$`)

// hostileBody is the text of a provider's 10 MB error page: HTML that echoes the request URL, with its key, near the start.
func hostileBody() string {
	return `<html><body>invalid key for https://eth-sepolia.g.alchemy.com/v2/` + leakKey + ` ` + strings.Repeat("<p>é€😀 error</p>", 10<<20/len("<p>é€😀 error</p>")+1)
}

func TestB13_BoundProviderTextCutsAfterRedactionOnAUTF8Boundary(t *testing.T) {
	max := ethproof.MaxReplayTextBytes
	if max != 1024 {
		t.Fatalf("the bound is %d, not 1024", max)
	}
	if got := ethproof.BoundProviderText(""); got != "" {
		t.Fatalf("empty text became %q", got)
	}
	short := "no provider could prove the slot: " + strings.Repeat("é", 100)
	if got := ethproof.BoundProviderText(short); got != short {
		t.Fatalf("a text within the bound was changed: %q", got)
	}
	exact := strings.Repeat("a", max)
	if got := ethproof.BoundProviderText(exact); got != exact {
		t.Fatalf("a text of exactly %d bytes was changed", max)
	}
	// Every rune width, at every offset of the cut: the result is valid UTF-8, within the bound, and says how much it dropped.
	for _, r := range []string{"a", "é", "€", "😀"} {
		for pad := 0; pad < 5; pad++ {
			in := strings.Repeat("x", pad) + strings.Repeat(r, 3000)
			out := ethproof.BoundProviderText(in)
			if len(out) > max || len(out) < max-len("…(truncated 99999 bytes)")-utf8.UTFMax {
				t.Fatalf("rune %q pad %d: %d bytes, want just under %d", r, pad, len(out), max)
			}
			if !utf8.ValidString(out) {
				t.Fatalf("rune %q pad %d: the cut is inside a character: %q", r, pad, out[len(out)-40:])
			}
			m := truncatedSuffix.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("rune %q pad %d: no visible suffix: %q", r, pad, out[len(out)-40:])
			}
			dropped, _ := strconv.Atoi(m[1])
			kept := out[:len(out)-len(m[0])]
			if !strings.HasPrefix(in, kept) || dropped != len(in)-len(kept) {
				t.Fatalf("rune %q pad %d: kept %d bytes and says %d dropped of %d", r, pad, len(kept), dropped, len(in))
			}
		}
	}
	if again := ethproof.BoundProviderText(ethproof.BoundProviderText(strings.Repeat("é", 5000))); again != ethproof.BoundProviderText(strings.Repeat("é", 5000)) {
		t.Fatal("bounding is not idempotent")
	}
	// Redaction first: a key whose URL straddles the cut is never kept, whatever the padding before it.
	for pad := 900; pad < 1100; pad++ {
		in := strings.Repeat("x", pad) + " Post \"https://eth-sepolia.g.alchemy.com/v2/" + leakKey + "\": dial tcp: i/o timeout " + strings.Repeat("y", 3000)
		out := ethproof.BoundProviderText(in)
		if strings.Contains(out, leakKey) || strings.Contains(out, "SECRET") || len(out) > max || !utf8.ValidString(out) {
			t.Fatalf("pad %d: the cut kept part of the key or broke the bound: %q", pad, out[len(out)-60:])
		}
	}
	// The redacted text is cut, not the raw one: the host of a URL placed late in 3 KB of text is named after redaction
	// shortens the URL (the key path is gone), so it falls inside the bound.
	in := strings.Repeat("z", 900) + " https://rpc.late.example/" + strings.Repeat("k", 2000)
	if out := ethproof.BoundProviderText(in); !strings.Contains(out, "rpc.late.example/<redacted>") {
		t.Fatalf("the host of a late URL is not named: %q", out)
	}
	// A 10 MB text costs a bounded amount.
	start := time.Now()
	out := ethproof.BoundProviderText(hostileBody())
	if len(out) > max || strings.Contains(out, leakKey) || !strings.Contains(out, "eth-sepolia.g.alchemy.com") || !utf8.ValidString(out) {
		t.Fatalf("the 10 MB body became %d bytes: %q", len(out), out[:200])
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("bounding a 10 MB text took %s", d)
	}
}

// hostileErrors are a provider's 10 MB answers as the transports surface them.
func hostileErrors() []leakError {
	body := hostileBody()
	return []leakError{
		{"an rpc.HTTPError with a 10 MB body", rpc.HTTPError{StatusCode: 502, Status: "502 Bad Gateway", Body: []byte(body)}, "eth-sepolia.g.alchemy.com"},
		{"a plain error with a 10 MB message", fmt.Errorf("provider failed: %s", body), "eth-sepolia.g.alchemy.com"},
	}
}

// maxFreeText is the longest free-text field of the evidence and the number of providers it lists.
func maxFreeText(ev *ethproof.ReplayGuardEvidence) (longest, providers int) {
	see := func(s string) {
		if len(s) > longest {
			longest = len(s)
		}
	}
	list := func(ps []ethproof.ReplayProviderFailure) {
		if len(ps) > providers {
			providers = len(ps)
		}
		for _, p := range ps {
			see(p.Host)
			see(p.Error)
		}
	}
	if p := ev.Proof; p != nil && p.BeforeUnavailable != nil {
		see(p.BeforeUnavailable.Reason)
		list(p.BeforeUnavailable.Providers)
	}
	if st := ev.State; st != nil {
		see(st.Detail)
		see(st.Reason)
		list(st.Providers)
	}
	return
}

// assertEmittable is what a reader of the stored evidence needs: it is smaller than the format's bound, its free text is
// bounded, no key is in it, the host is named, and it decodes strictly (not evidence_too_large) and verifies against the
// settlement it is about (as a proof or as the named state it is).
func assertEmittable(t *testing.T, f *fakeChain, ev *ethproof.ReplayGuardEvidence, host string, verify bool) {
	t.Helper()
	if ev == nil {
		t.Fatal("no evidence")
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the evidence is %d bytes, more than the %d the format allows", len(raw), ethproof.MaxReplayEvidenceBytes)
	}
	if len(raw) > 256<<10 {
		t.Fatalf("a bounded named state or one small proof is %d bytes", len(raw))
	}
	if longest, _ := maxFreeText(ev); longest > ethproof.MaxReplayTextBytes {
		t.Fatalf("a free-text field is %d bytes, more than the bound %d", longest, ethproof.MaxReplayTextBytes)
	}
	if strings.Contains(string(raw), leakKey) {
		t.Fatal("the key of the provider URL is in the evidence")
	}
	if !strings.Contains(string(raw), host) {
		t.Fatalf("the provider's host %s is no longer named: %s", host, raw)
	}
	if _, derr := ethproof.DecodeReplayGuardEvidence(raw); derr != nil {
		t.Fatalf("the evidence is refused by its own strict reader: %v", derr)
	}
	if verify {
		if _, verr := ev.Verify(f.w.settlement); verr != nil {
			t.Fatalf("the evidence does not verify against its settlement: %v", verr)
		}
	}
}

// A provider that answers 10 MB at every phase of the capture - the receipt, the transaction, the headers, the After proof,
// the parent header and the Before proof - leaves evidence the verifier reads: bounded, verifying, the host named, no key.
func TestB13_ATenMegabyteProviderAnswerAtEveryPhaseLeavesVerifyingEvidence(t *testing.T) {
	for _, ph := range leakPhases {
		for _, he := range hostileErrors() {
			t.Run(ph.name+"/"+he.name, func(t *testing.T) {
				src := ph.make(t, he.err)
				sink := &logSink{}
				cfg := cfgFor(src.fakeChain)
				cfg.Source, cfg.Budget, cfg.Poll, cfg.Logf = src, 80*time.Millisecond, 5*time.Millisecond, sink.logf
				// The capture itself.
				direct := ethproof.CaptureReplayGuard(context.Background(), cfg, src.w.tx.Hash())
				assertEmittable(t, src.fakeChain, direct, he.host, false)
				// Through the store, as the observers use it.
				store := ethproof.NewReplayGuardStore(16)
				cp := ethproof.NewReplayGuardCapturer(cfg, store)
				cp.Begin(src.w.tx.Hash())
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if _, _, err := store.Wait(ctx, testChainID, src.w.tx.Hash()); err != nil {
					t.Fatal(err)
				}
				stored, _, _ := store.Get(testChainID, src.w.tx.Hash())
				assertEmittable(t, src.fakeChain, stored, he.host, false)
				assertEmittable(t, src.fakeChain, cp.Resolve(src.w.settlement), he.host, true)
				cp.Bind(src.w.settlement)
				assertEmittable(t, src.fakeChain, waitStored(t, store, testChainID, src.w.tx.Hash(), true), he.host, true)
				if all := sink.all(); strings.Contains(all, leakKey) || len(all) > 1<<20 {
					t.Fatalf("the log holds the key or %d bytes of provider text", len(all))
				}
			})
		}
	}
}

// The number of providers a state lists is bounded: the first 64 and one last entry naming how many more there are.
func TestB13_TheProvidersListedAreBounded(t *testing.T) {
	last := func(ps []ethproof.ReplayProviderFailure) ethproof.ReplayProviderFailure { return ps[len(ps)-1] }
	for _, n := range []int{ethproof.MaxReplayProviderFailures, ethproof.MaxReplayProviderFailures + 1, 100} {
		t.Run(fmt.Sprintf("%d providers serve no state", n), func(t *testing.T) {
			f := newChain(t, worldOpts{after: 0}, testN)
			for i := 0; i < n; i++ {
				f.add(fmt.Sprintf("p%03d.example", i), 0, 0)
			}
			cfg := cfgFor(f)
			cfg.Budget, cfg.Poll = 100*time.Millisecond, 5*time.Millisecond
			ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
			if ev == nil || ev.State == nil || ev.State.Reason != ethproof.ReasonStateUnavailable {
				t.Fatalf("not the named state: %+v", ev)
			}
			ps := ev.State.Providers
			if n == ethproof.MaxReplayProviderFailures {
				if len(ps) != n || ps[0].Host != "p000.example" || last(ps).Host != "p063.example" {
					t.Fatalf("%d providers within the bound are listed as %d", n, len(ps))
				}
				return
			}
			if len(ps) != ethproof.MaxReplayProviderFailures+1 || ps[0].Host != "p000.example" || ps[63].Host != "p063.example" ||
				last(ps).Host != fmt.Sprintf("(%d more providers)", n-ethproof.MaxReplayProviderFailures) {
				t.Fatalf("%d providers are listed as %d, the last %+v", n, len(ps), last(ps))
			}
		})
	}
	t.Run("the Before disclosure", func(t *testing.T) {
		f := newChain(t, worldOpts{after: 0}, testN)
		for i := 0; i < 100; i++ {
			f.add(fmt.Sprintf("h%03d.example", i), testN, testN) // head-only: proves After, never the parent
		}
		cfg := cfgFor(f)
		cfg.Budget, cfg.Poll = 100*time.Millisecond, 5*time.Millisecond
		ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
		if ev == nil || ev.Proof == nil || ev.Proof.BeforeUnavailable == nil {
			t.Fatalf("not a proof disclosing the Before: %+v", ev)
		}
		ps := ev.Proof.BeforeUnavailable.Providers
		if len(ps) != 65 || ps[63].Host != "h063.example" || ps[64].Host != "(36 more providers)" {
			t.Fatalf("100 providers are listed as %d, the last %+v", len(ps), ps[len(ps)-1])
		}
		if _, err := ev.Verify(f.w.settlement); err != nil {
			t.Fatal(err)
		}
	})
}

// paddedEvidence is a proving capture whose After storage proof carries an extra node of padding bytes: the verifier uses the
// nodes that hash into the path and ignores the rest, so the padded evidence still verifies.
func paddedEvidence(t *testing.T, f *fakeChain, padding int) *ethproof.ReplayGuardEvidence {
	t.Helper()
	cfg := cfgFor(f)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
	if ev == nil || ev.Proof == nil {
		t.Fatalf("no proof to pad: %+v", ev)
	}
	ev.Proof.After.StorageProof = append(ev.Proof.After.StorageProof, hexutil.Bytes(make([]byte, padding)))
	return ev
}

// The guard, directly: evidence longer than the format allows is replaced by s6_replay_unproven{state_unavailable} built
// from what the evidence itself states, with the true reason; evidence of exactly the bound is kept; the argument is not
// changed.
func TestB13_TheGuardReplacesOversizeEvidenceByANamedState(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("head-only.example", testN, testN)
	tx := f.w.tx.Hash()

	honest := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), tx)
	if got := ethproof.BoundReplayEvidence(honest, testChainID, tx); got != honest {
		t.Fatal("honest evidence was replaced")
	}

	over := paddedEvidence(t, f, 3<<20) // 3 MiB of node, 6 MiB of hex
	raw, _ := json.Marshal(over)
	if len(raw) <= ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the test evidence is only %d bytes", len(raw))
	}
	if _, err := over.Verify(f.w.settlement); err != nil {
		t.Fatalf("the padded proof must still verify for this to be the attack it is: %v", err)
	}
	got := ethproof.BoundReplayEvidence(over, testChainID, tx)
	if got == over || got.Proof != nil || got.State == nil {
		t.Fatalf("oversize evidence was not replaced by a named state: %+v", got)
	}
	st := got.State
	want := fmt.Sprintf("the evidence would be %d bytes, more than the %d the format allows", len(raw), ethproof.MaxReplayEvidenceBytes)
	if st.State != ethproof.ReplayUnproven || st.Reason != ethproof.ReasonStateUnavailable || !strings.Contains(st.Detail, want) ||
		st.ChainID != testChainID || st.TxHash != tx || st.BlockNumber != testN || st.BlockHash != f.w.headerN.Hash() || st.Contract != f.w.contract {
		t.Fatalf("the named state is %+v, want the %d-byte reason, chain, tx, block %d and contract of the proof", st, len(raw), testN)
	}
	if over.Proof == nil || len(over.Proof.After.StorageProof) < 2 {
		t.Fatal("the guard changed the evidence it was given")
	}
	assertEmittable(t, f, got, "", true)

	// A named state with 5 MB of detail, and one with 200000 providers, are replaced too.
	huge := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven,
		Reason: ethproof.ReasonStateUnavailable, ChainID: testChainID, TxHash: tx, BlockNumber: testN, BlockHash: f.w.headerN.Hash(), Contract: f.w.contract,
		Detail: strings.Repeat("d", 5<<20)}}
	many := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven,
		Reason: ethproof.ReasonStateUnavailable, ChainID: testChainID, TxHash: tx, BlockNumber: testN, BlockHash: f.w.headerN.Hash(), Contract: f.w.contract,
		Providers: make([]ethproof.ReplayProviderFailure, 200000)}}
	for name, ev := range map[string]*ethproof.ReplayGuardEvidence{"detail": huge, "providers": many} {
		got := ethproof.BoundReplayEvidence(ev, testChainID, tx)
		if got == ev || got.State == nil || got.State.Reason != ethproof.ReasonStateUnavailable || !strings.Contains(got.State.Detail, "more than the 4194304 the format allows") {
			t.Fatalf("%s: not replaced: %+v", name, got)
		}
		if _, err := got.Verify(f.w.settlement); err != nil {
			t.Fatalf("%s: the replacement does not verify: %v", name, err)
		}
	}

	// The boundary is exact: 4194304 bytes are kept, 4194305 are replaced.
	exact := func(extra int) *ethproof.ReplayGuardEvidence {
		ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven,
			Reason: ethproof.ReasonStateUnavailable, ChainID: testChainID, TxHash: tx, BlockNumber: testN, BlockHash: f.w.headerN.Hash(), Contract: f.w.contract, Detail: "x"}}
		b, _ := json.Marshal(ev)
		ev.State.Detail = strings.Repeat("x", 1+ethproof.MaxReplayEvidenceBytes-len(b)+extra)
		return ev
	}
	atBound, pastBound := exact(0), exact(1)
	if b, _ := json.Marshal(atBound); len(b) != ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the boundary evidence is %d bytes", len(b))
	}
	if got := ethproof.BoundReplayEvidence(atBound, testChainID, tx); got != atBound {
		t.Fatal("evidence of exactly the bound was replaced")
	}
	if b, _ := json.Marshal(pastBound); len(b) != ethproof.MaxReplayEvidenceBytes+1 {
		t.Fatalf("the evidence one past the bound is %d bytes", len(b))
	}
	if got := ethproof.BoundReplayEvidence(pastBound, testChainID, tx); got == pastBound || got.State == nil || !strings.Contains(got.State.Detail, "4194305 bytes") {
		t.Fatalf("evidence one byte past the bound was not replaced: %+v", got)
	}
	if got := ethproof.BoundReplayEvidence(nil, testChainID, tx); got != nil {
		t.Fatal("nil evidence (no S6 claim) became something")
	}
}

// The store never holds, and a capturer never returns, oversize evidence: a provider that pads its eth_getProof answer
// with 5 MB of nodes the walk ignores gets a proof that verifies and is too long for the format, which reaches a reader
// as the named state saying so.
type paddingProvider struct {
	*fakeProvider
	padding int
}

func (p paddingProvider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	raw, err := p.fakeProvider.GetProof(ctx, account, keys, block)
	if err != nil {
		return nil, err
	}
	var ans map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, err
	}
	var sto []map[string]interface{}
	if err := json.Unmarshal(ans["storageProof"], &sto); err != nil {
		return nil, err
	}
	nodes, _ := sto[0]["proof"].([]interface{})
	sto[0]["proof"] = append(nodes, hexutil.Encode(make([]byte, p.padding)))
	ans["storageProof"], _ = json.Marshal(sto)
	return json.Marshal(ans)
}

type paddedSource struct {
	*fakeChain
	padding int
}

func (s paddedSource) StateProviders() []ethproof.ReplayStateProvider {
	var out []ethproof.ReplayStateProvider
	for _, p := range s.fakeChain.providers {
		out = append(out, paddingProvider{p, s.padding})
	}
	return out
}

func TestB13_APaddedProofNeverReachesAReaderAsEvidenceItRefuses(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("padder.example", testN, testN)
	src := paddedSource{f, 3 << 20}
	cfg := cfgFor(f)
	cfg.Source = src
	tx := f.w.tx.Hash()
	check := func(what string, ev *ethproof.ReplayGuardEvidence, verify bool) {
		t.Helper()
		if ev == nil || ev.State == nil || ev.Proof != nil {
			t.Fatalf("%s: not a named state: %+v", what, ev)
		}
		if ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonStateUnavailable || !strings.Contains(ev.State.Detail, "more than the 4194304 the format allows") {
			t.Fatalf("%s: the state is %s{%s}: %s", what, ev.State.State, ev.State.Reason, ev.State.Detail)
		}
		raw, _ := json.Marshal(ev)
		if len(raw) > ethproof.MaxReplayEvidenceBytes {
			t.Fatalf("%s: %d bytes", what, len(raw))
		}
		if verify {
			if _, err := ev.Verify(f.w.settlement); err != nil {
				t.Fatalf("%s: does not verify: %v", what, err)
			}
		}
	}
	check("the capture", ethproof.CaptureReplayGuard(context.Background(), cfg, tx), false)

	store := ethproof.NewReplayGuardStore(16)
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	cp.Begin(tx)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := store.Wait(ctx, testChainID, tx); err != nil {
		t.Fatal(err)
	}
	stored, _, _ := store.Get(testChainID, tx)
	check("the store after the capture", stored, false)
	check("Resolve", cp.Resolve(f.w.settlement), true)
	cp.Bind(f.w.settlement)
	check("the store after Bind", waitStored(t, store, testChainID, tx, true), true)

	// Evidence put directly into the store (a Put by any caller) is held to the same rule.
	direct := ethproof.NewReplayGuardStore(16)
	direct.Put(testChainID, tx, paddedEvidence(t, f, 3<<20), true)
	got, bound, ok := direct.Get(testChainID, tx)
	if !ok || !bound {
		t.Fatal("nothing stored")
	}
	check("Put", got, true)
	if direct.Bytes() > 64<<10 {
		t.Fatalf("the store was charged %d bytes for a named state", direct.Bytes())
	}
}
