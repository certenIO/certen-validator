// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/ethproof"
)

var chains = []uint64{11155111, 84532, 421614, 2017}

// capturedContainer runs E2 against the fake and assembles the whole container with the attestation stand-in.
func capturedContainer(t *testing.T, fc *fakeChain, res *capture.SettleResult) []byte {
	t.Helper()
	_, raw, err := capture.Assemble(capture.Parts{Chain: fc.w.Spec.Chain, Leg: res.Block, Facts: fc.facts(t), Settle: res, Attest: fc.attestPart(t)})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	return raw
}

func TestE2HonestCaptureEqualsTheWorldContainerByteForByte(t *testing.T) {
	for _, chain := range chains {
		for _, variant := range []string{"h0", "hops", "s6silent"} {
			t.Run(fmt.Sprintf("%d/%s", chain, variant), func(t *testing.T) {
				fc := newFakeChain(t, chain, variant)
				src, ps := fc.source(honest)
				res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
				if err != nil || res.Stated != nil {
					t.Fatalf("CaptureSettle: %v %+v", err, res)
				}
				if got := capturedContainer(t, fc, res); !bytes.Equal(got, fc.w.ContainerBytes) {
					t.Fatalf("assembled container (%d B) differs from the world's (%d B)", len(got), len(fc.w.ContainerBytes))
				}
				// one eth_getProof per contract and station: the provider was asked for each address once with all its slots
				if ps[0].count() > 40 {
					t.Fatalf("%d provider calls", ps[0].count())
				}
				if len(res.Codes) != 5 {
					t.Fatalf("%d codes carried, want anchor, verifier, generated, factory, account", len(res.Codes))
				}
			})
		}
	}
}

// enrich fills the settlement station with unrelated storage, so that a read of a wrong or missing slot visits other trie nodes than the
// plan reads (in the minimal world several slots share the one root node and a dropped read is invisible).
func enrich(sp *world.Spec) {
	st := sp.Stations[world.StationSettle]
	put := func(addr string, slot, val common.Hash) {
		for k, a := range st.Accounts {
			if strings.EqualFold(k, addr) {
				if a.Storage == nil {
					a.Storage = map[string]string{}
				}
				a.Storage[slot.Hex()] = val.Hex()
				return
			}
		}
		st.Accounts[addr] = &world.AcctSpec{Storage: map[string]string{slot.Hex(): val.Hex()}}
	}
	one := common.BigToHash(big.NewInt(1))
	for i := byte(1); i <= 7; i++ {
		noise := common.BytesToHash(bytes.Repeat([]byte{i * 17}, 32))
		put(sp.Roles.History, ci.SlotIndex(uint64(i)*911), noise)
		put(sp.Roles.Factory, ci.MappingSlotAt(ci.KeyAddress(common.BytesToAddress(noise[:20])), 2), one)
		put(sp.Roles.Factory, ci.MappingSlotAt(ci.KeyBytes32(noise), 3), noise)
		put(sp.Roles.Account, ci.MappingSlotAt(ci.KeyBytes4([4]byte{i, i, i, i}), 8), noise)
		put(sp.Roles.Account, ci.PageSlot(10, noise, uint64(i)), one)
		put(sp.Roles.Anchor, ci.MappingSlotAt(ci.KeyBytes32(noise), 4), one)
		put(sp.Roles.Anchor, ci.MappingSlotAt(ci.KeyBytes32(noise), 1), noise)
	}
	book := common.HexToHash(sp.Settlement.AuthorityBook)
	put(sp.Roles.Account, ci.PageSlot(10, book, sp.Settlement.AuthorityPage), one)
	put(sp.Roles.Account, ci.PageSlot(9, book, sp.Settlement.AuthorityPage), common.BigToHash(big.NewInt(3)))
	for _, l := range sp.Settlement.Legs {
		if d := common.FromHex(l.Data); len(d) >= 4 {
			put(sp.Roles.Account, ci.MappingSlotAt(ci.KeyBytes4([4]byte(d[:4])), 8), common.BigToHash(big.NewInt(2)))
		}
	}
}

func TestE2RichStorageEveryReadIsInTheEvidence(t *testing.T) {
	for _, chain := range chains {
		for _, variant := range []string{"h0", "hops"} {
			t.Run(fmt.Sprintf("%d/%s", chain, variant), func(t *testing.T) {
				fc := newFakeChainWith(t, chain, variant, enrich)
				src, _ := fc.source(honest)
				res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
				if err != nil || res.Stated != nil {
					t.Fatalf("CaptureSettle: %v %+v", err, res)
				}
				if got := capturedContainer(t, fc, res); !bytes.Equal(got, fc.w.ContainerBytes) {
					t.Fatalf("assembled container (%d B) differs from the world's (%d B)", len(got), len(fc.w.ContainerBytes))
				}
			})
		}
	}
}

func TestE2CaptureIsDeterministicAcrossRunsAndSevenConcurrentValidators(t *testing.T) {
	fc := newFakeChain(t, 11155111, "hops")
	var first []byte
	for i := 0; i < 2; i++ {
		src, _ := fc.source(honest)
		res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := capture.EncodeSettle(res)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = raw
		} else if !bytes.Equal(first, raw) {
			t.Fatal("two runs wrote different rows")
		}
	}
	st := capture.NewMemStore()
	var wg sync.WaitGroup
	errs := make([]error, 7)
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// each validator has its own providers (different order and hosts)
			modes := []hostile{honest, pruned, honest}
			src, _ := fc.source(modes[i%3:]...)
			res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
			if err == nil {
				err = capture.SaveSettle(context.Background(), st, res)
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("validator %d: %v", i, err)
		}
	}
	keys, _ := st.ListByAnchor(context.Background(), 11155111, fc.facts(t).AnchorID)
	if len(keys) != 1 || keys[0].Item != capture.ItemSettle {
		t.Fatalf("seven identical captures left %v", keys)
	}
	raw, _, _ := st.Get(context.Background(), keys[0])
	if !bytes.Equal(raw, first) {
		t.Fatal("the stored row is not the deterministic capture")
	}
	back, err := capture.LoadSettle(context.Background(), st, 11155111, keys[0].AnchorID, keys[0].BlockHash)
	if err != nil || back == nil || back.Stated != nil || len(back.Nodes) == 0 {
		t.Fatalf("LoadSettle = %+v, %v", back, err)
	}
	if again, _ := capture.EncodeSettle(back); !bytes.Equal(again, first) {
		t.Fatal("encode(decode(row)) != row")
	}
}

func TestE2ProviderLiesAreRefusedAndNothingUnverifiedIsKept(t *testing.T) {
	lies := map[string]hostile{"wrong code bytes": lieCode, "proof of another slot": lieSlot, "wrong value text": lieValue, "header mismatch (another block's state)": lieBlock,
		"answer above the size bound": hugeReply}
	for name, mode := range lies {
		t.Run(name, func(t *testing.T) {
			fc := newFakeChain(t, 11155111, "h0")
			// the liar first, an honest provider second: the capture equals the honest one and keeps nothing of the liar
			src, _ := fc.source(mode, honest)
			res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
			if err != nil || res.Stated != nil {
				t.Fatalf("with an honest provider behind the liar: %v %+v", err, res)
			}
			if got := capturedContainer(t, fc, res); !bytes.Equal(got, fc.w.ContainerBytes) {
				t.Fatal("a lie changed the captured evidence")
			}
			// the liar alone: Stated by name, no nodes, no codes, the block it was judged at, the failure names the host
			src, _ = fc.source(mode)
			res, err = capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
			if err != nil {
				t.Fatal(err)
			}
			st := res.Stated
			if st == nil || st.Reason != ci.StatedStateUnavailable || st.JudgedBlock != fc.w.Spec.Blocks.Settle.Number || st.JudgedHash != [32]byte(fc.w.BlockHashes["settle"]) {
				t.Fatalf("Stated = %+v", st)
			}
			if len(res.Nodes) != 0 || len(res.Codes) != 0 || len(st.Failures) != 1 || st.Failures[0].Host != "https://p0.example" || st.Failures[0].Error == "" {
				t.Fatalf("result keeps %d nodes %d codes, failures %+v", len(res.Nodes), len(res.Codes), st.Failures)
			}
		})
	}
}

func TestE2PrunedProofsAreStatedNeverGuessed(t *testing.T) {
	for _, mode := range []hostile{pruned, window, down} {
		fc := newFakeChain(t, 421614, "h0")
		src, _ := fc.source(mode, mode)
		clk := ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0))
		cfg := fc.config(src)
		cfg.Clock = clk
		res, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
		if err != nil {
			t.Fatal(err)
		}
		if res.Stated == nil || res.Stated.Reason != ci.StatedStateUnavailable || len(res.Stated.Failures) != 2 || len(res.Nodes) != 0 {
			t.Fatalf("mode %d: %+v", mode, res)
		}
		if _, err := capture.EncodeStated(res.Stated); err != nil {
			t.Fatal(err)
		}
		// the Stated part is a valid container part: the closed list of builder reasons accepts it
		fc2 := newFakeChain(t, 421614, "h0")
		if _, _, err := capture.Assemble(capture.Parts{Chain: 421614, Leg: res.Block, Facts: fc2.facts(t), Settle: res,
			Attest: &capture.AttestPart{Stated: &ci.Stated{State: ci.StatedState, Reason: ci.StatedAttestBlockStateUnavailable, JudgedBlock: 1, JudgedHash: [32]byte{1}}}}); err != nil {
			t.Fatalf("two Stated parts: %v", err)
		}
	}
}

func TestE2ProviderDownIsBoundedOnTheInjectedClock(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, ps := fc.source(down, down)
	clk := ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0))
	cfg := fc.config(src)
	cfg.Clock, cfg.Passes, cfg.Backoff = clk, 3, 2*time.Second
	start := clk.Now()
	res, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || res.Stated == nil {
		t.Fatalf("%v %+v", err, res)
	}
	// the first read asked is the settlement account's: three passes over two providers, a backoff between passes only
	if ps[0].count() != 3 || ps[1].count() != 3 {
		t.Fatalf("calls = %d, %d; want 3 passes each", ps[0].count(), ps[1].count())
	}
	if d := clk.Now().Sub(start); d != 4*time.Second {
		t.Fatalf("virtual time spent = %v, want two backoffs of 2s", d)
	}
	// a budget shorter than the backoffs ends the capture at the budget: fewer passes, still a Stated result
	src, ps = fc.source(down)
	cfg = fc.config(src)
	cfg.Clock, cfg.Passes, cfg.Backoff, cfg.Budget = ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), 50, time.Second, 3500*time.Millisecond
	res, err = capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || res.Stated == nil || ps[0].count() < 2 || ps[0].count() > 5 {
		t.Fatalf("budgeted capture: %v %+v calls %d", err, res, ps[0].count())
	}
}

func TestE2NoGoroutineLeakAndContextCancelReleasesEverything(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	base := runtime.NumGoroutine()
	gate := capture.NewGate(1)
	for i := 0; i < 20; i++ {
		src, _ := fc.source(down)
		cfg := fc.config(src)
		cfg.Gate, cfg.Clock, cfg.Backoff = gate, ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), time.Millisecond
		if _, err := capture.CaptureSettle(context.Background(), cfg, fc.request()); err != nil {
			t.Fatal(err)
		}
		if gate.InUse() != 0 {
			t.Fatal("the capture slot was not released")
		}
	}
	// a cancelled caller: its own error, slot released
	src, _ := fc.source(honest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := fc.config(src)
	cfg.Gate = gate
	if _, err := capture.CaptureSettle(ctx, cfg, fc.request()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: err = %v", err)
	}
	if gate.InUse() != 0 {
		t.Fatal("the slot leaked on cancel")
	}
	time.Sleep(50 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > base+1 {
		t.Fatalf("goroutines: %d before, %d after", base, n)
	}
}

func TestE2GateWaitThatEndsTheBudgetIsStatedNotAttempted(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	gate := capture.NewGate(1)
	release, _ := gate.Acquire(context.Background())
	defer release()
	src, _ := fc.source(honest)
	cfg := fc.config(src)
	cfg.Gate, cfg.Budget = gate, 50*time.Millisecond
	res, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || res.Stated == nil || res.Stated.Reason != ci.StatedCaptureNotAttemptedInWindow {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestE2PaddedAnswersAreNotKept(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(padNodes)
	res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
	if err != nil || res.Stated != nil {
		t.Fatalf("%v %+v", err, res)
	}
	if got := capturedContainer(t, fc, res); !bytes.Equal(got, fc.w.ContainerBytes) {
		t.Fatal("padding reached the evidence")
	}
}

func TestE2ByteBudgetBoundsMemory(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(honest)
	cfg := fc.config(src)
	cfg.MaxPoolBytes = 2000
	if res, err := capture.CaptureSettle(context.Background(), cfg, fc.request()); !errors.Is(err, capture.ErrTooLarge) || res != nil {
		t.Fatalf("2000-byte budget: %+v, %v", res, err)
	}
	// the default budget is twice the container cap, and the honest capture is far below it
	res, err := func() (*capture.SettleResult, error) {
		s, _ := fc.source(honest)
		return capture.CaptureSettle(context.Background(), fc.config(s), fc.request())
	}()
	if err != nil {
		t.Fatal(err)
	}
	size := 0
	for _, n := range res.Nodes {
		size += len(n)
	}
	if size >= 2*capture.MaxItemBytes() {
		t.Fatalf("capture of %d bytes", size)
	}
}

func TestE2ProviderTextIsRedactedAndBounded(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(leakyText)
	res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
	if err != nil || res.Stated == nil {
		t.Fatalf("%v %+v", err, res)
	}
	for _, f := range res.Stated.Failures {
		if strings.Contains(f.Error, "SECRETKEY") || strings.Contains(f.Host+res.Stated.Detail, "SECRETKEY") || len(f.Error) > 1024 {
			t.Fatalf("failure text leaks or is unbounded: %q", f.Error)
		}
	}
	raw, err := capture.EncodeStated(res.Stated)
	if err != nil || bytes.Contains(raw, []byte("SECRETKEY")) {
		t.Fatalf("stored Stated row leaks: %v", err)
	}
}

func TestE2PanicBecomesAnErrorAndSettlementNotAccountIsNamed(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(honest)
	src.panicOn = "header"
	var pe *capture.PanicError
	if _, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request()); !errors.As(err, &pe) {
		t.Fatalf("panicking source: %v", err)
	}
	// a transaction whose recipient emitted no LeafConsumed
	rc := *fc.rc
	rc.Logs = nil
	if _, err := capture.DeriveFacts(fc.w.Manifest, 11155111, fc.tx, &rc, fc.request()); !errors.Is(err, capture.ErrNotAccountSettlement) {
		t.Fatalf("no LeafConsumed: %v", err)
	}
	if _, err := capture.CaptureSettle(context.Background(), capture.Config{}, fc.request()); err == nil {
		t.Fatal("a Config without source, manifest and chain was accepted")
	}
}

func TestE2FailuresAreBoundedAndAPanicReleasesTheSlot(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src := &fakeSource{fc: fc}
	for i := 0; i < 70; i++ {
		src.providers = append(src.providers, &fakeProvider{name: fmt.Sprintf("https://h%02d.example", i), fc: fc, mode: down})
	}
	cfg := fc.config(src)
	cfg.Clock, cfg.Passes, cfg.Backoff = ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), 1, time.Second
	res, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || res.Stated == nil || len(res.Stated.Failures) != ci.DefaultLimits().MaxFailures {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := capture.EncodeStated(res.Stated); err != nil {
		t.Fatal(err)
	}
	// a source that panics while the capture holds its slot: the slot is released on the way out and the process lives on
	gate := capture.NewGate(1)
	psrc, _ := fc.source(honest)
	psrc.panicOn = "providers"
	cfg = fc.config(psrc)
	cfg.Gate = gate
	var pe *capture.PanicError
	if _, err := capture.CaptureSettle(context.Background(), cfg, fc.request()); !errors.As(err, &pe) || gate.InUse() != 0 {
		t.Fatalf("panic under the gate: err %v in use %d", err, gate.InUse())
	}
}

func TestE2DuplicateHostsCountOnce(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src := &fakeSource{fc: fc}
	var ps []*fakeProvider
	for _, n := range []string{"https://P.example", "https://p.example:443", "https://p.example./", "https://q.example"} {
		p := &fakeProvider{name: n, fc: fc, mode: down}
		ps, src.providers = append(ps, p), append(src.providers, p)
	}
	cfg := fc.config(src)
	cfg.Clock, cfg.Passes, cfg.Backoff = ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), 1, time.Second
	res, err := capture.CaptureSettle(context.Background(), cfg, fc.request())
	if err != nil || res.Stated == nil || len(res.Stated.Failures) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if ps[0].count() != 1 || ps[1].count() != 0 || ps[2].count() != 0 || ps[3].count() != 1 {
		t.Fatalf("calls %d %d %d %d: three spellings of one host must be one provider", ps[0].count(), ps[1].count(), ps[2].count(), ps[3].count())
	}
}

func TestSettleRowsAreCanonicalAndStrict(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	src, _ := fc.source(honest)
	res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := capture.EncodeSettle(res)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		if i < 4 || i%97 != 0 {
			continue
		}
		mut := append([]byte(nil), raw...)
		mut[i] ^= 0xff
		if d, err := capture.DecodeSettle(mut); err == nil {
			if again, e2 := capture.EncodeSettle(d); e2 != nil || !bytes.Equal(again, mut) {
				t.Fatalf("a mutated row decoded to something that does not re-encode to it (byte %d)", i)
			}
		}
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), nil, []byte("XXXX")} {
		if _, err := capture.DecodeSettle(bad); err == nil {
			t.Fatalf("accepted a malformed row of %d bytes", len(bad))
		}
	}
	// an unsorted node list is refused at encode
	swapped := *res
	swapped.Nodes = append([][]byte{res.Nodes[1], res.Nodes[0]}, res.Nodes[2:]...)
	if _, err := capture.EncodeSettle(&swapped); err == nil {
		t.Fatal("encoded unsorted nodes")
	}
	// Stated round trip and a captured/Stated conflict on different items
	sr := capture.NotAttempted(11155111, res.AnchorID, res.Block, "late")
	b, err := capture.EncodeStated(sr.Stated)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := capture.DecodeStated(b); err != nil || d.Reason != ci.StatedCaptureNotAttemptedInWindow || d.Detail != "late" {
		t.Fatalf("%+v %v", d, err)
	}
	st := capture.NewMemStore()
	if err := capture.SaveSettle(context.Background(), st, sr); err != nil {
		t.Fatal(err)
	}
	if err := capture.SaveSettle(context.Background(), st, res); err != nil {
		t.Fatal(err)
	}
	if err := capture.SaveSettle(context.Background(), st, sr); err != nil {
		t.Fatalf("the same Stated row twice: %v", err)
	}
	other := capture.NotAttempted(11155111, res.AnchorID, res.Block, "other")
	if err := capture.SaveSettle(context.Background(), st, other); !errors.Is(err, capture.ErrCaptureConflict) {
		t.Fatalf("a different Stated row: %v", err)
	}
	if l, _ := capture.LoadSettle(context.Background(), st, 11155111, res.AnchorID, res.Block.Hash); l == nil || l.Stated != nil {
		t.Fatalf("LoadSettle prefers the captured row: %+v", l)
	}
}

var _ = common.Hash{}
