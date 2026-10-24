// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

func e2(t *testing.T, fc *fakeChain) *capture.SettleResult {
	t.Helper()
	src, _ := fc.source(honest)
	res, err := capture.CaptureSettle(context.Background(), fc.config(src), fc.request())
	if err != nil || res.Stated != nil {
		t.Fatalf("CaptureSettle: %v %+v", err, res)
	}
	return res
}

func parts(t *testing.T, fc *fakeChain, res *capture.SettleResult) capture.Parts {
	return capture.Parts{Chain: fc.w.Spec.Chain, Leg: res.Block, Facts: fc.facts(t), Settle: res, Attest: fc.attestPart(t)}
}

func TestAssembleExactnessRefusesEveryDeviationFromTheReadPlan(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	res := e2(t, fc)

	t.Run("an unreferenced node", func(t *testing.T) {
		p := parts(t, fc, res)
		extra := *res
		// a node of the attestation stations that the settlement station never reads is unreferenced by the settle plan
		var foreign []byte
		have := map[string]bool{}
		for _, n := range append(append([][]byte(nil), res.Nodes...), p.Attest.Nodes...) {
			have[string(n)] = true
		}
		foreign = []byte{0xc2, 0x80, 0x80}
		if have[string(foreign)] {
			t.Fatal("test node is not foreign")
		}
		extra.Nodes = sortedHash(append(append([][]byte(nil), res.Nodes...), foreign))
		p.Settle = &extra
		var ue *capture.NodesUnreferencedError
		if _, _, err := capture.Assemble(p); !errors.As(err, &ue) {
			t.Fatalf("err = %v, want NodesUnreferencedError", err)
		}
	})
	t.Run("a missing node", func(t *testing.T) {
		// a node may be shared by both stations (identical storage subtrees): the container misses it only when no part carries it
		for i := range res.Nodes {
			short := *res
			short.Nodes = without(res.Nodes, res.Nodes[i])
			p := parts(t, fc, res)
			p.Settle = &short
			p.Attest.Nodes = without(p.Attest.Nodes, res.Nodes[i])
			if _, _, err := capture.Assemble(p); err == nil {
				t.Fatalf("a container without node %d of %d was assembled", i, len(res.Nodes))
			}
		}
		p := parts(t, fc, res)
		for i := range p.Attest.Nodes {
			p2 := parts(t, fc, res)
			p2.Attest.Nodes = without(p.Attest.Nodes, p.Attest.Nodes[i])
			p2.Settle = &capture.SettleResult{Chain: res.Chain, AnchorID: res.AnchorID, Block: res.Block, StateRoot: res.StateRoot, Codes: res.Codes,
				Nodes: without(res.Nodes, p.Attest.Nodes[i]), Facts: res.Facts}
			if _, _, err := capture.Assemble(p2); err == nil {
				t.Fatalf("a container without attestation node %d of %d was assembled", i, len(p.Attest.Nodes))
			}
		}
	})
	t.Run("codes", func(t *testing.T) {
		bad := *res
		bad.Codes = append([]ci.Code(nil), res.Codes...)
		bad.Codes[0].Runtime = append([]byte{0}, res.Codes[0].Runtime...)
		p := parts(t, fc, res)
		p.Settle = &bad
		if _, _, err := capture.Assemble(p); err == nil {
			t.Fatal("code bytes that hash to no proven code hash were assembled")
		}
		// an address carried by both parts with different bytes
		p = parts(t, fc, res)
		p.Attest.Codes = []ci.Code{{Address: res.Codes[0].Address, Runtime: []byte{1, 2, 3}}}
		if _, _, err := capture.Assemble(p); !errors.Is(err, capture.ErrCodeConflict) {
			t.Fatalf("err = %v, want ErrCodeConflict", err)
		}
		// an extra code nobody proved
		p = parts(t, fc, res)
		p.Attest.Codes = []ci.Code{{Address: [20]byte{0xee}, Runtime: []byte{9}}}
		if _, _, err := capture.Assemble(p); !errors.Is(err, capture.ErrCodeUnproven) {
			t.Fatalf("err = %v, want ErrCodeUnproven", err)
		}
	})
	t.Run("parts that disagree", func(t *testing.T) {
		p := parts(t, fc, res)
		p.Leg.Number++
		if _, _, err := capture.Assemble(p); !errors.Is(err, capture.ErrPartsDisagree) {
			t.Fatalf("leg mismatch: %v", err)
		}
		p = parts(t, fc, res)
		p.Attest = nil
		if _, _, err := capture.Assemble(p); !errors.Is(err, capture.ErrNoParts) {
			t.Fatalf("missing attest part: %v", err)
		}
		p = parts(t, fc, res)
		p.Facts.TxIndex++
		if _, _, err := capture.Assemble(p); !errors.Is(err, capture.ErrPartsDisagree) {
			t.Fatalf("txIndex mismatch: %v", err)
		}
		p = parts(t, fc, res)
		p.Facts = nil
		if _, _, err := capture.Assemble(p); err == nil {
			t.Fatal("assembled captured parts without plan facts")
		}
	})
	t.Run("the six builder reasons only", func(t *testing.T) {
		good := []string{ci.StatedCaptureNotAttemptedInWindow, ci.StatedStateUnavailable, ci.StatedAttestBlockStateUnavailable, ci.StatedAttestBlockOutOfReach,
			ci.StatedAttestEventNotFound, ci.StatedBlockTooLarge}
		for _, r := range append(good, "capture_not_attempted", "state_unavailable_", "unknown_reason", "Zzz") {
			isGood := false
			for _, g := range good {
				isGood = isGood || g == r
			}
			p := parts(t, fc, res)
			p.Attest = &capture.AttestPart{Stated: &ci.Stated{State: ci.StatedState, Reason: r, JudgedBlock: 5, JudgedHash: [32]byte{5}}}
			_, _, err := capture.Assemble(p)
			if isGood && err != nil {
				t.Fatalf("builder reason %q refused: %v", r, err)
			}
			if !isGood && err == nil {
				t.Fatalf("reason %q outside the closed list was assembled", r)
			}
		}
	})
	t.Run("a Stated settle part with an attested part", func(t *testing.T) {
		stated := capture.NotAttempted(11155111, res.AnchorID, res.Block, "late")
		p := parts(t, fc, res)
		p.Settle = stated
		sp := fc.w.Spec.Roles
		for _, a := range []string{sp.Anchor, sp.Verifier, sp.Groth16} { // the attestation stations carry the codes they read themselves
			addr := common.HexToAddress(a)
			p.Attest.Codes = append(p.Attest.Codes, ci.Code{Address: addr, Runtime: fc.codes[addr]})
		}
		sort.Slice(p.Attest.Codes, func(i, j int) bool {
			return bytes.Compare(p.Attest.Codes[i].Address[:], p.Attest.Codes[j].Address[:]) < 0
		})
		_, raw, err := capture.Assemble(p)
		if err != nil {
			t.Fatalf("settle Stated, attest captured: %v", err)
		}
		c, err := ci.Decode(raw, ci.DefaultLimits())
		if err != nil || c.Settle.Tag != ci.TagStated || c.Attest.Tag != ci.TagCaptured {
			t.Fatalf("decoded %+v %v", c, err)
		}
		for _, n := range res.Nodes { // nodes that only the settle plan reads are not in a container whose settle part is Stated
			for _, m := range c.Nodes {
				if bytes.Equal(n, m) && !containsNode(p.Attest.Nodes, n) {
					t.Fatal("a settle-only node leaked into a Stated settle container")
				}
			}
		}
	})
}

func without(list [][]byte, n []byte) [][]byte {
	var out [][]byte
	for _, m := range list {
		if !bytes.Equal(m, n) {
			out = append(out, m)
		}
	}
	return out
}

func containsNode(list [][]byte, n []byte) bool {
	for _, m := range list {
		if bytes.Equal(m, n) {
			return true
		}
	}
	return false
}

type recSink struct {
	puts int
	last []byte
}

func (s *recSink) AppendContainer(_ context.Context, _ uint64, _ ci.BlockRef, c []byte, _ [32]byte) error {
	s.puts++
	s.last = c
	return nil
}

func reportOf(kind string) ci.Report { return ci.Report{Headline: ci.Headline{Kind: kind}} }

func TestAppendUsesTheInjectedVerifierAndStoresNothingItRefuses(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	res := e2(t, fc)
	m := fc.w.Manifest
	sink := &recSink{}

	// construction errors: no default verifier, no fallback
	var nilV ci.Verifier
	if _, err := capture.NewAppender(sink, nilV, m); err == nil {
		t.Fatal("nil verifier accepted")
	}
	if _, err := capture.NewAppender(sink, ci.VerifierFunc(nil), nil); err == nil {
		t.Fatal("nil manifest accepted")
	}
	if _, err := capture.NewAppender(nil, ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { return ci.Report{}, nil }), m); err == nil {
		t.Fatal("nil sink accepted")
	}

	var gotRaw []byte
	run := func(rep ci.Report, verr error) (*capture.Appended, error) {
		v := ci.VerifierFunc(func(lc ci.LegContext, raw []byte, mm *ci.Manifest) (ci.Report, error) {
			gotRaw = raw
			if mm != m {
				t.Error("the verifier got another manifest")
			}
			return rep, verr
		})
		ap, err := capture.NewAppender(sink, v, m)
		if err != nil {
			t.Fatal(err)
		}
		return ap.Append(context.Background(), fc.w.Ctx, parts(t, fc, res))
	}

	// a refusal: nothing is stored, the report rides in the error
	var re *capture.RefusedError
	if _, err := run(reportOf(ci.HeadlineRefused), nil); !errors.As(err, &re) || sink.puts != 0 {
		t.Fatalf("refusal: err %v puts %d", err, sink.puts)
	}
	// a verifier error is no verdict: nothing is stored
	if _, err := run(ci.Report{}, errors.New("framework failure")); err == nil || sink.puts != 0 {
		t.Fatalf("verifier error: %v puts %d", err, sink.puts)
	}
	// unproven, pending and verified containers are stored (availability and finality are facts, not refusals)
	for i, kind := range []string{ci.HeadlineUnproven, ci.HeadlinePending, ci.HeadlineVerified} {
		out, err := run(reportOf(kind), nil)
		if err != nil || sink.puts != i+1 {
			t.Fatalf("%s: %v puts %d", kind, err, sink.puts)
		}
		if !bytes.Equal(out.Container, fc.w.ContainerBytes) || !bytes.Equal(sink.last, gotRaw) || out.Digest != ci.DigestOf(11155111, res.Block.Number, res.Block.Hash, gotRaw) {
			t.Fatalf("%s: the stored container is not what the verifier judged", kind)
		}
	}
	// the capture-store sink
	st := capture.NewMemStore()
	ap, _ := capture.NewAppender(capture.StoreSink{Store: st, AnchorID: res.AnchorID}, ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		return reportOf(ci.HeadlineUnproven), nil
	}), m)
	if _, err := ap.Append(context.Background(), fc.w.Ctx, parts(t, fc, res)); err != nil {
		t.Fatal(err)
	}
	raw, ok, _ := st.Get(context.Background(), capture.Key{Chain: 11155111, AnchorID: res.AnchorID, BlockHash: res.Block.Hash, Item: capture.ItemContainer})
	if !ok || !bytes.Equal(raw, fc.w.ContainerBytes) {
		t.Fatal("the container is not in the store")
	}
	// the verifier is never reached for a container that is not exact
	reached := false
	bad := parts(t, fc, res)
	bad.Settle = &capture.SettleResult{Chain: res.Chain, AnchorID: res.AnchorID, Block: res.Block, StateRoot: res.StateRoot, Codes: res.Codes, Nodes: without(res.Nodes, res.Nodes[0]), Facts: res.Facts}
	bad.Attest.Nodes = without(bad.Attest.Nodes, res.Nodes[0])
	ap2, _ := capture.NewAppender(sink, ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		reached = true
		return reportOf(ci.HeadlineVerified), nil
	}), m)
	before := sink.puts
	if _, err := ap2.Append(context.Background(), fc.w.Ctx, bad); err == nil || reached || sink.puts != before {
		t.Fatalf("a container with a missing node: err %v verifier reached %v", err, reached)
	}
}

func TestSettleNodesAreCanonicalSorted(t *testing.T) {
	fc := newFakeChain(t, 84532, "hops")
	res := e2(t, fc)
	for i := 1; i < len(res.Nodes); i++ {
		if bytes.Compare(crypto.Keccak256(res.Nodes[i-1]), crypto.Keccak256(res.Nodes[i])) >= 0 {
			t.Fatalf("nodes %d and %d are not strictly ascending by keccak256", i-1, i)
		}
	}
}
