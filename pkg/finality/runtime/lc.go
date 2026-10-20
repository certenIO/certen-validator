// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/build"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// codeLCUnavailable is the registered named state (testdata/finality/states.json, required field `endpoints`) of a light-client
// source none of whose endpoints could serve the L1-finality part.
const codeLCUnavailable = "finality_lc_unavailable"

// lcBootstrapMax bounds one bootstrap answer read into memory (a Gloas bootstrap is 25,472 bytes, an Electra one about 25.7 KB).
const lcBootstrapMax = 1 << 20

// lcBootstrapCacheMax bounds the number of cached bootstraps: one per pinned kind-2 anchor in use, a handful at most.
const lcBootstrapCacheMax = 8

// LC assembles ethl1.LC (the L1-finality part of the evidence, V2_SPEC_S7 3.2) from an ORDERED list of Lodestar-compatible
// beacon API bases, anchored in the pinned ledger. Endpoints are availability only, never evidence: whatever they serve is
// verified by ethl1 downstream (VerifyFinalizedHead under the same pins), and an endpoint that serves something that does not
// verify costs only the attempt.
//
// The anchor is the ledger's highest-period entry that carries a block_root (a kind-2 anchor: the bootstrap of that checkpoint).
// A ledger without such an entry is the named state finality_pin_unknown, not a weaker anchor: there is no kind-1 path here. The root-only
// ledger the embedded pins hold today (period 1378, the bootstrap pin) is exactly such an anchor: every L1 head is proven by the
// in-evidence links from 1378 to the signature period, at most max_links of them (spec 8.2); beyond that the source returns
// *LedgerIncompleteError, whose state is finality_pending{finality_ledger_incomplete} with the exact periods and the ETA of the next
// ledger publication, never a longer evidence the verifier would refuse.
type LC struct {
	URLs []string       // CERTEN_FINALITY_LC_URLS, tried in order
	Pins *finality.Pins // pins whose eth_sepolia.anchors ledger fixes the anchor
	HTTP *http.Client   // nil => a client with a 60s timeout (the runtime passes a rate-limited one)
	Now  func() time.Time
	// Logf receives one line per failed endpoint and per fallback (provider text redacted); nil logs nothing.
	Logf func(format string, args ...any)

	regOnce sync.Once
	mu      sync.Mutex
	boots   map[[32]byte][]byte // block root -> the verified-to-hash bootstrap bytes (immutable, pinned by root)
	order   [][32]byte          // insertion order of boots, for the bound
}

var _ build.LCSource = (*LC)(nil)

// LCUnavailableError is the error of a source none of whose endpoints answered: it carries the named state
// finality_lc_unavailable{endpoints} (scheme and host only) and, for the operator, the redacted cause of each endpoint.
type LCUnavailableError struct {
	State  *finality.StateError
	Causes []string
}

func (e *LCUnavailableError) Error() string { return e.State.Error() }

// Unwrap lets finality.AsNamed find the state.
func (e *LCUnavailableError) Unwrap() error { return e.State }

// LedgerIncompleteError is the error of a source whose final update lies more than max_links periods past the ledger anchor: the pins
// cannot carry a proof to it. Pending is the named state (finality_pending{reason: finality_ledger_incomplete}); the endpoint is
// not at fault and is not retried on the next one.
type LedgerIncompleteError struct{ Pending *finality.PendingState }

func (e *LedgerIncompleteError) Error() string { return e.Pending.Error() }

// Unwrap lets finality.AsNamed find the state.
func (e *LedgerIncompleteError) Unwrap() error { return e.Pending.State() }

func (l *LC) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *LC) client() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (l *LC) logf(format string, args ...any) {
	if l.Logf != nil {
		ethrpc.RedactingLogf(l.Logf)(format, args...)
	}
}

// lcLabel is the scheme and host of an endpoint: never the userinfo, the path or the query, where credentials live.
func lcLabel(raw string, i int) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Sprintf("endpoint#%d", i)
	}
	return u.Scheme + "://" + u.Host
}

func lcLabels(urls []string) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = lcLabel(u, i)
	}
	return out
}

// register makes the redactor learn the configured URLs once, so that a credential in a path or query is removed wherever it
// appears in provider text.
func (l *LC) register() {
	l.regOnce.Do(func() { ethrpc.RegisterProviderURLs(l.URLs...) })
}

// anchor is the ledger's checkpoint anchor: the highest-period entry with a block_root.
func (l *LC) anchor() (period uint64, root [32]byte, err error) {
	e, err := l.Pins.Sepolia()
	if err != nil {
		return 0, root, err
	}
	found := false
	for _, a := range e.Anchors {
		if a.BlockRoot == "" || (found && a.Period <= period) {
			continue
		}
		raw, derr := hex.DecodeString(strings.TrimPrefix(a.BlockRoot, "0x"))
		if derr != nil || len(raw) != 32 {
			return 0, root, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainSepolia, "kind", "eth_sepolia", "period", a.Period)
		}
		period, found = a.Period, true
		copy(root[:], raw)
	}
	if !found {
		l.logf("[FINALITY] light-client source: the pinned ledger has no anchor with a block_root (%d entries); no L1 finality evidence can be assembled until the ledger carries one", len(e.Anchors))
		return 0, root, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainSepolia, "kind", "eth_sepolia")
	}
	return period, root, nil
}

// bootstrapLayout fixes the layout byte of a bootstrap by its size (the Gloas bootstrap is fixed-size, every other size is the
// variable-size Electra/Fulu layout) and returns the 112-byte beacon block header its hash must equal the pinned root.
func bootstrapLayout(b []byte) (ethl1.Layout, []byte, bool) {
	if len(b) == ethl1.LightClientBootstrapSize {
		return ethl1.LayoutGloas, b[:ethl1.BeaconBlockHeaderSize], true
	}
	if len(b) < 4 {
		return ethl1.LayoutElectra, nil, false
	}
	off := int(binary.LittleEndian.Uint32(b[:4]))
	if off < 4 || off+ethl1.BeaconBlockHeaderSize > len(b) {
		return ethl1.LayoutElectra, nil, false
	}
	return ethl1.LayoutElectra, b[off : off+ethl1.BeaconBlockHeaderSize], true
}

func (l *LC) cached(root [32]byte) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.boots[root]
	return b, ok
}

func (l *LC) remember(root [32]byte, b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.boots == nil {
		l.boots = map[[32]byte][]byte{}
	}
	if _, ok := l.boots[root]; ok {
		return
	}
	if len(l.order) >= lcBootstrapCacheMax {
		delete(l.boots, l.order[0])
		l.order = l.order[1:]
	}
	l.boots[root] = b
	l.order = append(l.order, root)
}

// bootstrap returns the bootstrap of the checkpoint root from the cache or from base. The answer must hash to the pinned root
// before it is kept: a provider's garbage is refused here and costs the attempt, never the cache.
func (l *LC) bootstrap(ctx context.Context, base string, root [32]byte) (ethl1.LB, error) {
	b, ok := l.cached(root)
	if !ok {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(base, "/")+"/eth/v1/beacon/light_client/bootstrap/0x"+hex.EncodeToString(root[:]), nil)
		if err != nil {
			return ethl1.LB{}, ethrpc.RedactError(err)
		}
		req.Header.Set("Accept", "application/octet-stream")
		resp, err := l.client().Do(req)
		if err != nil {
			return ethl1.LB{}, ethrpc.RedactError(err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, lcBootstrapMax+1))
		resp.Body.Close()
		switch {
		case rerr != nil:
			return ethl1.LB{}, ethrpc.RedactError(rerr)
		case resp.StatusCode != http.StatusOK:
			return ethl1.LB{}, fmt.Errorf("bootstrap: HTTP %d", resp.StatusCode)
		case len(body) > lcBootstrapMax:
			return ethl1.LB{}, errors.New("bootstrap: the answer exceeds the size bound")
		}
		_, hdr, ok := bootstrapLayout(body)
		if !ok {
			return ethl1.LB{}, fmt.Errorf("bootstrap: %d bytes are not a light-client bootstrap", len(body))
		}
		got, herr := ethl1.HashTreeRootBeaconBlockHeader(hdr)
		if herr != nil || got != root {
			return ethl1.LB{}, errors.New("bootstrap: the served header does not hash to the pinned checkpoint root")
		}
		l.remember(root, body)
		b = body
	}
	layout, _, _ := bootstrapLayout(b)
	return ethl1.LB{Layout: layout, SSZ: append([]byte(nil), b...)}, nil
}

// LC returns the L1-finality part for the current finalized head. It tries the endpoints in order and returns the first
// complete answer; when none answers it returns an *LCUnavailableError (finality_lc_unavailable{endpoints}); when the ledger
// has no kind-2 anchor it returns finality_pin_unknown without contacting any endpoint.
func (l *LC) LC(ctx context.Context) (ethl1.LC, error) {
	l.register()
	period, root, err := l.anchor()
	if err != nil {
		return ethl1.LC{}, err
	}
	var causes []string
	for i, base := range l.URLs {
		if err := ctx.Err(); err != nil {
			return ethl1.LC{}, err
		}
		started := l.now()
		lc, err := l.fromEndpoint(ctx, base, period, root)
		var tooMany *build.TooManyLinksError
		if errors.As(err, &tooMany) {
			// not an endpoint failure: the ledger is too far behind the head for any endpoint's answer to be carried
			e, _ := l.Pins.Sepolia()
			var a *finality.AnchorPin
			for i := range e.Anchors {
				if e.Anchors[i].Period == tooMany.Anchor {
					a = &e.Anchors[i]
				}
			}
			pend := ethsepolia.LedgerIncomplete(l.Pins, e, tooMany.Signature, a, l.now())
			l.logf("[FINALITY] light-client source: %v", pend)
			return ethl1.LC{}, &LedgerIncompleteError{Pending: pend}
		}
		if err == nil {
			if len(causes) > 0 {
				l.logf("[FINALITY] light-client source: %s answered after %d endpoint(s) failed (%s)", lcLabel(base, i), len(causes), l.now().Sub(started))
			}
			return lc, nil
		}
		if ctx.Err() != nil {
			return ethl1.LC{}, ctx.Err()
		}
		cause := ethrpc.RedactText(err.Error())
		causes = append(causes, lcLabel(base, i)+": "+cause)
		l.logf("[FINALITY] light-client source: endpoint %s failed after %s: %s", lcLabel(base, i), l.now().Sub(started), cause)
	}
	return ethl1.LC{}, &LCUnavailableError{
		State:  finality.NewState(codeLCUnavailable, "endpoints", lcLabels(l.URLs)),
		Causes: causes,
	}
}

func (l *LC) fromEndpoint(ctx context.Context, base string, period uint64, root [32]byte) (ethl1.LC, error) {
	body, err := l.bootstrap(ctx, base, root)
	if err != nil {
		return ethl1.LC{}, err
	}
	b := &build.BeaconLC{Beacon: base, HTTP: l.client(), AnchorKind: 2, AnchorPeriod: period, AnchorRoot: root, AnchorBody: body}
	if e, perr := l.Pins.Sepolia(); perr == nil {
		b.MaxLinks = e.MaxLinks
	}
	lc, err := b.LC(ctx)
	if err != nil {
		var tooMany *build.TooManyLinksError
		if errors.As(err, &tooMany) {
			return ethl1.LC{}, err
		}
		return ethl1.LC{}, ethrpc.RedactError(err)
	}
	return lc, nil
}

// Finalized is baseposted.LCSource.
func (l *LC) Finalized(ctx context.Context) (ethl1.LC, error) { return l.LC(ctx) }

// FinalizedAt is the LC together with the beacon slot the finality update was signed at: the head the answer observed
// (basefinal reports it as observed_head_slot beside the finalized slot it judged).
func (l *LC) FinalizedAt(ctx context.Context) (ethl1.LC, uint64, error) {
	lc, err := l.LC(ctx)
	if err != nil {
		return lc, 0, err
	}
	return lc, finalUpdateSlot(lc.FinalUpdate.SSZ), nil
}

// finalUpdateSlot is the signature_slot of a light-client finality update: its last eight bytes, little-endian, in the Gloas
// layout (the layout BeaconLC accepts for the final update). A shorter blob has no slot (0); ethl1 refuses such a blob.
func finalUpdateSlot(ssz []byte) uint64 {
	if len(ssz) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(ssz[len(ssz)-8:])
}

// LCWithSlot adapts an LC to basefinal.LCSource, whose Finalized also returns the observed head slot.
type LCWithSlot struct{ *LC }

// Finalized is basefinal.LCSource.
func (s LCWithSlot) Finalized(ctx context.Context) (ethl1.LC, uint64, error) {
	return s.LC.FinalizedAt(ctx)
}
