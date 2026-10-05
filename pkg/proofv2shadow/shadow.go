// Copyright 2026 Certen Protocol
//
// Package proofv2shadow runs proof v2 beside v1 (docs/proof/PROOF_V2.md §11): at discovery it captures the governing
// pages as of the intent transaction's block, while that block is inside the public node's retention; after the v1
// proof is built it builds and verifies the v2 evidence and stores both, with any failure named. Only v1 feeds govRoot:
// nothing here can delay, fail or change an intent.

package proofv2shadow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/prometheus/client_golang/prometheus"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

var shadowResults = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "proof_v2_shadow",
	Name: "results_total", Help: "Proof v2 shadow outcomes by stage (capture, build) and result."}, []string{"stage", "result"})

func init() { prometheus.MustRegister(shadowResults) }

// certifyWait bounds how long a build waits for the Directory to anchor the block it needs certified.
const certifyWait = 20 * time.Minute

// Shadow captures and builds v2 proofs beside v1.
type Shadow struct {
	b    *proofv2.Builder
	c    *jsonrpc.Client
	repo *database.ProofV2ShadowRepository
	inc  *proof.IncarnationEvidence
	pin  [32]byte
	logf func(string, ...any)

	builds chan job
	stored int // major records already stored
	mu     sync.Mutex
}

type job struct{ intentID, account, tx, bvn string }

// New walks the spine from the pinned incarnation's genesis and stores it.
func New(ctx context.Context, endpoint string, repo *database.ProofV2ShadowRepository, inc *proof.IncarnationEvidence, pin [32]byte, logf func(string, ...any)) (*Shadow, error) {
	c := jsonrpc.NewClient(endpoint)
	b, err := proofv2.NewBuilder(ctx, c, proof.NewHTTPQuerier(endpoint), inc, pin)
	if err != nil {
		return nil, err
	}
	s := &Shadow{b: b, c: c, repo: repo, inc: inc, pin: pin, logf: logf, builds: make(chan job, 256)}
	if err := s.saveSpine(ctx); err != nil {
		return nil, err
	}
	go s.buildLoop()
	return s, nil
}

func (s *Shadow) saveSpine(ctx context.Context) error {
	majors := s.b.Archive().Majors
	if len(majors) <= s.stored {
		return nil
	}
	recs := make([][]byte, 0, len(majors)-s.stored)
	for _, m := range majors[s.stored:] {
		b, err := m.MarshalBinary()
		if err != nil {
			return err
		}
		recs = append(recs, b)
	}
	if err := s.repo.SaveSpine(ctx, uint64(s.stored)+1, recs); err != nil {
		return fmt.Errorf("store spine: %w", err)
	}
	s.stored = len(majors)
	return nil
}

// Capture reads the governing pages as of the transaction's block. It returns at once; the work runs in the
// background and its result, or the named reason it failed, is stored.
func (s *Shadow) Capture(intentID, account, tx string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		block, pages, err := s.capture(ctx, account, tx)
		msg := ""
		result := "ok"
		if err != nil {
			msg, result = err.Error(), "failed"
			s.logf("[PROOF-V2-SHADOW] capture %s: %v", intentID, err)
		}
		shadowResults.WithLabelValues("capture", result).Inc()
		if rerr := s.repo.RecordCapture(ctx, intentID, tx, account, block, pages, msg); rerr != nil {
			s.logf("[PROOF-V2-SHADOW] store capture %s: %v", intentID, rerr)
		}
	}()
}

func (s *Shadow) capture(ctx context.Context, account, tx string) (uint64, []*proofv2.PageState, error) {
	block, err := s.b.TxBlock(ctx, account, tx)
	if err != nil {
		return 0, nil, fmt.Errorf("transaction block: %w", err)
	}
	urls, skipped, err := s.governingPages(ctx, account)
	if err != nil {
		return block, nil, err
	}
	var pages []*proofv2.PageState
	for _, u := range urls {
		p, err := s.b.CapturePage(ctx, u, block)
		if err != nil {
			return block, pages, err
		}
		pages = append(pages, p)
	}
	if len(skipped) > 0 {
		return block, pages, fmt.Errorf("g1_cross_identity_pending: authorities on other identities are not captured yet: %s", strings.Join(skipped, ", "))
	}
	return block, pages, nil
}

// governingPages returns the principal account and every page of each key book governing it. A book of another
// identity may live on another partition, whose block numbering differs; those are returned as skipped, by name.
func (s *Shadow) governingPages(ctx context.Context, account string) ([]string, []string, error) {
	u, err := url.Parse(account)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.c.Query(ctx, u, &api.DefaultQuery{})
	if err != nil {
		return nil, nil, fmt.Errorf("principal %s: %w", account, err)
	}
	ar, ok := r.(*api.AccountRecord)
	if !ok {
		return nil, nil, fmt.Errorf("principal %s: got %T", account, r)
	}
	full, ok := ar.Account.(protocol.FullAccount)
	if !ok {
		return nil, nil, fmt.Errorf("principal %s is %T, which has no authorities", account, ar.Account)
	}
	out := []string{account}
	var skipped []string
	for _, a := range full.GetAuth().Authorities {
		if a.Disabled {
			continue
		}
		if !a.Url.RootIdentity().Equal(u.RootIdentity()) {
			skipped = append(skipped, a.Url.String())
			continue
		}
		br, err := s.c.Query(ctx, a.Url, &api.DefaultQuery{})
		if err != nil {
			return nil, nil, fmt.Errorf("key book %v: %w", a.Url, err)
		}
		bar, ok := br.(*api.AccountRecord)
		if !ok {
			return nil, nil, fmt.Errorf("key book %v: got %T", a.Url, br)
		}
		book, ok := bar.Account.(*protocol.KeyBook)
		if !ok {
			return nil, nil, fmt.Errorf("authority %v is %T, not a key book", a.Url, bar.Account)
		}
		for i := uint64(0); i < book.PageCount; i++ {
			out = append(out, protocol.FormatKeyPageUrl(a.Url, i).String())
		}
	}
	return out, skipped, nil
}

// Build queues the v2 build for an intent whose v1 proof was built. It never blocks.
func (s *Shadow) Build(intentID, account, tx, bvn string) {
	select {
	case s.builds <- job{intentID, account, tx, bvn}:
	default:
		shadowResults.WithLabelValues("build", "dropped").Inc()
		s.logf("[PROOF-V2-SHADOW] build queue full: %s not built", intentID)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.repo.RecordBuild(ctx, database.ProofV2Result{IntentID: intentID, TxHash: tx, Account: account, Verdict: "failed", Error: "shadow build queue full"})
	}
}

func (s *Shadow) buildLoop() {
	for j := range s.builds {
		s.build(j)
	}
}

func (s *Shadow) build(j job) {
	ctx, cancel := context.WithTimeout(context.Background(), certifyWait+10*time.Minute)
	defer cancel()
	res := database.ProofV2Result{IntentID: j.intentID, TxHash: j.tx, Account: j.account}
	ev, rep, err := s.buildOne(ctx, j)
	switch {
	case err != nil:
		res.Verdict, res.Error = "failed", err.Error()
		s.logf("[PROOF-V2-SHADOW] build %s: %v", j.intentID, err)
	default:
		res.Evidence, res.Verdict = ev, string(rep.SetVerdict)
		res.AnchorBlock, res.CertifiedBlock, res.Pages = rep.AnchorBlock, rep.CertifiedBlock, len(rep.Pages)
		s.logf("[PROOF-V2-SHADOW] %s: v2 verified - certified DN %d, anchor block %d, %d pages, set %s",
			j.intentID, rep.CertifiedBlock, rep.AnchorBlock, len(rep.Pages), rep.SetVerdict)
	}
	shadowResults.WithLabelValues("build", res.Verdict).Inc()
	if rerr := s.repo.RecordBuild(ctx, res); rerr != nil {
		s.logf("[PROOF-V2-SHADOW] store build %s: %v", j.intentID, rerr)
	}
}

func (s *Shadow) buildOne(ctx context.Context, j job) (*proofv2.Evidence, *proofv2.Report, error) {
	raw, ok, err := s.repo.Captured(ctx, j.intentID)
	if err != nil {
		return nil, nil, fmt.Errorf("load captured pages: %w", err)
	}
	var pages []*proofv2.PageState
	if ok && raw != nil {
		if err := json.Unmarshal(raw, &pages); err != nil {
			return nil, nil, fmt.Errorf("decode captured pages: %w", err)
		}
	}
	if len(pages) == 0 {
		return nil, nil, fmt.Errorf("g1_historical_unavailable: no pages were captured at discovery")
	}
	if err := s.b.Refresh(ctx); err != nil {
		return nil, nil, err
	}
	if err := s.saveSpine(ctx); err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(certifyWait)
	for {
		ev, err := s.b.Build(ctx, j.account, j.tx, j.bvn, pages...)
		if errors.Is(err, proofv2.ErrNotYetCertified) && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(15 * time.Second):
			}
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		rep, err := proofv2.Verify(ev, s.b.Archive(), s.inc, s.pin)
		if err != nil {
			return nil, nil, fmt.Errorf("built evidence does not verify: %w", err)
		}
		return ev, rep, nil
	}
}

// Lazy is installed in discovery at once and starts the shadow in the background: walking the spine from genesis
// takes seconds to minutes, and the shadow must never hold up the validator. Until it is ready, each intent it misses
// is recorded by name, never silently skipped.
type Lazy struct {
	p    atomic.Pointer[Shadow]
	repo *database.ProofV2ShadowRepository
	logf func(string, ...any)
}

// NewLazy returns a shadow that becomes ready when Start succeeds.
func NewLazy(repo *database.ProofV2ShadowRepository, logf func(string, ...any)) *Lazy {
	return &Lazy{repo: repo, logf: logf}
}

// Start derives the configured incarnation's evidence and walks the spine, retrying every minute until both succeed.
func (l *Lazy) Start(endpoint string, pin [32]byte) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		ev, _, err := proof.ConfiguredIncarnationEvidence(ctx, endpoint, pin, 10*time.Second)
		var s *Shadow
		if err == nil {
			s, err = New(ctx, endpoint, l.repo, ev, pin, l.logf)
		}
		cancel()
		if err == nil {
			l.p.Store(s)
			l.logf("[PROOF-V2-SHADOW] ready: spine walked from the pinned incarnation's genesis (%d major blocks)", len(s.b.Archive().Majors))
			return
		}
		shadowResults.WithLabelValues("start", "failed").Inc()
		l.logf("[PROOF-V2-SHADOW] not started: %v (retrying in 1m)", err)
		time.Sleep(time.Minute)
	}
}

// Capture implements intent.ProofV2Shadow.
func (l *Lazy) Capture(intentID, account, tx string) {
	if s := l.p.Load(); s != nil {
		s.Capture(intentID, account, tx)
		return
	}
	l.notReady(intentID, account, tx)
}

// Build implements intent.ProofV2Shadow.
func (l *Lazy) Build(intentID, account, tx, bvn string) {
	if s := l.p.Load(); s != nil {
		s.Build(intentID, account, tx, bvn)
		return
	}
	l.notReady(intentID, account, tx)
}

func (l *Lazy) notReady(intentID, account, tx string) {
	shadowResults.WithLabelValues("start", "not_ready").Inc()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = l.repo.RecordBuild(ctx, database.ProofV2Result{IntentID: intentID, TxHash: tx, Account: account, Verdict: "failed", Error: "shadow_not_ready: the spine walk had not finished when the intent was discovered"})
	}()
}
