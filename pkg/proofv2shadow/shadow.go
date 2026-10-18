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
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

var shadowResults = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "proof_v2_shadow",
	Name: "results_total", Help: "Proof v2 shadow outcomes by stage (capture, build) and result."}, []string{"stage", "result"})

func init() { prometheus.MustRegister(shadowResults) }

// certifyWait bounds how long a build waits for the Directory to anchor the block it needs certified.
const certifyWait = 20 * time.Minute

// Shadow captures and builds v2 proofs beside v1.
type Shadow struct {
	b        *proofv2.Builder
	c        *jsonrpc.Client
	endpoint string
	repo     *database.ProofV2ShadowRepository
	inc      *proof.IncarnationEvidence
	pin      [32]byte
	// inputs are what the pinned incarnation's evidence verified to: the genesis records a portable document carries.
	inputs proof.IncarnationInputs
	logf   func(string, ...any)

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
	rep, err := inc.Verify()
	if err != nil {
		return nil, fmt.Errorf("the incarnation evidence does not verify: %w", err)
	}
	s := &Shadow{b: b, c: c, endpoint: endpoint, repo: repo, inc: inc, pin: pin, inputs: rep.Inputs, logf: logf, builds: make(chan job, 256)}
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
	portable := make([][]byte, 0, len(majors)-s.stored)
	for _, m := range majors[s.stored:] {
		b, err := m.MarshalBinary()
		if err != nil {
			return err
		}
		recs = append(recs, b)
		j, err := proofv2.MajorJSON(m)
		if err != nil {
			return err
		}
		portable = append(portable, j)
	}
	if err := s.repo.SaveSpine(ctx, uint64(s.stored)+1, recs); err != nil {
		return fmt.Errorf("store spine: %w", err)
	}
	// The same records in the portable form, which a proof service serves inside each proof's document (RB7b-F30).
	if err := s.repo.SaveSpineJSON(ctx, uint64(s.stored)+1, portable); err != nil {
		return fmt.Errorf("store portable spine: %w", err)
	}
	s.stored = len(majors)
	return nil
}

// captureWait bounds one capture: every partition's pages are read as soon as their blocks are servable, which can take
// as long as the longest lull of a partition (about 15 minutes, R9 M4), and the transaction's own partition's anchor must be
// recorded by the Directory.
const captureWait = 30 * time.Minute

// Capture reads the governing pages as of the transaction's block, and of each other partition's block (design D2). It
// returns at once; the work runs in the background and its result, or the named reason it failed, is stored.
func (s *Shadow) Capture(intentID, account, tx, keyBook, keyPage string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), captureWait)
		defer cancel()
		cp, err := s.capture(ctx, account, tx, keyBook, keyPage)
		msg := ""
		result := "ok"
		if err != nil {
			msg, result = err.Error(), "failed"
			s.logf("[PROOF-V2-SHADOW] capture %s: %v", intentID, err)
		}
		shadowResults.WithLabelValues("capture", result).Inc()
		var block uint64
		var captured any
		if cp != nil {
			block, captured = cp.Block, cp
		}
		if rerr := s.repo.RecordCapture(ctx, intentID, tx, account, block, captured, msg); rerr != nil {
			s.logf("[PROOF-V2-SHADOW] store capture %s: %v", intentID, rerr)
		}
	}()
}

func (s *Shadow) capture(ctx context.Context, account, tx, keyBook, keyPage string) (*Capture, error) {
	col, err := s.collector(ctx, keyBook, keyPage)
	if err != nil {
		return nil, err
	}
	return col.Collect(ctx, account, tx)
}

// collector wires a Collector to the live network: the routing table as the network publishes it, the Directory's anchor
// chains, and each partition's retained range.
func (s *Shadow) collector(ctx context.Context, keyBook, keyPage string) (*Collector, error) {
	return NewCollector(ctx, s.endpoint, s.c, s.b, s.logf, keyBook, keyPage)
}

// NewCollector wires a Collector to a live network through the Builder that reads transaction positions.
func NewCollector(ctx context.Context, endpoint string, c *jsonrpc.Client, b *proofv2.Builder, logf func(string, ...any), keyBook, keyPage string) (*Collector, error) {
	router, err := proof.LoadNetworkRouter(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("routing: %w", err)
	}
	reader := &proofv2.PageReader{Net: c, Q: b.Q, Retention: &proofv2.ClientRetention{C: c}}
	resolver, err := proof.NewChainKeyPageResolver(endpoint, logf)
	if err != nil {
		return nil, err
	}
	return &Collector{
		Route: func(_ context.Context, account string) (string, error) { return router.PartitionID(account) },
		Block: func(ctx context.Context, account, tx string) (uint64, error) { return b.TxBlock(ctx, account, tx) },
		Position: func(ctx context.Context, account, tx, label string) (*proofv2.TxPosition, error) {
			return PositionFor(ctx, b, account, tx, label)
		},
		Facts: func(ctx context.Context, account, tx string) (*TxFacts, error) {
			return ReadTxFacts(ctx, c, account, tx)
		},
		Log:    proofv2.NetLog{Net: c},
		Chains: proofv2.NetChains{Net: c},
		Page:   reader.PageAt,
		Anchor: func(ctx context.Context, pb *proofv2.PartitionBlock) ([32]byte, error) {
			_, h, err := proofv2.AnchorAt(ctx, c, pb, 0)
			return h, err
		},
		Arrival: func(ctx context.Context, id *url.TxID) (string, uint64, error) {
			acct := id.Account()
			p, err := router.PartitionID(acct.String())
			if err != nil {
				return "", 0, err
			}
			blk, err := proofv2.ChainEntryBlock(ctx, c, acct, "signature", id.Hash())
			return p, blk, err
		},
		Trace: func(ctx context.Context, cause *url.TxID) ([]Hop, []*url.URL, error) {
			return TraceCause(ctx, c, cause)
		},
		// The certified key page is resolved exactly as the intent certificate resolves it (pkg/proof ResolveSigningKeyPage), from
		// the intent's declared key book and page and the transaction's signatures.
		Certified: func(ctx context.Context, account, tx string) (*url.URL, error) {
			page, err := resolver.ResolveSigningKeyPage(ctx, account, tx, keyBook, keyPage)
			if err != nil {
				return nil, err
			}
			return url.Parse(page)
		},
	}, nil
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
	ev, rep, err := s.buildOne(ctx, j, 0, false, false)
	s.record(ctx, j, ev, rep, err)
}

// record stores a build's evidence and verdict, or the named reason it failed.
func (s *Shadow) record(ctx context.Context, j job, ev *proofv2.Evidence, rep *proofv2.Report, err error) {
	res := database.ProofV2Result{IntentID: j.intentID, TxHash: j.tx, Account: j.account}
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
	if err == nil {
		s.storePortable(ctx, j.intentID, ev)
	}
}

// storePortable stores the intent's portable document (without the shared spine) beside its evidence, so a proof service can
// serve it. It can never fail a build: the evidence and its verdict are already stored, and a failure here is logged by name.
func (s *Shadow) storePortable(ctx context.Context, intentID string, ev *proofv2.Evidence) {
	doc, err := proofv2.ExportDocument(ev, s.inputs, s.pin)
	if err == nil {
		var raw []byte
		if raw, err = json.Marshal(doc); err == nil {
			err = s.repo.SavePortable(ctx, intentID, raw, proofv2.MajorsNeeded(ev))
		}
	}
	result := "ok"
	if err != nil {
		result = "failed"
		s.logf("[PROOF-V2-SHADOW] store portable document %s: %v", intentID, err)
	}
	shadowResults.WithLabelValues("portable", result).Inc()
}

// Prove builds an intent's v2 evidence now, for its intent certificate (docs/proof/GOVROOT_V3.md): from the pages
// captured at discovery - waiting for that capture to be recorded - on no more than maxMajors major blocks, the
// checkpoints the chain has verified. The result is also stored, as a shadow build's is. It is the certificate of a chain on which the rules
// v15 cross-partition activation is NOT in force: an intent whose governing pages are on other partitions is answered
// g1_evidence_21_not_in_force and retried (ProveG1 builds it once the activation is in force).
func (s *Shadow) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	return s.prove(ctx, intentID, account, tx, bvn, maxMajors, false)
}

// ProveG1 is Prove for a chain on which the rules v15 activation is in force when g1InForce is true: from the block after the
// activation consensus requires evidence 2.1 in every v3 certificate (a 2.0 certificate is refused, ErrIntentProofV21Missing), so the
// intent is proven as 2.1 whether its governing pages are on one partition or several. With g1InForce false it is Prove. The activation
// is the proposer's own view (consensus G1ActivationContext), read per intent: no setting of the shadow can say whether a governed
// activation has happened.
func (s *Shadow) ProveG1(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64, g1InForce bool) (*proofv2.Evidence, error) {
	return s.prove(ctx, intentID, account, tx, bvn, maxMajors, g1InForce)
}

func (s *Shadow) prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64, g1InForce bool) (*proofv2.Evidence, error) {
	if maxMajors == 0 {
		return nil, fmt.Errorf("proof v2: the chain has verified no major block to start from")
	}
	for {
		_, captureErr, done, err := s.repo.CaptureResult(ctx, intentID)
		if err != nil {
			return nil, fmt.Errorf("proof v2: read the capture: %w", err)
		}
		if done {
			if captureErr != "" {
				s.logf("[PROOF-V2] %s: capture fell short: %s", intentID, captureErr)
			}
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("proof v2: the governing pages were not captured in time: %w", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	j := job{intentID, account, tx, bvn}
	ev, rep, err := s.buildOne(ctx, j, maxMajors, true, g1InForce)
	s.record(ctx, j, ev, rep, err)
	if err != nil {
		return nil, fmt.Errorf("proof v2: %w", err)
	}
	return ev, nil
}

// buildPlan says how a capture becomes a document: evidence 2.0 over the transaction's own partition's pages, or evidence 2.1.
type buildPlan struct {
	is21  bool
	pages []*proofv2.PageState // the 2.0 pages
}

// planBuild decides the document for a capture. A capture with pages on other partitions needs 2.1. A proof for an intent's certificate
// (prove) may carry 2.1 only when allow21, which is the proposer's view that the rules v15 activation is in force for the next block (design
// D7): until then consensus refuses 2.1, so the certificate path is given the named state g1_evidence_21_not_in_force, never a document that
// fails later. From the block after the activation consensus REFUSES a 2.0 certificate (ErrIntentProofV21Missing), so with allow21 a
// certificate proof is 2.1 for every capture, one partition or several; the activation is read per intent, never configured. The shadow
// (not prove) builds and verifies 2.1 for a foreign capture either way.
func planBuild(cp *Capture, prove, allow21 bool) (*buildPlan, error) {
	if cp == nil {
		return &buildPlan{}, nil
	}
	if prove && allow21 {
		return &buildPlan{is21: true}, nil
	}
	if cp.HasForeignPages() {
		if prove && !allow21 {
			return nil, &proofv2.NamedState{Code: proofv2.StateEvidence21NotInForce, Block: cp.Block,
				Detail: "the governing pages are on more than one partition, so the proof is evidence 2.1: it is built and verified, but a certificate may carry it only after the rules that accept it are in force (design D7)"}
		}
		return &buildPlan{is21: true}, nil
	}
	pages, err := evidencePages(cp)
	if err != nil {
		return nil, err
	}
	return &buildPlan{pages: pages}, nil
}

func (s *Shadow) buildOne(ctx context.Context, j job, maxMajors uint64, prove, allow21 bool) (*proofv2.Evidence, *proofv2.Report, error) {
	raw, ok, err := s.repo.Captured(ctx, j.intentID)
	if err != nil {
		return nil, nil, fmt.Errorf("load captured pages: %w", err)
	}
	var cp *Capture
	var plan *buildPlan
	if ok && raw != nil && strings.TrimSpace(string(raw)) != "null" {
		if cp, err = DecodeCapture(raw); err != nil {
			return nil, nil, fmt.Errorf("decode captured pages: %w", err)
		}
	}
	if plan, err = planBuild(cp, prove, allow21); err != nil {
		return nil, nil, err
	}
	pages := plan.pages
	if len(pages) == 0 && !plan.is21 {
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
		if plan.is21 {
			asm, err := cp.Assembly(ctx, proofv2.NetLog{Net: s.c}, proofv2.NetChains{Net: s.c})
			if err != nil {
				return nil, nil, err
			}
			ev, rep, err := s.b.Build21(ctx, maxMajors, j.account, j.tx, j.bvn, asm)
			if errors.Is(err, proofv2.ErrNotYetCertified) && time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(15 * time.Second):
				}
				continue
			}
			// A certificate's proof is never a document the binding will refuse: a report that left anything unproven (the votes not
			// re-evaluated, a vote held, ...) is not a verified S3, so the intent is held with the state that says what is missing.
			if err == nil && prove && rep != nil && len(rep.Unproven) > 0 {
				u := rep.Unproven[0]
				return nil, rep, &u
			}
			return ev, rep, err
		}
		ev, err := s.b.BuildBounded(ctx, maxMajors, j.account, j.tx, j.bvn, pages...)
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
func (l *Lazy) Capture(intentID, account, tx, keyBook, keyPage string) {
	if s := l.p.Load(); s != nil {
		s.Capture(intentID, account, tx, keyBook, keyPage)
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

// Prove implements intent.ProofV2Shadow. Before the spine walk finishes there is nothing to prove from, by name.
func (l *Lazy) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	if s := l.p.Load(); s != nil {
		return s.Prove(ctx, intentID, account, tx, bvn, maxMajors)
	}
	return nil, fmt.Errorf("proof_v2_not_ready: the spine walk from the pinned incarnation's genesis has not finished")
}

// ProveG1 implements intent.ProofV2G1Prover: Prove for a chain on which the rules v15 activation is in force. Before the spine walk
// finishes there is nothing to prove from, by name.
func (l *Lazy) ProveG1(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64, g1InForce bool) (*proofv2.Evidence, error) {
	if s := l.p.Load(); s != nil {
		return s.ProveG1(ctx, intentID, account, tx, bvn, maxMajors, g1InForce)
	}
	return nil, fmt.Errorf("proof_v2_not_ready: the spine walk from the pinned incarnation's genesis has not finished")
}

// RecordGovRootInputs stores the govRoot v3 inputs of an intent whose certificate has been built, which a portable document carries
// beside the evidence. It needs no spine walk, so it works before the shadow is ready; it can never fail the intent, and a failure is logged.
func (l *Lazy) RecordGovRootInputs(intentID string, in *proofv2.PortableGovRootV3Inputs) {
	raw, err := json.Marshal(in)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = l.repo.RecordGovRootInputs(ctx, intentID, raw)
	}
	if err != nil {
		l.logf("[PROOF-V2-SHADOW] store govRoot v3 inputs %s: %v", intentID, err)
	}
}

func (l *Lazy) notReady(intentID, account, tx string) {
	shadowResults.WithLabelValues("start", "not_ready").Inc()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = l.repo.RecordBuild(ctx, database.ProofV2Result{IntentID: intentID, TxHash: tx, Account: account, Verdict: "failed", Error: "shadow_not_ready: the spine walk had not finished when the intent was discovered"})
	}()
}
