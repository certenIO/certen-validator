package execution

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// The batch outcome recorder (RB5 D4)
// =============================================================================
//
// Every validator runs it over the trees it kept. For each V8.2 anchor whose proof executed and whose outcome is not
// recorded, it derives the outcome; once every member is final, ONE elected validator collects the quorum's partials
// over the registry's outcome message and sends recordBatchOutcome. The registry is write-once:
//
//   - outcomeRoots(bundleId) equal to the derived root: the outcome is recorded - success, by whoever sent it; the
//     record is stored, and the kept tree released once the record is final;
//   - non-zero and different: a CONTRADICTION - the quorum certified an outcome this validator cannot reproduce. It is
//     alarmed by name, nothing is sent, and the tree is kept as evidence;
//   - zero: the elected validator records it.
//
// The election is deterministic over the leader roster, keyed by sha256("certen:outcome:v1|chain|bundleId"), with
// failover to the next roster validator every OutcomeFailoverAfter measured from the time of the finalized block that
// decided the batch's last member - a chain time every validator reads alike, so they agree who leads now.
//
// The shared database is a HINT throughout: it lists attested anchors whose outcome is not stored, so one this
// validator does not hold is named rather than silently skipped. Every fact the recorder acts on is re-derived from
// the chain.

// OutcomeFailoverAfter is how long the elected recorder has before the next roster validator takes over.
const OutcomeFailoverAfter = 10 * time.Minute

// OutcomeRecordInterval is how often the recorder passes over the kept trees.
const OutcomeRecordInterval = time.Minute

// OutcomeUnattestedRecheck is how often an anchor whose proof has not executed is read again. Its tree is kept: an
// anchor does not expire, and one attested later still has an outcome to record.
const OutcomeUnattestedRecheck = 10 * time.Minute

// outcomeRecordGas bounds recordBatchOutcome: the anchor's quorum verification (the Groth16 check of the aggregate)
// and two storage writes.
const outcomeRecordGas = 1_000_000

// ErrOutcomeContradiction: the registry records an outcome root this validator's derivation does not reproduce.
var ErrOutcomeContradiction = errors.New("the recorded batch outcome contradicts this validator's derivation")

// OutcomeLeaderIndex is the roster index of the validator that records chainID's bundleID outcome before any failover.
func OutcomeLeaderIndex(chainID int64, bundleID [32]byte, rosterLen int) int {
	if rosterLen <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("certen:outcome:v1|%d|%x", chainID, bundleID)))
	// Four bytes rather than one, so a 7-way modulus is not biased toward the low indices.
	return int(uint64(binary.BigEndian.Uint32(sum[:4])) % uint64(rosterLen))
}

// OutcomeRecorderFor is the roster validator that records the outcome now, resolvedAt the time of the block that
// decided the batch's last member.
func OutcomeRecorderFor(roster []string, chainID int64, bundleID [32]byte, resolvedAt, now time.Time, failover time.Duration) string {
	if len(roster) == 0 {
		return ""
	}
	idx := OutcomeLeaderIndex(chainID, bundleID, len(roster))
	if failover > 0 && now.After(resolvedAt) {
		idx = (idx + int(now.Sub(resolvedAt)/failover)) % len(roster)
	}
	return roster[idx]
}

// OutcomeRecorderChain is what the recorder reads of one chain.
type OutcomeRecorderChain interface {
	OutcomeChainReader
	OutcomeEvidenceReader
	RecordedOutcome(ctx context.Context, bundleID [32]byte, block uint64) (*RecordedOutcomeTx, error)
}

// OutcomeSubmission is a recordBatchOutcome this validator sent, or tried to.
type OutcomeSubmission struct {
	Tx     string
	Block  uint64
	Status uint64
	Proof  contracts.CertenAnchorV4BLSProofData
	Sender string
	// RevertName is the registry's custom error a simulation of the call reverted with ("" when it did not).
	RevertName string
}

// OutcomeSubmitter folds and sends: the anchor's validator registry the partials are checked against, and the send.
type OutcomeSubmitter interface {
	ValidatorRegistry(ctx context.Context, chainID int64) (map[string]consensus.ValidatorRegistryEntry, error)
	Submit(ctx context.Context, chainID int64, registry common.Address, bundleID, root [32]byte,
		agg *consensus.QuorumAggregate, msg [32]byte) (*OutcomeSubmission, error)
}

// OutcomeRecordStore is where recorded outcomes are kept (database.BatchOutcomeRepository).
type OutcomeRecordStore interface {
	RecordBatchOutcome(ctx context.Context, rec *database.BatchOutcomeRecord) error
	BatchOutcome(ctx context.Context, chainID int64, bundleID string) (*database.BatchOutcomeRecord, error)
	AttestedAnchorsWithoutOutcome(ctx context.Context, chainID int64, limit int) ([]string, error)
}

// BatchOutcomeRecorder records the outcomes of the anchors this validator kept trees for.
type BatchOutcomeRecorder struct {
	ValidatorID string
	Roster      func() []string
	Trees       *OutcomeTreeStore
	Chains      map[int64]OutcomeRecorderChain
	Registries  map[int64]common.Address
	Attempts    OutcomeAttemptSource
	Submitter   OutcomeSubmitter
	Records     OutcomeRecordStore
	// Evidence attaches a final record's offline evidence to its members' proofs (RB5-F15) before the tree is released.
	Evidence OutcomeEvidenceAttacher
	Peers    []string
	// Key is this validator's BLS key and SetRoot the CERTEN set it signs for; nil reads the process's.
	Key           func() *bls.PrivateKey
	SetRoot       func() ([32]byte, error)
	FailoverAfter time.Duration
	Timeout       time.Duration
	Now           func() time.Time
	Logf          func(string, ...interface{})

	mu sync.Mutex
	// hints carries the reverted attempts peers reported, per anchor, into the next round.
	hints map[[32]byte][]OutcomeMemberHint
	// unstored is a record this validator sent and saw mined whose evidence row could not be written yet, retried each
	// pass; sent is every record this validator broadcast, until its evidence is stored.
	unstored map[[32]byte]*database.BatchOutcomeRecord
	sent     map[[32]byte]*sentOutcome
	// named marks anchors the database lists as unrecorded but this validator does not hold, named once.
	named map[string]bool
	// unattestedUntil spaces out the reads of anchors whose proof has not executed.
	unattestedUntil map[[32]byte]time.Time
}

func (r *BatchOutcomeRecorder) logf(format string, a ...interface{}) {
	if r.Logf != nil {
		r.Logf(format, a...)
	}
}

func (r *BatchOutcomeRecorder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *BatchOutcomeRecorder) key() *bls.PrivateKey {
	if r.Key != nil {
		return r.Key()
	}
	km := bls.GetValidatorBLSKey()
	if km == nil {
		return nil
	}
	return km.PrivateKey()
}

func (r *BatchOutcomeRecorder) setRoot() ([32]byte, error) {
	if r.SetRoot != nil {
		return r.SetRoot()
	}
	return contracts.GetV6_1ValidatorSetRoot()
}

// Validate refuses a recorder missing anything it needs: it would otherwise run and never record.
func (r *BatchOutcomeRecorder) Validate() error {
	var missing []string
	if r.ValidatorID == "" {
		missing = append(missing, "validator id")
	}
	if r.Roster == nil {
		missing = append(missing, "leader roster")
	}
	if r.Trees == nil {
		missing = append(missing, "kept trees")
	}
	if len(r.Chains) == 0 {
		missing = append(missing, "chains")
	}
	if r.Submitter == nil {
		missing = append(missing, "submitter")
	}
	if r.Records == nil {
		missing = append(missing, "record store")
	}
	if r.Evidence == nil {
		missing = append(missing, "outcome evidence store")
	}
	for id := range r.Chains {
		if r.Registries[id] == (common.Address{}) {
			missing = append(missing, fmt.Sprintf("chain %d's outcome registry", id))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("batch outcome recorder: missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// Run passes over the kept trees every interval until ctx ends.
func (r *BatchOutcomeRecorder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = OutcomeRecordInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// OutcomeStep is what one pass did with one anchor.
type OutcomeStep string

const (
	OutcomeStepNotAttested   OutcomeStep = "anchor_not_attested"
	OutcomeStepNotFinal      OutcomeStep = "not_final"
	OutcomeStepNotElected    OutcomeStep = "not_elected"
	OutcomeStepRecorded      OutcomeStep = "recorded"
	OutcomeStepReleased      OutcomeStep = "released"
	OutcomeStepContradiction OutcomeStep = "contradiction"
	OutcomeStepNoQuorum      OutcomeStep = "no_quorum"
	OutcomeStepSent          OutcomeStep = "sent"
	OutcomeStepFailed        OutcomeStep = "failed"
)

// Pass handles every kept tree once and names, from the database's hint, attested anchors this validator does not hold.
// It returns what it did per anchor.
func (r *BatchOutcomeRecorder) Pass(ctx context.Context) map[[32]byte]OutcomeStep {
	out := map[[32]byte]OutcomeStep{}
	r.retryUnstored(ctx)
	trees, err := r.Trees.List()
	if err != nil {
		r.logf("🚨 [OUTCOME] the kept trees cannot be read: %v - no outcome is recorded or certified until they are", err)
		return out
	}
	held := map[string]bool{}
	for _, t := range trees {
		held[fmt.Sprintf("%d|0x%x", t.ChainID, t.BundleID)] = true
		r.mu.Lock()
		waitUntil := r.unattestedUntil[t.BundleID]
		r.mu.Unlock()
		if r.now().Before(waitUntil) {
			out[t.BundleID] = OutcomeStepNotAttested
			continue
		}
		step, err := r.handle(ctx, t)
		out[t.BundleID] = step
		r.mu.Lock()
		if step == OutcomeStepNotAttested {
			// An anchor whose proof has not executed may still be attested later, so its tree is kept; it is read again
			// less often than one in flight.
			if r.unattestedUntil == nil {
				r.unattestedUntil = map[[32]byte]time.Time{}
			}
			r.unattestedUntil[t.BundleID] = r.now().Add(OutcomeUnattestedRecheck)
		} else {
			delete(r.unattestedUntil, t.BundleID)
		}
		r.mu.Unlock()
		if err != nil {
			r.logf("⚠️ [OUTCOME] chain %d anchor 0x%x: %s: %v", t.ChainID, t.BundleID[:8], step, err)
		}
	}
	r.nameUnheld(ctx, held)
	return out
}

func (r *BatchOutcomeRecorder) nameUnheld(ctx context.Context, held map[string]bool) {
	if r.Records == nil {
		return
	}
	for id := range r.Chains {
		bundles, err := r.Records.AttestedAnchorsWithoutOutcome(ctx, id, 200)
		if err != nil {
			r.logf("⚠️ [OUTCOME] chain %d: the database's list of attested anchors without an outcome: %v", id, err)
			continue
		}
		for _, b := range bundles {
			key := fmt.Sprintf("%d|%s", id, strings.ToLower(b))
			r.mu.Lock()
			seen := r.named[key]
			if r.named == nil {
				r.named = map[string]bool{}
			}
			r.named[key] = true
			r.mu.Unlock()
			if !held[key] && !seen {
				r.logf("ℹ️ [OUTCOME] chain %d anchor %s: attested with no outcome stored, and this validator holds no tree for it "+
					"(it neither signed nor proved it); a validator that does will certify it", id, b)
			}
		}
	}
}

// handle is one pass over one kept tree.
func (r *BatchOutcomeRecorder) handle(ctx context.Context, t *OutcomeTree) (OutcomeStep, error) {
	c := r.Chains[t.ChainID]
	if c == nil {
		return OutcomeStepFailed, fmt.Errorf("chain %d is not a settlement chain here", t.ChainID)
	}
	view, err := c.AnchorView(ctx, t.BundleID)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	if err := checkAnchorIsTree(view, t); err != nil {
		if view.Anchor == nil || !view.Anchor.Valid {
			return OutcomeStepNotAttested, err
		}
		return OutcomeStepContradiction, fmt.Errorf("🚨 the anchor on the chain is not the tree this validator kept: %w", err)
	}
	if view.RecordedRoot != ([32]byte{}) {
		return r.recorded(ctx, c, t, view)
	}
	if !view.Anchor.ProofExecuted {
		return OutcomeStepNotAttested, nil
	}
	hints, err := r.hintsFor(ctx, t)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	derived, err := DeriveOutcome(ctx, c, t, hints)
	if err != nil {
		if IsOutcomeRetryable(err) {
			return OutcomeStepNotFinal, err
		}
		return OutcomeStepFailed, err
	}
	leader := OutcomeRecorderFor(r.Roster(), t.ChainID, t.BundleID, derived.ResolvedAt, r.now(), r.failover())
	if leader != r.ValidatorID {
		return OutcomeStepNotElected, nil
	}
	return r.record(ctx, c, t, view, derived)
}

func (r *BatchOutcomeRecorder) failover() time.Duration {
	if r.FailoverAfter > 0 {
		return r.FailoverAfter
	}
	return OutcomeFailoverAfter
}

// hintsFor is this validator's own attempts for the tree's members and every attempt a peer reported last round.
func (r *BatchOutcomeRecorder) hintsFor(ctx context.Context, t *OutcomeTree) (map[[32]byte][]common.Hash, error) {
	r.mu.Lock()
	peerHints := append([]OutcomeMemberHint(nil), r.hints[t.BundleID]...)
	r.mu.Unlock()
	return attemptHints(ctx, r.Attempts, t, peerHints)
}

// recorded handles an anchor whose outcome the registry holds: compared with this validator's own derivation, stored,
// and - once the record is final - its offline evidence attached to the members' proofs and its tree released.
func (r *BatchOutcomeRecorder) recorded(ctx context.Context, c OutcomeRecorderChain, t *OutcomeTree, view *OutcomeAnchorView) (OutcomeStep, error) {
	hints, err := r.hintsFor(ctx, t)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	derived, err := DeriveOutcome(ctx, c, t, hints)
	if err != nil {
		if IsOutcomeRetryable(err) {
			return OutcomeStepNotFinal, fmt.Errorf("recorded as 0x%x; this validator cannot compare yet: %w", view.RecordedRoot[:8], err)
		}
		return OutcomeStepFailed, err
	}
	if derived.Root != view.RecordedRoot {
		r.logf("🚨🚨 [OUTCOME] CONTRADICTION chain %d anchor 0x%x: the registry records outcome root 0x%x (block %d), this "+
			"validator derives 0x%x from the tree it signed and the finalized chain. Nothing is sent; the tree is kept as evidence.",
			t.ChainID, t.BundleID[:8], view.RecordedRoot, view.RecordedIn, derived.Root)
		return OutcomeStepContradiction, fmt.Errorf("%w: chain %d anchor 0x%x", ErrOutcomeContradiction, t.ChainID, t.BundleID[:8])
	}
	if err := r.storeRecorded(ctx, c, t, view, derived); err != nil {
		return OutcomeStepRecorded, err
	}
	// The record is final once its transaction's block is at or below the finalized block and canonical at its height.
	// It is judged by that block, never by recordedInBlock: on Arbitrum a contract's block.number is the L1 block number.
	rec, err := c.RecordedOutcome(ctx, t.BundleID, view.RecordedIn)
	if err != nil {
		return OutcomeStepRecorded, err
	}
	fin, err := c.FinalizedHeader(ctx)
	if err != nil {
		return OutcomeStepRecorded, err
	}
	if rec.Block == 0 || rec.Block > fin.Number.Uint64() {
		return OutcomeStepRecorded, nil // released once the record is final
	}
	if hdr, err := c.HeaderAt(ctx, rec.Block); err != nil {
		return OutcomeStepRecorded, err
	} else if hdr.Hash() != rec.BlockHash {
		return OutcomeStepRecorded, fmt.Errorf("the record %s names block %s, the finalized block at %d is %s", rec.Tx.Hex(),
			rec.BlockHash.Hex(), rec.Block, hdr.Hash().Hex())
	}
	in := OutcomeEvidenceInput{Registry: r.Registries[t.ChainID], Anchor: c.Anchor(), Tree: t, Leaves: derived.Leaves, View: view, Record: rec}
	if row, err := r.Records.BatchOutcome(ctx, t.ChainID, "0x"+hex.EncodeToString(t.BundleID[:])); err == nil && row != nil &&
		row.EvidenceSource == database.BatchOutcomeEvidenceRecorder && strings.EqualFold(row.RecordTx, rec.Tx.Hex()) {
		in.AggregateSignature, in.AggregatePublicKey = row.AggregateSignature, row.AggregatePublicKey
	}
	n, err := r.Evidence.AttachOutcomeEvidence(ctx, c, in)
	if err != nil {
		return OutcomeStepRecorded, fmt.Errorf("the record is final; its offline evidence is not attached to the members' proofs, so "+
			"the tree is kept: %w", err)
	}
	r.logf("🧾 [OUTCOME] chain %d anchor 0x%x: offline evidence attached to %d member proof(s)", t.ChainID, t.BundleID[:8], n)
	if err := r.Trees.Release(t.ChainID, t.BundleID); err != nil {
		return OutcomeStepRecorded, err
	}
	r.mu.Lock()
	delete(r.hints, t.BundleID)
	delete(r.unattestedUntil, t.BundleID)
	r.mu.Unlock()
	return OutcomeStepReleased, nil
}

// storeRecorded makes sure the database holds the record: this validator's own evidence if it sent it, otherwise the
// record rebuilt from its transaction on the chain.
func (r *BatchOutcomeRecorder) storeRecorded(ctx context.Context, c OutcomeRecorderChain, t *OutcomeTree, view *OutcomeAnchorView, d *DerivedOutcome) error {
	bundle := "0x" + hex.EncodeToString(t.BundleID[:])
	r.mu.Lock()
	own := r.unstored[t.BundleID]
	sent := r.sent[t.BundleID]
	r.mu.Unlock()
	if own != nil {
		return r.store(ctx, t.BundleID, own)
	}
	stored, err := r.Records.BatchOutcome(ctx, t.ChainID, bundle)
	if err != nil {
		return err
	}
	if stored != nil {
		if !strings.EqualFold(stored.OutcomeRoot, "0x"+hex.EncodeToString(view.RecordedRoot[:])) {
			return fmt.Errorf("%w: the database stores outcome root %s for anchor %s, the registry 0x%x", ErrOutcomeContradiction,
				stored.OutcomeRoot, bundle, view.RecordedRoot)
		}
		if stored.EvidenceSource == database.BatchOutcomeEvidenceRecorder || sent == nil {
			return nil
		}
	}
	tx, err := c.RecordedOutcome(ctx, t.BundleID, view.RecordedIn)
	if err != nil {
		return err
	}
	// The record's message commits the anchor's validator set root AT RECORDING. The row states the current one only when
	// it reproduces the message the registry emitted; a set root that moved since is not guessed.
	if m := contracts.ComputeEvmMessageHashV8_2_Outcome(t.ChainID, t.BundleID, tx.Root, view.CurrentSetRoot, t.AccumulateSetRoot,
		t.Incarnation); m != tx.MessageHash {
		return fmt.Errorf("record %s signed message 0x%x, which the anchor's current validator set root 0x%x does not reproduce: "+
			"the set root it committed is not known here, so its evidence is not stored", tx.Tx.Hex(), tx.MessageHash[:8], view.CurrentSetRoot[:8])
	}
	// This validator's own aggregate completes the row when the record is the one it sent.
	var agg *consensus.QuorumAggregate
	if sent != nil && strings.EqualFold(sent.sender, tx.Recorder.Hex()) && sameSignerSet(sent.agg, tx.Proof) {
		agg = sent.agg
	}
	rec, err := outcomeRecordRow(t, d, view, r.Registries[t.ChainID], tx.Tx.Hex(), tx.Block, tx.Recorder.Hex(), tx.Proof,
		tx.MessageHash, agg)
	if err != nil {
		return err
	}
	if err := r.Records.RecordBatchOutcome(ctx, rec); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.sent, t.BundleID)
	r.mu.Unlock()
	return nil
}

// sentOutcome is a recordBatchOutcome this validator broadcast: its aggregate, which only it holds, and its sender.
type sentOutcome struct {
	agg    *consensus.QuorumAggregate
	sender string
}

// sameSignerSet reports whether a record's proof carries exactly the aggregate's signers at their powers.
func sameSignerSet(agg *consensus.QuorumAggregate, p contracts.CertenAnchorV4BLSProofData) bool {
	if agg == nil || len(agg.Signers) != len(p.ValidatorAddresses) || len(agg.SignerPowers) != len(p.VotingPowers) {
		return false
	}
	for i, s := range agg.Signers {
		if !strings.EqualFold(s, p.ValidatorAddresses[i].Hex()) || agg.SignerPowers[i].Cmp(p.VotingPowers[i]) != 0 {
			return false
		}
	}
	return agg.SignedVotingPower != nil && p.SignedVotingPower != nil && agg.SignedVotingPower.Cmp(p.SignedVotingPower) == 0
}

func (r *BatchOutcomeRecorder) store(ctx context.Context, bundle [32]byte, rec *database.BatchOutcomeRecord) error {
	if err := r.Records.RecordBatchOutcome(ctx, rec); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.unstored, bundle)
	delete(r.sent, bundle)
	r.mu.Unlock()
	return nil
}

func (r *BatchOutcomeRecorder) retryUnstored(ctx context.Context) {
	r.mu.Lock()
	pending := make(map[[32]byte]*database.BatchOutcomeRecord, len(r.unstored))
	for k, v := range r.unstored {
		pending[k] = v
	}
	r.mu.Unlock()
	for b, rec := range pending {
		if err := r.store(ctx, b, rec); err != nil {
			r.logf("⚠️ [OUTCOME] anchor 0x%x: storing the record this validator sent: %v", b[:8], err)
		}
	}
}

// record is the elected validator's round: its partial, the peers', the fold, and the send.
func (r *BatchOutcomeRecorder) record(ctx context.Context, c OutcomeRecorderChain, t *OutcomeTree, view *OutcomeAnchorView, d *DerivedOutcome) (OutcomeStep, error) {
	setRoot, err := r.setRoot()
	if err != nil {
		return OutcomeStepFailed, err
	}
	if view.CurrentSetRoot != setRoot {
		return OutcomeStepFailed, fmt.Errorf("the anchor's currentValidatorSetRoot 0x%x is not the CERTEN set 0x%x this validator "+
			"signs for; no quorum this validator can join would verify", view.CurrentSetRoot[:8], setRoot[:8])
	}
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(t.ChainID, t.BundleID, d.Root, setRoot, t.AccumulateSetRoot, t.Incarnation)
	onChain, err := c.OutcomeMessage(ctx, t.BundleID, d.Root, view.At)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	if onChain != msg {
		return OutcomeStepFailed, fmt.Errorf("the registry signs outcome message 0x%x, this validator computes 0x%x", onChain[:8], msg[:8])
	}
	registry, err := r.Submitter.ValidatorRegistry(ctx, t.ChainID)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	me, err := ownRegistryAddress(registry, r.key())
	if err != nil {
		return OutcomeStepFailed, err
	}
	sk := r.key()
	ownSig, err := consensus.SignBatchAttestation(sk, msg)
	if err != nil {
		return OutcomeStepFailed, err
	}
	partials := []consensus.BatchAttestationEntry{{ValidatorID: r.ValidatorID, EVMAddress: me, SignatureHex: ownSig,
		PublicKeyHex: sk.PublicKey().Hex()}}

	req := &OutcomeRequest{ChainID: t.ChainID, BundleID: "0x" + hex.EncodeToString(t.BundleID[:]),
		OutcomeRoot: "0x" + hex.EncodeToString(d.Root[:]), ProposerID: r.ValidatorID, Members: hintsOf(d.Attempts)}
	res := CollectOutcomeAttestations(ctx, log.New(log.Writer(), "[OUTCOME-QUORUM] ", log.LstdFlags), r.Peers, req, msg, r.Timeout)
	r.mu.Lock()
	if r.hints == nil {
		r.hints = map[[32]byte][]OutcomeMemberHint{}
	}
	r.hints[t.BundleID] = append(r.hints[t.BundleID], res.Attempts...)
	r.mu.Unlock()
	for _, p := range res.Responses {
		partials = append(partials, consensus.BatchAttestationEntry{ValidatorID: p.ValidatorID, EVMAddress: p.EVMAddress,
			SignatureHex: p.SignatureHex, PublicKeyHex: p.PublicKeyHex})
	}
	agg, err := consensus.AggregateBatchAttestations(partials, registry, msg, batchQuorumThresholdNum, batchQuorumThresholdDen)
	if err != nil {
		return OutcomeStepNoQuorum, fmt.Errorf("quorum not formed over outcome root 0x%x (%d partial(s), refusals %v, %d unreachable): %w",
			d.Root[:8], len(partials), res.Refusals, res.Unreachable, err)
	}

	// Read again before sending: another validator may have recorded meanwhile, and the message commits the anchor's
	// CURRENT set root - one that changed since the partials were signed would fail the registry's check.
	fresh, err := c.AnchorView(ctx, t.BundleID)
	if err != nil {
		return OutcomeStepNotFinal, err
	}
	if fresh.RecordedRoot != ([32]byte{}) {
		return r.recorded(ctx, c, t, fresh)
	}
	if fresh.CurrentSetRoot != view.CurrentSetRoot {
		return OutcomeStepNoQuorum, fmt.Errorf("the anchor's validator set root moved from 0x%x to 0x%x while the quorum signed; "+
			"re-signing next round", view.CurrentSetRoot[:8], fresh.CurrentSetRoot[:8])
	}

	sub, err := r.Submitter.Submit(ctx, t.ChainID, r.Registries[t.ChainID], t.BundleID, d.Root, agg, msg)
	if sub != nil && sub.RevertName != "" {
		return r.reverted(ctx, c, t, view, sub.RevertName, err)
	}
	if sub != nil && sub.Tx != "" {
		// Broadcast: it may land even without a result here, and only this validator holds its aggregate.
		r.mu.Lock()
		if r.sent == nil {
			r.sent = map[[32]byte]*sentOutcome{}
		}
		r.sent[t.BundleID] = &sentOutcome{agg: agg, sender: sub.Sender}
		r.mu.Unlock()
	}
	if err != nil {
		return OutcomeStepFailed, fmt.Errorf("recordBatchOutcome: %w", err)
	}
	if sub.Status != types.ReceiptStatusSuccessful {
		// A reverted record may have lost a race to another validator's: read the registry before calling it a failure.
		after, verr := c.AnchorView(ctx, t.BundleID)
		if verr == nil && after.RecordedRoot != ([32]byte{}) {
			return r.recorded(ctx, c, t, after)
		}
		return OutcomeStepFailed, fmt.Errorf("recordBatchOutcome %s reverted in block %d, and the registry records no outcome", sub.Tx, sub.Block)
	}
	rec, err := outcomeRecordRow(t, d, view, r.Registries[t.ChainID], sub.Tx, sub.Block, sub.Sender, sub.Proof, msg, agg)
	if err != nil {
		return OutcomeStepSent, fmt.Errorf("record %s mined; its evidence cannot be stated: %w", sub.Tx, err)
	}
	r.mu.Lock()
	if r.unstored == nil {
		r.unstored = map[[32]byte]*database.BatchOutcomeRecord{}
	}
	r.unstored[t.BundleID] = rec
	r.mu.Unlock()
	r.logf("✅ [OUTCOME] chain %d anchor 0x%x: outcome root 0x%x recorded by %s in block %d (%s of %s voting power)",
		t.ChainID, t.BundleID[:8], d.Root[:8], sub.Tx, sub.Block, agg.SignedVotingPower, agg.TotalVotingPower)
	r.retryUnstored(ctx)
	return OutcomeStepSent, nil
}

// reverted handles a simulation the registry refused with its own error, by name.
func (r *BatchOutcomeRecorder) reverted(ctx context.Context, c OutcomeRecorderChain, t *OutcomeTree, view *OutcomeAnchorView, name string, cause error) (OutcomeStep, error) {
	after, err := c.AnchorView(ctx, t.BundleID)
	if err != nil {
		return OutcomeStepNotFinal, fmt.Errorf("the registry refused with %s, and it cannot be read again: %w", name, err)
	}
	switch name {
	case "OutcomeAlreadyRecorded":
		// The registry is write-once and has just said it holds a record. A zero root in the agreed view means the view is
		// older than the record - not visible yet, never a contradiction (RB7-ADIRI-F1).
		if after.RecordedRoot == ([32]byte{}) {
			return OutcomeStepNotFinal, fmt.Errorf("the registry refused with OutcomeAlreadyRecorded, but the agreed view %s "+
				"does not show the record yet", viewBlock(after))
		}
		return r.recorded(ctx, c, t, after)
	case "QuorumAttestationInvalid":
		if after.CurrentSetRoot != view.CurrentSetRoot {
			return OutcomeStepNoQuorum, fmt.Errorf("QuorumAttestationInvalid: the anchor's validator set root moved to 0x%x; "+
				"re-signing next round", after.CurrentSetRoot[:8])
		}
		return OutcomeStepFailed, fmt.Errorf("QuorumAttestationInvalid under an unchanged validator set root 0x%x: %v",
			view.CurrentSetRoot[:8], cause)
	}
	return OutcomeStepFailed, fmt.Errorf("the registry refuses recordBatchOutcome with %s: %v", name, cause)
}

// ownRegistryAddress is this validator's address in the anchor's registry, by its BLS key.
func ownRegistryAddress(registry map[string]consensus.ValidatorRegistryEntry, sk *bls.PrivateKey) (string, error) {
	if sk == nil {
		return "", fmt.Errorf("validator BLS private key not loaded")
	}
	return matchRegistryByPubkey(registry, sk.PublicKey().Hex())
}

// outcomeRecordRow is the database row of a record: agg is the BLS aggregate when this validator sent it, nil for a
// record rebuilt from its transaction.
func outcomeRecordRow(t *OutcomeTree, d *DerivedOutcome, view *OutcomeAnchorView, registry common.Address, tx string, block uint64,
	recorder string, proof contracts.CertenAnchorV4BLSProofData, msg [32]byte, agg *consensus.QuorumAggregate) (*database.BatchOutcomeRecord, error) {
	h := func(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }
	if proof.SignedVotingPower == nil || proof.TotalVotingPower == nil || len(proof.ValidatorAddresses) != len(proof.VotingPowers) {
		return nil, fmt.Errorf("the record's proof states no signer set")
	}
	rec := &database.BatchOutcomeRecord{
		ChainID: t.ChainID, BundleID: h(t.BundleID), Registry: strings.ToLower(registry.Hex()), OutcomeRoot: h(d.Root),
		MessageHash: h(msg), CertenValidatorSetRoot: h(view.CurrentSetRoot), AccumulateSetRoot: h(t.AccumulateSetRoot),
		AccumulateIncarnation: h(t.Incarnation), LeafCount: int64(len(d.Leaves)), RecordTx: strings.ToLower(tx),
		RecordBlock: int64(block), Recorder: strings.ToLower(recorder), SignedVotingPower: new(big.Int).Set(proof.SignedVotingPower),
		TotalVotingPower: new(big.Int).Set(proof.TotalVotingPower), QuorumProof: append([]byte(nil), proof.AggregateSignature...),
		EvidenceSource: database.BatchOutcomeEvidenceChain,
	}
	for i, a := range proof.ValidatorAddresses {
		rec.Signers = append(rec.Signers, strings.ToLower(a.Hex()))
		rec.SignerPowers = append(rec.SignerPowers, new(big.Int).Set(proof.VotingPowers[i]))
	}
	if agg != nil {
		rec.EvidenceSource = database.BatchOutcomeEvidenceRecorder
		rec.AggregateSignature = "0x" + strings.ToLower(strings.TrimPrefix(agg.AggregateSignatureHex, "0x"))
		rec.AggregatePublicKey = "0x" + strings.ToLower(strings.TrimPrefix(agg.AggregatePublicKeyHex, "0x"))
	}
	for _, l := range d.Leaves {
		lh, err := l.Hash()
		if err != nil {
			return nil, err
		}
		rec.Leaves = append(rec.Leaves, database.BatchOutcomeLeafRow{LeafIndex: int64(l.LeafIndex), BatchLeaf: h(l.BatchLeaf),
			OperationID: h(l.OperationID), Status: int(l.Status), Tx: h(l.Tx), BlockNumber: int64(l.BlockNumber), BlockHash: h(l.BlockHash),
			ReceiptsRoot: h(l.ReceiptsRoot), EffectsHash: h(l.EffectsHash), LeafHash: h(lh)})
	}
	return rec, nil
}

// =============================================================================
// The production submitter: the batch path's chain managers and nonce discipline
// =============================================================================

// ResolverOutcomeSubmitter folds against the anchor's on-chain registry and sends through the chain's manager - the
// same key, nonce sequence and outbox as every batch-lane transaction.
type ResolverOutcomeSubmitter struct{ Resolver EVMChainResolver }

func (s ResolverOutcomeSubmitter) ValidatorRegistry(ctx context.Context, chainID int64) (map[string]consensus.ValidatorRegistryEntry, error) {
	ecm, anchor, err := s.Resolver.ManagerForChain(chainID)
	if err != nil {
		return nil, err
	}
	return ReadValidatorRegistry(ctx, ecm, anchor)
}

// Submit simulates recordBatchOutcome first - a refusal is named (OutcomeRegistryError) and nothing is spent - then
// sends it inside the key's nonce sequence and returns its receipt.
func (s ResolverOutcomeSubmitter) Submit(ctx context.Context, chainID int64, registry common.Address, bundleID, root [32]byte,
	agg *consensus.QuorumAggregate, msg [32]byte) (*OutcomeSubmission, error) {
	ecm, _, err := s.Resolver.ManagerForChain(chainID)
	if err != nil {
		return nil, err
	}
	if ecm == nil || ecm.client == nil || ecm.auth == nil {
		return nil, fmt.Errorf("chain %d: no client or key to send with", chainID)
	}
	proof, _, err := ecm.BuildQuorumBLSProofData(agg, msg)
	if err != nil {
		return nil, err
	}
	reg, err := contracts.NewCertenOutcomeRegistryV1(registry, ecm.client)
	if err != nil {
		return nil, err
	}
	sub := &OutcomeSubmission{Proof: proof, Sender: strings.ToLower(ecm.SenderAddress().Hex())}
	data, err := reg.ABI().Pack("recordBatchOutcome", bundleID, root, proof)
	if err != nil {
		return nil, err
	}
	if _, err := ecm.client.CallContract(ctx, ethereum.CallMsg{From: ecm.auth.From, To: &registry, Data: data, Gas: outcomeRecordGas}, nil); err != nil {
		sub.RevertName = reg.OutcomeRegistryError(err)
		return sub, fmt.Errorf("simulating recordBatchOutcome: %w", err)
	}
	if err := ecm.beginNonceSequence(ctx); err != nil {
		return nil, err
	}
	defer ecm.endNonceSequence()
	owner := fmt.Sprintf("outcome:%d:0x%x", chainID, bundleID)
	rcpt, hash, err := ecm.sendBatchTx(ctx, "outcome", owner, outcomeRecordGas, func(opts *bind.TransactOpts) (*types.Transaction, error) {
		return reg.RecordBatchOutcome(opts, bundleID, root, proof)
	}, func(_ uint64, h string) { sub.Tx = h })
	if err != nil {
		return sub, err
	}
	sub.Tx, sub.Block, sub.Status = hash, rcpt.BlockNumber.Uint64(), rcpt.Status
	return sub, nil
}

// viewBlock names the block an agreed view was read at.
func viewBlock(v *OutcomeAnchorView) string {
	if v == nil || v.At == nil || v.At.Number == nil {
		return "(block unknown)"
	}
	return fmt.Sprintf("at block %d", v.At.Number.Uint64())
}
