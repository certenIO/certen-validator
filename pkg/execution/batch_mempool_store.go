package execution

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// Mempool durability
// =============================================================================
//
// # THE FAILURE THIS CLOSES
//
// The mempool is in-memory. A restart emptied it, but the consensus round had already returned
// batch_queued and the intent therefore took no other path. It was neither settled, failed, nor
// retried — the one outcome the whole failure policy exists to prevent, and the fallback could
// not fire because the process holding the member no longer existed.
//
// The discovery watermark rewind mitigates this by re-deriving members from committed
// Accumulate state, and that remains the backstop. It is not a complete answer on its own:
//
//   - it only works while the intent still falls inside the rewind window;
//   - it re-runs L1-L3 and G0/G1/G2 from scratch, minutes per intent;
//   - and a RESTARTED PEER cannot attest until that re-derivation finishes, so a rolling deploy
//     can drop a batch below quorum even though every node is healthy.
//
// Persisting the queue removes all three. Restart resumes with the members already in hand.
//
// # WHY PERSISTING IS SAFE
//
// Membership stays a pure function of committed state — this stores a derivation, it does not
// become the authority for one. A restored member carries the same CommitHeight, so it lands in
// exactly the same period and produces the same leaf, root and bundleId it would have produced
// had the process never stopped. Nothing about determinism depends on the file.
//
// Replay is safe for the same reasons re-derivation is: leaves are single-use on chain, the
// bundleId is deterministic, and FlushChain short-circuits an already-attested anchor and
// releases its members without re-executing.
//
// # WHY JSON AND A PLAIN FILE
//
// The member is small and the write is off the hot path (enqueue and flush only). A file keeps
// this independent of the ledger store's schema, so a corrupt or missing snapshot degrades to
// exactly today's behaviour — re-derivation — rather than failing the validator.

// persistedLeg mirrors LegExecution with JSON-safe types.
type persistedLeg struct {
	LegID  string `json:"leg_id"`
	Target string `json:"target"`
	Value  string `json:"value"`
	Data   string `json:"data"`
	// Deadline: omitempty, for the same version-skew reason as persistedMember.Lane.
	Deadline int64 `json:"deadline,omitempty"`
}

// persistedMember is one queued batch member on disk.
type persistedMember struct {
	IntentID    string `json:"intent_id"`
	ADIURL      string `json:"adi_url"`
	ChainID     int64  `json:"chain_id"`
	Account     string `json:"account"`
	OperationID string `json:"operation_id"`
	// AccumTxHash is omitempty for the same version-skew reason as Lane below: an old file restores it
	// empty, which is honest, and an old binary ignores it.
	AccumTxHash  string         `json:"accum_tx_hash,omitempty"`
	Legs         []persistedLeg `json:"legs"`
	CommitHeight uint64         `json:"commit_height"`
	// Lane routes the member back to the structure that owns it. Absent means on_cadence.
	//
	// WHY THE FILE STAYS A BARE ARRAY, AND WHY THE DEFAULT IS SAFE. Both directions of a
	// version skew have to work, and with `omitempty` they do:
	//
	//   - Old file, new binary: no member carries a lane, so every one restores to the period
	//     pool. Correct — that is where on-demand intents go today, since the enqueue has never
	//     been gated on proofClass.
	//   - New file, old binary: encoding/json ignores the unknown field and the old binary
	//     restores every member into the period pool, which is exactly its current behaviour.
	//
	// Turning the file into an object keyed by lane would break the second case: the old
	// binary's json.Unmarshal into []persistedMember would fail and it would drop the WHOLE
	// queue back to re-derivation. So the discriminator goes on the member, not the container.
	//
	// omitempty also keeps the snapshot byte-identical to today whenever no on-demand member is
	// queued, so this change produces no file churn on its own.
	Lane string `json:"lane,omitempty"`
	// Attestation is the Phase 7-9 snapshot, stored as opaque JSON. The concrete type lives in
	// pkg/consensus, which this package must not import, so it is re-attached on load by a
	// decoder the wiring supplies.
	Attestation json.RawMessage `json:"attestation,omitempty"`
	// This validator's own settlement progress on an on-demand member. omitempty for the same
	// version-skew reason as Lane.
	AnchorProved    bool   `json:"anchor_proved,omitempty"`
	AnchorTx        string `json:"anchor_tx,omitempty"`
	VerifyTx        string `json:"verify_tx,omitempty"`
	AnchorBlock     uint64 `json:"anchor_block,omitempty"`
	AttestedSeen    bool   `json:"attested_seen,omitempty"`
	FirstSeen       int64  `json:"first_seen,omitempty"` // unix seconds
	CommitPartition string `json:"commit_partition,omitempty"`
	CommitTimeMs    int64  `json:"commit_time_ms,omitempty"` // unix milliseconds
	// The commit block (RB5-F57); omitempty, for the same version-skew reason as Lane.
	ExecPartition      string   `json:"exec_partition,omitempty"`
	ExecBlock          uint64   `json:"exec_block,omitempty"`
	SettlementTx       string   `json:"settlement_tx,omitempty"`
	SettlementTxs      []string `json:"settlement_txs,omitempty"`
	SettlementNonce    uint64   `json:"settlement_nonce,omitempty"`
	SettlementNonceSet bool     `json:"settlement_nonce_set,omitempty"`
	// Outcome is the member's terminal outcome here; absent while it is pending. omitempty for the
	// same version-skew reason as Lane: an older binary restores such a member as pending, and its
	// settlement pre-check finds the leaf already consumed.
	Outcome string `json:"outcome,omitempty"`
	// After and SequencePosition: a successor in a sequential cross-chain intent (batch_sequence.go).
	// omitempty for the same version-skew reason as Lane.
	After            *persistedPredecessor `json:"after,omitempty"`
	SequencePosition int                   `json:"sequence_position,omitempty"`
	// GovernanceCommitment is the commitment to who decided the intent (RB4-F66), 0x-hex. Absent on a member
	// written before it existed: that member restores as LegacyNoGovernance and is batched with the v1 operation
	// id its anchor may already carry. omitempty for the same version-skew reason as Lane.
	GovernanceCommitment string `json:"governance_commitment,omitempty"`
	// AccumulateSetRoot is the root of the Accumulate validator set the member's proof was verified against (RB5 D2),
	// 0x-hex. Required: a member written without it was admitted for the retired V8.1 anchor, which its intent still
	// declares, and it cannot be settled on V8.2 - the restore refuses it by name (drain before the V8.2 rollout).
	AccumulateSetRoot string `json:"accumulate_set_root,omitempty"`
	// IntentMessage is the intent message this validator's block signed (RB5 D3), 0x-hex; absent for a member
	// committed before a BLS registry was in force. The certified message is re-read from the chain's record.
	IntentMessage string `json:"intent_message,omitempty"`
}

// persistedPredecessor is a MemberPredecessor on disk.
type persistedPredecessor struct {
	ChainID             int64  `json:"chain_id"`
	OperationID         string `json:"operation_id"`
	Account             string `json:"account"`
	ADIURL              string `json:"adi_url"`
	ExecutionCommitment string `json:"execution_commitment"`
	Deadline            int64  `json:"deadline"` // unix seconds
	ContinueOnFailure   bool   `json:"continue_on_failure,omitempty"`
}

// AttestationCodec converts the opaque Phase 7-9 snapshot to and from JSON.
//
// Supplied by the wiring because the concrete type (*consensus.PendingAttestation) belongs to a
// package this one cannot import. A nil codec means members persist WITHOUT their snapshot: they
// still settle, but their proof cycle cannot be replayed, so the wiring should always provide
// one in production.
type AttestationCodec interface {
	Encode(interface{}) (json.RawMessage, error)
	Decode(json.RawMessage) (interface{}, error)
}

// BatchMempoolStore persists queued members across restarts.
type BatchMempoolStore struct {
	path  string
	codec AttestationCodec
	logf  func(string, ...interface{})

	mu sync.Mutex
}

// NewBatchMempoolStore opens (or creates) the snapshot at path.
func NewBatchMempoolStore(path string, codec AttestationCodec, logf func(string, ...interface{})) (*BatchMempoolStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("batch mempool store path is empty")
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	return &BatchMempoolStore{path: path, codec: codec, logf: logf}, nil
}

// Save writes the whole queue.
//
// Written to a temporary file and renamed, so a crash mid-write leaves the previous snapshot
// intact rather than a truncated one. A half-written queue would be worse than none: it could
// restore a SUBSET of a period's members, and this node would then derive a different bundleId
// from its peers and refuse to attest — the silent divergence the design exists to prevent.
func (s *BatchMempoolStore) Save(m *BatchMempool) error {
	if s == nil || m == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	m.mu.Lock()
	var out []persistedMember
	for _, members := range m.pool {
		for _, p := range members {
			pm, err := s.encodeMember(p, LaneOnCadence)
			if err != nil {
				m.mu.Unlock()
				return fmt.Errorf("encoding batch mempool: %w", err)
			}
			out = append(out, pm)
		}
	}
	// On-demand members live in their own index and must be snapshotted too, or a restart would
	// strand exactly the intents that were meant to settle fastest.
	for _, byOp := range m.onDemand {
		for _, p := range byOp {
			pm, err := s.encodeMember(p, LaneOnDemand)
			if err != nil {
				m.mu.Unlock()
				return fmt.Errorf("encoding batch mempool: %w", err)
			}
			out = append(out, pm)
		}
	}
	m.mu.Unlock()

	// Deterministic ordering keeps the file diffable and makes an operator comparison across
	// nodes meaningful. Lane is part of the key so the order is total even if the same intent
	// were briefly present in both structures during a rollout.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CommitHeight != out[j].CommitHeight {
			return out[i].CommitHeight < out[j].CommitHeight
		}
		if out[i].IntentID != out[j].IntentID {
			return out[i].IntentID < out[j].IntentID
		}
		if out[i].ChainID != out[j].ChainID {
			return out[i].ChainID < out[j].ChainID
		}
		return out[i].Lane < out[j].Lane
	})

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding batch mempool: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("writing batch mempool snapshot: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replacing batch mempool snapshot: %w", err)
	}
	return nil
}

// encodeMember converts one in-memory member to its on-disk form. Caller holds m.mu.
//
// Shared by both lanes so a field added to one can never be silently missing from the other —
// a member restored without its legs or its attestation is a member that cannot settle.
func (s *BatchMempoolStore) encodeMember(p *PendingBatchIntent, lane BatchLane) (persistedMember, error) {
	if p == nil {
		return persistedMember{}, fmt.Errorf("a nil member in the %s lane", lane)
	}
	pm := persistedMember{
		IntentID:           p.IntentID,
		ADIURL:             p.ADIURL,
		ChainID:            p.ChainID,
		Account:            p.Account.Hex(),
		OperationID:        "0x" + common.Bytes2Hex(p.OperationID[:]),
		AccumTxHash:        p.AccumTxHash,
		CommitHeight:       p.CommitHeight,
		AnchorProved:       p.AnchorProved,
		AnchorTx:           p.AnchorTx,
		VerifyTx:           p.VerifyTx,
		AnchorBlock:        p.AnchorBlock,
		AttestedSeen:       p.AttestedSeen,
		FirstSeen:          unixOrZero(p.FirstSeen),
		CommitPartition:    p.CommitPartition,
		CommitTimeMs:       unixMilliOrZero(p.CommitTime),
		ExecPartition:      p.ExecPartition,
		ExecBlock:          p.ExecBlock,
		SettlementTx:       p.SettlementTx,
		SettlementTxs:      append([]string(nil), p.SettlementTxs...),
		SettlementNonce:    p.SettlementNonce,
		SettlementNonceSet: p.SettlementNonceSet,
		Outcome:            string(p.Outcome),
		SequencePosition:   p.SequencePosition,
	}
	switch {
	case p.LegacyNoGovernance:
		// Absent: it restores as the legacy member it is.
	case p.GovernanceCommitment == ([32]byte{}):
		return persistedMember{}, fmt.Errorf("intent %s on chain %d has no governance commitment and is not a member "+
			"admitted before commitments existed", p.IntentID, p.ChainID)
	default:
		pm.GovernanceCommitment = "0x" + common.Bytes2Hex(p.GovernanceCommitment[:])
	}
	if p.AccumulateSetRoot == ([32]byte{}) {
		return persistedMember{}, fmt.Errorf("intent %s on chain %d has no Accumulate validator set root", p.IntentID, p.ChainID)
	}
	pm.AccumulateSetRoot = "0x" + common.Bytes2Hex(p.AccumulateSetRoot[:])
	if p.IntentMessage != ([32]byte{}) {
		pm.IntentMessage = "0x" + common.Bytes2Hex(p.IntentMessage[:])
	}
	if a := p.After; a != nil {
		pm.After = &persistedPredecessor{
			ChainID: a.ChainID, OperationID: "0x" + common.Bytes2Hex(a.OperationID[:]), Account: a.Account.Hex(),
			ADIURL: a.ADIURL, ExecutionCommitment: "0x" + common.Bytes2Hex(a.ExecutionCommitment[:]),
			Deadline: a.Deadline.Unix(), ContinueOnFailure: a.ContinueOnFailure,
		}
	}
	// on_cadence is the absent default, so it is never written. See persistedMember.Lane.
	if lane == LaneOnDemand {
		pm.Lane = string(LaneOnDemand)
	}
	for _, l := range p.Legs {
		v := "0"
		if l.Value != nil {
			v = l.Value.String()
		}
		pm.Legs = append(pm.Legs, persistedLeg{
			LegID:    l.LegID,
			Target:   l.Target.Hex(),
			Value:    v,
			Data:     "0x" + common.Bytes2Hex(l.Data),
			Deadline: l.Deadline,
		})
	}
	if s.codec != nil && p.Attestation != nil {
		// Encoded or the snapshot fails: a member saved without its attestation settles but its proof
		// cycle can never replay after a restart. It used to be saved without it (RB3 sweep).
		raw, err := s.codec.Encode(p.Attestation)
		if err != nil {
			return pm, fmt.Errorf("intent %s: attestation does not encode: %w", p.IntentID, err)
		}
		pm.Attestation = raw
	}
	return pm, nil
}

// Load restores members into the mempool and reports how many were restored.
//
// A missing or unreadable snapshot is NOT an error: the validator falls back to re-deriving
// from Accumulate via the discovery watermark rewind, which is the behaviour it had before this
// existed. Refusing to start would turn a recoverable situation into an outage.
func (s *BatchMempoolStore) Load(m *BatchMempool) (int, error) {
	if s == nil || m == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	blob, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	// The queue on disk is restored whole or the node does not start, and the file is left where it is
	// for the operator. Every path below used to drop what it could not read - the file ("falling back to
	// re-derivation from Accumulate", which cannot recover a member's anchor, settlement transactions or
	// nonce), a member without its commit height, a leg value that did not parse (it became 0), an
	// attestation that did not decode, a lane this binary does not know - with at most a log line
	// (RB3 sweep).
	if err != nil {
		return 0, fmt.Errorf("batch mempool %s cannot be read: %w", s.path, err)
	}
	var in []persistedMember
	if err := json.Unmarshal(blob, &in); err != nil {
		return 0, fmt.Errorf("batch mempool %s does not decode: %w", s.path, err)
	}

	restored := 0
	for _, pm := range in {
		// A member with no commit height could never be selected deterministically. Dropping it
		// here is the same rule Add enforces, applied to persisted state.
		if pm.CommitHeight == 0 || pm.IntentID == "" {
			return restored, fmt.Errorf("batch mempool %s: a member (intent %q, chain %d) has no commit height or intent id", s.path, pm.IntentID, pm.ChainID)
		}
		var opID [32]byte
		rawOp := common.FromHex(pm.OperationID)
		if len(rawOp) != 32 {
			// It used to be copied as it came: a short id restored zero-padded, a long one truncated.
			return restored, fmt.Errorf("batch mempool %s: intent %s on chain %d: operation id %q is not 32 bytes",
				s.path, pm.IntentID, pm.ChainID, pm.OperationID)
		}
		copy(opID[:], rawOp)
		var governance [32]byte
		legacy := pm.GovernanceCommitment == ""
		if !legacy {
			raw := common.FromHex(pm.GovernanceCommitment)
			if len(raw) != 32 || common.BytesToHash(raw) == (common.Hash{}) {
				return restored, fmt.Errorf("batch mempool %s: intent %s on chain %d: governance commitment %q is not a "+
					"32-byte commitment", s.path, pm.IntentID, pm.ChainID, pm.GovernanceCommitment)
			}
			copy(governance[:], raw)
		}

		var accSetRoot [32]byte
		rawAcc := common.FromHex(pm.AccumulateSetRoot)
		if len(rawAcc) != 32 || common.BytesToHash(rawAcc) == (common.Hash{}) {
			return restored, fmt.Errorf("batch mempool %s: intent %s on chain %d carries no Accumulate validator set root "+
				"(%q): it was admitted for the retired V8.1 anchor its intent declares and cannot settle on V8.2; drain the "+
				"batch path before deploying the V8.2 rollout", s.path, pm.IntentID, pm.ChainID, pm.AccumulateSetRoot)
		}
		copy(accSetRoot[:], rawAcc)

		var intentMessage [32]byte
		if pm.IntentMessage != "" {
			raw := common.FromHex(pm.IntentMessage)
			if len(raw) != 32 || common.BytesToHash(raw) == (common.Hash{}) {
				return restored, fmt.Errorf("batch mempool %s: intent %s on chain %d: intent message %q is not a 32-byte "+
					"message", s.path, pm.IntentID, pm.ChainID, pm.IntentMessage)
			}
			copy(intentMessage[:], raw)
		}

		p := &PendingBatchIntent{
			AccumulateSetRoot:    accSetRoot,
			IntentMessage:        intentMessage,
			IntentID:             pm.IntentID,
			ADIURL:               pm.ADIURL,
			ChainID:              pm.ChainID,
			Account:              common.HexToAddress(pm.Account),
			OperationID:          opID,
			GovernanceCommitment: governance,
			LegacyNoGovernance:   legacy,
			AccumTxHash:          pm.AccumTxHash,
			CommitHeight:         pm.CommitHeight,
			AnchorProved:         pm.AnchorProved,
			AnchorTx:             pm.AnchorTx,
			VerifyTx:             pm.VerifyTx,
			AnchorBlock:          pm.AnchorBlock,
			AttestedSeen:         pm.AttestedSeen,
			FirstSeen:            timeOrZero(pm.FirstSeen),
			CommitPartition:      pm.CommitPartition,
			CommitTime:           timeOrZeroMilli(pm.CommitTimeMs),
			ExecPartition:        pm.ExecPartition,
			ExecBlock:            pm.ExecBlock,
			SettlementTx:         pm.SettlementTx,
			SettlementTxs:        pm.SettlementTxs,
			SettlementNonce:      pm.SettlementNonce,
			SettlementNonceSet:   pm.SettlementNonceSet,
			Outcome:              MemberOutcome(pm.Outcome),
			SequencePosition:     pm.SequencePosition,
		}
		if a := pm.After; a != nil {
			op, exec := common.FromHex(a.OperationID), common.FromHex(a.ExecutionCommitment)
			if len(op) != 32 || len(exec) != 32 || a.ADIURL == "" || a.Deadline <= 0 {
				// A successor restored without its predecessor would settle out of its declared order. A record from
				// before RB5-F29 carries a v1 leaf and no leaf inputs: its predecessor's v2 leaf cannot be formed.
				return restored, fmt.Errorf("batch mempool %s: intent %s on chain %d: its predecessor record is malformed "+
					"or carries no leaf inputs, and without it the member would settle out of its declared order",
					s.path, pm.IntentID, pm.ChainID)
			}
			pred := &MemberPredecessor{ChainID: a.ChainID, Account: common.HexToAddress(a.Account), ADIURL: a.ADIURL,
				Deadline: time.Unix(a.Deadline, 0).UTC(), ContinueOnFailure: a.ContinueOnFailure}
			copy(pred.OperationID[:], op)
			copy(pred.ExecutionCommitment[:], exec)
			p.After = pred
		}
		for _, l := range pm.Legs {
			v, ok := new(big.Int).SetString(l.Value, 10)
			if !ok {
				return restored, fmt.Errorf("batch mempool %s: intent %s leg %s: value %q is not an integer", s.path, pm.IntentID, l.LegID, l.Value)
			}
			p.Legs = append(p.Legs, LegExecution{
				LegID: l.LegID,
				// Not persisted per leg: Add enforces that every leg targets the member's own
				// chain, so it is the member's ChainID by construction. Omitting it here left it
				// zero and the restore was silently rejected.
				ChainID:  pm.ChainID,
				Target:   common.HexToAddress(l.Target),
				Value:    v,
				Data:     common.FromHex(l.Data),
				Deadline: l.Deadline,
			})
		}
		if s.codec != nil && len(pm.Attestation) > 0 {
			att, derr := s.codec.Decode(pm.Attestation)
			if derr != nil {
				return restored, fmt.Errorf("batch mempool %s: intent %s: attestation does not decode: %w", s.path, pm.IntentID, derr)
			}
			p.Attestation = att
		}
		// Route by lane. An empty lane is a member written before lanes existed: the period pool, where
		// every member then went. A lane this binary does not know is refused, not re-routed.
		//
		// m.add / m.addOnDemand, NOT the exported forms: those snapshot the queue, and this call
		// already holds s.mu, so re-entering Save here would deadlock. Load restores what is
		// already on disk, so re-writing it would be pointless as well as unsafe.
		var err error
		switch BatchLane(pm.Lane) {
		case LaneOnDemand:
			err = m.addOnDemand(p)
		case LaneOnCadence, "":
			err = m.add(p)
		default:
			return restored, fmt.Errorf("batch mempool %s: intent %s: lane %q is not one this binary settles", s.path, pm.IntentID, pm.Lane)
		}
		if err != nil {
			return restored, fmt.Errorf("batch mempool %s: intent %s not restored: %w", s.path, pm.IntentID, err)
		}
		restored++
	}
	return restored, nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func unixMilliOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func timeOrZeroMilli(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
