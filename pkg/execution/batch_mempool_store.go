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
}

// persistedMember is one queued batch member on disk.
type persistedMember struct {
	IntentID     string         `json:"intent_id"`
	ADIURL       string         `json:"adi_url"`
	ChainID      int64          `json:"chain_id"`
	Account      string         `json:"account"`
	OperationID  string         `json:"operation_id"`
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
			if pm, ok := s.encodeMember(p, LaneOnCadence); ok {
				out = append(out, pm)
			}
		}
	}
	// On-demand members live in their own index and must be snapshotted too, or a restart would
	// strand exactly the intents that were meant to settle fastest.
	for _, byOp := range m.onDemand {
		for _, p := range byOp {
			if pm, ok := s.encodeMember(p, LaneOnDemand); ok {
				out = append(out, pm)
			}
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
func (s *BatchMempoolStore) encodeMember(p *PendingBatchIntent, lane BatchLane) (persistedMember, bool) {
	if p == nil {
		return persistedMember{}, false
	}
	pm := persistedMember{
		IntentID:     p.IntentID,
		ADIURL:       p.ADIURL,
		ChainID:      p.ChainID,
		Account:      p.Account.Hex(),
		OperationID:  "0x" + common.Bytes2Hex(p.OperationID[:]),
		CommitHeight: p.CommitHeight,
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
			LegID:  l.LegID,
			Target: l.Target.Hex(),
			Value:  v,
			Data:   "0x" + common.Bytes2Hex(l.Data),
		})
	}
	if s.codec != nil && p.Attestation != nil {
		if raw, err := s.codec.Encode(p.Attestation); err == nil {
			pm.Attestation = raw
		} else {
			s.logf("[BATCH-STORE] intent %s: attestation not encodable (%v); persisting "+
				"the member without it — it can still settle but its proof cycle will not replay",
				p.IntentID, err)
		}
	}
	return pm, true
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
	if err != nil {
		s.logf("[BATCH-STORE] cannot read %s (%v); falling back to re-derivation from Accumulate", s.path, err)
		return 0, nil
	}
	var in []persistedMember
	if err := json.Unmarshal(blob, &in); err != nil {
		s.logf("[BATCH-STORE] %s is unreadable (%v); falling back to re-derivation from Accumulate", s.path, err)
		return 0, nil
	}

	restored := 0
	for _, pm := range in {
		// A member with no commit height could never be selected deterministically. Dropping it
		// here is the same rule Add enforces, applied to persisted state.
		if pm.CommitHeight == 0 || pm.IntentID == "" {
			continue
		}
		var opID [32]byte
		copy(opID[:], common.FromHex(pm.OperationID))

		p := &PendingBatchIntent{
			IntentID:     pm.IntentID,
			ADIURL:       pm.ADIURL,
			ChainID:      pm.ChainID,
			Account:      common.HexToAddress(pm.Account),
			OperationID:  opID,
			CommitHeight: pm.CommitHeight,
		}
		for _, l := range pm.Legs {
			v := new(big.Int)
			if _, ok := v.SetString(l.Value, 10); !ok {
				v = big.NewInt(0)
			}
			p.Legs = append(p.Legs, LegExecution{
				LegID: l.LegID,
				// Not persisted per leg: Add enforces that every leg targets the member's own
				// chain, so it is the member's ChainID by construction. Omitting it here left it
				// zero and the restore was silently rejected.
				ChainID: pm.ChainID,
				Target:  common.HexToAddress(l.Target),
				Value:   v,
				Data:    common.FromHex(l.Data),
			})
		}
		if s.codec != nil && len(pm.Attestation) > 0 {
			if att, derr := s.codec.Decode(pm.Attestation); derr == nil {
				p.Attestation = att
			} else {
				s.logf("[BATCH-STORE] intent %s: attestation not decodable (%v); restoring the "+
					"member without it", pm.IntentID, derr)
			}
		}
		// Route by lane. An unrecognised value restores to the period pool rather than being
		// dropped: that is where every member went before lanes existed, so an unknown lane
		// written by a NEWER binary degrades to slower settlement, never to a lost intent.
		//
		// m.add / m.addOnDemand, NOT the exported forms: those snapshot the queue, and this call
		// already holds s.mu, so re-entering Save here would deadlock. Load restores what is
		// already on disk, so re-writing it would be pointless as well as unsafe.
		var err error
		switch BatchLane(pm.Lane) {
		case LaneOnDemand:
			err = m.addOnDemand(p)
		default:
			err = m.add(p)
		}
		if err != nil {
			s.logf("[BATCH-STORE] intent %s not restored: %v", pm.IntentID, err)
			continue
		}
		restored++
	}
	return restored, nil
}
