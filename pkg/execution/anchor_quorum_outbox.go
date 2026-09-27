// Copyright 2026 Certen Protocol
//
// Durable hand-off for anchor quorum evidence the database could not take yet.

package execution

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/database"
)

// AnchorQuorumOutbox holds evidence that has been proven on-chain but not yet recorded in the database.
//
// # WHY IT IS ON DISK AND NOT IN A TABLE
//
// The runbook specifies "an anchor_quorum_outbox table". A table cannot serve this purpose: every way the
// in-memory hand-off loses a record is a way the database is unavailable or the process is dying —
//
//	queue full          the database is too slow to keep up
//	retries exhausted   the database is down
//	shutdown / crash    the process is going away with records still queued
//
// — so an outbox in that same database would need exactly the resource whose absence created the entry. It
// would work only in the one case that does not need it. The outbox therefore lives on local disk, beside
// the validator's other durable state, and survives both a database outage and a process restart.
//
// # WHAT IS AND IS NOT GUARANTEED
//
// An entry is written with a temporary file and an atomic rename, so a crash mid-write leaves either the
// previous entry or the new one, never half of one. Entries are keyed by (chain_id, bundle_id) — the same
// key the contract uses and the canonical row is stored under — so re-queuing the same anchor overwrites
// its own entry instead of accumulating duplicates.
//
// Disk loss is not covered, and does not need to be: the chain still holds the evidence, and
// `anchorquorumbackfill` reconstructs any anchor from it. The outbox removes the need for that to be a
// manual step in the ordinary case; it does not replace it as the backstop.
type AnchorQuorumOutbox interface {
	// Put stores one record durably, replacing any existing entry for the same anchor.
	Put(rec *database.AnchorQuorumRecord) error
	// List returns every pending entry, oldest key first.
	List() ([]AnchorQuorumOutboxEntry, error)
	// Remove deletes an entry that has been recorded (or is being quarantined).
	Remove(id string) error
	// Quarantine moves an entry aside for investigation instead of deleting it.
	Quarantine(id, reason string) error
	// Depth reports how many entries are pending.
	Depth() (int, error)
}

// AnchorQuorumOutboxEntry is one pending record and the id it is stored under.
type AnchorQuorumOutboxEntry struct {
	ID     string
	Record *database.AnchorQuorumRecord
}

// FileAnchorQuorumOutbox is the on-disk implementation: one JSON file per anchor.
type FileAnchorQuorumOutbox struct {
	store *jsonFileOutbox
}

// The on-disk layout, shared with every outbox (jsonFileOutbox).
const (
	anchorQuorumOutboxSuffix     = outboxSuffix
	anchorQuorumQuarantineSubdir = quarantineSubdir
)

// NewFileAnchorQuorumOutbox opens (creating if needed) an outbox directory.
func NewFileAnchorQuorumOutbox(dir string) (*FileAnchorQuorumOutbox, error) {
	store, err := newJSONFileOutbox("anchor quorum outbox", dir)
	if err != nil {
		return nil, err
	}
	return &FileAnchorQuorumOutbox{store: store}, nil
}

// Dir reports where entries are stored, for the startup log.
func (o *FileAnchorQuorumOutbox) Dir() string { return o.store.dir }

// AnchorQuorumOutboxID is the deterministic entry id for one anchor.
//
// Deterministic on purpose: the same anchor re-queued (a retry, a restart, another leader's evidence
// arriving late) must land on the same entry rather than creating a second one. Hashed rather than used
// raw because a bundle id is attacker-influenced text heading for a file path.
func AnchorQuorumOutboxID(chainID int64, bundleID string) string {
	return outboxID(fmt.Sprintf("%d/%s", chainID, strings.ToLower(bundleID)))
}

func (o *FileAnchorQuorumOutbox) Put(rec *database.AnchorQuorumRecord) error {
	if rec == nil {
		return fmt.Errorf("anchor quorum outbox: nil record")
	}
	if rec.ChainID == 0 || rec.BundleID == "" {
		return fmt.Errorf("anchor quorum outbox: chain id and bundle id are required")
	}
	return o.store.put(AnchorQuorumOutboxID(rec.ChainID, rec.BundleID), rec.BundleID, rec)
}

func (o *FileAnchorQuorumOutbox) List() ([]AnchorQuorumOutboxEntry, error) {
	raw, err := o.store.list()
	if err != nil {
		return nil, err
	}
	out := make([]AnchorQuorumOutboxEntry, 0, len(raw))
	for _, e := range raw {
		rec := &database.AnchorQuorumRecord{}
		if err := json.Unmarshal(e.Body, rec); err != nil {
			// A file that cannot be parsed will never become parseable. Report it and keep going, so one
			// corrupt entry cannot stall every healthy one behind it.
			out = append(out, AnchorQuorumOutboxEntry{ID: e.ID, Record: nil})
			continue
		}
		out = append(out, AnchorQuorumOutboxEntry{ID: e.ID, Record: rec})
	}
	return out, nil
}

func (o *FileAnchorQuorumOutbox) Remove(id string) error { return o.store.remove(id) }

// Quarantine moves an entry into a subdirectory rather than deleting it.
//
// Used for the two cases a retry can never fix: evidence the database says disagrees with what is already
// stored, and a file that does not parse. Deleting either would destroy the only local copy of the thing
// an operator has to look at; leaving either in place would make the reconciler retry it forever.
func (o *FileAnchorQuorumOutbox) Quarantine(id, reason string) error {
	return o.store.quarantine(id, reason)
}

func (o *FileAnchorQuorumOutbox) Depth() (int, error) { return o.store.depth() }
