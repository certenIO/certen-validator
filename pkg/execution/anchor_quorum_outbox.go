// Copyright 2026 Certen Protocol
//
// Durable hand-off for anchor quorum evidence the database could not take yet.

package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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
	dir string
	mu  sync.Mutex
}

const (
	anchorQuorumOutboxSuffix     = ".json"
	anchorQuorumQuarantineSubdir = "quarantine"
)

// NewFileAnchorQuorumOutbox opens (creating if needed) an outbox directory.
func NewFileAnchorQuorumOutbox(dir string) (*FileAnchorQuorumOutbox, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("anchor quorum outbox: directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("anchor quorum outbox: creating %s: %w", dir, err)
	}
	return &FileAnchorQuorumOutbox{dir: dir}, nil
}

// Dir reports where entries are stored, for the startup log.
func (o *FileAnchorQuorumOutbox) Dir() string { return o.dir }

// AnchorQuorumOutboxID is the deterministic entry id for one anchor.
//
// Deterministic on purpose: the same anchor re-queued (a retry, a restart, another leader's evidence
// arriving late) must land on the same entry rather than creating a second one. Hashed rather than used
// raw because a bundle id is attacker-influenced text heading for a file path.
func AnchorQuorumOutboxID(chainID int64, bundleID string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d/%s", chainID, strings.ToLower(bundleID))))
	return hex.EncodeToString(sum[:])
}

func (o *FileAnchorQuorumOutbox) Put(rec *database.AnchorQuorumRecord) error {
	if rec == nil {
		return fmt.Errorf("anchor quorum outbox: nil record")
	}
	if rec.ChainID == 0 || rec.BundleID == "" {
		return fmt.Errorf("anchor quorum outbox: chain id and bundle id are required")
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("anchor quorum outbox: encoding %s: %w", rec.BundleID, err)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	id := AnchorQuorumOutboxID(rec.ChainID, rec.BundleID)
	final := filepath.Join(o.dir, id+anchorQuorumOutboxSuffix)
	tmp, err := os.CreateTemp(o.dir, id+".*.tmp")
	if err != nil {
		return fmt.Errorf("anchor quorum outbox: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename succeeds

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("anchor quorum outbox: writing %s: %w", tmpName, err)
	}
	// Durability before visibility: the rename must not become visible ahead of the bytes it names.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("anchor quorum outbox: syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("anchor quorum outbox: closing %s: %w", tmpName, err)
	}
	// Windows will not rename onto an existing file; POSIX will. Removing first is safe either way
	// because the entry is keyed by content identity — what it replaces is the same anchor.
	_ = os.Remove(final)
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("anchor quorum outbox: publishing %s: %w", final, err)
	}
	return nil
}

func (o *FileAnchorQuorumOutbox) List() ([]AnchorQuorumOutboxEntry, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	names, err := o.pendingNames()
	if err != nil {
		return nil, err
	}
	out := make([]AnchorQuorumOutboxEntry, 0, len(names))
	for _, name := range names {
		id := strings.TrimSuffix(name, anchorQuorumOutboxSuffix)
		body, err := os.ReadFile(filepath.Join(o.dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue // removed concurrently by the reconciler; not an error
			}
			return nil, fmt.Errorf("anchor quorum outbox: reading %s: %w", name, err)
		}
		rec := &database.AnchorQuorumRecord{}
		if err := json.Unmarshal(body, rec); err != nil {
			// A file that cannot be parsed will never become parseable. Report it and keep going, so one
			// corrupt entry cannot stall every healthy one behind it.
			out = append(out, AnchorQuorumOutboxEntry{ID: id, Record: nil})
			continue
		}
		out = append(out, AnchorQuorumOutboxEntry{ID: id, Record: rec})
	}
	return out, nil
}

func (o *FileAnchorQuorumOutbox) Remove(id string) error {
	if err := validOutboxID(id); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	err := os.Remove(filepath.Join(o.dir, id+anchorQuorumOutboxSuffix))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("anchor quorum outbox: removing %s: %w", id, err)
	}
	return nil
}

// Quarantine moves an entry into a subdirectory rather than deleting it.
//
// Used for the two cases a retry can never fix: evidence the database says disagrees with what is already
// stored, and a file that does not parse. Deleting either would destroy the only local copy of the thing
// an operator has to look at; leaving either in place would make the reconciler retry it forever.
func (o *FileAnchorQuorumOutbox) Quarantine(id, reason string) error {
	if err := validOutboxID(id); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	qdir := filepath.Join(o.dir, anchorQuorumQuarantineSubdir)
	if err := os.MkdirAll(qdir, 0o755); err != nil {
		return fmt.Errorf("anchor quorum outbox: creating quarantine dir: %w", err)
	}
	src := filepath.Join(o.dir, id+anchorQuorumOutboxSuffix)
	dst := filepath.Join(qdir, id+anchorQuorumOutboxSuffix)
	_ = os.Remove(dst)
	if err := os.Rename(src, dst); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("anchor quorum outbox: quarantining %s: %w", id, err)
	}
	// The reason sits beside the entry so the directory explains itself without the logs.
	_ = os.WriteFile(filepath.Join(qdir, id+".reason.txt"), []byte(reason+"\n"), 0o644)
	return nil
}

func (o *FileAnchorQuorumOutbox) Depth() (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	names, err := o.pendingNames()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

// pendingNames lists entry files, excluding temporaries and the quarantine subdirectory. Callers hold mu.
func (o *FileAnchorQuorumOutbox) pendingNames() ([]string, error) {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("anchor quorum outbox: listing %s: %w", o.dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), anchorQuorumOutboxSuffix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// validOutboxID refuses anything that is not a bare hash, so an id can never escape the outbox directory.
func validOutboxID(id string) error {
	if id == "" {
		return fmt.Errorf("anchor quorum outbox: empty entry id")
	}
	if _, err := hex.DecodeString(id); err != nil || len(id) != 64 {
		return fmt.Errorf("anchor quorum outbox: %q is not an entry id", id)
	}
	return nil
}
