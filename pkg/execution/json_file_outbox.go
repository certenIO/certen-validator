// Copyright 2026 Certen Protocol
//
// The durable on-disk hand-off shared by the validator's outboxes.

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
)

// jsonFileOutbox keeps records the database could not take yet, one JSON file per record, on local disk -
// every way a record fails to reach the database is a way the database is unavailable or the process is
// going away, so the hand-off cannot live in that database (see AnchorQuorumOutbox).
//
// An entry is written with a temporary file and an atomic rename, so a crash mid-write leaves either the
// previous entry or the new one. Entries are keyed by a deterministic id, so re-queuing the same record
// replaces its own entry. Entries a retry can never fix are quarantined beside a reason, never deleted.
type jsonFileOutbox struct {
	label string // e.g. "anchor quorum outbox", prefixes every error
	dir   string
	mu    sync.Mutex
}

const (
	outboxSuffix     = ".json"
	quarantineSubdir = "quarantine"
)

func newJSONFileOutbox(label, dir string) (*jsonFileOutbox, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%s: directory is required", label)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("%s: creating %s: %w", label, dir, err)
	}
	return &jsonFileOutbox{label: label, dir: dir}, nil
}

// outboxID is a deterministic entry id: the hash of the record's identity, so an id is never
// attacker-influenced text heading for a file path.
func outboxID(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

// put stores v under id durably, replacing any existing entry with that id.
func (o *jsonFileOutbox) put(id, name string, v interface{}) error {
	if err := o.validID(id); err != nil {
		return err
	}
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%s: encoding %s: %w", o.label, name, err)
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	final := filepath.Join(o.dir, id+outboxSuffix)
	tmp, err := os.CreateTemp(o.dir, id+".*.tmp")
	if err != nil {
		return fmt.Errorf("%s: creating temp file: %w", o.label, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename succeeds

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: writing %s: %w", o.label, tmpName, err)
	}
	// Durability before visibility: the rename must not become visible ahead of the bytes it names.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%s: syncing %s: %w", o.label, tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%s: closing %s: %w", o.label, tmpName, err)
	}
	// Windows will not rename onto an existing file; POSIX will. Removing first is safe either way
	// because the entry is keyed by the record's identity - what it replaces is the same record.
	_ = os.Remove(final)
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("%s: publishing %s: %w", o.label, final, err)
	}
	return nil
}

// rawEntry is one pending entry's id and bytes.
type rawEntry struct {
	ID   string
	Body []byte
}

// list returns every pending entry, oldest key first.
func (o *jsonFileOutbox) list() ([]rawEntry, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	names, err := o.pendingNames()
	if err != nil {
		return nil, err
	}
	out := make([]rawEntry, 0, len(names))
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(o.dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue // removed concurrently by the reconciler; not an error
			}
			return nil, fmt.Errorf("%s: reading %s: %w", o.label, name, err)
		}
		out = append(out, rawEntry{ID: strings.TrimSuffix(name, outboxSuffix), Body: body})
	}
	return out, nil
}

func (o *jsonFileOutbox) remove(id string) error {
	if err := o.validID(id); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	err := os.Remove(filepath.Join(o.dir, id+outboxSuffix))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%s: removing %s: %w", o.label, id, err)
	}
	return nil
}

// quarantine moves an entry into a subdirectory, with its reason beside it, rather than deleting it.
func (o *jsonFileOutbox) quarantine(id, reason string) error {
	if err := o.validID(id); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	qdir := filepath.Join(o.dir, quarantineSubdir)
	if err := os.MkdirAll(qdir, 0o755); err != nil {
		return fmt.Errorf("%s: creating quarantine dir: %w", o.label, err)
	}
	src := filepath.Join(o.dir, id+outboxSuffix)
	dst := filepath.Join(qdir, id+outboxSuffix)
	_ = os.Remove(dst)
	if err := os.Rename(src, dst); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s: quarantining %s: %w", o.label, id, err)
	}
	// The reason sits beside the entry so the directory explains itself without the logs.
	_ = os.WriteFile(filepath.Join(qdir, id+".reason.txt"), []byte(reason+"\n"), 0o644)
	return nil
}

func (o *jsonFileOutbox) depth() (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	names, err := o.pendingNames()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

// pendingNames lists entry files, excluding temporaries and the quarantine subdirectory. Callers hold mu.
func (o *jsonFileOutbox) pendingNames() ([]string, error) {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: listing %s: %w", o.label, o.dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), outboxSuffix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// validID refuses anything that is not a bare hash, so an id can never escape the outbox directory.
func (o *jsonFileOutbox) validID(id string) error {
	if id == "" {
		return fmt.Errorf("%s: empty entry id", o.label)
	}
	if _, err := hex.DecodeString(id); err != nil || len(id) != 64 {
		return fmt.Errorf("%s: %q is not an entry id", o.label, id)
	}
	return nil
}
