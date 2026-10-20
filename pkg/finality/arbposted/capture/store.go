// Copyright 2026 Certen Protocol

// Package capture is the leg-independent CAPTURE phase of the Arbitrum Sepolia l1_posted kind (V2_SPEC_S7 section 2.8). Public
// Sepolia providers serve eth_getProof only near the head, while a kind is verifiable only once its L1 blocks are covered by a
// finalized head (13-19 minutes later), so everything the builder needs from L1 is captured on every parent-chain head, into an
// INSERT-ONLY store, and attested later from the stored bytes.
//
// A capture row is keyed (chain, l1Block, l1Hash, item). chain is the ROLLUP chain id the capture serves (421614), l1Block and
// l1Hash name the parent-chain block the row belongs to (a reorg yields a second row for the same height under another hash),
// and item is one of the names documented in records.go. A row is never updated or deleted; the same key with identical bytes
// is a no-op and with different bytes is ErrExists. Nothing here is ever read by a verifier.
package capture

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrExists: the key is already stored with different bytes. A capture row is insert-only.
var ErrExists = errors.New("capture: row exists with different bytes")

// Key addresses one capture row.
type Key struct {
	Chain   uint64
	L1Block uint64
	L1Hash  [32]byte
	Item    string
}

func (k Key) String() string {
	return fmt.Sprintf("chain %d l1 %d %x item %s", k.Chain, k.L1Block, k.L1Hash[:4], k.Item)
}

// Row is a key and its bytes.
type Row struct {
	Key   Key
	Bytes []byte
}

// itemRE is the shape of every item name: lower-case letters, digits, '_' and '-' separated by single '/'.
var itemRE = regexp.MustCompile(`^[a-z0-9_-]+(/[a-z0-9_-]+)*$`)

// CheckItem refuses an item name outside the documented alphabet (the DirStore maps '/' to '+' and must stay reversible).
func CheckItem(item string) error {
	if !itemRE.MatchString(item) || len(item) > 120 {
		return fmt.Errorf("capture: bad item name %q", item)
	}
	return nil
}

// CaptureStore is the insert-only row store. The production table is proof_finality_capture (RB11-B2B2); MemStore and DirStore
// implement the same contract for tests and for the live runner.
type CaptureStore interface {
	// Put inserts a row. Identical bytes under an existing key are a no-op (nil); different bytes are ErrExists.
	Put(k Key, b []byte) error
	// Get returns the bytes of a row.
	Get(k Key) ([]byte, bool, error)
	// List returns every row of (chain, l1Block), ascending by (l1Hash, item).
	List(chain, l1Block uint64) ([]Row, error)
	// Keys returns the keys of a chain whose item has the given prefix, ascending by (l1Block, l1Hash, item).
	Keys(chain uint64, itemPrefix string) ([]Key, error)
}

func sortKeys(ks []Key) {
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.L1Block != b.L1Block {
			return a.L1Block < b.L1Block
		}
		if c := bytes.Compare(a.L1Hash[:], b.L1Hash[:]); c != 0 {
			return c < 0
		}
		return a.Item < b.Item
	})
}

// MemStore is the in-memory CaptureStore.
type MemStore struct {
	mu   sync.Mutex
	rows map[Key][]byte
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{rows: map[Key][]byte{}} }

func (s *MemStore) Put(k Key, b []byte) error {
	if err := CheckItem(k.Item); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.rows[k]; ok {
		if bytes.Equal(old, b) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrExists, k)
	}
	s.rows[k] = append([]byte(nil), b...)
	return nil
}

func (s *MemStore) Get(k Key) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[k]
	return append([]byte(nil), b...), ok, nil
}

func (s *MemStore) List(chain, l1Block uint64) ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Row
	for k, b := range s.rows {
		if k.Chain == chain && k.L1Block == l1Block {
			out = append(out, Row{Key: k, Bytes: append([]byte(nil), b...)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Key.L1Hash[:], out[j].Key.L1Hash[:]); c != 0 {
			return c < 0
		}
		return out[i].Key.Item < out[j].Key.Item
	})
	return out, nil
}

func (s *MemStore) Keys(chain uint64, itemPrefix string) ([]Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Key
	for k := range s.rows {
		if k.Chain == chain && strings.HasPrefix(k.Item, itemPrefix) {
			out = append(out, k)
		}
	}
	sortKeys(out)
	return out, nil
}

// DirStore keeps rows as files: <dir>/<chain>/<l1Block>-<l1Hash hex>/<item with '/' as '+'>. It survives a restart; a row is
// written to a temporary file and linked into place only if absent, so a crash never leaves a partial row under its key.
type DirStore struct {
	dir string
	mu  sync.Mutex
}

// NewDirStore opens (creating it if needed) a store under dir.
func NewDirStore(dir string) (*DirStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &DirStore{dir: dir}, nil
}

func (s *DirStore) path(k Key) string {
	return filepath.Join(s.dir, strconv.FormatUint(k.Chain, 10), fmt.Sprintf("%d-%s", k.L1Block, hex.EncodeToString(k.L1Hash[:])), strings.ReplaceAll(k.Item, "/", "+"))
}

func (s *DirStore) Put(k Key, b []byte) error {
	if err := CheckItem(k.Item); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.path(k)
	if old, err := os.ReadFile(p); err == nil {
		if bytes.Equal(old, b) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrExists, k)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(name)
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Link(name, p); err != nil {
		os.Remove(name)
		return err
	}
	return os.Remove(name)
}

func (s *DirStore) Get(k Key) ([]byte, bool, error) {
	b, err := os.ReadFile(s.path(k))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func parseDirName(name string) (uint64, [32]byte, bool) {
	var h [32]byte
	i := strings.IndexByte(name, '-')
	if i <= 0 {
		return 0, h, false
	}
	n, err := strconv.ParseUint(name[:i], 10, 64)
	if err != nil {
		return 0, h, false
	}
	hb, err := hex.DecodeString(name[i+1:])
	if err != nil || len(hb) != 32 {
		return 0, h, false
	}
	copy(h[:], hb)
	return n, h, true
}

func (s *DirStore) blockDirs(chain uint64) ([]os.DirEntry, error) {
	ents, err := os.ReadDir(filepath.Join(s.dir, strconv.FormatUint(chain, 10)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return ents, err
}

func (s *DirStore) List(chain, l1Block uint64) ([]Row, error) {
	ents, err := s.blockDirs(chain)
	if err != nil {
		return nil, err
	}
	var out []Row
	for _, e := range ents {
		n, h, ok := parseDirName(e.Name())
		if !ok || !e.IsDir() || n != l1Block {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, strconv.FormatUint(chain, 10), e.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".put-") {
				continue
			}
			item := strings.ReplaceAll(f.Name(), "+", "/")
			k := Key{Chain: chain, L1Block: n, L1Hash: h, Item: item}
			b, err := os.ReadFile(s.path(k))
			if err != nil {
				return nil, err
			}
			out = append(out, Row{Key: k, Bytes: b})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Key.L1Hash[:], out[j].Key.L1Hash[:]); c != 0 {
			return c < 0
		}
		return out[i].Key.Item < out[j].Key.Item
	})
	return out, nil
}

func (s *DirStore) Keys(chain uint64, itemPrefix string) ([]Key, error) {
	ents, err := s.blockDirs(chain)
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, e := range ents {
		n, h, ok := parseDirName(e.Name())
		if !ok || !e.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, strconv.FormatUint(chain, 10), e.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".put-") {
				continue
			}
			item := strings.ReplaceAll(f.Name(), "+", "/")
			if strings.HasPrefix(item, itemPrefix) {
				out = append(out, Key{Chain: chain, L1Block: n, L1Hash: h, Item: item})
			}
		}
	}
	sortKeys(out)
	return out, nil
}
