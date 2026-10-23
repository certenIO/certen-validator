// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MaxCaptureBlock is the largest L1 block number a CaptureStore addresses: the production column is a signed 64-bit integer, so
// an unbounded range scan passes this, never math.MaxUint64.
const MaxCaptureBlock uint64 = math.MaxInt64

func sameOrConflict(old, data []byte, k CaptureKey) error {
	if bytes.Equal(old, data) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrCaptureConflict, k)
}

func sortCaptureKeys(ks []CaptureKey) {
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

func sortCaptureRows(rs []CaptureRow) {
	sort.Slice(rs, func(i, j int) bool {
		if c := bytes.Compare(rs[i].L1Hash[:], rs[j].L1Hash[:]); c != 0 {
			return c < 0
		}
		return rs[i].Item < rs[j].Item
	})
}

// CaptureKeysOfItem returns the keys of a chain that hold exactly the item, ascending by (l1Block, l1Hash): the question the
// builders ask of the store ("which L1 blocks did the capturer record this item for"). ListByRange matches an item PREFIX, so
// the exact name is filtered here.
func CaptureKeysOfItem(ctx context.Context, s CaptureStore, chain uint64, item string) ([]CaptureKey, error) {
	ks, err := s.ListByRange(ctx, chain, 0, MaxCaptureBlock, item)
	if err != nil {
		return nil, err
	}
	out := ks[:0:0]
	for _, k := range ks {
		if k.Item == item {
			out = append(out, k)
		}
	}
	return out, nil
}

// CaptureRowsOfItem returns every row of a chain that holds exactly the item, with its bytes, ascending by (l1Block, l1Hash).
func CaptureRowsOfItem(ctx context.Context, s CaptureStore, chain uint64, item string) ([]CaptureRow, error) {
	ks, err := CaptureKeysOfItem(ctx, s, chain, item)
	if err != nil {
		return nil, err
	}
	out := make([]CaptureRow, 0, len(ks))
	for _, k := range ks {
		b, ok, err := s.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("finality: capture row listed but not readable: %s", k)
		}
		out = append(out, CaptureRow{CaptureKey: k, Bytes: b})
	}
	return out, nil
}

// MemCaptureStore is the in-memory CaptureStore of tests and one-shot recorders. Rows are insert-only like the production table.
// The zero value is an empty store.
type MemCaptureStore struct {
	mu   sync.Mutex
	rows map[CaptureKey][]byte
}

// NewMemCaptureStore returns an empty store.
func NewMemCaptureStore() *MemCaptureStore { return &MemCaptureStore{rows: map[CaptureKey][]byte{}} }

// Put implements CaptureStore.
func (m *MemCaptureStore) Put(_ context.Context, k CaptureKey, data []byte) error {
	if err := CheckCaptureItem(k.Item); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.rows[k]; ok {
		return sameOrConflict(old, data, k)
	}
	if m.rows == nil {
		m.rows = map[CaptureKey][]byte{}
	}
	m.rows[k] = append([]byte(nil), data...)
	return nil
}

// Get implements CaptureStore.
func (m *MemCaptureStore) Get(_ context.Context, k CaptureKey) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.rows[k]
	return append([]byte(nil), b...), ok, nil
}

// ListByBlock implements CaptureStore.
func (m *MemCaptureStore) ListByBlock(_ context.Context, chain, l1Block uint64) ([]CaptureRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CaptureRow
	for k, b := range m.rows {
		if k.Chain == chain && k.L1Block == l1Block {
			out = append(out, CaptureRow{CaptureKey: k, Bytes: append([]byte(nil), b...)})
		}
	}
	sortCaptureRows(out)
	return out, nil
}

// ListByRange implements CaptureStore.
func (m *MemCaptureStore) ListByRange(_ context.Context, chain, from, to uint64, itemPrefix string) ([]CaptureKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CaptureKey
	for k := range m.rows {
		if k.Chain == chain && k.L1Block >= from && k.L1Block <= to && strings.HasPrefix(k.Item, itemPrefix) {
			out = append(out, k)
		}
	}
	sortCaptureKeys(out)
	return out, nil
}

// Len is the number of rows (tests).
func (m *MemCaptureStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// DirCaptureStore keeps rows as files, for the recorder commands: <Dir>/<chain>/<l1Block>-<l1Hash hex>/<item with '/' as '+'>. A
// row is written to a temporary file and linked into place only if absent, so a crash never leaves a partial row under its key
// and two writers racing on one key cannot both win with different bytes. It survives a restart; a row is never rewritten.
type DirCaptureStore struct{ Dir string }

// NewDirCaptureStore opens (creating it if needed) a store under dir.
func NewDirCaptureStore(dir string) (*DirCaptureStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &DirCaptureStore{Dir: dir}, nil
}

func (d DirCaptureStore) path(k CaptureKey) string {
	return filepath.Join(d.Dir, strconv.FormatUint(k.Chain, 10), fmt.Sprintf("%d-%s", k.L1Block, hex.EncodeToString(k.L1Hash[:])), strings.ReplaceAll(k.Item, "/", "+"))
}

// Put implements CaptureStore.
func (d DirCaptureStore) Put(_ context.Context, k CaptureKey, data []byte) error {
	if err := CheckCaptureItem(k.Item); err != nil {
		return err
	}
	p := d.path(k)
	if old, err := os.ReadFile(p); err == nil {
		return sameOrConflict(old, data, k)
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
	_, werr := tmp.Write(data)
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
		// a writer that linked the same key first decides: identical bytes are a no-op, different bytes a conflict
		if old, rerr := os.ReadFile(p); rerr == nil {
			return sameOrConflict(old, data, k)
		}
		return err
	}
	return os.Remove(name)
}

// Get implements CaptureStore.
func (d DirCaptureStore) Get(_ context.Context, k CaptureKey) ([]byte, bool, error) {
	b, err := os.ReadFile(d.path(k))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func parseCaptureDir(name string) (uint64, [32]byte, bool) {
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

// scan lists the keys of a chain whose block directory passes want and whose item passes the prefix.
func (d DirCaptureStore) scan(chain uint64, want func(block uint64) bool, itemPrefix string) ([]CaptureKey, error) {
	root := filepath.Join(d.Dir, strconv.FormatUint(chain, 10))
	ents, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []CaptureKey
	for _, e := range ents {
		n, h, ok := parseCaptureDir(e.Name())
		if !ok || !e.IsDir() || !want(n) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".put-") {
				continue
			}
			item := strings.ReplaceAll(f.Name(), "+", "/")
			if strings.HasPrefix(item, itemPrefix) {
				out = append(out, CaptureKey{Chain: chain, L1Block: n, L1Hash: h, Item: item})
			}
		}
	}
	sortCaptureKeys(out)
	return out, nil
}

// ListByBlock implements CaptureStore.
func (d DirCaptureStore) ListByBlock(_ context.Context, chain, l1Block uint64) ([]CaptureRow, error) {
	ks, err := d.scan(chain, func(n uint64) bool { return n == l1Block }, "")
	if err != nil {
		return nil, err
	}
	var out []CaptureRow
	for _, k := range ks {
		b, err := os.ReadFile(d.path(k))
		if err != nil {
			return nil, err
		}
		out = append(out, CaptureRow{CaptureKey: k, Bytes: b})
	}
	sortCaptureRows(out)
	return out, nil
}

// ListByRange implements CaptureStore.
func (d DirCaptureStore) ListByRange(_ context.Context, chain, from, to uint64, itemPrefix string) ([]CaptureKey, error) {
	return d.scan(chain, func(n uint64) bool { return n >= from && n <= to }, itemPrefix)
}

var _ BlockPutter = (*MemCaptureStore)(nil)

// PutBlock implements BlockPutter: under one lock, every row is checked first (an item outside the alphabet, a key stored with other
// bytes) and the rows are stored only if none is refused.
func (m *MemCaptureStore) PutBlock(_ context.Context, rows []CaptureRow) error {
	for _, r := range rows {
		if err := CheckCaptureItem(r.Item); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := map[CaptureKey][]byte{}
	for _, r := range rows {
		if old, ok := m.rows[r.CaptureKey]; ok {
			if err := sameOrConflict(old, r.Bytes, r.CaptureKey); err != nil {
				return err
			}
			continue
		}
		if prev, ok := staged[r.CaptureKey]; ok {
			if err := sameOrConflict(prev, r.Bytes, r.CaptureKey); err != nil {
				return err
			}
			continue
		}
		staged[r.CaptureKey] = append([]byte(nil), r.Bytes...)
	}
	if m.rows == nil {
		m.rows = map[CaptureKey][]byte{}
	}
	for k, b := range staged {
		m.rows[k] = b
	}
	return nil
}
