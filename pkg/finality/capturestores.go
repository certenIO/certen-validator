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
	return CaptureKeysOfItemIn(ctx, s, chain, 0, MaxCaptureBlock, item)
}

// CaptureCursorItem is the capture row that remembers how far a capture loop has scanned: keyed at the scanned block under the zero
// hash, written once per tick, insert-only. The lowest such row is the end of the first range the loop scanned.
const CaptureCursorItem = "runtime/cursor"

// BlockBounder is the optional fast form of CaptureCoverageOf: a store that can answer "the lowest and the highest L1 block holding
// exactly this item" without listing every row (the database store does, with one aggregate query).
type BlockBounder interface {
	BlockBounds(ctx context.Context, chain uint64, item string) (lo, hi uint64, ok bool, err error)
}

// CaptureCoverage is what the capture cursor rows of a chain say: the first scan of the capture loop ended at First (so the loop
// scanned every block from First minus its first range on, and nothing before), and the latest scan ended at Last.
type CaptureCoverage struct{ First, Last uint64 }

// CaptureCoverageOf reads the coverage of the chain's capture loop. ok is false when the store holds no cursor row (a store filled by
// a one-shot recorder, or a loop that never ticked): nothing is then known about its coverage and no builder may conclude anything
// from it.
func CaptureCoverageOf(ctx context.Context, s CaptureStore, chain uint64) (CaptureCoverage, bool, error) {
	lo, hi, ok, err := BlockBoundsOf(ctx, s, chain, CaptureCursorItem)
	return CaptureCoverage{First: lo, Last: hi}, ok, err
}

// BlockBoundsOf is the lowest and highest L1 block of the chain's rows of exactly item (BlockBounder when the store has it, else
// the key listing: the same answer).
func BlockBoundsOf(ctx context.Context, s CaptureStore, chain uint64, item string) (lo, hi uint64, ok bool, err error) {
	if e, fast := s.(BlockBounder); fast {
		return e.BlockBounds(ctx, chain, item)
	}
	ks, err := s.ListByRange(ctx, chain, 0, MaxCaptureBlock, item)
	if err != nil {
		return 0, 0, false, err
	}
	for _, k := range ks {
		if k.Item != item {
			continue
		}
		if !ok || k.L1Block < lo {
			lo = k.L1Block
		}
		if !ok || k.L1Block > hi {
			hi = k.L1Block
		}
		ok = true
	}
	return lo, hi, ok, nil
}

// BlockBounds implements BlockBounder.
func (m *MemCaptureStore) BlockBounds(_ context.Context, chain uint64, item string) (lo, hi uint64, ok bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.rows {
		if k.Chain != chain || k.Item != item {
			continue
		}
		if !ok || k.L1Block < lo {
			lo = k.L1Block
		}
		if !ok || k.L1Block > hi {
			hi = k.L1Block
		}
		ok = true
	}
	return lo, hi, ok, nil
}

// CaptureKeysOfItemIn is CaptureKeysOfItem restricted to the L1 blocks [from, to].
func CaptureKeysOfItemIn(ctx context.Context, s CaptureStore, chain, from, to uint64, item string) ([]CaptureKey, error) {
	ks, err := s.ListByRange(ctx, chain, from, to, item)
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
		if err := ReserveRow(ctx, len(b)); err != nil {
			return nil, err
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
