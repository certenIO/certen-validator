// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DirStore is an insert-only CaptureStore on a directory (the recorder command's store): one file per row, never rewritten.
type DirStore struct{ Dir string }

func (d DirStore) path(k CaptureKey) string {
	return filepath.Join(d.Dir, strconv.FormatUint(k.Chain, 10), fmt.Sprintf("%012d-%s", k.L1Block, hex.EncodeToString(k.L1Hash[:6])),
		strings.ReplaceAll(k.Item, "/", "_"))
}

func (d DirStore) Put(_ context.Context, k CaptureKey, data []byte) error {
	p := d.path(k)
	if old, err := os.ReadFile(p); err == nil {
		if bytes.Equal(old, data) {
			return nil
		}
		return ErrCaptureConflict
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// the full hash is recorded beside the rows so a 6-byte directory prefix is never the identity
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "l1_hash"), []byte(hex.EncodeToString(k.L1Hash[:])), 0o644); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func (d DirStore) Get(_ context.Context, k CaptureKey) ([]byte, bool, error) {
	b, err := os.ReadFile(d.path(k))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return b, err == nil, err
}

func (d DirStore) Blocks(_ context.Context, chain uint64, item string) ([]CaptureKey, error) {
	root := filepath.Join(d.Dir, strconv.FormatUint(chain, 10))
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []CaptureKey
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), strings.ReplaceAll(item, "/", "_"))); err != nil {
			continue
		}
		num, err := strconv.ParseUint(strings.SplitN(e.Name(), "-", 2)[0], 10, 64)
		if err != nil {
			continue
		}
		hb, err := os.ReadFile(filepath.Join(root, e.Name(), "l1_hash"))
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(hb)))
		if err != nil || len(raw) != 32 {
			continue
		}
		k := CaptureKey{Chain: chain, L1Block: num, Item: item}
		copy(k.L1Hash[:], raw)
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].L1Block != out[j].L1Block {
			return out[i].L1Block < out[j].L1Block
		}
		return bytes.Compare(out[i].L1Hash[:], out[j].L1Hash[:]) < 0
	})
	return out, nil
}
