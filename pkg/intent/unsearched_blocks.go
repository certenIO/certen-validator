// Copyright 2026 Certen Protocol

package intent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Blocks discovery could not search yet (RB3-F125).
//
// A block whose search failed used to be passed by the watermark "to prevent getting stuck", on the
// stated theory that it "will appear again on a future polling cycle" - it never did: the watermark had
// moved past it, and every intent anchored in it was lost. Now a failed block is written here before the
// watermark passes it, and the retry loop searches it again until it is searched. The watermark keeps
// moving (one unreadable block no longer stops discovery), no block is ever counted as searched without
// being searched, and health reports how many are waiting and since when.

// UnsearchedBlock is one block waiting to be searched.
type UnsearchedBlock struct {
	Height    uint64    `json:"height"`
	FirstSeen time.Time `json:"first_seen"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error"`
}

// UnsearchedBlockStore keeps unsearched blocks durably.
type UnsearchedBlockStore interface {
	Put(height uint64, reason string) error
	List() ([]UnsearchedBlock, error)
	Remove(height uint64) error
}

// FileUnsearchedBlocks keeps the set in one JSON file, replaced atomically on every change.
type FileUnsearchedBlocks struct {
	path string
	mu   sync.Mutex
}

// OpenFileUnsearchedBlocks opens (creating if needed) the store at path; an unreadable file is an error.
func OpenFileUnsearchedBlocks(path string) (*FileUnsearchedBlocks, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("unsearched blocks: %w", err)
	}
	s := &FileUnsearchedBlocks{path: path}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path reports where the set is stored.
func (s *FileUnsearchedBlocks) Path() string { return s.path }

func (s *FileUnsearchedBlocks) load() (map[uint64]UnsearchedBlock, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[uint64]UnsearchedBlock{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unsearched blocks %s: %w", s.path, err)
	}
	var list []UnsearchedBlock
	if err := json.Unmarshal(raw, &list); err != nil {
		// Unreadable is not empty: the blocks it held would be lost.
		return nil, fmt.Errorf("unsearched blocks %s does not decode: %w", s.path, err)
	}
	m := make(map[uint64]UnsearchedBlock, len(list))
	for _, b := range list {
		m[b.Height] = b
	}
	return m, nil
}

func (s *FileUnsearchedBlocks) save(m map[uint64]UnsearchedBlock) error {
	list := make([]UnsearchedBlock, 0, len(m))
	for _, b := range m {
		list = append(list, b)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Height < list[j].Height })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, raw); err != nil {
		return fmt.Errorf("unsearched blocks: %w", err)
	}
	return nil
}

// Put records a failed search of height (a new entry, or one more attempt of an existing one).
func (s *FileUnsearchedBlocks) Put(height uint64, reason string) error {
	if height == 0 {
		return fmt.Errorf("unsearched blocks: height is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	b, ok := m[height]
	if !ok {
		b = UnsearchedBlock{Height: height, FirstSeen: time.Now().UTC()}
	}
	b.Attempts++
	b.LastError = reason
	m[height] = b
	return s.save(m)
}

// List returns the waiting blocks, lowest first.
func (s *FileUnsearchedBlocks) List() ([]UnsearchedBlock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]UnsearchedBlock, 0, len(m))
	for _, b := range m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Height < out[j].Height })
	return out, nil
}

// Remove drops a block that has now been searched.
func (s *FileUnsearchedBlocks) Remove(height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := m[height]; !ok {
		return nil
	}
	delete(m, height)
	return s.save(m)
}
