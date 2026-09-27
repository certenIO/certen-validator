// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB3-F116: discovery starts only from a height it can vouch for. A watermark it could not read
// used to become "start at the tip" - every intent between the watermark and the tip was never
// looked at - and a tip it could not read used to become the configured minimum.

type heightStore struct {
	h       uint64
	loadErr error
	saveErr error
	saved   []uint64
}

func (s *heightStore) LoadIntentLastBlock() (uint64, error) { return s.h, s.loadErr }
func (s *heightStore) SaveIntentLastBlock(h uint64) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, h)
	return nil
}

type tipClient struct {
	accumulate.Client
	tip uint64
	err error
}

func (c tipClient) GetLatestBlock(context.Context) (*accumulate.Block, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &accumulate.Block{Height: c.tip}, nil
}

func startDiscovery(store LedgerStoreInterface, c accumulate.Client) *IntentDiscovery {
	return &IntentDiscovery{
		client:      c,
		ledgerStore: store,
		config:      &IntentDiscoveryConfig{MinStartHeight: 7},
		logger:      log.New(io.Discard, "", 0),
	}
}

func TestAnUnreadableWatermarkIsNotTheTip(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	store := &heightStore{loadErr: errors.New("leveldb: corrupted block")}
	id := startDiscovery(store, tipClient{tip: 5000})
	if err := id.initializeStartingHeight(context.Background()); err == nil {
		t.Fatalf("started at %d from a watermark it could not read", id.lastProcessedBlock)
	}
	if len(store.saved) != 0 || id.lastProcessedBlock != 0 {
		t.Fatalf("saved %v, watermark %d", store.saved, id.lastProcessedBlock)
	}
}

func TestAnUnreadableTipIsNotTheConfiguredMinimum(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	store := &heightStore{}
	id := startDiscovery(store, tipClient{err: errors.New("dial tcp: connection refused")})
	if err := id.initializeStartingHeight(context.Background()); err == nil {
		t.Fatalf("started at %d without knowing the tip", id.lastProcessedBlock)
	}
	if len(store.saved) != 0 {
		t.Fatalf("saved %v", store.saved)
	}
}

func TestAStartThatCannotBePersistedIsNotTaken(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	id := startDiscovery(&heightStore{saveErr: errors.New("disk full")}, tipClient{tip: 5000})
	if err := id.initializeStartingHeight(context.Background()); err == nil {
		t.Fatal("a starting height that was not persisted was taken")
	}
}

// A chain younger than the five-block look-back starts at the configured minimum, not near 2^64.
func TestAYoungChainDoesNotWrapTheStartHeight(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	store := &heightStore{}
	id := startDiscovery(store, tipClient{tip: 3})
	if err := id.initializeStartingHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if id.lastProcessedBlock != 7 {
		t.Fatalf("watermark %d, want the configured minimum 7", id.lastProcessedBlock)
	}
}

// The normal paths are unchanged.
func TestTheStartHeightStillComesFromTheWatermarkOrTheTip(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	id := startDiscovery(&heightStore{h: 4200}, tipClient{tip: 5000})
	if err := id.initializeStartingHeight(context.Background()); err != nil || id.lastProcessedBlock != 4200 {
		t.Fatalf("(%d, %v)", id.lastProcessedBlock, err)
	}
	store := &heightStore{}
	id = startDiscovery(store, tipClient{tip: 5000})
	if err := id.initializeStartingHeight(context.Background()); err != nil || id.lastProcessedBlock != 4995 {
		t.Fatalf("(%d, %v)", id.lastProcessedBlock, err)
	}
	if len(store.saved) != 1 || store.saved[0] != 4995 {
		t.Fatalf("saved %v", store.saved)
	}
}

// Until it has a starting height, discovery does not start - and says so on the health surface.
func TestDiscoveryWaitsForAStartingHeightAndSaysWhy(t *testing.T) {
	t.Setenv("INTENT_REWIND_BLOCKS", "0")
	id := startDiscovery(&heightStore{loadErr: errors.New("leveldb: corrupted block")}, tipClient{tip: 5000})
	id.config.BlockPollInterval = time.Hour
	id.stopCh = make(chan struct{})
	done := make(chan struct{})
	go func() { id.monitoringLoop(); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(id.Status().LastPollError, "discovery not started") {
		if time.Now().After(deadline) {
			t.Fatalf("health does not say discovery has not started: %+v", id.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := id.Status(); st.Watermark != 0 {
		t.Fatalf("a watermark was taken: %+v", st)
	}
	close(id.stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop while waiting for a starting height")
	}
}
