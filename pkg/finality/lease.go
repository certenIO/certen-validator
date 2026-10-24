// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// RB12-ARCHIVE-BACKFILL: the claim that keeps validators sharing one database from fetching the same blocks.

// Lease is the cross-validator claim on a chunk of prefix blocks. A claim is one insert-only row whose KEY holds the chunk and the time
// bucket and whose BYTES hold the claimant: the first writer of a (chunk, bucket) wins, any other claimant meets the store's own
// "same key, other bytes" refusal (ErrCaptureConflict) and has lost; the holder claiming again is a no-op. Nothing is updated or deleted
// and nothing needs releasing: a claim ends with its bucket, so a validator that dies holding one blocks its chunk for one bucket.
type Lease struct {
	Store  CaptureStore
	Chain  uint64
	Holder [16]byte      // unique to the process (NewLease draws it at random)
	Span   time.Duration // the bucket: how long a claim lasts (default 10 minutes)
	Chunk  uint64        // blocks per claim, aligned at multiples of Chunk (default 8)
}

const (
	// DefaultLeaseSpan is how long a chunk stays claimed: long enough for a validator to work through a chunk at the gap-fill pace, short
	// enough that a chunk whose holder is gone is retaken within one backoff.
	DefaultLeaseSpan = 10 * time.Minute
	// DefaultLeaseChunk is the claim granularity; it equals the default blocks per backfill tick.
	DefaultLeaseChunk uint64 = 8
	leaseMagic               = "CGCL1"
	// GapClaimPrefix is the item prefix of the claim rows; it is not one of the gap bookkeeping prefixes, so no gap reader sees a claim.
	GapClaimPrefix = "gapclaim/"
)

// NewLease returns a lease for the chain with a fresh random holder.
func NewLease(store CaptureStore, chain uint64) (*Lease, error) {
	l := &Lease{Store: store, Chain: chain}
	if _, err := rand.Read(l.Holder[:]); err != nil {
		return nil, fmt.Errorf("finality: drawing a claim holder: %w", err)
	}
	return l, nil
}

func (l *Lease) span() time.Duration {
	if l.Span >= time.Second {
		return l.Span
	}
	return DefaultLeaseSpan
}

func (l *Lease) ChunkBlocks() uint64 {
	if l.Chunk > 0 {
		return l.Chunk
	}
	return DefaultLeaseChunk
}

// ChunkBlocks is the number of blocks per claim.
// ChunkStart is the first block of the chunk n belongs to.
func (l *Lease) ChunkStart(n uint64) uint64 { return n - n%l.ChunkBlocks() }

// Claim tries to take the chunk starting at chunkStart for the time bucket of now. won is false (and err nil) when another holder owns it
// for this bucket; err is a store failure.
func (l *Lease) Claim(ctx context.Context, now time.Time, chunkStart uint64) (won bool, err error) {
	if l.Store == nil {
		return false, errors.New("finality: a lease needs a store")
	}
	bucket := uint64(now.Unix()) / uint64(l.span()/time.Second)
	h := sha256.New()
	h.Write([]byte("certen:gapclaim:v1"))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], bucket)
	h.Write(be[:])
	var key [32]byte
	copy(key[:], h.Sum(nil))
	k := CaptureKey{Chain: l.Chain, L1Block: chunkStart, L1Hash: key, Item: fmt.Sprintf("%s%d", GapClaimPrefix, chunkStart)}
	err = l.Store.Put(ctx, k, append([]byte(leaseMagic), l.Holder[:]...))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrCaptureConflict):
		return false, nil
	}
	return false, err
}
