// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"context"
	"errors"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// The states of a legacy leg.
const (
	// StatePending: not judged yet, or the judgement was interrupted or could not be made (the capture store failed): asked again.
	StatePending = "pending"
	// StateReconstructed: the verified header is in the capture store and the leg's stored proofs resolve from it.
	StateReconstructed = "reconstructed"
	// StateUnserved: no configured provider served the block; the state names how each failed. Asked again later.
	StateUnserved = "unserved"
	// StateInvalid: the stored component cannot be read, or the block's own header contradicts it (or the store holds other bytes
	// under the header's key). Final until the bundle changes.
	StateInvalid = "invalid"
)

// CheckStoreConflict is the `check` of a leg whose header key already holds other bytes in the insert-only capture store.
const CheckStoreConflict = "store_conflict"

// Outcome is the judgement of one leg.
type Outcome struct {
	State string
	// State is the named state of an unserved or invalid leg (nil for the others).
	Named *finality.StateError
	// Cause is a log-safe summary (counts and tokens only; never provider text).
	Cause string
	// Fetched is whether a provider was asked.
	Fetched bool
	// Stored is whether this call wrote the header row.
	Stored bool
}

// Judge reconstructs one leg: the header already in store is verified and never fetched again; otherwise src is asked (every
// configured provider of the leg's chain in turn), and the header it returns, which hashes to the stored block hash, is kept in the
// store (it is the block's own whatever the bundle says, and is not fetched again) before the leg is judged against it with
// Leg.Verify. A store that cannot be read or written, or a source failure that is not *Unserved, judges nothing (StatePending); logf
// receives the redacted text. Judge never returns a weaker answer: every leg is exactly one of the four states.
func Judge(ctx context.Context, leg Leg, store finality.CaptureStore, src HeaderSource, logf func(format string, args ...any)) Outcome {
	say := func(format string, args ...any) {
		if logf != nil && ctx.Err() == nil {
			logf(format, args...)
		}
	}
	key := leg.Key()
	hdr, have, err := store.Get(ctx, key)
	if err != nil {
		say("%s: reading the capture store: %s (asked again)", leg, ethrpc.RedactText(err.Error()))
		return Outcome{State: StatePending, Cause: "capture store unreadable"}
	}
	var out Outcome
	if !have {
		out.Fetched = true
		hdr, err = src.HeaderByHash(ctx, leg.Chain, leg.BlockHash)
		if err != nil {
			var un *Unserved
			switch {
			case ctx.Err() != nil:
				out.State = StatePending
			case errors.As(err, &un):
				out.State, out.Named, out.Cause = StateUnserved, un.State(leg), un.Error()
			default:
				// a source answers with *Unserved or a context error; anything else judges nothing
				say("%s: %s", leg, Describe(err))
				out.State, out.Cause = StatePending, "header source failed"
			}
			return out
		}
		if err := store.Put(ctx, key, hdr); err != nil {
			say("%s: storing the header: %s", leg, ethrpc.RedactText(err.Error()))
			if errors.Is(err, finality.ErrCaptureConflict) {
				named := invalid(leg.ProofID, leg.Chain, leg.BlockNumber, CheckStoreConflict, "the capture store holds other bytes under this header's key")
				out.State, out.Named, out.Cause = StateInvalid, named, named.Error()
				return out
			}
			out.State, out.Cause = StatePending, "capture store write failed"
			return out
		}
		out.Stored = true
	}
	if err := leg.Verify(hdr); err != nil {
		named, ok := finality.AsNamed(err)
		if !ok {
			named = invalid(leg.ProofID, leg.Chain, leg.BlockNumber, "", err.Error())
		}
		out.State, out.Named, out.Cause = StateInvalid, named, named.Error()
		return out
	}
	out.State = StateReconstructed
	return out
}
