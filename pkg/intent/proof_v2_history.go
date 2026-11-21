// Copyright 2026 Certen Protocol

package intent

import (
	"errors"
	"fmt"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// ProofV2HistoryUnavailable is the stable machine reason of an intent whose required proof v2 could not be captured because the
// Accumulate node no longer serves a governing page's admissible block (AGT-F104, owner item OQ12): an infrastructure limit of the node
// the validator reads, not a verdict on the intent and not a validator defect.
//
// The intent's lifecycle failure records it at the START of intent_lifecycle.error_message, in exactly this form:
//
//	proof_v2_history_unavailable{partition=<P>,height=<H>}: <cause>
//
// <P> is the partition as the routing table names it (BVN1, BVN2, BVN3, Directory), <H> the decimal block of that partition the governing
// page had to be read at (design D2). The failure class stays processing_failed. api-bridge and api-gateway read the token from that
// message (gateway reason_code proof_history_unavailable); it is written only from the typed error below, never from text.
const ProofV2HistoryUnavailable = "proof_v2_history_unavailable"

// ProofV2HistoryUnavailableError is that failure, typed (errors.As) with where it was judged. Cause keeps the refusal it was made from:
// the *proofv2.NamedState g1_historical_unavailable{<partition>,<block>} and the chained-proof class the intent is failed under.
type ProofV2HistoryUnavailableError struct {
	Partition string
	Height    uint64
	Cause     error
}

// Token is the machine reason with its place: proof_v2_history_unavailable{partition=<P>,height=<H>}.
func (e *ProofV2HistoryUnavailableError) Token() string {
	return fmt.Sprintf("%s{partition=%s,height=%d}", ProofV2HistoryUnavailable, e.Partition, e.Height)
}

func (e *ProofV2HistoryUnavailableError) Error() string {
	if e.Cause == nil {
		return e.Token()
	}
	return e.Token() + ": " + e.Cause.Error()
}

func (e *ProofV2HistoryUnavailableError) Unwrap() error { return e.Cause }

// proofV2HistoryRefusal is the history refusal a proof v2 error carries by type - a g1_historical_unavailable named state that names both
// its partition and its block - or nil.
func proofV2HistoryRefusal(err error) *proofv2.NamedState {
	var ns *proofv2.NamedState
	if errors.As(err, &ns) && ns.Code == proofv2.StateHistoricalUnavailable && ns.Partition != "" && ns.Block != 0 {
		return ns
	}
	return nil
}

// lifecycleErrorMessage is the error_message a terminal failure is recorded with: the cause's text, led by the history token when the
// cause is the typed history failure (whatever wrapped it on the way).
func lifecycleErrorMessage(cause error) string {
	msg := cause.Error()
	var hist *ProofV2HistoryUnavailableError
	if errors.As(cause, &hist) {
		token := hist.Token()
		if strings.HasPrefix(msg, token) {
			return msg
		}
		// Wrapped on the way: the token leads once, and the wrapped text keeps the cause in its place.
		if hist.Cause != nil {
			msg = strings.Replace(msg, hist.Error(), hist.Cause.Error(), 1)
		}
		return token + ": " + msg
	}
	return msg
}
