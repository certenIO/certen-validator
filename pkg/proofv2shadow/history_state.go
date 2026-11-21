// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"regexp"
	"strconv"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The capture runs in the background and stores why it fell short as text (proof_v2_shadow.capture_error, CaptureG1 stores err.Error()).
// A history refusal (AGT-F104) is rendered there by proofv2.NamedState.Error as g1_historical_unavailable{<partition>,<block>}, the
// canonical form of that state. historicalUnavailableIn inverts exactly that rendering, so the certificate's proof can return the refusal
// as the *proofv2.NamedState it was - errors.As-able, with its partition and block - and the intent's failure can be recorded by type. It
// reads nothing else from the text: any other named state, a rendering without a partition or block, or two different places, is left text.
var historicalUnavailableRendering = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(proofv2.StateHistoricalUnavailable) +
	`\{([A-Za-z0-9_.-]+),([0-9]+)\}`)

// historicalUnavailableIn is the history refusal a stored capture error renders, or nil when it renders none or more than one place.
func historicalUnavailableIn(text string) *proofv2.NamedState {
	var found *proofv2.NamedState
	for _, m := range historicalUnavailableRendering.FindAllStringSubmatch(text, -1) {
		block, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil || block == 0 {
			return nil
		}
		if found != nil && (found.Partition != m[1] || found.Block != block) {
			return nil
		}
		found = &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: m[1], Block: block}
	}
	return found
}

// storedCaptureError is a capture's stored error as the certificate's proof answers it: the stored text, unchanged, carrying the named
// state it renders (when it renders a history refusal) and ErrPartialCapture (when pages were kept from the capture that stopped).
type storedCaptureError struct {
	text    string
	state   *proofv2.NamedState
	partial bool
}

func newStoredCaptureError(text string, partial bool) error {
	return &storedCaptureError{text: text, state: historicalUnavailableIn(text), partial: partial}
}

func (e *storedCaptureError) Error() string {
	if e.partial {
		return e.text + ": " + ErrPartialCapture.Error()
	}
	return e.text
}

func (e *storedCaptureError) Unwrap() []error {
	var out []error
	if e.state != nil {
		out = append(out, e.state)
	}
	if e.partial {
		out = append(out, ErrPartialCapture)
	}
	return out
}
