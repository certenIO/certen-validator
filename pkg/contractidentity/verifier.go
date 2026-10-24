// Copyright 2026 Certen Protocol

package contractidentity

// Verifier is the S8 judgement of one leg (steps 1b-24 of V2_SPEC_S8.md): it decodes the container, judges every part against the
// manifest and the LegContext and returns the Report. It is pure: no network, no database, no clock, and it never mutates its inputs.
//
// A returned error is NOT a verdict: every verdict, including every refusal and every unproven state, is in the Report (steps 0-2 and
// 22b refuse by a framework state in the Report's headline). The error is for defects of the caller or of the implementation (a nil
// manifest, a headline algebra that rejected its input) and for nothing else, so that "could not judge" is never confused with
// "judged and refused".
//
// The interface is defined by this package so that the capture assembly (WP-S8-3a Append takes a Verifier by injection; a nil
// Verifier is a construction error with no fallback) and the real implementation (WP-S8-2a/2b/2c) can be built independently.
type Verifier interface {
	Verify(ctx LegContext, container []byte, m *Manifest) (Report, error)
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(ctx LegContext, container []byte, m *Manifest) (Report, error)

// Verify calls f.
func (f VerifierFunc) Verify(ctx LegContext, container []byte, m *Manifest) (Report, error) {
	return f(ctx, container, m)
}
