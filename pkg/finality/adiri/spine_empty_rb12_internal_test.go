// Copyright 2026 Certen Protocol

package adiri

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-OPS-A1 item 8 (sibling of B-ADIRI-1): verifySpine indexes the last header of the spine it is given. DecodeBody refuses an empty spine
// (spine_empty) before it gets here; the function states the same refusal itself, so that no caller can reach the index with no header.
func TestVerifySpineRefusesAnEmptySpineWithTheNamedState(t *testing.T) {
	for _, spine := range [][][]byte{nil, {}} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("verifySpine panicked on an empty spine: %v", p)
				}
			}()
			_, err := verifySpine(&ChainResult{}, spine, finality.BlockRef{Chain: 2017, Number: 7})
			s, ok := finality.AsNamed(err)
			if !ok || s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != "spine" || s.Fields["reason"] != finality.ReasonSpineEmpty {
				t.Errorf("got %v, want finality_evidence_malformed{spine, spine_empty}", err)
			}
		}()
	}
}
