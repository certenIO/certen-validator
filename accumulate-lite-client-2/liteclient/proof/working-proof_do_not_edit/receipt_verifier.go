// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ReceiptVerifier validates receipt integrity deterministically (fail-closed).
//
// Normative requirements implemented:
// - start/anchor/steps must be 32 bytes
// - Merkle path must recompute exactly to anchor
type ReceiptVerifier struct {
	Debug bool
}

func NewReceiptVerifier(debug bool) *ReceiptVerifier {
	return &ReceiptVerifier{Debug: debug}
}

// ValidateIntegrity verifies receipt structure + Merkle recomputation.
func (rv *ReceiptVerifier) ValidateIntegrity(r Receipt) error {
	startHex, err := MustHex32Lower(r.Start, "receipt.start")
	if err != nil {
		return err
	}
	anchorHex, err := MustHex32Lower(r.Anchor, "receipt.anchor")
	if err != nil {
		return err
	}

	start, _ := hex.DecodeString(startHex)
	anchor, _ := hex.DecodeString(anchorHex)

	cur := start
	for i, e := range r.Entries {
		hHex, err := MustHex32Lower(e.Hash, fmt.Sprintf("receipt.entries[%d].hash", i))
		if err != nil {
			return err
		}
		h, _ := hex.DecodeString(hHex)

		if e.Right {
			cur = hashPair(cur, h)
		} else {
			cur = hashPair(h, cur)
		}
	}

	if !bytes.Equal(cur, anchor) {
		return fmt.Errorf("receipt merkle recomputation mismatch: got=%x expect=%x", cur, anchor)
	}
	return nil
}

// hashPair is the canonical Merkle node compression used here.
// If Accumulate changes receipt hashing semantics, this must be updated.
// (In DevNet validation for chainEntry receipts, this SHA-256(left||right) rule matches observed behavior.)
func hashPair(left, right []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)
}