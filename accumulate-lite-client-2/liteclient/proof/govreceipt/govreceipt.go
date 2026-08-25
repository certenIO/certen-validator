// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package govreceipt recomputes a governance receipt's merkle path.
//
// # WHY THIS PACKAGE EXISTS
//
// This logic lived in consolidated_governance-proof/receipt_merkle.go, in
// `package main`. A package main is not importable, so the only consumer it
// could ever have was the CLI that contained it — while the thing that most
// needs to recompute a governance receipt is the validator, reading one back out
// of storage. Moving it to a real package is what makes that possible.
//
// # ONE RECOMPUTATION, NOT TWO
//
// Nothing here re-implements the merkle walk. It delegates to
// chained_proof.ReceiptVerifier.ValidateIntegrity — the same SHA-256 hashPair
// walk L1-L3 have always used, and the only receipt recomputation in the tree. A
// second walk would be a second thing to keep correct, and receipt hashing is
// precisely the kind of detail where two implementations diverge quietly.
//
// # THE SINGLE-LEAF RULE, AND WHY IT IS FAIL-CLOSED
//
// A receipt with no entries is legitimate ONLY when start == anchor: the leaf is
// itself the anchor, a one-leaf tree. Any other empty path is an error. Accepting
// one would make every receipt verify vacuously, which is indistinguishable from
// not verifying at all — and that is the state the governance stack was in before
// the path was captured, when "receipt binding" meant comparing a start and an
// anchor that came from the same response.
package govreceipt

import (
	"fmt"

	cp "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// Step is one step of a receipt's merkle path.
//
// A type ALIAS of the chained-proof step, not a copy: a stored governance
// receipt and a working-proof testdata fixture must be the same document. Right
// reports that the sibling is on the right, matching Accumulate's encoding,
// which OMITS the field when false.
type Step = cp.ReceiptStep

// Receipt is the minimum a receipt needs to be recomputable: the leaf, the root,
// and the path between them.
type Receipt struct {
	Start      string `json:"start"`
	Anchor     string `json:"anchor"`
	LocalBlock int64  `json:"localBlock"`
	Entries    []Step `json:"entries"`
}

// Error is a receipt verification failure. A distinct type so a caller can tell
// "this receipt does not check out" from an I/O or decoding problem.
type Error struct{ Msg string }

func (e Error) Error() string { return e.Msg }

// VerifyMerkle recomputes a receipt's merkle path and requires it to reach the
// receipt's own anchor.
//
// Fails closed: a receipt with no path and start != anchor is REJECTED rather
// than treated as vacuously valid. label names the receipt in the error, because
// "recomputation mismatch" with no subject is unactionable when three levels are
// being checked in a row.
func VerifyMerkle(r Receipt, label string) error {
	if r.Start == "" || r.Anchor == "" {
		return Error{Msg: fmt.Sprintf("%s: receipt missing start or anchor", label)}
	}
	if len(r.Entries) == 0 {
		if r.Start != r.Anchor {
			return Error{Msg: fmt.Sprintf(
				"%s: receipt carries no merkle path but start != anchor (%s != %s); "+
					"the leaf is not proven to be under the anchor",
				label, truncate(r.Start, 16), truncate(r.Anchor, 16))}
		}
		return nil // single-leaf tree: the leaf IS the anchor
	}

	rec := cp.Receipt{
		Start:      r.Start,
		Anchor:     r.Anchor,
		LocalBlock: uint64(r.LocalBlock),
		Entries:    r.Entries,
	}
	if err := cp.NewReceiptVerifier(false).ValidateIntegrity(rec); err != nil {
		return Error{Msg: fmt.Sprintf("%s: %v", label, err)}
	}
	return nil
}

// ParseEntries reads the merkle path out of a v3 receipt object.
//
// Returns (nil, nil) when the field is absent — the CALLER decides whether an
// absent path is allowed for its context, because the answer differs: absent is
// fine for a single-leaf receipt and fatal for anything else. VerifyMerkle makes
// that decision for the recomputation case.
func ParseEntries(receiptMap map[string]interface{}) ([]Step, error) {
	raw, ok := receiptMap["entries"]
	if !ok {
		return nil, nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, Error{Msg: "receipt.entries is not an array"}
	}

	out := make([]Step, 0, len(arr))
	for i, e := range arr {
		m, ok := e.(map[string]interface{})
		if !ok {
			return nil, Error{Msg: fmt.Sprintf("receipt.entries[%d] is not an object", i)}
		}
		h, ok := m["hash"].(string)
		if !ok {
			return nil, Error{Msg: fmt.Sprintf("receipt.entries[%d] missing hash", i)}
		}
		norm, err := cp.MustHex32Lower(h, fmt.Sprintf("receipt.entries[%d].hash", i))
		if err != nil {
			return nil, Error{Msg: err.Error()}
		}
		// "right" is omitted when false, matching Accumulate's JSON encoding.
		right, _ := m["right"].(bool)
		out = append(out, Step{Hash: norm, Right: right})
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
