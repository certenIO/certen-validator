// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"fmt"
	"os"
	"strings"

	cp "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// Merkle recomputation for governance receipts.
//
// Until now the governance stack could not recompute a receipt at all:
// ReceiptData carried start, anchor and localBlock, and the merkle path was
// discarded during parsing. Nothing in G0, G1 or G2 ever walked a receipt.
// "Receipt binding" meant, at best, comparing start and anchor to values that
// came from the same response - which proves the response is self-consistent,
// not that the leaf is under the anchor.
//
// That absence is why G2's outcome binding degenerated into a non-empty string
// check: there was no path available to check against.
//
// ReceiptEntries now carries the path, and VerifyReceiptMerkle recomputes it
// using ReceiptVerifier.ValidateIntegrity from the chained-proof package -
// the same SHA-256 hashPair walk L1-L3 have always used. There is exactly one
// implementation of receipt recomputation in the tree, and this defers to it.

// ParseReceiptEntries reads the merkle path out of a v3 receipt object.
//
// A receipt with no entries is legitimate only when start == anchor, i.e. the
// leaf is itself the anchor. Any other empty path is an error: silently
// accepting one would make every receipt trivially "verify".
func ParseReceiptEntries(receiptMap map[string]interface{}) ([]ReceiptStep, error) {
	raw, ok := receiptMap["entries"]
	if !ok {
		return nil, nil // absent; the caller decides whether that is allowed
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, ValidationError{Msg: "receipt.entries is not an array"}
	}

	hv := HexValidator{}
	out := make([]ReceiptStep, 0, len(arr))
	for i, e := range arr {
		m, ok := e.(map[string]interface{})
		if !ok {
			return nil, ValidationError{Msg: fmt.Sprintf("receipt.entries[%d] is not an object", i)}
		}
		h, ok := m["hash"].(string)
		if !ok {
			return nil, ValidationError{Msg: fmt.Sprintf("receipt.entries[%d] missing hash", i)}
		}
		norm, err := hv.RequireHex32(h, fmt.Sprintf("receipt.entries[%d].hash", i))
		if err != nil {
			return nil, err
		}
		// "right" is omitted when false, matching Accumulate's JSON encoding.
		right, _ := m["right"].(bool)
		out = append(out, ReceiptStep{Hash: norm, Right: right})
	}
	return out, nil
}

// VerifyReceiptMerkle recomputes a receipt's merkle path and requires it to
// reach the receipt's own anchor.
//
// It fails closed: a receipt with no path and start != anchor is rejected
// rather than treated as vacuously valid.
func VerifyReceiptMerkle(r ReceiptData, label string) error {
	if r.Start == "" || r.Anchor == "" {
		return ValidationError{Msg: fmt.Sprintf("%s: receipt missing start or anchor", label)}
	}
	if len(r.Entries) == 0 {
		if r.Start != r.Anchor {
			return ValidationError{Msg: fmt.Sprintf(
				"%s: receipt carries no merkle path but start != anchor (%s != %s); "+
					"the leaf is not proven to be under the anchor",
				label, SafeTruncate(r.Start, 16), SafeTruncate(r.Anchor, 16))}
		}
		return nil // single-leaf tree: the leaf IS the anchor
	}

	steps := make([]cp.ReceiptStep, 0, len(r.Entries))
	for _, e := range r.Entries {
		steps = append(steps, cp.ReceiptStep{Hash: e.Hash, Right: e.Right})
	}
	rec := cp.Receipt{
		Start:      r.Start,
		Anchor:     r.Anchor,
		LocalBlock: uint64(r.LocalBlock),
		Entries:    steps,
	}
	if err := cp.NewReceiptVerifier(false).ValidateIntegrity(rec); err != nil {
		return ValidationError{Msg: fmt.Sprintf("%s: %v", label, err)}
	}
	return nil
}

// RequirePayloadVerifier enforces at CONFIGURATION time what the G2 bypass
// used to paper over at proof time.
//
// The bypass existed because the failure was discovered while building a
// proof, when the only options were to lie or to abort. Detecting it at
// startup removes that dilemma: a node that cannot produce G2 proofs refuses
// to claim it can.
func RequirePayloadVerifier(level string, txhashPath string) error {
	if !strings.EqualFold(strings.TrimSpace(level), "G2") {
		return nil
	}
	if strings.TrimSpace(txhashPath) == "" {
		return fmt.Errorf("G2 requires --txhash: the payload verifier recomputes the canonical " +
			"transaction hash, without which expanded JSON would be trusted (section 2.2)")
	}
	info, err := os.Stat(txhashPath)
	if err != nil {
		return fmt.Errorf("G2 payload verifier %q is not usable: %w", txhashPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("G2 payload verifier %q is a directory", txhashPath)
	}
	return nil
}
