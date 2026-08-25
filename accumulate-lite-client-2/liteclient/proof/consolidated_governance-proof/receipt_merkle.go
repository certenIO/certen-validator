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

	"github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
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
//
// STAGE 2 MOVED THE LOGIC OUT OF package main.
//
// It used to live here in full, and a package main is not importable - so the
// only consumer it could ever have was this CLI, while the thing that most
// needs to recompute a governance receipt is the VALIDATOR, reading one back
// out of PostgreSQL. The implementation now lives in the govreceipt package.
// The two functions below stay as thin adapters because this package's own
// call sites and tests reference them by these names; renaming them would be
// churn with no benefit. There is still exactly one recomputation in the tree.

// ParseReceiptEntries reads the merkle path out of a v3 receipt object.
//
// A receipt with no entries is legitimate only when start == anchor, i.e. the
// leaf is itself the anchor. Any other empty path is an error: silently
// accepting one would make every receipt trivially "verify".
func ParseReceiptEntries(receiptMap map[string]interface{}) ([]ReceiptStep, error) {
	steps, err := govreceipt.ParseEntries(receiptMap)
	if err != nil {
		// Re-wrapped so this package's existing callers keep seeing the
		// ValidationError they already handle. The message text is unchanged.
		return nil, ValidationError{Msg: err.Error()}
	}
	return steps, nil
}

// VerifyReceiptMerkle recomputes a receipt's merkle path and requires it to
// reach the receipt's own anchor.
//
// It fails closed: a receipt with no path and start != anchor is rejected
// rather than treated as vacuously valid.
func VerifyReceiptMerkle(r ReceiptData, label string) error {
	if err := govreceipt.VerifyMerkle(govreceipt.Receipt{
		Start:      r.Start,
		Anchor:     r.Anchor,
		LocalBlock: r.LocalBlock,
		Entries:    r.Entries,
	}, label); err != nil {
		return ValidationError{Msg: err.Error()}
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
