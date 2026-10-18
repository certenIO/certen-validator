// Copyright 2026 Certen Protocol
//
// The evidence budget (docs/proof/G1_CROSS_PARTITION.md D6 g1_closure_exceeds_budget; RB9 Phase C1b-2).
//
// Evidence travels inside the intent certificate, which is ONE transaction of CERTEN's consensus (CometBFT v0.38.21). pkg/consensus sets no
// size limit of its own, so the engine's defaults bind: the mempool refuses a transaction over max_tx_bytes = 1 MiB
// (cometbft/config/config.go:799, "MaxTxBytes: 1024 * 1024"), and a block holds at most 21 MiB (cometbft/types/params.go:99,
// "MaxBytes: 22020096"). One transaction is the tighter bound. The certificate also carries the intent, its legs and signatures; 96 KiB is
// reserved for them, which leaves MaxEvidenceBytes for the document.
//
// MEASURED (go test, xworld timeline world, 2026-10-18; compact JSON of Evidence):
//   - the fixed part of a real evidence (Certify runs, validator-set check, anchors): the real 2.0 evidence of 3cfb04cf holds 731,778 bytes
//     with 3 pages (testdata/evidence_3cfb04cf.json.gz; 357,638 of them are the minor-root runs, which grow with the distance from the last
//     major block). FixedEvidenceBytes is that figure rounded up.
//   - a page with its receipt and chain roots: about 1.1 KB; a key page's History: about 258 bytes per main-chain entry and 90 per
//     main-index entry (55 entries: 14,461 bytes); a vote hop with its signature, receipt and two signature-index proofs: about 4 KB.
//   - a harbor-mfg-style closure (principal chain of 3 accounts, an authority book of 3 pages, two delegate books of 2 pages, a synthetic
//     ledger, 6 hop pages with 55-entry histories, 6 hops with arrival proofs, 3 partition anchors, the routing proof) is about 180 KB of
//     2.1 members; with the fixed part it is about 912 KB, inside MaxEvidenceBytes (950,272).
//
// A closure over the budget cannot travel in a consensus block: it is the named state g1_closure_exceeds_budget{pages, limit}, never a
// document trimmed to fit.
package proofv2

import (
	"encoding/json"
	"fmt"
)

const (
	// ConsensusTxLimit is the largest transaction CERTEN's consensus engine accepts by default (CometBFT max_tx_bytes).
	ConsensusTxLimit = 1 << 20
	// CertificateReserve is what the rest of the intent certificate may take of that transaction.
	CertificateReserve = 96 << 10
	// MaxEvidenceBytes is the budget of the encoded evidence document.
	MaxEvidenceBytes = ConsensusTxLimit - CertificateReserve
	// FixedEvidenceBytes is the largest fixed part (everything but the pages, votes and transaction) measured on a real evidence.
	FixedEvidenceBytes = 760_000
)

func budgetState(pages int, size int, x xAnchor) error {
	return refusal21(StateClosureExceedsBudget, x.id, x.block, "pages=%d limit=%d: the encoded evidence is %d bytes, over the %d bytes the consensus transaction limit (%d) leaves it",
		pages, MaxEvidenceBytes, size, MaxEvidenceBytes, ConsensusTxLimit)
}

// CheckEvidenceBudget refuses an evidence whose compact JSON encoding is over MaxEvidenceBytes.
func CheckEvidenceBudget(ev *Evidence, x xAnchor) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode the evidence: %w", err)
	}
	if len(raw) > MaxEvidenceBytes {
		return budgetState(len(ev.Pages), len(raw), x)
	}
	return nil
}

// CheckClosureBudget is the capture's check, before the evidence exists: the captured pages and votes encoded, plus the fixed part, must
// fit MaxEvidenceBytes. partition and block are where the capture judged it.
func CheckClosureBudget(pages []PageState, votes []Vote, partition string, block uint64) error {
	size := FixedEvidenceBytes
	for i := range pages {
		raw, err := json.Marshal(&pages[i])
		if err != nil {
			return err
		}
		size += len(raw)
	}
	raw, err := json.Marshal(votes)
	if err != nil {
		return err
	}
	size += len(raw)
	if size > MaxEvidenceBytes {
		return &NamedState{Code: StateClosureExceedsBudget, Partition: partition, Block: block,
			Detail: fmt.Sprintf("pages=%d limit=%d: the pages and votes encode to %d bytes with the %d-byte fixed part, over the %d bytes the consensus transaction limit (%d) leaves the evidence",
				len(pages), MaxEvidenceBytes, size, FixedEvidenceBytes, MaxEvidenceBytes, ConsensusTxLimit)}
	}
	return nil
}
