// Copyright 2026 Certen Protocol
//
// BINDING G0 TO THE CHAINED PROOF.
//
// G0 proves that the intent's transaction is on its account's main chain, with
// a receipt from the entry to an anchor it calls EXEC_WITNESS, at a block it
// calls EXEC_MBI. On its own that anchor is whatever the endpoint answered:
// nothing ties it to a root anyone signed, so "finality" was a name.
//
// The chained proof for the same intent proves the same entry on the same
// chain: its L1 receipt runs from the transaction to the BVN root chain anchor
// of the block that recorded it, and its L4-BVN leg is a validator quorum over
// an anchor whose signed bytes carry that root and that block. Both receipts
// are the entry's receipt to its own block's root, so for a genuine intent they
// are the same receipt.
//
// Requiring them to agree is what makes G0 final: EXEC_WITNESS becomes the root
// the BVN quorum signed, and EXEC_MBI the block it signed it at. If they do not
// agree, the two proofs describe different facts, and the intent is refused
// rather than attested on the weaker of them.
package proof

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// BindG0ToChainedProof requires G0's execution entry, witness and block to be
// the ones the chained proof's L1 receipt and signed L4-BVN anchor establish.
func BindG0ToChainedProof(g0 *G0Result, cp *lcproof.CompleteProof) error {
	if g0 == nil {
		return fmt.Errorf("G0 binding: no G0 result")
	}
	if cp == nil || cp.MainChainProof == nil {
		return fmt.Errorf("G0 binding: no chained proof L1 receipt to bind G0 to")
	}
	if cp.Layer4BVN == nil {
		return fmt.Errorf("G0 binding: the chained proof carries no signed BVN anchor, so G0's " +
			"execution block and witness would rest on the endpoint's word alone")
	}

	entry, err := hash32(g0.EntryHashExec, "G0 entry_hash_exec")
	if err != nil {
		return err
	}
	start, err := hash32(g0.Receipt.Start, "G0 receipt.start")
	if err != nil {
		return err
	}
	witness, err := hash32(g0.ExecWitness, "G0 exec_witness")
	if err != nil {
		return err
	}
	receiptAnchor, err := hash32(g0.Receipt.Anchor, "G0 receipt.anchor")
	if err != nil {
		return err
	}

	l1Leaf := strings.ToLower(hex.EncodeToString(cp.AccountHash))
	l1Start := strings.ToLower(hex.EncodeToString(cp.MainChainProof.Start))
	l1Anchor := strings.ToLower(hex.EncodeToString(cp.MainChainProof.Anchor))
	signedRoot := strings.ToLower(cp.Layer4BVN.RootChainAnchor)

	switch {
	case start != entry:
		return fmt.Errorf("G0 binding: G0's receipt starts at %s, not at its entry %s", short(start), short(entry))
	case witness != receiptAnchor:
		return fmt.Errorf("G0 binding: exec_witness %s is not the anchor of G0's own receipt %s",
			short(witness), short(receiptAnchor))
	case entry != l1Leaf || entry != l1Start:
		return fmt.Errorf("G0 binding: G0 proves entry %s but the chained proof's L1 proves %s",
			short(entry), short(l1Leaf))
	case witness != l1Anchor:
		return fmt.Errorf("G0 binding: G0's receipt ends at %s but L1's ends at %s; the two proofs "+
			"of one entry must reach the same root", short(witness), short(l1Anchor))
	case witness != signedRoot:
		return fmt.Errorf("G0 binding: G0's witness %s is not the root chain anchor the BVN quorum "+
			"signed (%s)", short(witness), short(signedRoot))
	case g0.ExecMBI <= 0 || uint64(g0.ExecMBI) != cp.Layer4BVN.MinorBlockIndex:
		return fmt.Errorf("G0 binding: G0's execution block %d is not the block the BVN quorum signed "+
			"the anchor at (%d)", g0.ExecMBI, cp.Layer4BVN.MinorBlockIndex)
	}
	return nil
}

func hash32(s, label string) (string, error) {
	s = strings.ToLower(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return "", fmt.Errorf("G0 binding: %s is not a 32-byte hash (%q)", label, s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("G0 binding: %s is not hex: %w", label, err)
	}
	return s, nil
}

// ErrG0BindingUncheckable reports that no stored governance level carries
// anything the binding could be checked against. Like summary-only, it is not
// a failure - nothing was found wrong - and must never read as a pass.
var ErrG0BindingUncheckable = errors.New("no stored governance level carries a G-result or a G0 receipt to bind to the chained proof")

// VerifyStoredG0Binding checks, from storage alone, what BindG0ToChainedProof
// checked in flight: every stored level's G0 fields (G1 and G2 embed G0's), and
// the stored G0 receipt, against the reassembled chained proof.
func VerifyStoredG0Binding(levels []StoredGovernanceLevel, cp *chained_proof.ChainedProof) error {
	if cp == nil {
		return fmt.Errorf("G0 binding: no chained proof")
	}
	complete := ChainedProofToCompleteProof(cp)
	checked := 0
	for i := range levels {
		l := &levels[i]
		if l.HasResult() {
			var g0 G0Result
			if err := json.Unmarshal(l.Result, &g0); err != nil {
				return fmt.Errorf("level %s: decode stored result: %w", l.Level, err)
			}
			if err := BindG0ToChainedProof(&g0, complete); err != nil {
				return fmt.Errorf("level %s: %w", l.Level, err)
			}
			checked++
		}
		if strings.EqualFold(l.Level, string(GovLevelG0)) && l.HasEvidence() {
			r := l.Receipt
			switch {
			case !strings.EqualFold(r.Start, cp.Layer1.Leaf):
				return fmt.Errorf("level G0: stored receipt starts at %s, the chained proof's L1 at %s",
					short(r.Start), short(cp.Layer1.Leaf))
			case !strings.EqualFold(r.Anchor, cp.Layer1.Receipt.Anchor):
				return fmt.Errorf("level G0: stored receipt ends at %s, the chained proof's L1 at %s",
					short(r.Anchor), short(cp.Layer1.Receipt.Anchor))
			case cp.Layer4BVN == nil || r.LocalBlock <= 0 || uint64(r.LocalBlock) != cp.Layer4BVN.MinorBlockIndex:
				return fmt.Errorf("level G0: stored receipt's block %d is not the block the BVN quorum signed",
					r.LocalBlock)
			}
			checked++
		}
	}
	if checked == 0 {
		return ErrG0BindingUncheckable
	}
	return nil
}
