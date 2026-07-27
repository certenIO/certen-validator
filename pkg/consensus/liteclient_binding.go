package consensus

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/entitlement"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// Binding the entitlement principal to Accumulate's own record.
//
// # WHAT THIS CLOSES, AND WHAT IT DOES NOT
//
// The entitlement gate decides whether CERTEN spends, keyed on the principal
// the block declares. Requiring that principal to agree with the governance
// proof (see validator_block_invariants.go) removed the trivial substitution —
// a proposer can no longer name an entitled account while the rest of the block
// describes someone else.
//
// It did not make the claim TRUE. A proposer able to write every field can
// still produce a self-consistent block naming an entitled identity throughout.
// The only thing that can settle it is evidence from Accumulate, and every
// ValidatorBlock already carries some: the lite-client proof, a chain of Merkle
// receipts running from the transaction to an anchor.
//
// Those receipts are self-validating. merkle.Receipt.Validate walks Start
// through Entries and checks it arrives at Anchor — pure hashing, no network,
// no clock, so it is safe inside a consensus rule and reproduces exactly on
// replay.
//
// # THE HONEST LIMIT
//
// Validating a receipt proves it is internally consistent, not that its anchor
// is one Accumulate actually produced. Closing that needs the anchor checked
// against Accumulate's validator set — L3/L4 — which this fleet cannot do
// deterministically today. So a validator willing to fabricate a complete,
// self-consistent receipt chain can still get past this.
//
// What it does buy is real: the proof must exist, be structurally sound, name
// the same account as the principal, and be tied to the same transaction the
// block anchors. Forgery moves from editing one string to constructing a
// coherent Merkle chain, and every inconsistency between the block's own claims
// is caught.
//
// Verified.Error and Verified are IGNORED. They are the proposer's own
// assertions about its own proof; trusting them would make the whole check
// decorative.

// LiteClientProofView is the part of the carried proof this package needs. It
// is an interface so pkg/consensus does not take a hard dependency on the
// lite-client package's evolving shape.
type LiteClientProofView interface {
	GetAccountURL() string
	GetMainChainProof() *merkle.Receipt
	GetBPTProof() *merkle.Receipt
	GetCombinedReceipt() *merkle.Receipt
}

// verifyLiteClientBinding checks a carried proof against the block's own claims.
//
// principal is the account the entitlement gate will key on; txHash is the
// Accumulate transaction the block anchors. Returns nil when the proof is
// absent — presence is a policy decision made by the caller, because requiring
// it is what would refuse every block that does not carry one.
func verifyLiteClientBinding(accountURL, txHash string, main, bpt, combined *merkle.Receipt, principal string) error {
	if accountURL == "" && main == nil && bpt == nil && combined == nil {
		return nil // no proof carried; the caller decides whether that is allowed
	}

	// 1. The proof must be ABOUT the account the gate will spend for. A proof
	//    for a different account proves nothing about this one, however valid.
	if accountURL == "" {
		return fmt.Errorf("lite_client_proof carries no account_url, so it binds nothing")
	}
	if !entitlement.SameIdentity(accountURL, principal) {
		return fmt.Errorf(
			"lite_client_proof is for %q but the entitlement principal is %q; "+
				"a proof for another account cannot authorise this one",
			accountURL, principal)
	}

	// 2. Every carried receipt must actually reach its own anchor. This is the
	//    part a fabricated proof most easily gets wrong, and it is pure hashing.
	for _, r := range []struct {
		name string
		r    *merkle.Receipt
	}{
		{"main_chain_proof", main},
		{"bpt_proof", bpt},
		{"combined_receipt", combined},
	} {
		if r.r == nil {
			continue
		}
		if len(r.r.Start) == 0 || len(r.r.Anchor) == 0 {
			return fmt.Errorf("lite_client_proof.%s has no start or anchor", r.name)
		}
		if !r.r.Validate(nil) {
			return fmt.Errorf(
				"lite_client_proof.%s does not hash from its start to its anchor; "+
					"the receipt is not internally consistent", r.name)
		}
	}

	// 3. The proof must concern the SAME transaction the block anchors.
	//    Without this a valid proof for some other transaction by the same
	//    account would satisfy the check — real evidence, wrong subject.
	if main != nil && txHash != "" {
		want, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(txHash)), "0x"))
		if err == nil && len(want) == 32 && !bytes.Equal(main.Start, want) {
			return fmt.Errorf(
				"lite_client_proof.main_chain_proof starts at %x but the block anchors "+
					"transaction %s; the proof is for a different transaction",
				main.Start, txHash)
		}
	}

	return nil
}
