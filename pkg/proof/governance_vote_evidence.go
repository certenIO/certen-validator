// Copyright 2026 Certen Protocol
//
// THE VOTE RECORD'S EVIDENCE (RB4-F66).
//
// The governance decision is derived from the G1 vote record, and the vote record was the CLI's word for who
// decided. The CLI now emits, beside it, everything the vote read - the governed transaction, each signature and
// recorded vote with its bytes and the receipt naming its block, each page's history from its genesis - and
// govvote.VerifyEvidence checks every binding and evaluates the vote again from nothing else.
//
// VerifyVoteEvidence is that check with the two things the evidence cannot bind by itself: the transaction it is
// about is the one G0 proved executed, and the vote it reaches is the stored record, exactly. The validator runs it
// before committing a decision, again before storing one, and proofverify runs it on what was stored.
package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// VoteEvidenceFromRaw reads the vote's evidence out of a G1 or G2 CLI output. An output with none returns nil (a
// govproof build predating it); evidence that is present but does not parse is an error, never an absence.
func VoteEvidenceFromRaw(raw json.RawMessage) (*govvote.Evidence, error) {
	var env struct {
		VoteEvidence json.RawMessage `json:"voteEvidence"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("read the vote's evidence: %w", err)
	}
	if len(env.VoteEvidence) == 0 || string(env.VoteEvidence) == "null" {
		return nil, nil
	}
	return DecodeVoteEvidence(env.VoteEvidence)
}

// DecodeVoteEvidence decodes stored vote evidence strictly.
func DecodeVoteEvidence(raw []byte) (*govvote.Evidence, error) {
	var ev govvote.Evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("the vote's evidence is malformed: %w", err)
	}
	return &ev, nil
}

// VerifyVoteEvidence requires the evidence to be about the transaction g0 proved executed, on its principal, to
// verify, and to reach exactly rec.
func VerifyVoteEvidence(ctx context.Context, g0 *G0Result, ev *govvote.Evidence, rec *AuthorizationRecord) error {
	if g0 == nil || ev == nil || rec == nil {
		return fmt.Errorf("the vote's evidence, its vote record and the G0 result are all required")
	}
	b, err := hex.DecodeString(ev.Transaction)
	if err != nil {
		return fmt.Errorf("the vote's evidence: the governed transaction is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(b); err != nil {
		return fmt.Errorf("the vote's evidence: the governed transaction does not decode: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(txn.GetHash()), strings.TrimPrefix(g0.TxHash, "0x")) {
		return fmt.Errorf("the vote's evidence is about transaction %x, not the executed %s", txn.GetHash(), g0.TxHash)
	}
	if txn.Header.Principal == nil || govvote.CanonicalAccSpelling(txn.Header.Principal.String()) !=
		govvote.CanonicalAccSpelling(ev.Account) {
		return fmt.Errorf("the vote's evidence evaluates %s, but the transaction's principal is %v", ev.Account,
			txn.Header.Principal)
	}

	vote, err := govvote.VerifyEvidence(ctx, ev)
	if err != nil {
		return fmt.Errorf("the vote's evidence does not verify: %w", err)
	}
	raw, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	var again AuthorizationRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&again); err != nil {
		return fmt.Errorf("the vote the evidence reaches is not a vote record: %w", err)
	}
	want, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	got, err := json.Marshal(&again)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("the vote's evidence reaches a different vote than the record")
	}
	return nil
}
