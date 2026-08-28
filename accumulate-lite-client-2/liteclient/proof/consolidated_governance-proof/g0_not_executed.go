// Copyright 2026 Certen Protocol
//
// A TRANSACTION THAT NEVER EXECUTED IS NOT A TRANSACTION THAT WAS REFUSED.
//
// # THE DEFECT, MEASURED
//
// G0 proves execution inclusion by asking for the transaction's entry on the
// account's main chain. When the transaction has not executed there is no such
// entry, and Accumulate answers with a notFound:
//
//	get entry index: Account.acc://certen-p8l.acme/data.MainChain.ElementIndex.fd279178… not found
//
// extractChainEntryAndReceipt then found no result{} and no data{}, and said so:
//
//	failed to extract chain entry and receipt: Response missing result{} or data{}
//
// Measured on Kermit 2026-08-28, corpus case L-partial
// (acc://certen-p8l.acme/data, transaction fd279178fb52a6e0) — a transaction the
// network is deliberately holding PENDING because only one of the account's two
// authorities has voted. That is the single most interesting governance state
// the corpus contains, and the proof reported it as a malformed RPC response.
//
// # WHY THAT IS THE FAILURE RULE 8 RANKS WORST
//
// Rule 8 requires that a proof say WHICH thing went wrong, because these three
// are different findings and only one of them is about governance:
//
//	the transaction executed and the authority set was not satisfied
//	                                  -> a governance rejection. A real finding.
//	the transaction has not executed  -> nothing to prove YET. Not a finding.
//	we could not read the chain       -> an infrastructure failure. Not a finding.
//
// "Response missing result{} or data{}" names the third when the truth was the
// second, and an operator reading it has no way to tell either from the first.
// A pending transaction is the normal, correct state of a multi-authority
// transaction that is still collecting votes — case L-partial exists precisely
// to hold that state — and it must never reach a reader as an error about the
// shape of a JSON payload.
//
// # WHAT THIS FILE DOES
//
// It recognises the notFound, and then asks a second question the first answer
// cannot settle: is the transaction PENDING (submitted, awaiting votes) or
// ABSENT (never seen)? Both mean "did not execute", and they are different
// facts, so both are named rather than collapsed.
//
// It fails closed either way. No proof is produced; the only thing that changes
// is that the reason is true.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// NotExecutedOnChain reports that the transaction has no entry on the account's
// main chain, so there is nothing for G0 to prove inclusion of.
//
// It is deliberately NOT a ValidationError: nothing about the response was
// malformed, and nothing about the governance was wrong. The transaction simply
// has not executed.
type NotExecutedOnChain struct {
	Account string
	TxHash  string
	// State is what the network says about the transaction itself: "pending"
	// when it exists and is awaiting authorization, "absent" when the network
	// has no record of it, "unknown" when the follow-up query could not be
	// answered. Empty is never written.
	State string
	// Detail carries the network's own words, so the operator can see what was
	// actually said rather than only our reading of it.
	Detail string
}

func (e NotExecutedOnChain) Error() string {
	var what string
	switch e.State {
	case notExecutedPending:
		what = "the transaction is PENDING - it exists and the network is still " +
			"collecting the authorization it requires, so it has not executed"
	case notExecutedAbsent:
		what = "the network has NO RECORD of the transaction - it was never " +
			"submitted, or was rejected before execution"
	default:
		what = "the transaction has not executed, and the follow-up query that " +
			"would say whether it is pending could not be answered"
	}
	msg := fmt.Sprintf("no execution to prove: %s has no entry on %s's main chain. %s. "+
		"This is NOT a governance rejection and NOT a threshold shortfall - nothing was "+
		"evaluated, because a transaction that has not executed has no authority set to "+
		"evaluate against", SafeTruncate(e.TxHash, 16), e.Account, what)
	if e.Detail != "" {
		msg += fmt.Sprintf(" (network said: %s)", e.Detail)
	}
	return msg
}

// Reason is the distinct reason code, in the shape UnsupportedSignatureType
// established: a caller distinguishing outcomes must never have to match on
// prose.
func (e NotExecutedOnChain) Reason() string { return "not-executed" }

// The three states, named once.
const (
	notExecutedPending = "pending"
	notExecutedAbsent  = "absent"
	notExecutedUnknown = "unknown"
)

// IsNotExecuted reports whether err is, or wraps, a NotExecutedOnChain.
//
// errors.As and not a type assertion: the real call path wraps this twice
// before any caller sees it (g0_layer wraps proveExecutionInclusion, g1_layer
// wraps ProveG0), and a check that only matched the bare error would answer
// "no" for every error that actually reaches a reader.
func IsNotExecuted(err error) bool {
	var target NotExecutedOnChain
	return errors.As(err, &target)
}

// missingMainChainEntry reports whether an RPC response is Accumulate saying
// "this transaction has no entry on that chain", as opposed to any other
// failure.
//
// It matches on the error's own code plus the chain element it names. Matching
// on notFound ALONE would be wrong: a missing ACCOUNT is also notFound, and
// that is an entirely different fact - it means the account URL is wrong, not
// that a transaction is waiting for a vote.
func missingMainChainEntry(response map[string]interface{}) (bool, string) {
	if response == nil {
		return false, ""
	}
	pu := ProofUtilities{}

	raw := pu.CaseInsensitiveGet(response, "error")
	errMap, ok := raw.(map[string]interface{})
	if !ok {
		return false, ""
	}

	message, _ := pu.CaseInsensitiveGet(errMap, "message").(string)

	// The code lives on the nested data{} object as a string ("notFound"), and
	// on the error itself as a number. Either is enough to establish the class;
	// the element name is what establishes WHICH thing was not found.
	code := ""
	if data, ok := pu.CaseInsensitiveGet(errMap, "data").(map[string]interface{}); ok {
		code, _ = pu.CaseInsensitiveGet(data, "code").(string)
	}
	if code == "" {
		if s, ok := pu.CaseInsensitiveGet(errMap, "code").(string); ok {
			code = s
		}
	}
	if !strings.EqualFold(code, "notFound") && !strings.Contains(strings.ToLower(message), "not found") {
		return false, ""
	}

	// "...MainChain.ElementIndex.<hash> not found" - the entry, not the account.
	lower := strings.ToLower(message)
	if !strings.Contains(lower, "elementindex") {
		return false, ""
	}

	return true, strings.TrimSpace(message)
}

// classifyNotExecuted turns a missing main-chain entry into a named state by
// asking the network about the transaction itself.
//
// The probe is best-effort by design: if it cannot be answered, the state is
// "unknown" and the error says so. Guessing "pending" because it is the common
// case would be inventing a fact about a transaction we could not read, which
// is the thing rule 8 exists to prevent.
func classifyNotExecuted(ctx context.Context, client RPCClientInterface,
	account, txHash, detail string) NotExecutedOnChain {

	out := NotExecutedOnChain{
		Account: account,
		TxHash:  txHash,
		State:   notExecutedUnknown,
		Detail:  detail,
	}
	if client == nil {
		return out
	}

	// A txID scope is acc://<hash>@<account-without-scheme>.
	scope := fmt.Sprintf("acc://%s@%s", txHash, strings.TrimPrefix(account, "acc://"))
	resp, err := client.Query(ctx, scope, map[string]interface{}{"queryType": "default"})
	if err != nil || resp == nil {
		return out
	}

	pu := ProofUtilities{}
	if _, isErr := pu.CaseInsensitiveGet(resp, "error").(map[string]interface{}); isErr {
		// The network has no record of it at all.
		out.State = notExecutedAbsent
		return out
	}

	result, ok := pu.CaseInsensitiveGet(resp, "result").(map[string]interface{})
	if !ok {
		return out
	}

	if status, ok := pu.CaseInsensitiveGet(result, "status").(string); ok && status != "" {
		switch strings.ToLower(status) {
		case "pending":
			out.State = notExecutedPending
		case "delivered":
			// The transaction DID execute, on some chain other than the one
			// queried. Say nothing false: leave the state unknown and carry the
			// network's answer, because this contradicts the premise and the
			// operator needs to see that rather than a tidy story.
			out.State = notExecutedUnknown
			out.Detail = strings.TrimSpace(detail +
				"; the transaction reports status \"delivered\" - it executed, but not on the chain queried")
		default:
			out.State = notExecutedUnknown
			out.Detail = strings.TrimSpace(detail + "; transaction status " + status)
		}
		return out
	}

	// It exists (we got a record) but carries no status: pending is the state
	// Accumulate leaves a signed-but-unauthorized transaction in.
	out.State = notExecutedPending
	return out
}
