// Copyright 2026 Certen Protocol

package main

// The authority vote lives in package govvote, where the validator can import it and re-run it offline from a proof's
// stored evidence (RB4-F66). These names keep the CLI reading as it did.

import (
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
)

type (
	sigFact          = govvote.SigFact
	arrivalFact      = govvote.ArrivalFact
	recordedVote     = govvote.RecordedVote
	voteFacts        = govvote.Facts
	VoteUnevaluable  = govvote.VoteUnevaluable
	PageVote         = govvote.PageVote
	CountedEntry     = govvote.CountedEntry
	ExcludedMessage  = govvote.ExcludedMessage
	BookVote         = govvote.BookVote
	AuthorityVote    = govvote.AuthorityVote
	AccountVote      = govvote.AccountVote
	AccountAuthority = govvote.AccountAuthority
)

func bookOfPage(page string) string { return govvote.BookOfPage(page) }
