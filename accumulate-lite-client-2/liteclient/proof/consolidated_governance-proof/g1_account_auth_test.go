// Copyright 2026 Certen Protocol

package main

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The principal's authority set is the one at execution, not the one the
// network holds today. Each test builds a main chain and asks the replay for
// the set after entry `last` (the last entry at or before execution).

const (
	aDataAcct = "acc://p.acme/data"
	aBookP    = "acc://p.acme/book"
	aBookX    = "acc://x.acme/book"
)

func authOf(t *testing.T, books ...string) *protocol.AccountAuth {
	t.Helper()
	a := new(protocol.AccountAuth)
	for _, b := range books {
		a.AddAuthority(mustURL(t, b))
	}
	return a
}

func mainChain(t *testing.T, bodies ...protocol.TransactionBody) []*protocol.Transaction {
	t.Helper()
	txns := []*protocol.Transaction{{Header: protocol.TransactionHeader{Principal: mustURL(t, aDataAcct)},
		Body: &protocol.CreateDataAccount{Url: mustURL(t, aDataAcct)}}}
	for _, b := range bodies {
		txns = append(txns, &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(t, aDataAcct)}, Body: b})
	}
	return txns
}

// An authority added AFTER execution did not govern the transaction. Reading
// the live set would require its vote; the replay does not.
func TestAccountAuth_AuthorityAddedAfterExecutionIsNotRequired(t *testing.T) {
	txns := mainChain(t,
		&protocol.WriteData{},
		&protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{
			&protocol.AddAccountAuthorityOperation{Authority: mustURL(t, aBookX)}}})
	atExec, live, err := replayAccountAuth(mustURL(t, aDataAcct), authOf(t, aBookP), txns, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !authEqual(atExec, authOf(t, aBookP)) {
		t.Fatalf("set at execution = %s, want [%s]", describeAuth(atExec), aBookP)
	}
	if authEqual(atExec, live) {
		t.Fatalf("the live set %s must differ from the set at execution, or this test proves nothing", describeAuth(live))
	}
}

// An authority disabled before execution does not vote; one disabled after it
// did. The live set has it disabled in both cases.
func TestAccountAuth_DisableIsJudgedAtExecution(t *testing.T) {
	disable := &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{
		&protocol.DisableAccountAuthOperation{Authority: mustURL(t, aBookX)}}}
	txns := mainChain(t, &protocol.WriteData{}, disable)

	before, _, err := replayAccountAuth(mustURL(t, aDataAcct), authOf(t, aBookP, aBookX), txns, 2)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := before.GetAuthority(mustURL(t, aBookX)); !e.Disabled {
		t.Fatalf("executed after the disable: %s must be disabled", aBookX)
	}

	after, live, err := replayAccountAuth(mustURL(t, aDataAcct), authOf(t, aBookP, aBookX), txns, 1)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := after.GetAuthority(mustURL(t, aBookX)); e.Disabled {
		t.Fatalf("executed before the disable: %s must still be enabled", aBookX)
	}
	if e, _ := live.GetAuthority(mustURL(t, aBookX)); !e.Disabled {
		t.Fatalf("the live set must have %s disabled", aBookX)
	}
}

// An UpdateAccountAuth the executor could not have applied means the replay is
// not the chain's history; it must refuse rather than guess.
func TestAccountAuth_ImpossibleOperationRefuses(t *testing.T) {
	txns := mainChain(t, &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{
		&protocol.RemoveAccountAuthorityOperation{Authority: mustURL(t, aBookX)}}})
	if _, _, err := replayAccountAuth(mustURL(t, aDataAcct), authOf(t, aBookP), txns, 1); err == nil {
		t.Fatal("removing an authority the account never had must refuse the replay")
	}
}

// An UpdateAccountAuth on this chain naming another principal is not this
// account's history.
func TestAccountAuth_ForeignPrincipalRefuses(t *testing.T) {
	txns := mainChain(t)
	txns = append(txns, &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(t, "acc://other.acme/data")},
		Body: &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{
			&protocol.AddAccountAuthorityOperation{Authority: mustURL(t, aBookX)}}}})
	if _, _, err := replayAccountAuth(mustURL(t, aDataAcct), authOf(t, aBookP), txns, 1); err == nil {
		t.Fatal("an updateAccountAuth naming another principal must refuse the replay")
	}
}
