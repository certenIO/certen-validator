// Copyright 2026 Certen Protocol

package contractidentity

import "github.com/ethereum/go-ethereum/common"

// FactsB2 are the facts of package 2b-2 (steps 18, 18b, 19 and 22). Package 2b-2 owns this file.
type FactsB2 struct {
	// Pre and Post are the AUTH slot set read at stateRoot_pre and stateRoot_post (step 18).
	Pre  AuthStation
	Post AuthStation
	// Changed lists the AUTH rows that differ between pre and post OTHER than the expected flips (each is state_changed_in_block).
	Changed []AuthDiff
	// RecordCreatedInBlock is the n1 case: the record is not valid at pre.
	RecordCreatedInBlock bool
	// Validators are the registry rows proven at post (and equal at pre): the validatorList entries with their registry words.
	Validators []ValidatorRow
	// IB is rule IB (step 22): its verdict conditions the R-versus-U precedence of steps 19 and 21b.
	IB IBResult
}

// AuthStation is the AUTH slot set at one attestation station.
type AuthStation struct {
	StateRoot [32]byte
	// Words maps an AUTH row id (vocabulary auth_row_field: "A14", "A02:10", "V03", ...) to the proven word.
	Words map[string]common.Hash
	// Accounts maps "A", "V", "G", "owner:A", "owner:V" to the proven account (row C01).
	Accounts map[string]AccountState
}

// AuthDiff is one AUTH row that differs between the stations.
type AuthDiff struct {
	Row  string
	Pre  common.Hash
	Post common.Hash
}

// ValidatorRow is one validator of the anchor's registry as proven on-chain.
type ValidatorRow struct {
	Address    common.Address
	Registered bool
	Power      common.Hash
	BLSKey     []byte
}

// IBResult is the verdict of rule IB. Verified means "no transaction of B_v executed as the owner"; otherwise State is the U that says why.
type IBResult struct {
	Evaluated bool
	Verified  bool
	State     *StateError
}

var factSpecsB2 = []FactSpec{
	{"B2.Pre", Step18, []StepID{Step13, Step19, Step20, Step21, Step22}, "AUTH words and accounts at stateRoot_pre"},
	{"B2.Post", Step18, []StepID{Step13, Step19, Step21, Step22}, "AUTH words and accounts at stateRoot_post"},
	{"B2.Changed", Step18, []StepID{Step19, Step21}, "rows that differ outside the flips; the precedence rule needs 'equal at pre and post'"},
	{"B2.RecordCreatedInBlock", Step18, []StepID{Step18b, Step19}, "n1: record not valid at pre"},
	{"B2.Validators", Step18, []StepID{Step19, Step21}, "validatorList entries with registered, power, BLS key"},
	{"B2.IB", Step22, []StepID{Step19, Step21}, "rule IB verdict; executes before 19 and 21 (ExecOrder)"},
}
