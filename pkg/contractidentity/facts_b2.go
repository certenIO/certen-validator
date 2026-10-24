// Copyright 2026 Certen Protocol

package contractidentity

import "github.com/ethereum/go-ethereum/common"

// FactsB2 are the facts of package 2b-2 (steps 18, 18b, 19 and 22). Package 2b-2 owns this file.
type FactsB2 struct {
	// Pre and Post are the AUTH slot set read at stateRoot_pre and stateRoot_post (step 18). A station is published only when EVERY read of it
	// verified (a station with no words and no state root was not read: step 13 then computes no drift).
	Pre  AuthStation
	Post AuthStation
	// Changed lists the AUTH rows that differ between pre and post OTHER than the expected flips (each is state_changed_in_block), in AUTH
	// row order (the first one decides the part).
	Changed []AuthDiff
	// RecordCreatedInBlock is the n1 case: the record is not valid at pre.
	RecordCreatedInBlock bool
	// GovernanceExecutedFlip is the reported refinement of the byte rule: b22 of anchors[anchorId] word 10 went 0 to 1 inside B_v.
	GovernanceExecutedFlip bool
	// Validators are the registry rows proven at post (and equal at pre): the validatorList entries with their registry words.
	Validators []ValidatorRow
	// CodeFailure is the first code-identity failure of A, V, G at the attestation stations (nil: all verified or not judged); it decides
	// code_identity and, because the authorization words of another code mean nothing, authorization_attest as well.
	CodeFailure *StateError
	// IB is rule IB (step 22): its verdict conditions the R-versus-U precedence of steps 19 and 21b.
	IB IBResult
}

// AuthStation is the AUTH slot set at one attestation station.
//
// Words maps an AUTH row id (vocabulary auth_row_field) to the proven word. The spelling is a contract with step 13 (S8_FREEZE.md D4, D-B2-9):
//
//	A01 A03 A04 A05 A07 A08 A11 A12 A13 A14 A15 A16 A17       the word of the slot (A05 for the blob's pkc, A15 for the used commitment)
//	A02:<k>                                                    word k (0-12) of anchors[anchorId]
//	A10                                                        validatorList length; A10:<i> the address word of element i
//	A09:<lowercase 0x address>:0 | :1 | :3                     words 0, 1, 3 of validators[addr]; A09:<addr>:key = keccak256(blsPublicKey bytes)
//	A18                                                        the verifier address right-aligned in a word; A19 A20 A21 = the byte value of slot 30 b20 b21 b22
//	V01 V02 V03                                                verifier slots 0, 1, 2
type AuthStation struct {
	StateRoot [32]byte
	Words     map[string]common.Hash
	// Accounts maps "A", "V", "G" to the proven account (row C01); the owners of rule IB are in IBResult.
	Accounts map[string]AccountState
	// Verifier is V_station (anchor slot 30, low 20 bytes) and VerifierPublished says whether it is a manifest blsZkVerifier row of the chain.
	Verifier          common.Address
	VerifierPublished bool
	// Groth16 is the generated verifier G the carried code of V names (zero when V's code is not carried or V is not a published row).
	Groth16 common.Address
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

// OwnerCheck is the evidence of rule IB1 for one owner address: its account at both stations.
type OwnerCheck struct {
	Address common.Address
	Pre     AccountState
	Post    AccountState
}

// IBResult is the verdict of rule IB. Verified means "no transaction of B_v executed as the owner"; otherwise State is the state that says
// why (a U of the part intra_block_window; the R attest_mismatch{block_txs} when the carried transaction list is not the block's).
type IBResult struct {
	Evaluated bool
	Verified  bool
	State     *StateError
	// Owners are the owner accounts read at the two stations (IB1); Types is the sorted set of transaction types of B_v (IB2).
	Owners []OwnerCheck
	Types  []byte
}

var factSpecsB2 = []FactSpec{
	{"B2.Pre", Step18, []StepID{Step13, Step19, Step20, Step21, Step22}, "AUTH words and accounts at stateRoot_pre"},
	{"B2.Post", Step18, []StepID{Step13, Step19, Step21, Step22}, "AUTH words and accounts at stateRoot_post"},
	{"B2.Changed", Step18, []StepID{Step19, Step21}, "rows that differ outside the flips; the precedence rule needs 'equal at pre and post'"},
	{"B2.RecordCreatedInBlock", Step18, []StepID{Step18b, Step19}, "n1: record not valid at pre"},
	{"B2.GovernanceExecutedFlip", Step18, nil, "b22 of the record went 0 to 1 inside B_v (passes, reported)"},
	{"B2.Validators", Step18, []StepID{Step19, Step21}, "validatorList entries with registered, power, BLS key"},
	{"B2.CodeFailure", Step18, []StepID{Step19}, "first code-identity failure of A, V, G at the attestation stations"},
	{"B2.IB", Step22, []StepID{Step19, Step21}, "rule IB verdict; executes before 19 and 21 (ExecOrder)"},
}
