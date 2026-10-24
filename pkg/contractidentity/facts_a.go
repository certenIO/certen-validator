// Copyright 2026 Certen Protocol

package contractidentity

import (
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
)

// FactsA are the facts of package 2a (steps 1c-14). Package 2a owns this file: it adds fields and rows of factSpecsA here and nowhere else.
type FactsA struct {
	// SettleHeader is the settlement header read positionally (number, hash, stateRoot, parent, roots).
	SettleHeader finality.HeaderFields
	// Account, AnchorID, LeafKey and Selector are the settlement path: the emitter of the selected LeafConsumed log, its topics 1 and 2, and
	// the first four bytes of the settlement transaction input. Generation is the pinned account build key the code selected.
	Account    common.Address
	AnchorID   [32]byte
	LeafKey    [32]byte
	Selector   [4]byte
	Generation string
	// GenerationState is the `U account_generation_unpinned` of step 3(e) when the account code is a pinned:false generation row (nil otherwise);
	// AccountRefusal is the judgement refusal of step 5 (account_absent, code_unproven_bytes, code_not_published, proof_invalid) while the account is
	// not established. The steps that depend on the account (6-9, 14) decide their part with these states and read nothing from it.
	GenerationState *StateError
	// PathFailure is the unproven state step 3 decided settlement_path with (settlement_not_executed, settlement_event_missing, settlement_path_unsupported)
	// while the account is not selected or its settlement selector is not pinned: the steps that need the account or the calldata decide their part with it.
	PathFailure    *StateError
	AccountRefusal *StateError
	// StateRootN is item 3 of the settlement header: the root every settle-station read is judged against.
	StateRootN [32]byte
	// AccountState and AccountCode are the proven account of step 5 and its carried runtime code.
	AccountState AccountState
	AccountCode  []byte
	// ADIURL and GoverningBook are the account strings of step 6 (slots 0 and 11); GoverningBookHash is the immutable value of step 7.
	ADIURL            string
	GoverningBook     string
	GoverningBookHash [32]byte
	// FactoryAddress is the manifest accountFactory row of the chain (step 8).
	FactoryAddress common.Address
	// Anchor is the anchor `A`: the manifest `anchor` deployment row of the chain. Step 9 judges that the account's pointer (slot 2) equals it
	// (part pointer); it publishes the row address WHENEVER the manifest has it, also when the settle part is Stated and the pointer could not
	// be read, so that the attestation steps can still be judged from their own evidence (spec 1c(b)).
	Anchor common.Address
	// AnchorState and AnchorCode are the proven anchor account and its carried code (step 10).
	AnchorState AccountState
	AnchorCode  []byte
	// AnchorRefusal is the refusal of step 10 while the anchor account is not established (steps 11 and 12 read nothing from it then).
	AnchorRefusal *StateError
	// Record is the anchors[anchorId] record at stateRoot_N (step 11).
	Record AnchorRecord
	// Verifier chain (step 12): V (slot 30 low 20 bytes), its proven state and code, and G (the generated Groth16 verifier) with its build.
	Verifier      common.Address
	VerifierState AccountState
	VerifierCode  []byte
	Groth16       common.Address
	Groth16State  AccountState
	Groth16Code   []byte
	Groth16Build  string
	VerifierFlags [2]byte // bytes 21 and 22 of anchor slot 30, reported
	// SettleAUTH are the step-18 AUTH words read at stateRoot_N (row id -> word), for the settle-state alerts and drifts (step 13).
	SettleAUTH map[string]common.Hash
	// Authority is the report's `authority` object (step 14); nil when the level was not established.
	Authority *AuthorityObject
}

// AnchorRecord is the 13-word anchors[anchorId] record with the words steps 17, 18 and 20 compare. All fields are the stored words
// (bytes32 / uint256 as read); Words holds the 13 raw words in slot order.
type AnchorRecord struct {
	Words                 [13]common.Hash
	BundleID              [32]byte
	MerkleRoot            [32]byte
	OperationID           [32]byte
	ExecutionCommitment   [32]byte
	AccSetRoot            [32]byte
	AccIncarnation        [32]byte
	BatchLeafCount        [32]byte
	AccumulateBlockHeight [32]byte
	Valid                 bool
	ProofExecuted         bool
	GovernanceExecuted    bool
	GovernanceLevel       uint8
	IsBatchAnchor         bool
}

var factSpecsA = []FactSpec{
	{"A.PathFailure", Step3, []StepID{Step5, Step6, Step7, Step8, Step9, Step11, Step14}, "the unproven state of step 3 while no account is selected or the selector is not pinned"},
	{"A.GenerationState", Step3, []StepID{Step5, Step6, Step7, Step8, Step9, Step14}, "U account_generation_unpinned of step 3(e); the account-dependent steps decide their part with it"},
	{"A.AccountRefusal", Step5, []StepID{Step6, Step7, Step8, Step9, Step14}, "the refusal of step 5 while the account is not established"},
	{"A.AnchorRefusal", Step10, []StepID{Step11, Step12}, "the refusal of step 10 while the anchor account is not established"},
	{"A.SettleHeader", Step2, []StepID{Step4, Step24}, "positional header of Settlement.Header; hash equals Leg.blockHash"},
	{"A.Account", Step3, []StepID{Step4, Step5, Step6, Step7, Step8, Step9, Step14}, "emitter of the selected LeafConsumed log; the account is identified by emitter and code"},
	{"A.AnchorID", Step3, []StepID{Step11, Step13, Step14, Step17, Step18, Step18b, Step20}, "topic1 of the selected LeafConsumed log; not an input"},
	{"A.LeafKey", Step3, []StepID{Step4}, "topic2 of the selected log; equals S6.Slot.Key when s6_proven"},
	{"A.Selector", Step3, []StepID{Step14}, "settlement input selector: one of [MAN].selectors.account.V7_3"},
	{"A.Generation", Step3, []StepID{Step7, Step8, Step14}, "account build key chosen by the masked code hash (3e, 5)"},
	{"A.StateRootN", Step4, []StepID{Step5, Step6, Step8, Step9, Step10, Step11, Step12, Step13, Step14, Step24}, "stateRoot of the settlement header"},
	{"A.AccountState", Step5, []StepID{Step6, Step7, Step8, Step9, Step14}, "account proof of `account` at stateRoot_N"},
	{"A.AccountCode", Step5, []StepID{Step7}, "carried runtime code of the account (references for the immutables)"},
	{"A.ADIURL", Step6, []StepID{Step7, Step8, Step14}, "account slot 0 string, byte-equal to LegContext.ADIURL"},
	{"A.GoverningBook", Step6, []StepID{Step7, Step8}, "account slot 11 string"},
	{"A.GoverningBookHash", Step7, []StepID{Step14}, "keccak256(bytes(book)): the immutable the level rule compares the authority book with"},
	{"A.FactoryAddress", Step8, []StepID{Step9}, "manifest accountFactory row (address_not_published judgement of step 9)"},
	{"A.Anchor", Step9, []StepID{Step10, Step11, Step12, Step13, Step17, Step18, Step19, Step21, Step22}, "A: the manifest anchor row the account pointer must equal"},
	{"A.AnchorState", Step10, []StepID{Step11, Step12, Step13, Step18}, "account proof of A at stateRoot_N"},
	{"A.AnchorCode", Step10, []StepID{Step18, Step19}, "carried runtime code of A (code identity at pre and post)"},
	{"A.Record", Step11, []StepID{Step17, Step18, Step18b, Step20}, "anchors[anchorId] at stateRoot_N; bound to Batch"},
	{"A.Verifier", Step12, []StepID{Step13, Step18, Step19, Step21}, "V: anchor slot 30 low 20 bytes"},
	{"A.VerifierState", Step12, []StepID{Step13}, "account proof of V at stateRoot_N"},
	{"A.VerifierCode", Step12, []StepID{Step19}, "carried code of V (judged again for V_attest = V_settle)"},
	{"A.Groth16", Step12, []StepID{Step18, Step19}, "G: the generated verifier address (3 references in V)"},
	{"A.Groth16State", Step12, []StepID{Step13}, "account proof of G at stateRoot_N"},
	{"A.Groth16Code", Step12, []StepID{Step19}, "carried code of G"},
	{"A.Groth16Build", Step12, []StepID{Step19}, "manifest build key (r5 or r7) of the generated verifier"},
	{"A.VerifierFlags", Step12, []StepID{Step21}, "bytes 21 and 22 of anchor slot 30, reported"},
	{"A.SettleAUTH", Step13, nil, "AUTH words at stateRoot_N; compared with Facts.B2 for drift/alert (Open entries only)"},
	{"A.Authority", Step14, []StepID{Step23}, "report.authority {level, logged_level, book, page, source, legs[]}"},
}
