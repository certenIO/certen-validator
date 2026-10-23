// Copyright 2026 Certen Protocol

package arbfinal

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The codes this kind raises beyond the framework's (V2_SPEC_S7 section 7, Arbitrum R, Base R shared, L1 head R). The machine
// registry is pkg/finality/testdata/finality/states.json; the conformance test of this package asserts that every code and
// every closed reason set below is the registry's.
const (
	CodePreBold             = "pre_bold_block"
	CodePinMismatch         = "pin_mismatch"
	CodeL1FinalityUnproven  = "l1_finality_unproven"
	CodeContractIdentity    = "contract_identity_unproven"
	CodeStateProofInvalid   = "l1_state_proof_invalid"
	CodeTxProofInvalid      = "l1_tx_proof_invalid"
	CodeMachineNotFinished  = "assertion_machine_not_finished"
	CodeNotConfirmed        = "assertion_not_confirmed"
	CodeAssertionUnknown    = "assertion_unknown"
	CodePreimageMismatch    = "assertion_preimage_mismatch"
	CodeHeaderChainExceeds  = "header_chain_exceeds_bound"
	CodeHeaderChainBroken   = "finality_header_chain_broken"
	CodeConfirmedByOwner    = "confirmed_by_owner_force"
	CodeConfirmationUnproof = "confirmation_path_unproven"
	CodeHistoryUnavailable  = "assertion_history_unavailable"
	CodeL2HeadersUnavail    = "l2_headers_unavailable"
	CodeL2HeaderUnavail     = "l2_header_unavailable"
	CodeProofWindow         = "l1_proof_window_unavailable"
	CodeL1StateUnavailable  = "l1_state_unavailable"
	CodeSourceUnavailable   = "finality_source_unavailable"
	pendingCodeAwaitCover   = "awaiting_covering_assertion"
	pendingCodeAwaitConfirm = "awaiting_assertion_confirmation"
	pendingCodeAwaitL1Final = "awaiting_l1_finality_of_confirmation"
)

// L1FinalityReason is the reason of l1_finality_unproven (a closed set in states.json).
type L1FinalityReason string

const (
	L1FinalityLCRefused    L1FinalityReason = "lc_refused"
	L1FinalitySpineRefused L1FinalityReason = "spine_refused"
)

// PreimagePart is the part of assertion_preimage_mismatch (a closed set in states.json): which recomputed value disagrees with
// the value proven on L1.
type PreimagePart string

const (
	PreimageParentConfig    PreimagePart = "parent_config"
	PreimageConfirmationLog PreimagePart = "confirmation_log"
)

// ConfirmReason is the reason of confirmation_path_unproven (a closed set in states.json).
type ConfirmReason string

const (
	// ConfirmIndirect: the transaction's caller is code the verifier does not decode (a statement about unknown code, never a
	// weaker level).
	ConfirmIndirect ConfirmReason = "indirect"
	// ConfirmReceiptStatus: the confirmation receipt's status is not 1.
	ConfirmReceiptStatus ConfirmReason = "receipt_status_not_one"
	// ConfirmLogMissing: the receipt holds no AssertionConfirmed log of the Rollup for this assertion hash.
	ConfirmLogMissing ConfirmReason = "confirmation_log_missing"
	// ConfirmWalletNoConfirm: a ValidatorWallet call decoded, but no decoded call targets the Rollup with confirmAssertion.
	ConfirmWalletNoConfirm ConfirmReason = "wallet_no_confirm_call"
	// ConfirmWalletUndecodable: the transaction selects a ValidatorWallet entry point whose arguments do not decode.
	ConfirmWalletUndecodable ConfirmReason = "wallet_calldata_undecodable"
	// ConfirmFastConfirmerSet: a wallet confirmation while anyTrustFastConfirmer is not the zero address at K.
	ConfirmFastConfirmerSet ConfirmReason = "fast_confirmer_set"
)

// HeaderChainReason is the reason of finality_header_chain_broken (the L2 spine).
type HeaderChainReason string

const (
	ReasonParentHash HeaderChainReason = "parent_hash_mismatch"
	ReasonNumberGap  HeaderChainReason = "number_gap"
)

// SpineL2 is the spine field of finality_header_chain_broken for the Arbitrum L2 spine.
const SpineL2 = "l2"

// Forced-path names of confirmed_by_owner_force.
const (
	PathForce = "force"
	PathFast  = "fast"
)

// Roles of the logic_pins.
const (
	RoleAdminLogic = "rollup_admin_logic"
	RoleUserLogic  = "rollup_user_logic"
	roleRollup     = "rollup"
	// RoleWalletProxy is the exact runtime code of a ValidatorWallet proxy: the OpenZeppelin 4.7.3 TransparentUpgradeableProxy that
	// ValidatorWalletCreator.createWallet deploys (it has no immutables, so every wallet of the build has this code hash).
	RoleWalletProxy = "validator_wallet_proxy"
	// RoleWalletLogic is the exact runtime code of the pinned ValidatorWallet implementation (the creator's template, which embeds
	// its own address as the DelegateCallAware immutable, so the code hash names one deployment).
	RoleWalletLogic = "validator_wallet_logic"
)

// PinMismatch is pin_mismatch{field}.
func PinMismatch(field string) *finality.StateError {
	return finality.NewState(CodePinMismatch, "field", field)
}

// StateProofInvalid is l1_state_proof_invalid{which}.
func StateProofInvalid(which string, kv ...any) *finality.StateError {
	return finality.NewState(CodeStateProofInvalid, append([]any{"which", which}, kv...)...)
}

// TxProofInvalid is l1_tx_proof_invalid{which}.
func TxProofInvalid(which string) *finality.StateError {
	return finality.NewState(CodeTxProofInvalid, "which", which)
}

// ContractIdentity is contract_identity_unproven{role, address, code_hash, judged_at}: judged_at is the L1 block number whose
// state (S or K) was read.
func ContractIdentity(role string, address, codeHash []byte, judgedAt uint64) *finality.StateError {
	return finality.NewState(CodeContractIdentity, "role", role, "address", address, "code_hash", codeHash, "judged_at", judgedAt)
}

// L1FinalityUnproven is l1_finality_unproven{reason, inner}: the inner code of the refusal of the L1 head verifier.
func L1FinalityUnproven(reason L1FinalityReason, inner string) *finality.StateError {
	return finality.NewState(CodeL1FinalityUnproven, "reason", reason, "inner", inner)
}

// HeaderChainBroken is finality_header_chain_broken{spine:"l2", at_number, want_hash, got_hash, reason}.
func HeaderChainBroken(atNumber uint64, want, got [32]byte, reason HeaderChainReason) *finality.StateError {
	return finality.NewState(CodeHeaderChainBroken, "spine", SpineL2, "at_number", atNumber, "want_hash", want, "got_hash", got, "reason", reason)
}

// HeaderChainExceeds is header_chain_exceeds_bound{needed, max}.
func HeaderChainExceeds(needed, max uint64) *finality.StateError {
	return finality.NewState(CodeHeaderChainExceeds, "needed", needed, "max", max)
}

// ConfirmedByOwnerForce is confirmed_by_owner_force{path, tx, l1_block}.
func ConfirmedByOwnerForce(path string, tx [32]byte, l1Block uint64) *finality.StateError {
	return finality.NewState(CodeConfirmedByOwner, "path", path, "tx", tx, "l1_block", l1Block)
}

// ConfirmationUnproven is confirmation_path_unproven{reason, tx, l1_block}.
func ConfirmationUnproven(reason ConfirmReason, tx [32]byte, l1Block uint64) *finality.StateError {
	return finality.NewState(CodeConfirmationUnproof, "reason", reason, "tx", tx, "l1_block", l1Block)
}

// PreimageMismatch is assertion_preimage_mismatch{part}.
func PreimageMismatch(part PreimagePart) *finality.StateError {
	return finality.NewState(CodePreimageMismatch, "part", part)
}

// FaultState adapts an L1 head fault to the framework's state, same code and same field names (l1adapt's conversion).
func FaultState(f *ethl1.Fault) *finality.StateError { return l1adapt.FaultState(f) }

// asState returns err as a *StateError: a StateError as is, an L1 head fault adapted, anything else a verifier failure (never
// a silent pass).
func asState(err error) error {
	if err == nil {
		return nil
	}
	if s, ok := finality.AsNamed(err); ok {
		return s
	}
	if _, ok := err.(*ethl1.Fault); ok {
		return l1adapt.State(err)
	}
	return finality.NewState(finality.CodeVerifierFailed, "cause", err.Error())
}

// innerCode is the code of the named state carried by err ("" for an error that is not one).
func innerCode(err error) string {
	if f, ok := err.(*ethl1.Fault); ok {
		return f.Code
	}
	if s, ok := finality.AsNamed(err); ok {
		return s.Code
	}
	return ""
}
