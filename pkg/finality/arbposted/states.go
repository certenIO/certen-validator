// Copyright 2026 Certen Protocol

package arbposted

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The codes this kind raises beyond the framework's (V2_SPEC_S7 section 7, Arbitrum R, Base R shared, L1 head R). The machine
// registry is pkg/finality/testdata/finality/states.json.
const (
	CodeContentNotFound       = "l1_posted_content_not_found"
	CodeBatchDataOffL1        = "l1_batch_data_off_l1"
	CodeBatchHeaderUnknown    = "l1_batch_header_unknown"
	CodeDelayedOriginUnproven = "l1_posted_delayed_origin_unproven"
	CodePreBold               = "pre_bold_block"
	CodePinMismatch           = "pin_mismatch"
	CodeL1FinalityUnproven    = "l1_finality_unproven"
	CodeContractIdentity      = "contract_identity_unproven"
	CodeStateProofInvalid     = "l1_state_proof_invalid"
	CodeBlobCommitment        = "blob_commitment_mismatch"
)

// ContentReason is the reason of l1_posted_content_not_found (a closed set in states.json).
type ContentReason string

const (
	ContentNoDataBatch            ContentReason = "no_data_batch"
	ContentAccumulatorMismatch    ContentReason = "accumulator_mismatch"
	ContentBlockTxsRootMismatch   ContentReason = "block_txs_root_mismatch"
	ContentNoStandardTransactions ContentReason = "no_standard_transactions"
	ContentNoMatchingMessage      ContentReason = "no_matching_message"
	ContentPayloadUndecodable     ContentReason = "payload_undecodable"
	ContentUnsupportedTxType      ContentReason = "unsupported_tx_type"
)

// L1FinalityReason is the reason of l1_finality_unproven (a closed set in states.json).
type L1FinalityReason string

const (
	L1FinalityLCRefused    L1FinalityReason = "lc_refused"
	L1FinalitySpineRefused L1FinalityReason = "spine_refused"
)

// PinMismatch is pin_mismatch{field}.
func PinMismatch(field string) *finality.StateError {
	return finality.NewState(CodePinMismatch, "field", field)
}

func contentNotFound(reason ContentReason, kv ...any) *finality.StateError {
	return finality.NewState(CodeContentNotFound, append([]any{"reason", reason}, kv...)...)
}

func stateProofInvalid(which string) *finality.StateError {
	return finality.NewState(CodeStateProofInvalid, "which", which)
}

func contractIdentity(role string, address, codeHash []byte, judgedAt uint64) *finality.StateError {
	return finality.NewState(CodeContractIdentity, "role", role, "address", address, "code_hash", codeHash, "judged_at", judgedAt)
}

func blobMismatch() *finality.StateError { return finality.NewState(CodeBlobCommitment) }

func l1FinalityUnproven(reason L1FinalityReason, inner string) *finality.StateError {
	return finality.NewState(CodeL1FinalityUnproven, "reason", reason, "inner", inner)
}

// FaultState adapts an L1 head fault to the framework's state, same code and same field names (l1adapt's conversion).
func FaultState(f *ethl1.Fault) *finality.StateError { return l1adapt.FaultState(f) }
