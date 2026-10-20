// Copyright 2026 Certen Protocol

package adiri

import (
	"github.com/certen/independant-validator/pkg/finality"
)

// The Adiri group of V2_SPEC_S7 section 7 (field names exactly those of testdata/finality/states.json).
const (
	CodeIncarnationMismatch = "adiri_incarnation_mismatch"
	CodePinMismatch         = "evidence_pin_mismatch"
	CodeCommitteeBroken     = "committee_chain_broken"
	CodeCodecUnsupported    = "epoch_record_codec_unsupported"
	CodeLinkBroken          = "finality_link_broken"
	CodeCommitteeShrunk     = "committee_shrunk"
	CodeHeaderChainBroken   = "finality_header_chain_broken"
	CodeSourceUnavailable   = "finality_source_unavailable"
)

// The checks of committee_chain_broken that the compact encoding can reach. epoch_slot, digest_mismatch and
// parent_hash_mismatch of the annex are unreachable in CFA1: the epoch is the position and parent_hash and the digest are
// recomputed, so a tampered field changes the digest the signature is checked against (signature_invalid).
const (
	CheckCommitteeIncompatible = "committee_incompatible"
	CheckDuplicateKey          = "committee_duplicate_key"
	CheckBelowQuorum           = "signers_below_quorum"
	CheckSignerIndexInvalid    = "signer_index_invalid"
	CheckPublicKeyInvalid      = "public_key_invalid"
	CheckSignatureInvalid      = "signature_invalid"
)

// The checks of finality_link_broken.
const (
	LinkTipNotFinalState  = "tip_not_final_state"
	LinkBlockAfterSeal    = "block_after_seal"
	LinkSlotValueMismatch = "slot_value_mismatch"
	LinkCodeHashMismatch  = "account_codehash_mismatch"
	LinkProofInvalid      = "proof_invalid"
	LinkHeaderDecode      = "header_decode"
	SpineName             = "adiri"
	PendingEpochOpen      = "epoch_open"
	PendingCertPending    = "epoch_certificate_pending"
	PendingEpochOverdue   = "epoch_overdue"
	PendingHistoryProof   = "history_proof_unavailable"
)

// ChainBroken is committee_chain_broken{epoch, check, ...}.
func ChainBroken(epoch uint64, check string, kv ...any) *finality.StateError {
	return finality.NewState(CodeCommitteeBroken, append([]any{"epoch", epoch, "check", check}, kv...)...)
}

// PinMismatch is evidence_pin_mismatch{pin, want, got}.
func PinMismatch(pin string, want, got any) *finality.StateError {
	return finality.NewState(CodePinMismatch, "pin", pin, "want", want, "got", got)
}

// IncarnationMismatch is adiri_incarnation_mismatch{expected_genesis, served_genesis}: the pinned epoch0_final_state against
// record(0).final_state (the first block the committee chain commits to, which the pinned genesis link ties to the genesis).
func IncarnationMismatch(want, got NumHash) *finality.StateError {
	return finality.NewState(CodeIncarnationMismatch, "expected_genesis", want.Hash, "served_genesis", got.Hash,
		"expected_number", want.Number, "served_number", got.Number, "pin", "epoch0_final_state")
}

// CodecUnsupported is epoch_record_codec_unsupported{epoch, ...}.
func CodecUnsupported(epoch uint64, pinned, supported string) *finality.StateError {
	return finality.NewState(CodeCodecUnsupported, "epoch", epoch, "pinned", pinned, "supported", supported)
}

// LinkBroken is finality_link_broken{from, to, at, check, ...}: from = the seal F, to = the leg block, at = the block number
// the check failed at.
func LinkBroken(check string, from, to, at uint64, kv ...any) *finality.StateError {
	return finality.NewState(CodeLinkBroken, append([]any{"from", from, "to", to, "at", at, "check", check}, kv...)...)
}

// HeaderChainBroken is finality_header_chain_broken{spine:"adiri", at_number, want_hash, got_hash, reason}.
func HeaderChainBroken(atNumber uint64, want, got [32]byte, reason HeaderChainReason) *finality.StateError {
	return finality.NewState(CodeHeaderChainBroken, "spine", SpineName, "at_number", atNumber, "want_hash", want, "got_hash", got, "reason", reason)
}

// Shrunk is the reported attribute committee_shrunk{epoch, size, expected}.
func Shrunk(epoch uint64, size, expected int) *finality.StateError {
	return finality.NewState(CodeCommitteeShrunk, "epoch", epoch, "size", uint64(size), "expected", uint64(expected))
}

// SourceUnavailable is finality_source_unavailable{reason, endpoints} (builder side); endpoints are already redacted.
func SourceUnavailable(reason SourceReason, endpoints []string, kv ...any) *finality.StateError {
	return finality.NewState(CodeSourceUnavailable, append([]any{"reason", reason, "endpoints", endpoints}, kv...)...)
}

// The closed reason sets of the Adiri states (testdata/finality/states.json enums.reason of each state); the conformance test
// adiri_test.go asserts that these constants are exactly the registry sets and that no other reason is ever raised.

// IncompatibleReason is the reason of committee_chain_broken{check:"committee_incompatible"}.
type IncompatibleReason string

const (
	ReasonLargerThanExpected    IncompatibleReason = "larger_than_expected"
	ReasonSetMismatch           IncompatibleReason = "set_mismatch"
	ReasonNotSubset             IncompatibleReason = "not_subset"
	ReasonBelowTwoThirds        IncompatibleReason = "below_two_thirds"
	ReasonBelowMinCommitteeSize IncompatibleReason = "below_min_committee_size"
)

// SignatureReason is the reason of committee_chain_broken{check:"signature_invalid"}.
type SignatureReason string

// HeaderChainReason is the reason of finality_header_chain_broken{spine:"adiri"}.
type HeaderChainReason string

const (
	ReasonParentHash HeaderChainReason = "parent_hash_mismatch"
	ReasonNumberGap  HeaderChainReason = "number_gap"
)

// SourceReason is the reason of finality_source_unavailable.
type SourceReason string

const (
	SourceEpochRecord      SourceReason = "epoch_record_unavailable"
	SourceHeaders          SourceReason = "headers_unavailable"
	SourceEpochRecordsFail SourceReason = "epoch_records_invalid"
	SourceHistoryProof     SourceReason = "history_proof_unavailable"
)
