// Copyright 2026 Certen Protocol

// Package ethl1 is the offline verifier of the Ethereum L1 finalized head (V2_SPEC_S7 section 5.2): a beacon light-client
// walk from a pinned sync committee to a finality update, read spec-literally from ethereum/consensus-specs
// v1.7.0-beta.4 (aa16bb4c) for the Gloas layout, and the execution-header spine that connects a block to the finalized
// execution head. It is pure: no I/O, no clock, no randomness, and it trusts only its Pins argument and standard
// cryptography. It imports nothing else from pkg/finality; its Fault type is adapted to the framework's StateError by
// the framework, with the same code and the same field names.
package ethl1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Fault is a named state of the L1 head verifier (spec section 7, "L1 head R"). Code is one of the Code* constants and
// Fields holds exactly the field names of the spec for that code (plus the extra judged-at fields the spec elides with an
// ellipsis). Values are uint64, int, string, bool, [32]byte, [4]byte or []byte.
type Fault struct {
	Code   string
	Fields map[string]any
}

// Error implements error with the canonical JSON form.
func (f *Fault) Error() string { return string(f.CanonicalJSON()) }

// The L1 head codes of spec section 7.
const (
	CodeNetworkMismatch     = "finality_network_mismatch"
	CodeForkUnsupported     = "finality_fork_unsupported"
	CodeEvidenceMalformed   = "finality_evidence_malformed"
	CodePinUnknown          = "finality_pin_unknown"
	CodePinMismatch         = "finality_pin_mismatch"
	CodePinWindow           = "finality_pin_window"
	CodeBootstrapInvalid    = "finality_bootstrap_invalid"
	CodeLinkInvalid         = "finality_link_invalid"
	CodeParticipationInsuff = "finality_participation_insufficient"
	CodeSignatureInvalid    = "finality_signature_invalid"
	CodePeriodGap           = "finality_period_gap"
	CodeBlockNotCovered     = "finality_block_not_covered"
	CodeLedgerBehind        = "finality_ledger_behind"
	CodeHeaderChainBroken   = "finality_header_chain_broken"
	CodeEvidenceTooLarge    = "finality_evidence_too_large"
)

// AllCodes lists every code this package can return, in the order of spec section 7.
func AllCodes() []string {
	return []string{
		CodeNetworkMismatch, CodeForkUnsupported, CodePinUnknown, CodePinMismatch, CodePinWindow, CodeBootstrapInvalid,
		CodeLinkInvalid, CodeParticipationInsuff, CodeSignatureInvalid, CodePeriodGap, CodeBlockNotCovered,
		CodeLedgerBehind, CodeHeaderChainBroken, CodeEvidenceMalformed, CodeEvidenceTooLarge,
	}
}

func fault(code string, kv ...any) *Fault {
	f := &Fault{Code: code, Fields: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Fields[kv[i].(string)] = kv[i+1]
	}
	return f
}

// NetworkMismatch: the pins' network is not the chain the caller is judging.
func NetworkMismatch(chainID, wantChainID uint64) *Fault {
	return fault(CodeNetworkMismatch, "chain_id", chainID, "want_chain_id", wantChainID)
}

// ForkUnsupported: the object's attested (or bootstrap) header lies in a fork whose layout this verifier does not carry.
// layout is the carried layout name ("electra", "gloas").
func ForkUnsupported(slot, epoch uint64, layout string) *Fault {
	return fault(CodeForkUnsupported, "slot", slot, "epoch", epoch, "layout", layout)
}

// EvidenceMalformed: a part does not parse at its layout's lengths or has a forbidden value.
func EvidenceMalformed(part string, index int, reason string, gotLen, wantLen int) *Fault {
	return fault(CodeEvidenceMalformed, "part", part, "index", index, "reason", reason, "got_len", gotLen, "want_len", wantLen)
}

// PinUnknown: the anchor period has no ledger entry (or no block_root for a kind-2 anchor) although it lies inside the ledger.
func PinUnknown(kind uint8, period uint64, root [32]byte) *Fault {
	return fault(CodePinUnknown, "kind", int(kind), "period", period, "root", root)
}

// PinMismatch: a committee or bootstrap root the walk met differs from the ledger entry of its period.
func PinMismatch(period uint64, wantRoot, gotRoot [32]byte) *Fault {
	return fault(CodePinMismatch, "period", period, "want_root", wantRoot, "got_root", gotRoot)
}

// PinWindow: a step moved the finalized epoch further than the weak-subjectivity period published with the anchor.
func PinWindow(anchorEpoch, finalizedEpoch, wspEpochs uint64) *Fault {
	return fault(CodePinWindow, "anchor_epoch", anchorEpoch, "finalized_epoch", finalizedEpoch, "wsp_epochs", wspEpochs)
}

// BootstrapInvalid: the kind-2 anchor's bootstrap failed an initialize_light_client_store check.
func BootstrapInvalid(check string, slot uint64) *Fault {
	return fault(CodeBootstrapInvalid, "check", check, "slot", slot)
}

// LinkInvalid: update number index (the final update has index len(links)) failed a validate/apply check.
func LinkInvalid(index int, check string, attestedSlot, signatureSlot, period uint64) *Fault {
	return fault(CodeLinkInvalid, "index", index, "check", check, "attested_slot", attestedSlot,
		"signature_slot", signatureSlot, "period", period)
}

// ParticipationInsufficient: fewer than 342 of 512 sync-committee bits are set.
func ParticipationInsufficient(index, participants, required, committee int) *Fault {
	return fault(CodeParticipationInsuff, "index", index, "participants", participants, "required", required, "committee", committee)
}

// SignatureInvalid: the aggregate signature does not verify (or a key or the signature is not a valid non-identity point).
func SignatureInvalid(index int, signatureSlot uint64, forkVersion [4]byte, participants int) *Fault {
	return fault(CodeSignatureInvalid, "index", index, "signature_slot", signatureSlot, "fork_version", forkVersion, "participants", participants)
}

// PeriodGap: the final update was signed in a period the walk has no committee for.
func PeriodGap(signaturePeriod, storePeriod uint64) *Fault {
	return fault(CodePeriodGap, "signature_period", signaturePeriod, "store_period", storePeriod)
}

// BlockNotCovered: the block lies above the finalized execution head of the spine (the builder maps this to pending).
func BlockNotCovered(blockNumber, spineTopNumber uint64) *Fault {
	return fault(CodeBlockNotCovered, "block_number", blockNumber, "finalized_exec_number", spineTopNumber)
}

// LedgerBehind: the proof needs a ledger period beyond the ledger's head (the verifier is older than the proof).
func LedgerBehind(neededPeriod, ledgerHeadPeriod uint64) *Fault {
	return fault(CodeLedgerBehind, "needed_period", neededPeriod, "ledger_head_period", ledgerHeadPeriod)
}

// HeaderChainBroken: a spine header does not follow its child. spine is "l1" for this package; reason is hash, number or rlp.
func HeaderChainBroken(spine string, atNumber uint64, wantHash, gotHash [32]byte, reason string) *Fault {
	return fault(CodeHeaderChainBroken, "spine", spine, "at_number", atNumber, "want_hash", wantHash, "got_hash", gotHash, "reason", reason)
}

// EvidenceTooLarge: a count exceeds its bound; the number is reported, nothing is truncated.
func EvidenceTooLarge(part string, count, limit int) *Fault {
	return fault(CodeEvidenceTooLarge, "part", part, "count", count, "limit", limit)
}

// Canonical renders the fields as strings: every integer as a decimal string, byte arrays as 0x-prefixed lower-case hex.
func (f *Fault) canonicalFields() map[string]any {
	out := make(map[string]any, len(f.Fields))
	for k, v := range f.Fields {
		switch x := v.(type) {
		case uint64:
			out[k] = strconv.FormatUint(x, 10)
		case uint32:
			out[k] = strconv.FormatUint(uint64(x), 10)
		case uint8:
			out[k] = strconv.FormatUint(uint64(x), 10)
		case int:
			out[k] = strconv.FormatInt(int64(x), 10)
		case int64:
			out[k] = strconv.FormatInt(x, 10)
		case string:
			out[k] = x
		case bool:
			out[k] = x
		case [32]byte:
			out[k] = "0x" + hex.EncodeToString(x[:])
		case [4]byte:
			out[k] = "0x" + hex.EncodeToString(x[:])
		case []byte:
			out[k] = "0x" + hex.EncodeToString(x)
		default:
			panic(fmt.Sprintf("ethl1: fault field %q has unsupported type %T", k, v))
		}
	}
	return out
}

// CanonicalJSON is {"code":...,"fields":{...}} with keys sorted at every level, no whitespace, every integer a decimal
// string and every byte string 0x-lower-case hex. Go and TypeScript must produce identical bytes for identical faults.
func (f *Fault) CanonicalJSON() []byte {
	var b bytes.Buffer
	b.WriteString(`{"code":`)
	writeJSONString(&b, f.Code)
	b.WriteString(`,"fields":{`)
	cf := f.canonicalFields()
	keys := make([]string, 0, len(cf))
	for k := range cf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(&b, k)
		b.WriteByte(':')
		switch x := cf[k].(type) {
		case string:
			writeJSONString(&b, x)
		case bool:
			if x {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		}
	}
	b.WriteString(`}}`)
	return b.Bytes()
}

func writeJSONString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimSuffix(tmp.Bytes(), []byte{'\n'}))
}
