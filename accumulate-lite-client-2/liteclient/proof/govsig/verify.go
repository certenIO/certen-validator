// Copyright 2026 Certen Protocol

package govsig

import (
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Digest-form labels. "metadata" and "initiator-merkle" are the two digests protocol/signature_utils.go
// verifySigSplit tries, in that order; "eip712" is the typedData digest, which is neither. Recorded for observability;
// the DECISION is always protocol's own Verify.
const (
	FormMetadata = "metadata"
	FormMerkle   = "initiator-merkle"
	FormEIP712   = "eip712"
)

// Eth rules. An ETH signature is verified by one of two rules: the V2 (>= v2-baikonur) raw 64/65-byte r||s rule, or
// the V1 (< v2-baikonur) DER rule. protocol.VerifyUserSignature is V2; protocol.VerifyUserSignatureV1 is V1.
const (
	EthRuleNone  = ""
	EthRuleV2RSV = "v2-rsv"
	EthRuleV1DER = "v1-der"
)

// SignatureMalformed is a signature the Accumulate library cannot even evaluate: its own Verify panics on the input (for
// example a delegated typedData signature with no delegator dereferences it). The executor never records such a
// signature, so it can never count; a validator must refuse it by name and keep running, never crash on it.
type SignatureMalformed struct{ Reason string }

func (e SignatureMalformed) Error() string {
	return "signature_malformed: Accumulate's own verification cannot evaluate it (" + e.Reason + ")"
}

// callVerify runs one of Accumulate's own Verify functions and turns a panic inside it into the named refusal
// SignatureMalformed. It is a refusal, never an acceptance, and is not a fallback to any weaker check.
func callVerify(f func(protocol.UserSignature, protocol.Signable) bool, us protocol.UserSignature, msg protocol.Signable) (valid bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			valid, err = false, SignatureMalformed{Reason: fmt.Sprint(r)}
		}
	}()
	return f(us, msg), nil
}

// Where is where a signature was recorded: the partition whose chain holds it and that partition's local block.
// Block numbers are per partition (the Directory's are ~9.5M, a BVN's ~12.5M), so a block without its partition says
// nothing about the executor version.
type Where struct {
	Partition string
	Block     int64
}

// Env is everything a verification reads besides the signature.
type Env struct {
	// TxHash is the governed transaction's hash; it is the message every non-typedData type signs.
	TxHash [32]byte
	// Transaction is the full governed transaction. typedData signs an EIP-712 encoding of the whole transaction, so it
	// cannot be verified without it.
	Transaction *protocol.Transaction
	// NetworkName is the network's name ("DevNet" on Kermit); typedData's chain id is protocol.EthChainID of it.
	NetworkName string
	// Where is where the signature was recorded, for the executor-version gate. The zero value is "unknown": a gated
	// type then gets the named state ExecutorVersionUnproven, never acceptance.
	Where Where
}

// Verified is a signature that Accumulate's own code accepts.
type Verified struct {
	Inner      protocol.KeySignature
	Delegators []*url.URL // outermost first
	KeyHash    []byte
	Form       string
	EthRule    string
}

// SignatureInvalid is a genuine rejection: Accumulate's Verify says this signature does not sign this transaction.
type SignatureInvalid struct {
	Type  string
	Forms []string
}

func (e SignatureInvalid) Error() string {
	return fmt.Sprintf("signature verification failed against all %d accepted digest form(s) (%s) for a %s signature",
		len(e.Forms), strings.Join(e.Forms, ", "), e.Type)
}
func (e SignatureInvalid) Reason() string { return "signature-invalid" }

// TransactionUnavailableForTypedData: typedData cannot be verified from a hash.
type TransactionUnavailableForTypedData struct{ TxHash string }

func (e TransactionUnavailableForTypedData) Error() string {
	return fmt.Sprintf("a typedData signature signs the EIP-712 encoding of the whole transaction, not its hash; the "+
		"transaction %s was not supplied, so the signature cannot be verified. This is NOT a governance rejection", e.TxHash)
}
func (e TransactionUnavailableForTypedData) Reason() string {
	return "transaction_unavailable_for_typed_data"
}

// NetworkNameUnproven: typedData's chain id is the network's, and the network's name was not supplied.
type NetworkNameUnproven struct{}

func (NetworkNameUnproven) Error() string {
	return "a typedData signature carries the network's EIP-155 chain id, derived from the network's name; the name " +
		"was not supplied, so the chain id cannot be checked. This is NOT a governance rejection"
}
func (NetworkNameUnproven) Reason() string { return "network_name_unproven" }

// TypedDataChainIDMismatch: the executor refuses a typedData signature whose ChainID is not the network's
// (sig_user.go checkChainID); the signature verifies cryptographically under any chain id.
type TypedDataChainIDMismatch struct {
	Want, Got   string
	NetworkName string
}

func (e TypedDataChainIDMismatch) Error() string {
	return fmt.Sprintf("invalid chain ID: want %s (network %q), got %s", e.Want, e.NetworkName, e.Got)
}
func (e TypedDataChainIDMismatch) Reason() string { return "typed_data_chain_id_mismatch" }

// Verify verifies sig exactly as Accumulate's executor does and returns what was established, or a typed refusal.
func Verify(sig protocol.Signature, env Env) (*Verified, error) {
	us, ok := sig.(protocol.UserSignature)
	if !ok {
		t := "nil"
		if sig != nil {
			t = sig.Type().String()
		}
		return nil, NotKeySignature{Type: t}
	}
	un, err := Unwrap(sig)
	if err != nil {
		return nil, err
	}
	inner := un.Inner
	typed := inner.Type() == protocol.SignatureTypeTypedData

	var msg protocol.Signable = protocol.SignableHash(env.TxHash)
	if typed {
		if env.Transaction == nil {
			return nil, TransactionUnavailableForTypedData{TxHash: fmt.Sprintf("%x", env.TxHash)}
		}
		if h := env.Transaction.Hash(); h != env.TxHash {
			return nil, fmt.Errorf("the supplied transaction hashes to %x, not to %x", h, env.TxHash)
		}
		msg = env.Transaction
	}

	// The verdict: Accumulate's own Verify on the OUTERMOST signature.
	rule := EthRuleNone
	valid, perr := callVerify(protocol.VerifyUserSignature, us, msg)
	if perr != nil {
		return nil, perr
	}
	if valid && inner.Type() == protocol.SignatureTypeETH {
		rule = EthRuleV2RSV
	}
	if !valid && inner.Type() == protocol.SignatureTypeETH {
		v1, perr := callVerify(protocol.VerifyUserSignatureV1, us, msg)
		if perr != nil {
			return nil, perr
		}
		if v1 {
			valid, rule = true, EthRuleV1DER
		}
	}
	if !valid {
		return nil, SignatureInvalid{Type: inner.Type().String(), Forms: formsTried(inner)}
	}

	if typed {
		if strings.TrimSpace(env.NetworkName) == "" {
			return nil, NetworkNameUnproven{}
		}
		want := protocol.EthChainID(env.NetworkName)
		td, ok := inner.(*protocol.TypedDataSignature)
		if !ok || td.ChainID == nil || want.Cmp(td.ChainID) != 0 {
			got := "<none>"
			if ok && td.ChainID != nil {
				got = td.ChainID.String()
			}
			return nil, TypedDataChainIDMismatch{Want: want.String(), Got: got, NetworkName: env.NetworkName}
		}
	}

	if err := CheckExecutorGate(inner.Type(), rule, env.Where); err != nil {
		return nil, err
	}

	kh, err := KeyHash(inner)
	if err != nil {
		return nil, err
	}
	return &Verified{Inner: inner, Delegators: un.Delegators, KeyHash: kh, Form: digestForm(sig, inner, msg, rule), EthRule: rule}, nil
}

func formsTried(inner protocol.KeySignature) []string {
	switch inner.Type() {
	case protocol.SignatureTypeTypedData:
		return []string{FormEIP712}
	case protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256:
		// Initiator() refuses for these two (ErrCannotInitiate): only the metadata digest exists.
		return []string{FormMetadata}
	default:
		return []string{FormMetadata, FormMerkle}
	}
}

// metadataOnly is an outer signature that exposes only protocol.Signature, so the inner key's own Verify cannot reach
// the Initiator() merkle form (verifySigSplit asserts outer.(UserSignature) and stops when it is not one). Asking the
// key's own Verify with it answers "did the METADATA digest carry this signature?" without recomputing any digest here.
type metadataOnly struct{ protocol.Signature }

// FormV1Rule labels an eth signature accepted under the pre-Baikonur DER rule: protocol keeps that rule in an
// unexported wrapper, so which of the two digests carried it is not asked.
const FormV1Rule = "v1-rule"

// Form labels which digest carried an outer signature that is already known to verify over msg: "metadata",
// "initiator-merkle", or "eip712". It asks the inner key's own Verify; it recomputes no digest.
func Form(outer protocol.Signature, msg protocol.Signable) (string, error) {
	un, err := Unwrap(outer)
	if err != nil {
		return "", err
	}
	return digestForm(outer, un.Inner, msg, EthRuleNone), nil
}

// digestForm labels which digest carried a signature that is already known to verify.
func digestForm(outer protocol.Signature, inner protocol.KeySignature, msg protocol.Signable, rule string) string {
	if inner.Type() == protocol.SignatureTypeTypedData {
		return FormEIP712
	}
	if rule == EthRuleV1DER {
		return FormV1Rule
	}
	if inner.Verify(metadataOnly{outer}, msg) {
		return FormMetadata
	}
	return FormMerkle
}
