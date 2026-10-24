// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// FactsB1 are the facts of package 2b-1 (steps 15-17 and 20). Package 2b-1 owns this file.
type FactsB1 struct {
	// AttestCaptured is true when the attest part is captured (step 15); false means steps 16-22 judge nothing.
	AttestCaptured bool
	// HeaderV and HeaderVParent are B_v and its parent read positionally (step 16d); StateRootPre/Post are their state roots.
	HeaderV       finality.HeaderFields
	HeaderVParent finality.HeaderFields
	StateRootPre  [32]byte
	StateRootPost [32]byte
	// HopChain is the link evidence (step 16): the link kind and the number of headers walked.
	HopChain HopChainResult
	// AttestTx and AttestReceipt are the verified attestation transaction and receipt (step 17); TxIndex is its index in B_v.
	AttestTx      *types.Transaction
	AttestReceipt *ethproof.ReceiptLeaf
	TxIndex       uint32
	// Call is the strictly decoded executeComprehensiveProof(anchorId, proof) (step 17).
	Call AttestCall
	// MessageHash is M (blob word 12 == messageHash); PKC is the blob's pubkeyCommitment (word 13); MessageRecomputed is step 20's
	// recomputation (equal to M when the binding holds).
	MessageHash       [32]byte
	PKC               [32]byte
	MessageRecomputed [32]byte
}

// HopChainResult is what step 16 established about the link from B_v to the settlement block.
type HopChainResult struct {
	Link   uint8 // LinkSameBlock | LinkHops | LinkSpine
	Walked int   // number of header links verified
}

// AttestCall is the decoded attestation call (step 17): the outer numbers and lists, the governance level and the blob words.
type AttestCall struct {
	AnchorID            [32]byte
	OperationCommitment [32]byte
	OuterSigned         *big.Int
	OuterTotal          *big.Int
	ValidatorAddresses  []common.Address
	VotingPowers        []*big.Int
	AuthorityLevel      uint8
	BlobInnerSigned     *big.Int
	BlobInnerTotal      *big.Int
}

var factSpecsB1 = []FactSpec{
	{"B1.AttestCaptured", Step15, []StepID{Step16, Step17, Step18, Step18b, Step19, Step20, Step21, Step22}, "false: the attest part is Stated or absent; the later attest steps judge nothing"},
	{"B1.HeaderV", Step16, []StepID{Step17, Step18, Step21, Step22}, "B_v header, authenticated by the link to the settlement header"},
	{"B1.HeaderVParent", Step16, []StepID{Step18, Step22}, "B_v-1 header"},
	{"B1.StateRootPre", Step16, []StepID{Step18, Step21, Step22}, "stateRoot(headerVParent)"},
	{"B1.StateRootPost", Step16, []StepID{Step18, Step21, Step22}, "stateRoot(headerV)"},
	{"B1.HopChain", Step16, nil, "link kind and links walked (reported)"},
	{"B1.AttestTx", Step17, []StepID{Step18, Step22}, "verified attestation transaction (type, to, selector checked)"},
	{"B1.AttestReceipt", Step17, nil, "verified attestation receipt (status 1, ProofExecuted log)"},
	{"B1.TxIndex", Step17, []StepID{Step22}, "index of the attestation in B_v (rule IB census: blockTxs[txIndex] == txLeaf)"},
	{"B1.Call", Step17, []StepID{Step18, Step19, Step21}, "decoded ComprehensiveProof call"},
	{"B1.MessageHash", Step17, []StepID{Step19, Step20}, "M = blob word 12 = blsProof.messageHash"},
	{"B1.PKC", Step17, []StepID{Step19, Step21}, "pubkeyCommitment (blob word 13), non-zero"},
	{"B1.MessageRecomputed", Step20, nil, "keccak256(abi.encode(certen:bls:v2:pre, ...)) from the proven record and set root"},
}
