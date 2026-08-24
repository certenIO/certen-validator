// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

// L4 replaces the former CometBFT `bindConsensusAppHash` assertions.
//
// The old binding asked a trusted consensus RPC "what was the app hash at
// height H?" and compared the answer to the layer under it. It stored nothing,
// checked no signature, required a live CometBFT endpoint at verify time, and
// was coupled to a consensus engine Accumulate is removing.
//
// L4 instead reads Accumulate's own signed record. A partition anchor carries
// the same BPT root CometBFT reports as AppHash, and anchors are
// threshold-signed at the *executor* layer (see accumulate-core
// internal/core/execute/v2/block/msg_block_anchor.go: txnIsReady requires
// len(sigs) >= globals.Active.ValidatorThreshold(partition)). That is chain
// state, not engine state, so the same evidence exists on CometBFT and on
// DAG-BFT.
//
// Everything needed to check an L4 leg is stored in the leg. Verification
// performs no network access.

// Layer4 binds one partition's stateTreeAnchor to a threshold-signed validator
// quorum. One instance per leg (BVN and DN).
type Layer4 struct {
	// Partition is the SIGNING partition - the partition whose validators
	// signed this anchor, which is the anchor's *source*. "BVN1", "Directory".
	Partition string `json:"partition"`

	// Source and Destination are the anchor's routing, as recorded in the
	// signed SequencedMessage.
	Source      string `json:"source"`      // acc://dn.acme | acc://bvn-BVN1.acme
	Destination string `json:"destination"` // partition URL the anchor was delivered to

	// AnchorPool is the account whose `main` chain records the delivered
	// anchor transaction, and AnchorIndex its index on that chain.
	AnchorPool  string `json:"anchorPool"`
	AnchorIndex uint64 `json:"anchorIndex"`

	// SequenceNumber is the anchor's sequence number on the source->destination
	// stream.
	SequenceNumber uint64 `json:"sequenceNumber"`

	// AnchorTxHash is the delivered anchor transaction's own hash. It equals
	// the `main` chain entry at AnchorIndex.
	AnchorTxHash string `json:"anchorTxHash"` // hex32

	// SignedHash is what the validator signatures actually cover. It is the
	// hash of the SequencedMessage wrapping the anchor transaction, NOT the
	// transaction hash - see accumulate-core BlockAnchor.checkSignature, which
	// calls Signature.Verify(nil, &seq). These two hashes differ; conflating
	// them yields a well-formed digest that never verifies.
	SignedHash string `json:"signedHash"` // hex32

	// SequencedMessage is the canonical binary encoding of the signed
	// SequencedMessage, hex-encoded. This is what makes the leg self-contained:
	// a verifier recomputes SignedHash and AnchorTxHash from it and reads the
	// anchor body out of it, so the anchor's claimed StateTreeAnchor is bound
	// to the hash the quorum signed rather than merely asserted alongside it.
	SequencedMessage string `json:"sequencedMessage"` // hex

	// Anchor body fields, restated for readability. The verifier does not
	// trust these: it recomputes them from SequencedMessage and rejects any
	// disagreement.
	MinorBlockIndex uint64 `json:"minorBlockIndex"`
	RootChainAnchor string `json:"rootChainAnchor"` // hex32
	StateTreeAnchor string `json:"stateTreeAnchor"` // hex32 - MUST equal the layer it binds

	Signatures   []AnchorSignature `json:"signatures"`
	ValidatorSet []ValidatorKey    `json:"validatorSet"`

	// Threshold is the number of distinct valid signers required. It is
	// restated for readability and recomputed by the verifier from
	// AcceptThreshold and the count of validators active on Partition.
	Threshold uint64 `json:"threshold"`

	// AcceptThreshold is globals.validatorAcceptThreshold, the network's own
	// rational. Storing it rather than a hardcoded fraction means the proof
	// tracks the network instead of a snapshot of today's deployment.
	AcceptThreshold Rational `json:"acceptThreshold"`

	// NetworkVersion is NetworkDefinition.Version. It is 0 when the network
	// has never versioned its definition, which is also the SignerVersion the
	// validators sign with.
	NetworkVersion uint64 `json:"networkVersion"`
}

// AnchorSignature is one validator's ed25519 signature over SignedHash.
type AnchorSignature struct {
	PublicKey string `json:"publicKey"` // hex, 32 bytes
	Signature string `json:"signature"` // hex, 64 bytes
	Signer    string `json:"signer"`    // acc://dn.acme/network
	Timestamp uint64 `json:"timestamp"`
	// SignerVersion is omitted from Accumulate's JSON when zero. Absent means
	// zero; guessing any other value produces a wrong digest and a valid
	// signature fails.
	SignerVersion uint64 `json:"signerVersion"`
}

// ValidatorKey is one entry of the network's validator set.
type ValidatorKey struct {
	PublicKey     string   `json:"publicKey"`
	PublicKeyHash string   `json:"publicKeyHash"` // sha256(publicKey)
	ActiveOn      []string `json:"activeOn"`      // partition IDs where active
}

// Rational mirrors protocol.Rational.
type Rational struct {
	Numerator   uint64 `json:"numerator"`
	Denominator uint64 `json:"denominator"`
}
