// Copyright 2026 The Accumulate Authors; adapted by Certen Protocol.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.
//
// Vendored from gitlab.com/accumulatenetwork/accumulate internal/fastsync/spine.go at e1d1db9eb (the commit the
// validator pins). Upstream keeps it internal; CERTEN's verifier needs it on the public v3 record types, so this copy
// differs only in taking api.MajorHeaderRecord / api.MinorRootRecord / api.NetworkUpdateProof, and in recording every
// update it applies so the caller can account for them against the network accounts' main chains (PROOF_V2 §4.3).

package proofv2

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// AppliedUpdate is one network-account write the walk applied, with the anchor whose root its receipt ends at.
type AppliedUpdate struct {
	Principal string
	TxHash    [32]byte
	// AnchorMinorBlock is the Directory minor block of the anchor the update's receipt is bound to.
	AnchorMinorBlock uint64
}

// Spine walks the directory's major-block spine, verifying each major block's closing anchor against the validator
// set tracked by induction: each anchor is verified with the set as of the previous anchor, then the network updates
// it carries are applied. The initial state comes from the trust anchor (the genesis network values).
type Spine struct {
	globals *network.GlobalValues

	// NextMajor is the index of the next major block to verify.
	NextMajor uint64

	// LastMinorBlock is the minor block of the last verified anchor.
	LastMinorBlock uint64

	// RootChainAnchor is the root chain anchor of the last verified anchor.
	RootChainAnchor [32]byte

	// StateTreeAnchor is the state tree (BPT) anchor of the last verified anchor.
	StateTreeAnchor [32]byte

	// Applied lists every update the walk applied, in order.
	Applied []AppliedUpdate

	// priorNetworkUpdates counts the writes to the network definition applied before this walk started, when it was
	// restored from a checkpoint (RestoreSpine) rather than walked from genesis.
	priorNetworkUpdates uint64

	// priorGlobalsUpdates is the same for the globals account, as the checkpoint recorded it (evidence 2.1: ledger.AccumulateSpineCheckpoint
	// GlobalsUpdates, held from the activation of rules v15; a spine restored from an earlier checkpoint starts at 0).
	priorGlobalsUpdates uint64

	// refuseReplay, set by the evidence 2.1 verifier on the spines it walks, makes a record that applies an update the walk already
	// applied (the same transaction hash) a refusal, certify_update_replayed. A 2.0 spine never sets it, so 2.0 verdicts do not move.
	refuseReplay bool
}

// NetworkUpdates is the number of writes to acc://dn.acme/network the spine has applied since genesis: what the network
// account's main chain must account for, beside its genesis entry.
func (s *Spine) NetworkUpdates() uint64 {
	n := s.priorNetworkUpdates
	for _, a := range s.Applied {
		if a.Principal == protocol.DnUrl().JoinPath(protocol.Network).String() {
			n++
		}
	}
	return n
}

// GlobalsUpdates is the number of writes to acc://dn.acme/globals the spine has counted (V-E A2(b)): what the globals account's main
// chain must account for, beside its genesis entry. Only the evidence 2.1 verifier compares it; 2.0 never has.
func (s *Spine) GlobalsUpdates() uint64 {
	n := s.priorGlobalsUpdates
	for _, a := range s.Applied {
		if a.Principal == protocol.DnUrl().JoinPath(protocol.Globals).String() {
			n++
		}
	}
	return n
}

// RestoreSpine rebuilds a spine at a checkpoint the chain verified: the set in force, the next major block, the last
// verified anchor's minor block and roots, and how many network-definition writes were applied up to it.
func RestoreSpine(g *network.GlobalValues, next, lastMinor uint64, root, state [32]byte, networkUpdates uint64) (*Spine, error) {
	s, err := NewSpine(g, next)
	if err != nil {
		return nil, err
	}
	s.LastMinorBlock, s.RootChainAnchor, s.StateTreeAnchor, s.priorNetworkUpdates = lastMinor, root, state, networkUpdates
	return s, nil
}

// NewSpine constructs a spine walk starting from the given trust anchor state, expecting major block `next` as the
// first record.
func NewSpine(genesis *network.GlobalValues, next uint64) (*Spine, error) {
	if genesis == nil || genesis.Network == nil || genesis.Globals == nil {
		return nil, errors.BadRequest.With("missing network definition or globals")
	}
	if next == 0 {
		return nil, errors.BadRequest.With("major blocks are 1-based")
	}
	return &Spine{globals: genesis.Copy(), NextMajor: next}, nil
}

// Clone returns an independent copy, so one verified spine can be extended to several targets.
func (s *Spine) Clone() *Spine {
	c := *s
	c.globals = s.globals.Copy()
	c.Applied = append([]AppliedUpdate(nil), s.Applied...)
	return &c
}

// Globals returns the validator set and globals as of the last verified anchor.
func (s *Spine) Globals() *network.GlobalValues { return s.globals }

// Advance verifies one major header record and advances the spine. The record must be the next major block in
// sequence. Any invalid signature rejects the record outright.
func (s *Spine) Advance(r *api.MajorHeaderRecord) error {
	if r == nil || r.Entry == nil || r.Anchor == nil {
		return errors.BadRequest.With("incomplete major header record")
	}
	if r.Index != s.NextMajor {
		return errors.Conflict.WithFormat("expected major block %d, got %d", s.NextMajor, r.Index)
	}
	if r.Entry.BlockIndex != r.Index {
		return errors.BadRequest.WithFormat("index entry is for major block %d, not %d", r.Entry.BlockIndex, r.Index)
	}

	body, err := checkDirectorySelfAnchor(r.Anchor)
	if err != nil {
		return err
	}
	if body.MinorBlockIndex <= s.LastMinorBlock {
		return errors.Conflict.WithFormat("anchor for minor block %d does not advance past %d", body.MinorBlockIndex, s.LastMinorBlock)
	}

	err = s.verifyAndCommit(body, r.Anchor, r.Signatures, r.Updates, s.refuseReplay)
	if err != nil {
		return errors.UnknownError.WithFormat("major block %d: %w", r.Index, err)
	}
	s.NextMajor++
	return nil
}

// AdvanceEpoch verifies a minor-root record and advances the walk. In addition to the quorum check, the root proof
// must chain the previously verified root chain anchor to this anchor's, proving the anchor extends the verified
// history rather than forking it.
func (s *Spine) AdvanceEpoch(r *api.MinorRootRecord) error {
	if r == nil || r.Anchor == nil || r.RootProof == nil {
		return errors.BadRequest.With("incomplete minor root record")
	}
	body, err := checkDirectorySelfAnchor(r.Anchor)
	if err != nil {
		return err
	}
	if body.MinorBlockIndex <= s.LastMinorBlock {
		return errors.Conflict.WithFormat("anchor for minor block %d does not advance past %d", body.MinorBlockIndex, s.LastMinorBlock)
	}

	proof := r.RootProof
	if proof.MerkleState == nil || proof.Receipt == nil {
		return errors.BadRequest.With("incomplete root proof")
	}
	// A record decoded from JSON can hold a null step in either receipt, which Accumulate's Validate dereferences (RB9-L).
	if !stepsPresent(proof.Receipt) || !stepsPresent(proof.ContinuedReceipt) {
		return errors.BadRequest.With("incomplete root proof")
	}
	if !bytes.Equal(proof.MerkleState.Anchor(), s.RootChainAnchor[:]) {
		return errors.Unauthenticated.With("root proof does not start at the verified root")
	}
	if !bytes.Equal(proof.Receipt.Anchor, body.RootChainAnchor[:]) {
		return errors.Unauthenticated.With("root proof does not end at the anchor's root")
	}
	if !proof.Validate(nil) {
		return errors.Unauthenticated.With("invalid root proof")
	}

	err = s.verifyAndCommit(body, r.Anchor, r.Signatures, r.Updates, s.refuseReplay)
	if err != nil {
		if cs, ok := err.(*CertifyState); ok {
			return cs
		}
		return errors.UnknownError.WithFormat("block %d: %w", body.MinorBlockIndex, err)
	}
	return nil
}

// AdvanceAnchored verifies an anchored minor-root record (evidence 2.1): a record without a root proof, whose continuity with the
// previously verified root chain anchor is the O(log n) link instead of the walk of every root chain entry in between. The record's
// anchor must be a Directory self-anchor of a later minor block; the link must start at the verified root chain anchor, end at the
// anchor's own, and validate; the updates are applied and the quorum checked exactly as AdvanceEpoch does, and (on a spine the 2.1
// verifier walks) an update the walk already applied is refused. The refusals are *CertifyState with index 0: the caller, who knows
// the link's ordinal, renames the index (reindexCertifyState).
func (s *Spine) AdvanceAnchored(r *api.MinorRootRecord, link *merkle.Receipt) error {
	if r == nil || r.Anchor == nil {
		return errors.BadRequest.With("incomplete minor root record")
	}
	if r.RootProof != nil {
		return errors.BadRequest.With("an anchored record carries no root proof")
	}
	body, err := checkDirectorySelfAnchor(r.Anchor)
	if err != nil {
		return err
	}
	if body.MinorBlockIndex <= s.LastMinorBlock {
		return errors.Conflict.WithFormat("anchor for minor block %d does not advance past %d", body.MinorBlockIndex, s.LastMinorBlock)
	}
	if link == nil {
		return certifyState(StateCertifyLinkMissing, "0")
	}
	if !stepsPresent(link) { // a null step, which Accumulate's Validate dereferences
		return certifyState(StateCertifyLinkInvalid, "0")
	}
	if !bytes.Equal(link.Start, s.RootChainAnchor[:]) {
		return certifyState(StateCertifyLinkStart, "0")
	}
	if !bytes.Equal(link.Anchor, body.RootChainAnchor[:]) {
		return certifyState(StateCertifyLinkEnd, "0")
	}
	if !link.Validate(nil) {
		return certifyState(StateCertifyLinkInvalid, "0")
	}

	err = s.verifyAndCommit(body, r.Anchor, r.Signatures, r.Updates, true)
	if err != nil {
		if cs, ok := err.(*CertifyState); ok {
			return cs
		}
		return errors.UnknownError.WithFormat("block %d: %w", body.MinorBlockIndex, err)
	}
	return nil
}

// reindexCertifyState names the ordinal (index) a *CertifyState was judged at, for the index-carrying codes the spine produces; any other
// error is returned as it is.
func reindexCertifyState(err error, index int) error {
	cs, ok := err.(*CertifyState)
	if !ok {
		return err
	}
	switch cs.Code {
	case StateCertifyLinkMissing, StateCertifyLinkStart, StateCertifyLinkEnd, StateCertifyLinkInvalid:
		return certifyState(cs.Code, strconv.Itoa(index))
	}
	return err
}

func hasUpdate(list []AppliedUpdate, h [32]byte) bool {
	for _, a := range list {
		if a.TxHash == h {
			return true
		}
	}
	return false
}

func (s *Spine) verifyAndCommit(body *protocol.DirectoryAnchor, anchor *messaging.SequencedMessage, sigs []protocol.KeySignature, updates []*api.NetworkUpdateProof, refuseReplay bool) error {
	candidate := s.globals.Copy()
	var applied []AppliedUpdate
	for _, u := range updates {
		a, err := applyProvenUpdate(candidate, u, body.RootChainAnchor)
		if err != nil {
			return err
		}
		if a != nil {
			if refuseReplay && (hasUpdate(s.Applied, a.TxHash) || hasUpdate(applied, a.TxHash)) {
				return certifyState(StateCertifyUpdateReplayed, hex.EncodeToString(a.TxHash[:]))
			}
			a.AnchorMinorBlock = body.MinorBlockIndex
			applied = append(applied, *a)
		}
	}

	// Updates take effect when they execute, so an anchor after a mid-window set change is signed by the post-update
	// set, but a change in the anchor's own block is signed by the pre-update set, so accept either.
	err := verifyQuorum(candidate, anchor, sigs)
	if err != nil && len(updates) > 0 {
		err = verifyQuorum(s.globals, anchor, sigs)
	}
	if err != nil {
		return err
	}

	s.globals = candidate
	s.LastMinorBlock = body.MinorBlockIndex
	s.RootChainAnchor = body.RootChainAnchor
	s.StateTreeAnchor = body.StateTreeAnchor
	s.Applied = append(s.Applied, applied...)
	return nil
}

// checkDirectorySelfAnchor returns the Directory anchor a record's anchor message carries.
//
// CERTEN: every field it reads is checked present first. A record is chosen by whoever submits it - a spine extension
// in CERTEN's consensus - and a missing field must be a named error, never a nil dereference: in FinalizeBlock a panic
// stops every node judging the transaction (upstream reads Body.Type() of a nil body to word its error).
func checkDirectorySelfAnchor(anchor *messaging.SequencedMessage) (*protocol.DirectoryAnchor, error) {
	if anchor == nil {
		return nil, errors.BadRequest.With("the record has no anchor")
	}
	txnMsg, ok := anchor.Message.(*messaging.TransactionMessage)
	if !ok || txnMsg == nil {
		return nil, errors.BadRequest.With("anchor is not a transaction")
	}
	if txnMsg.Transaction == nil || txnMsg.Transaction.Body == nil {
		return nil, errors.BadRequest.With("the anchor transaction or its body is missing")
	}
	body, ok := txnMsg.Transaction.Body.(*protocol.DirectoryAnchor)
	if !ok {
		return nil, errors.BadRequest.WithFormat("anchor is %v, not a directory anchor", txnMsg.Transaction.Body.Type())
	}
	if body == nil {
		return nil, errors.BadRequest.With("the directory anchor body is missing")
	}
	if anchor.Source == nil || anchor.Destination == nil || txnMsg.Transaction.Header.Principal == nil {
		return nil, errors.BadRequest.With("anchor is not a directory self-anchor: its source, destination or principal is missing")
	}
	if !protocol.DnUrl().Equal(anchor.Source) ||
		!protocol.DnUrl().Equal(anchor.Destination) ||
		!protocol.DnUrl().JoinPath(protocol.AnchorPool).Equal(txnMsg.Transaction.Header.Principal) {
		return nil, errors.BadRequest.With("anchor is not a directory self-anchor")
	}
	return body, nil
}

func verifyQuorum(g *network.GlobalValues, anchor *messaging.SequencedMessage, sigs []protocol.KeySignature) error {
	seen := map[[32]byte]bool{}
	for _, sig := range sigs {
		// CERTEN: an empty signature entry is refused by name, never dereferenced (checkDirectorySelfAnchor).
		if isNil(sig) {
			return errors.BadRequest.With("the record carries an empty signature")
		}
		if !sig.Verify(nil, anchor) {
			return errors.Unauthenticated.With("invalid signature")
		}
		v, ok := findDirectoryValidator(g, sig.GetPublicKey())
		if !ok {
			return errors.Unauthorized.With("signer is not an active directory validator")
		}
		seen[v.PublicKeyHash] = true
	}
	threshold := g.ValidatorThreshold(protocol.Directory)
	if uint64(len(seen)) < threshold {
		return errors.Unauthorized.WithFormat("quorum not met: %d of %d validator signatures", len(seen), threshold)
	}
	return nil
}

func findDirectoryValidator(g *network.GlobalValues, key []byte) (*protocol.ValidatorInfo, bool) {
	for _, v := range g.Network.Validators {
		if !bytes.Equal(v.PublicKey, key) {
			continue
		}
		for _, p := range v.Partitions {
			if p.Active && strings.EqualFold(p.ID, protocol.Directory) {
				return v, true
			}
		}
	}
	return nil, false
}

// applyProvenUpdate verifies that the update's receipt binds its transaction to the anchor's root chain anchor, then
// applies it. It returns the applied update for a write to the Directory's network or globals account, nil otherwise.
//
// Upstream skips a network definition whose version is not above the current one as a "complete-state no-op". CERTEN
// keeps that rule but still records the write: every write to the account must be accounted for against its main
// chain, and a skipped stale definition is a write like any other.
func applyProvenUpdate(g *network.GlobalValues, u *api.NetworkUpdateProof, root [32]byte) (*AppliedUpdate, error) {
	// CERTEN: an empty update, or one without its principal, is refused by name, never dereferenced.
	if u == nil || u.Transaction == nil || u.Receipt == nil || u.Transaction.Header.Principal == nil {
		return nil, errors.BadRequest.With("incomplete network update proof")
	}
	txHash, err := transactionHash(u.Transaction)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(u.Receipt.Start, txHash) {
		return nil, errors.Unauthenticated.With("network update receipt does not start at the transaction")
	}
	if !bytes.Equal(u.Receipt.Anchor, root[:]) {
		return nil, errors.Unauthenticated.With("network update receipt does not end at the anchor's root")
	}
	if !stepsPresent(u.Receipt) { // a null step, which Accumulate's Validate dereferences (RB9-L)
		return nil, errors.BadRequest.With("incomplete network update proof")
	}
	if !u.Receipt.Validate(nil) {
		return nil, errors.Unauthenticated.With("invalid network update receipt")
	}

	wd, ok := u.Transaction.Body.(*protocol.WriteData)
	if ok && (wd == nil || isNil(wd.Entry)) {
		wd = &protocol.WriteData{} // CERTEN: a typed-nil entry reads as missing (ParseNetwork/ParseGlobals refuse it by name)
	}
	if !ok {
		// Other transaction types do not affect the consensus validator set
		return nil, nil
	}

	principal := u.Transaction.Header.Principal
	var h [32]byte
	copy(h[:], txHash)
	switch {
	case protocol.DnUrl().JoinPath(protocol.Network).Equal(principal):
		a := &AppliedUpdate{Principal: principal.String(), TxHash: h}
		def := new(protocol.NetworkDefinition)
		if entry := wd.Entry; entry != nil && len(entry.GetData()) == 1 && def.UnmarshalBinary(entry.GetData()[0]) == nil && def.Version <= g.Network.Version {
			return a, nil // Stale or genesis definition: a complete-state no-op, still accounted for
		}
		return a, g.ParseNetwork(wd.Entry)
	case protocol.DnUrl().JoinPath(protocol.Globals).Equal(principal):
		return &AppliedUpdate{Principal: principal.String(), TxHash: h}, g.ParseGlobals(wd.Entry)
	}
	return nil, nil
}

// stepsPresent reports whether every step of a receipt (nil: none) is present. A receipt decoded from JSON can hold a null step, and
// Accumulate's Validate reads the hash of every step it is given.
func stepsPresent(r *merkle.Receipt) bool {
	if r == nil {
		return true
	}
	for _, e := range r.Entries {
		if e == nil {
			return false
		}
	}
	return true
}

// isNil reports whether v is nil or a nil pointer inside an interface (CERTEN: a decoded record can hold either).
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// transactionHash is tx's hash, or a named error for a transaction it cannot be computed for. CERTEN: Accumulate's
// GetHash dereferences the body and panics when the body does not marshal; a record a submitter chose can hold either,
// so the body is checked present here and a marshalling panic inside Accumulate's code, which this package cannot
// change, is returned as an error rather than stopping the node.
func transactionHash(tx *protocol.Transaction) (h []byte, err error) {
	if isNil(tx.Body) {
		return nil, errors.BadRequest.With("the network update transaction has no body")
	}
	defer func() {
		if p := recover(); p != nil {
			h, err = nil, errors.BadRequest.WithFormat("the network update transaction cannot be hashed: %v", p)
		}
	}()
	return tx.GetHash(), nil
}
