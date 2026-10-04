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
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
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

	err = s.verifyAndCommit(body, r.Anchor, r.Signatures, r.Updates)
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
	if !bytes.Equal(proof.MerkleState.Anchor(), s.RootChainAnchor[:]) {
		return errors.Unauthenticated.With("root proof does not start at the verified root")
	}
	if !bytes.Equal(proof.Receipt.Anchor, body.RootChainAnchor[:]) {
		return errors.Unauthenticated.With("root proof does not end at the anchor's root")
	}
	if !proof.Validate(nil) {
		return errors.Unauthenticated.With("invalid root proof")
	}

	err = s.verifyAndCommit(body, r.Anchor, r.Signatures, r.Updates)
	if err != nil {
		return errors.UnknownError.WithFormat("block %d: %w", body.MinorBlockIndex, err)
	}
	return nil
}

func (s *Spine) verifyAndCommit(body *protocol.DirectoryAnchor, anchor *messaging.SequencedMessage, sigs []protocol.KeySignature, updates []*api.NetworkUpdateProof) error {
	candidate := s.globals.Copy()
	var applied []AppliedUpdate
	for _, u := range updates {
		a, err := applyProvenUpdate(candidate, u, body.RootChainAnchor)
		if err != nil {
			return err
		}
		if a != nil {
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

func checkDirectorySelfAnchor(anchor *messaging.SequencedMessage) (*protocol.DirectoryAnchor, error) {
	txnMsg, ok := anchor.Message.(*messaging.TransactionMessage)
	if !ok {
		return nil, errors.BadRequest.With("anchor is not a transaction")
	}
	body, ok := txnMsg.Transaction.Body.(*protocol.DirectoryAnchor)
	if !ok {
		return nil, errors.BadRequest.WithFormat("anchor is %v, not a directory anchor", txnMsg.Transaction.Body.Type())
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
	if u.Transaction == nil || u.Receipt == nil {
		return nil, errors.BadRequest.With("incomplete network update proof")
	}
	if !bytes.Equal(u.Receipt.Start, u.Transaction.GetHash()) {
		return nil, errors.Unauthenticated.With("network update receipt does not start at the transaction")
	}
	if !bytes.Equal(u.Receipt.Anchor, root[:]) {
		return nil, errors.Unauthenticated.With("network update receipt does not end at the anchor's root")
	}
	if !u.Receipt.Validate(nil) {
		return nil, errors.Unauthenticated.With("invalid network update receipt")
	}

	wd, ok := u.Transaction.Body.(*protocol.WriteData)
	if !ok {
		// Other transaction types do not affect the consensus validator set
		return nil, nil
	}

	principal := u.Transaction.Header.Principal
	var h [32]byte
	copy(h[:], u.Transaction.GetHash())
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
