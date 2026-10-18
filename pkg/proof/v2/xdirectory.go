// Copyright 2026 Certen Protocol
//
// The Directory as a partition of evidence 2.1 (docs/proof/G1_CROSS_PARTITION.md D2b and D2c; RB9 Phase C1b-2).
//
// A block validator partition proves a block to the Directory with a BlockValidatorAnchor it sends and the Directory executes. The
// Directory has no such anchor: it anchors itself with a DirectoryAnchor addressed to its own anchor pool (the self-anchor the
// spine walks; spine.go checkDirectorySelfAnchor), whose body carries the Directory block, its root chain anchor and its state tree
// anchor exactly as a BlockValidatorAnchor does (protocol.PartitionAnchor). The anchor kind is therefore checked per partition
// kind: a block validator partition is proven by a BlockValidatorAnchor delivered to the Directory's anchor pool from that
// partition; the Directory is proven by a DirectoryAnchor whose Source and Destination are both the Directory. Either kind is
// proven into the same certified Directory root by a receipt from the anchor transaction, and a kind that does not match the
// partition the anchor names is the named state g1_foreign_partition_mismatch with the derived partition and the block.
//
// Evidence 2.0 is untouched: it accepts the BlockValidatorAnchor of the transaction's own partition only (anchorBody).

package proofv2

import (
	"encoding/hex"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// partitionAnchor21 is a partition anchor of either kind, decoded.
type partitionAnchor21 struct {
	body      *protocol.PartitionAnchor // the fields both kinds carry
	seq       *messaging.SequencedMessage
	tx        []byte // the anchor transaction's hash
	directory bool   // the body is a DirectoryAnchor
}

// decodeAnchor21 decodes a delivered partition anchor of either kind and checks its shape: a BlockValidatorAnchor is delivered
// to the Directory's anchor pool; a DirectoryAnchor is the Directory's self-anchor (Source and Destination the Directory, the
// Directory's anchor pool its principal). Whether the kind fits the partition its Source names is checked by partition().
func decodeAnchor21(msgHex string) (*partitionAnchor21, error) {
	raw, err := hex.DecodeString(msgHex)
	if err != nil {
		return nil, err
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("partition anchor: %w", err)
	}
	txm, ok := seq.Message.(*messaging.TransactionMessage)
	if !ok || txm.Transaction == nil || txm.Transaction.Body == nil {
		return nil, fmt.Errorf("partition anchor is %T, not a transaction", seq.Message)
	}
	if seq.Source == nil || seq.Destination == nil || txm.Transaction.Header.Principal == nil {
		return nil, fmt.Errorf("partition anchor names no source, destination or principal")
	}
	// Both kinds are executed by the Directory: delivered to its anchor pool. (A DirectoryAnchor's Source being the Directory, the
	// self-anchor, is the per-kind check partition() makes, so that a wrong kind is a named state with its partition and block.)
	if !protocol.DnUrl().Equal(seq.Destination) || !protocol.DnUrl().JoinPath(protocol.AnchorPool).Equal(txm.Transaction.Header.Principal) {
		return nil, fmt.Errorf("partition anchor is not delivered to the Directory's anchor pool")
	}
	out := &partitionAnchor21{seq: seq, tx: txm.Transaction.GetHash()}
	switch b := txm.Transaction.Body.(type) {
	case *protocol.BlockValidatorAnchor:
		out.body = &b.PartitionAnchor
	case *protocol.DirectoryAnchor:
		out.body, out.directory = &b.PartitionAnchor, true
	default:
		return nil, fmt.Errorf("partition anchor is %v, not a block validator or directory anchor", txm.Transaction.Body.Type())
	}
	return out, nil
}

// partition derives the partition the anchor proves from its Source and requires the anchor's kind to be the one that partition's
// kind is proven by. The returned id is "Directory" or the block validator partition's ID ("BVN2").
func (a *partitionAnchor21) partition() (string, error) {
	// The partition is the one the committed anchor body names: the transaction's hash (header and body) is what the anchor's receipt
	// proves into the certified root, and the executor keys the partition's anchor chain by ParsePartitionUrl(body.Source)
	// (partition_anchor.go:49-56). The SequencedMessage wrapper that carries the transaction is not covered by that hash, so its Source
	// is only a claim that must equal the body's (RB9 verifier round VA, DEF-2).
	if a.body.Source == nil {
		return "", refusal21(StateForeignPartitionMismatch, "", a.body.MinorBlockIndex, "the anchor body names no source")
	}
	id, ok := protocol.ParsePartitionUrl(a.body.Source)
	if !ok {
		return "", refusal21(StateForeignPartitionMismatch, "", a.body.MinorBlockIndex, "the anchor's source %v is not a partition", a.body.Source)
	}
	if !strings.EqualFold(a.seq.Source.String(), a.body.Source.String()) {
		return id, refusal21(StateForeignPartitionMismatch, id, a.body.MinorBlockIndex,
			"url %v: the anchor's body (the committed value) names %v, the message that delivered it %v", a.body.Source, a.body.Source, a.seq.Source)
	}
	isDir := strings.EqualFold(id, protocol.Directory)
	switch {
	case isDir && !a.directory:
		return id, refusal21(StateForeignPartitionMismatch, id, a.body.MinorBlockIndex,
			"url %v: the Directory is proven by a DirectoryAnchor, this anchor is a BlockValidatorAnchor", a.body.Source)
	case !isDir && a.directory:
		return id, refusal21(StateForeignPartitionMismatch, id, a.body.MinorBlockIndex,
			"url %v: a block validator partition is proven by a BlockValidatorAnchor, this anchor is a DirectoryAnchor", a.body.Source)
	}
	return id, nil
}

// anchorOf decodes the anchor of the transaction's own partition. Evidence 2.0 accepts only the BlockValidatorAnchor of a block
// validator partition (anchorBody, unchanged); 2.1 accepts the anchor of either partition kind, kind-checked.
func anchorOf(msgHex string, is21 bool) (*protocol.PartitionAnchor, *messaging.SequencedMessage, []byte, error) {
	if !is21 {
		bv, seq, tx, err := anchorBody(msgHex)
		if err != nil {
			return nil, nil, nil, err
		}
		return &bv.PartitionAnchor, seq, tx, nil
	}
	a, err := decodeAnchor21(msgHex)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := a.partition(); err != nil {
		return nil, nil, nil, err
	}
	return a.body, a.seq, a.tx, nil
}

// anchorFields reads a partition anchor body of either kind as the BlockValidatorAnchor shape both share. A DirectoryAnchor carries the
// same protocol.PartitionAnchor (Source, MinorBlockIndex, RootChainAnchor, StateTreeAnchor) as a BlockValidatorAnchor, which is all a
// block selection and an anchor lookup read; the transaction itself keeps its real body, and the per-kind check is anchorKindFits.
func anchorFields(b protocol.TransactionBody) (*protocol.BlockValidatorAnchor, bool) {
	switch v := b.(type) {
	case *protocol.BlockValidatorAnchor:
		return v, true
	case *protocol.DirectoryAnchor:
		return &protocol.BlockValidatorAnchor{PartitionAnchor: v.PartitionAnchor}, true
	}
	return nil, false
}

// anchorKindFits says whether a body is the anchor kind the named partition is proven by: the Directory by a DirectoryAnchor (its
// self-anchor), a block validator partition by a BlockValidatorAnchor.
func anchorKindFits(partition string, b protocol.TransactionBody) bool {
	_, isDir := b.(*protocol.DirectoryAnchor)
	_, isBVN := b.(*protocol.BlockValidatorAnchor)
	if strings.EqualFold(partition, protocol.Directory) {
		return isDir
	}
	return isBVN
}
