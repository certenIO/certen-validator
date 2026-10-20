// Copyright 2026 Certen Protocol

package finality

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// The legacy Evidence container of bf1e5d8 (be32(Version) || lp(Kind) || Subject || lp(Body)) is superseded by the CFE1
// container of V2_SPEC_S7 section 3.1 (codec.go): it had no magic, no chain or level in the header and carried a transaction
// hash the spec's header does not have. The v1 interface of this package never shipped in a release (the branch was never
// merged), so no stored row holds the old encoding.

// BlockRef is the leg's Settlement block: the block that holds the settled transaction on the target chain. HeaderRLP is the
// raw header (nil for a block known only by its triple, e.g. the carried `finality.leg`).
type BlockRef struct {
	Chain     uint64
	Number    uint64
	Hash      [32]byte
	HeaderRLP []byte
}

// Triple is the (chain, number, hash) a leg binding and a container header commit to.
func (b BlockRef) Triple() map[string]any {
	return map[string]any{"chain": b.Chain, "blockNumber": b.Number, "blockHash": b.Hash}
}

func (b BlockRef) String() string {
	return fmt.Sprintf("chain %d block %d %x", b.Chain, b.Number, b.Hash[:4])
}

// Subject is the settlement a stored leg is about: the block (number and hash) that holds the transaction, and the
// transaction. The transaction is not part of the leg binding (the binding is the block); it is kept for the leg source.
type Subject struct {
	BlockNumber uint64
	BlockHash   [32]byte
	TxHash      [32]byte
}

// Settlement is what the leg source loads for the upgrader: the settlement's chain and Subject and the L6 evidence already
// held for it.
type Settlement struct {
	Chain uint64
	Subject
	// Included is today's L6 evidence for the settlement: the block header and the transaction and receipt MPT proofs.
	Included *ethproof.Settlement
}

// Block is the leg's BlockRef (header included when the L6 evidence is held).
func (s Settlement) Block() BlockRef {
	b := BlockRef{Chain: s.Chain, Number: s.BlockNumber, Hash: s.BlockHash}
	if s.Included != nil {
		b.HeaderRLP = append([]byte(nil), s.Included.Header...)
	}
	return b
}

// DeriveIncluded is level 1 (5.1): VerifySettlement (S6) succeeds for the leg, the header hash equals the block hash, the
// block number is read POSITIONALLY from the header (item 8), and the chain id is the one the caller expects. Level 1 has no
// addendum; its result is the BlockRef every other level binds to.
func DeriveIncluded(chain uint64, s *ethproof.Settlement) (BlockRef, error) {
	if s == nil {
		return BlockRef{}, NewState(CodeIncludedUnavailable, "chain", chain, "reason", "the leg carries no settlement")
	}
	if _, _, err := s.Verify(); err != nil {
		return BlockRef{}, NewState(CodeIncludedInvalid, "chain", chain, "cause", err.Error())
	}
	h, err := ReadHeader(s.Header)
	if err != nil {
		return BlockRef{}, err
	}
	if h.Hash != [32]byte(s.BlockHash) {
		return BlockRef{}, NewState(CodeIncludedInvalid, "chain", chain, "cause", "the header does not hash to the block hash")
	}
	return BlockRef{Chain: chain, Number: h.Number, Hash: h.Hash, HeaderRLP: append([]byte(nil), s.Header...)}, nil
}

// SubjectOfSettlement is the Subject a proven ethproof.Settlement names (the block number is read positionally from its
// header, which VerifySettlement has checked hashes to the block hash).
func SubjectOfSettlement(s *ethproof.Settlement) (Subject, error) {
	b, err := DeriveIncluded(0, s)
	if err != nil {
		return Subject{}, err
	}
	return Subject{BlockNumber: b.Number, BlockHash: b.Hash, TxHash: [32]byte(s.TxHash)}, nil
}
