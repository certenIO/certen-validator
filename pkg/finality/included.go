// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// KindIncluded is the evidence kind of level 1 on every EVM chain CERTEN settles on: today's L6 settlement evidence
// (block header, transaction and receipt Merkle-Patricia proofs; pkg/ethproof.Settlement) re-expressed as a finality level.
const KindIncluded = "included.eth-mpt/v1"

// EncodeIncludedBody is the canonical body of an included.eth-mpt/v1 Evidence:
//
//	lp(headerRLP) || proof(tx) || proof(receipt)
//	proof = be64(leafIndex) || expectedRoot(32) || be32(nodeCount) || lp(node)* || lp(leafValue)
//
// The block hash and transaction hash are the Evidence's Subject and are not repeated; a proof's leaf hash and node hashes
// are recomputed on decode, and its Verified flag is never carried (a reader trusts nothing the proof states about itself).
func EncodeIncludedBody(s *ethproof.Settlement) ([]byte, error) {
	if s == nil || len(s.Header) == 0 || s.Tx == nil || s.Receipt == nil {
		return nil, NewState(CodeIncludedUnavailable, "reason", "the settlement carries no header, or no transaction or receipt proof")
	}
	out := appendLP(nil, s.Header)
	for _, p := range []*ethproof.InclusionProof{s.Tx, s.Receipt} {
		out = binary.BigEndian.AppendUint64(out, p.LeafIndex)
		out = append(out, p.ExpectedRoot[:]...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(p.ProofNodes)))
		for _, n := range p.ProofNodes {
			out = appendLP(out, n)
		}
		out = appendLP(out, p.LeafValue)
	}
	return out, nil
}

// DecodeIncludedBody rebuilds the settlement an included.eth-mpt/v1 Evidence carries, strictly (a truncated field or
// trailing bytes are finality_evidence_malformed). It does not verify it.
func DecodeIncludedBody(subject Subject, body []byte) (*ethproof.Settlement, error) {
	r := reader{b: body}
	header, ok := r.lp()
	if !ok {
		return nil, malformed("included.header", "truncated", r.left(), 0)
	}
	s := &ethproof.Settlement{BlockHash: common.Hash(subject.BlockHash), TxHash: common.Hash(subject.TxHash), Header: append([]byte(nil), header...)}
	for i, dst := range []**ethproof.InclusionProof{&s.Tx, &s.Receipt} {
		part := []string{"included.tx", "included.receipt"}[i]
		p := &ethproof.InclusionProof{}
		idx, ok := r.u64()
		if !ok || !r.fixed(p.ExpectedRoot[:]) {
			return nil, malformed(part, "truncated", r.left(), 40)
		}
		p.LeafIndex = idx
		count, ok := r.u32()
		if !ok || uint64(count) > uint64(r.left())/4 {
			return nil, malformed(part+".nodes", "node count exceeds the remaining bytes", r.left(), int(count))
		}
		for j := uint32(0); j < count; j++ {
			n, ok := r.lp()
			if !ok {
				return nil, malformed(part+".node", "truncated", r.left(), 0)
			}
			p.ProofNodes = append(p.ProofNodes, append([]byte(nil), n...))
			p.ProofHashes = append(p.ProofHashes, [32]byte(crypto.Keccak256Hash(n)))
		}
		leaf, ok := r.lp()
		if !ok {
			return nil, malformed(part+".leaf", "truncated", r.left(), 0)
		}
		p.LeafValue = append([]byte(nil), leaf...)
		p.LeafHash = [32]byte(crypto.Keccak256Hash(leaf))
		*dst = p
	}
	if r.left() != 0 {
		return nil, malformed("included.end", "trailing bytes", r.left(), 0)
	}
	return s, nil
}

// IncludedVerifier verifies level 1: the header hashes to the Subject's block hash and its number is the Subject's, the
// transaction proof resolves from the header's transactionsRoot to the Subject's transaction, and the receipt proof resolves
// from receiptsRoot at the same index (ethproof.VerifySettlement, the same check L6 has always been). It proves inclusion
// and nothing about the block being canonical, posted or final.
type IncludedVerifier struct{ ChainID uint64 }

func (v IncludedVerifier) Chain() uint64   { return v.ChainID }
func (v IncludedVerifier) Kind() string    { return KindIncluded }
func (v IncludedVerifier) MaxLevel() Level { return LevelIncluded }

func (v IncludedVerifier) Verify(s Settlement, ev Evidence, _ *Pins) (Level, error) {
	settlement, err := DecodeIncludedBody(ev.Subject, ev.Body)
	if err != nil {
		return LevelNone, err
	}
	header, _, err := settlement.Verify()
	if err != nil {
		return LevelNone, NewState(CodeIncludedInvalid, "chain", v.ChainID, "block", ev.Subject.BlockNumber, "cause", err.Error())
	}
	if header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != ev.Subject.BlockNumber {
		return LevelNone, NewState(CodeSubjectMismatch, "field", "blockNumber", "chain", v.ChainID, "want", ev.Subject.BlockNumber)
	}
	return LevelIncluded, nil
}

// IncludedProver builds level 1 from the L6 evidence a leg already holds (Settlement.Included). It never fetches: the
// evidence was proven when the settlement was observed, and it is verified here again before it is returned.
type IncludedProver struct{ ChainID uint64 }

func (p IncludedProver) Chain() uint64  { return p.ChainID }
func (p IncludedProver) Ceiling() Level { return LevelIncluded }

func (p IncludedProver) Build(_ context.Context, s Settlement) (Evidence, Level, error) {
	body, err := EncodeIncludedBody(s.Included)
	if err != nil {
		return Evidence{}, LevelNone, err
	}
	ev := NewEvidence(KindIncluded, s, body)
	level, err := IncludedVerifier{ChainID: p.ChainID}.Verify(s, ev, nil)
	if err != nil {
		return Evidence{}, LevelNone, err
	}
	return ev, level, nil
}

// SubjectOfSettlement is the Subject a proven ethproof.Settlement names (the block number is read from its header, which
// VerifySettlement has checked hashes to the block hash).
func SubjectOfSettlement(s *ethproof.Settlement) (Subject, error) {
	header, _, err := s.Verify()
	if err != nil {
		return Subject{}, NewState(CodeIncludedInvalid, "cause", err.Error())
	}
	if header.Number == nil || !header.Number.IsUint64() {
		return Subject{}, NewState(CodeIncludedInvalid, "cause", "the header has no block number")
	}
	return Subject{BlockNumber: header.Number.Uint64(), BlockHash: s.BlockHash, TxHash: s.TxHash}, nil
}
