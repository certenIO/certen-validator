// Copyright 2026 Certen Protocol

// Package legacyhdr reconstructs the block header of the legs whose stored execution proof (bundle component 5) was written before
// block_header_rlp was captured (RB12-LEGACY-191: 191 of the 782 production bundles, written 2026-09-06..2026-10-04).
//
// A leg's S7 evidence is derived from its Settlement: the header, the transaction proof and the receipt proof. Those bundles hold the
// proofs, the roots and the block hash but not the header, so level 1 could not be derived and the leg sat in the named state
// finality_included_unavailable{no_block_header}. A header is SELF-AUTHENTICATING: it is the preimage of the block hash the bundle
// stores. Reading it from any provider is therefore availability only, and nothing a provider says is trusted:
//
//   - keccak256(header RLP) must equal the stored block hash (a provider that serves another block is refused);
//   - the header must decode and carry the stored block number;
//   - the header's transactionsRoot and receiptsRoot must equal the roots the bundle stores;
//   - the stored transaction and receipt proofs must verify against those roots (ethproof.VerifySettlement, the same check the
//     new-shape path runs).
//
// The verified header is kept as ONE row of the insert-only capture store, keyed (leg chain, block number, block hash,
// ItemLegacyHeader); every validator derives the same bytes, so a duplicate is byte-identical and any other bytes under the key are the
// named finality.ErrCaptureConflict. The leg source (pkg/database) reads the row and hands it to ethproof.Settlement.Verify like any
// header: the store is not trusted either.
package legacyhdr

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// ItemLegacyHeader is the capture item of a reconstructed header. It is not under "hdr": the Base and Arbitrum posted-batch
// capturers scan prefixes of their rollup chain's rows, and a header of the ROLLUP itself is not an L1 capture.
const ItemLegacyHeader = "legacyleg/header"

// MaxHeaderRLP bounds a header (a few hundred bytes today) before it is hashed or stored.
const MaxHeaderRLP = 16 << 10

// The closed set of `check` tokens of a refused leg (the check that failed, in the order Verify runs them).
const (
	CheckHeaderSize  = "header_size"
	CheckHeaderHash  = "header_hash"
	CheckHeaderParse = "header_decode"
	CheckBlockNumber = "block_number"
	CheckStoredRoots = "stored_roots"
	CheckInclusion   = "inclusion"
)

// Leg is what a legacy bundle's execution proof holds that the reconstruction needs, parsed strictly.
type Leg struct {
	ProofID  string
	BundleID string

	Chain       uint64
	BlockNumber uint64
	BlockHash   common.Hash
	TxHash      common.Hash

	// The roots the bundle states for its block; the header's own must equal them.
	TransactionsRoot common.Hash
	ReceiptsRoot     common.Hash

	Tx      *ethproof.InclusionProof
	Receipt *ethproof.InclusionProof
}

// Key is the capture key of the leg's reconstructed header.
func (l Leg) Key() finality.CaptureKey {
	return finality.CaptureKey{Chain: l.Chain, L1Block: l.BlockNumber, L1Hash: l.BlockHash, Item: ItemLegacyHeader}
}

func (l Leg) String() string {
	return fmt.Sprintf("proof %s chain %d block %d %x", l.ProofID, l.Chain, l.BlockNumber, l.BlockHash[:4])
}

// invalid is the named finality_included_invalid state of a stored component the reconstruction cannot read or that contradicts the
// block it names.
func invalid(proofID string, chain, block uint64, check, cause string) *finality.StateError {
	kv := []any{"proof_id", proofID, "cause", cause}
	if chain != 0 {
		kv = append(kv, "chain", chain)
	}
	if check != "" {
		kv = append(kv, "check", check, "block", block)
	}
	return finality.NewState(finality.CodeIncludedInvalid, kv...)
}

// ParseLeg reads the members of a stored execution proof (component 5) the reconstruction needs. Every member is required and
// strictly typed; the proofs are decoded as ethproof.InclusionProof (members this struct does not name, such as proof_directions,
// are ignored exactly as the leg source ignores them). It does not verify anything: Verify does.
func ParseLeg(proofID, bundleID string, comp json.RawMessage) (Leg, error) {
	l := Leg{ProofID: proofID, BundleID: bundleID}
	var m struct {
		ChainID          *string                  `json:"chain_id"`
		BlockNumber      *json.Number             `json:"block_number"`
		BlockHash        *common.Hash             `json:"block_hash"`
		TxHash           *common.Hash             `json:"tx_hash"`
		TransactionsRoot *common.Hash             `json:"transactions_root"`
		ReceiptsRoot     *common.Hash             `json:"receipts_root"`
		Tx               *ethproof.InclusionProof `json:"tx_inclusion_proof"`
		Receipt          *ethproof.InclusionProof `json:"receipt_inclusion_proof"`
	}
	if err := json.Unmarshal(comp, &m); err != nil {
		return l, invalid(proofID, 0, 0, "", "the stored execution proof does not decode: "+err.Error())
	}
	missing := func(name string) error {
		return invalid(proofID, l.Chain, 0, "", "the stored execution proof has no usable "+name)
	}
	if m.ChainID == nil {
		return l, missing("chain_id")
	}
	chain, err := strconv.ParseUint(strings.TrimSpace(*m.ChainID), 10, 64)
	if err != nil || chain == 0 {
		return l, missing("chain_id (a decimal chain id)")
	}
	l.Chain = chain
	if m.BlockNumber == nil {
		return l, missing("block_number")
	}
	n, err := strconv.ParseUint(m.BlockNumber.String(), 10, 64)
	if err != nil {
		return l, missing("block_number (a non-negative integer)")
	}
	l.BlockNumber = n
	for _, f := range []struct {
		name string
		src  *common.Hash
		dst  *common.Hash
	}{
		{"block_hash", m.BlockHash, &l.BlockHash}, {"tx_hash", m.TxHash, &l.TxHash},
		{"transactions_root", m.TransactionsRoot, &l.TransactionsRoot}, {"receipts_root", m.ReceiptsRoot, &l.ReceiptsRoot},
	} {
		if f.src == nil || *f.src == (common.Hash{}) {
			return l, missing(f.name)
		}
		*f.dst = *f.src
	}
	if m.Tx == nil || m.Receipt == nil {
		return l, missing("tx_inclusion_proof and receipt_inclusion_proof")
	}
	l.Tx, l.Receipt = m.Tx, m.Receipt
	return l, nil
}

// Verify judges a header against the leg's stored component, trusting neither the header's source nor the store it came from. The
// first check that fails is returned as finality_included_invalid{check, cause} carrying the chain and block the leg names; the
// checks run in the order of the Check* constants. A nil result means the header is the leg's own block and the stored proofs resolve
// from its roots: ethproof.Settlement{BlockHash, header, TxHash, Tx, Receipt}.Verify() succeeds.
func (l Leg) Verify(header []byte) error {
	bad := func(check, format string, args ...any) error {
		return invalid(l.ProofID, l.Chain, l.BlockNumber, check, fmt.Sprintf(format, args...))
	}
	if len(header) == 0 || len(header) > MaxHeaderRLP {
		return bad(CheckHeaderSize, "the header is %d bytes, the bound is 1..%d", len(header), MaxHeaderRLP)
	}
	if got := crypto.Keccak256Hash(header); got != l.BlockHash {
		return bad(CheckHeaderHash, "the header hashes to %s, the stored block hash is %s", got.Hex(), l.BlockHash.Hex())
	}
	var h types.Header
	if err := rlp.DecodeBytes(header, &h); err != nil {
		return bad(CheckHeaderParse, "the header does not decode: %v", err)
	}
	if h.Number == nil || !h.Number.IsUint64() || h.Number.Uint64() != l.BlockNumber {
		return bad(CheckBlockNumber, "the header is block %v, the stored block number is %d", h.Number, l.BlockNumber)
	}
	if h.TxHash != l.TransactionsRoot {
		return bad(CheckStoredRoots, "the header's transactionsRoot is %s, the stored transactions_root is %s", h.TxHash.Hex(), l.TransactionsRoot.Hex())
	}
	if h.ReceiptHash != l.ReceiptsRoot {
		return bad(CheckStoredRoots, "the header's receiptsRoot is %s, the stored receipts_root is %s", h.ReceiptHash.Hex(), l.ReceiptsRoot.Hex())
	}
	if _, _, err := l.Settlement(header).Verify(); err != nil {
		return bad(CheckInclusion, "%v", err)
	}
	return nil
}

// Settlement is the leg's L6 evidence with this header: exactly the value the new-shape bundles carry in component 5.
func (l Leg) Settlement(header []byte) *ethproof.Settlement {
	return &ethproof.Settlement{BlockHash: l.BlockHash, Header: append([]byte(nil), header...), TxHash: l.TxHash, Tx: l.Tx, Receipt: l.Receipt}
}

// Candidate is one legacy leg a lister found: the leg, or the named state of a legacy component that cannot be read as a leg (Leg then
// holds only ProofID and BundleID).
type Candidate struct {
	Leg Leg
	Err error
}

// LegLister lists the legacy legs of a chain a page at a time (pkg/database.FinalityAddendaRepository.LegacyLegs): up to limit
// proofs are examined, newest first after the proof id `after`; next is the cursor of the following page, "" at the end.
type LegLister interface {
	LegacyLegs(ctx context.Context, chain uint64, after string, limit int) (cands []Candidate, next string, err error)
}
