// Copyright 2026 Certen Protocol

// Package adiri is the S7 kind adiri/finalized/v1 (V2_SPEC_S7 sections 3.3 and 5.8, annex R11-adiri): a leg block on Adiri
// (chain 2017, Telcoin Network) is finalized when it is an ancestor of the last block F of an epoch E whose EpochRecord a
// super-quorum of committee(E) signed, with committee(E) chained from the pinned genesis committee through certified records
// 0..E.
//
// Order of judgement (the TypeScript port follows it exactly, so that Go and TS return the same code and fields):
//
//  1. the container and its body decode strictly (finality_evidence_malformed / _too_large); the CFA1 decodes strictly,
//     including strictly increasing, in-range signer indices (committee_chain_broken{signer_index_invalid});
//  2. the pins: chain id, record codec, genesis committee as a set, record(0).final_state (O1);
//  3. every record in ascending order: key validity, duplicates, committee compatibility, minimum size, quorum (O2); the exported
//     VerifyCommitteeChain first re-applies the decoder's table-index and signer-index rules to every record, so a CFA1 that was
//     built rather than decoded is judged like a decoded one;
//  4. every signature (O3): decoded with the G1 subgroup and non-identity checks, then verified one by one with
//     pkg/crypto/bls or as one random linear combination; the verdict is the lowest failing epoch either way;
//  5. the seal and the link (O4).
//
// Fields the TypeScript port must reproduce exactly (they extend the field lists of states.json; extra fields are allowed there):
//
//   - committee_chain_broken{epoch, check, ...}: signers_below_quorum adds got, need; signer_index_invalid adds index, signer,
//     committee_size; committee_duplicate_key and public_key_invalid add index; committee_incompatible adds reason
//     (larger_than_expected, set_mismatch, not_subset, below_two_thirds, below_min_committee_size), size, expected,
//     min_committee_size; signature_invalid adds reason (encoding, identity, subgroup, pairing). The lowest failing epoch
//     is named in both signature modes.
//   - evidence_pin_mismatch{pin, want, got}: chain_id (numbers) or genesis_committee (set sizes).
//   - adiri_incarnation_mismatch{expected_genesis, served_genesis, expected_number, served_number, pin}.
//   - epoch_record_codec_unsupported{epoch:0, pinned, supported}.
//   - finality_link_broken{from=F, to=N, at, check, ...}; finality_header_chain_broken{spine:"adiri", at_number, want_hash,
//     got_hash, reason}; finality_block_mismatch{field: spineLastNumber | spineLastHash | spineLastHeader | blockNumber | blockHash}.
//   - the verdict (code "finalized" in the vectors): epoch, chain_len, committee_size, signers, final_number, final_hash,
//     distance, link_kind, consensus_root_matches (F.parentBeaconBlockRoot == record(E).final_consensus.hash, reported),
//     committee_shrunk (a list of the canonical committee_shrunk{epoch,size,expected} texts, ascending).
//
// The package has no init(): Register(reg) is called by the integration package.
package adiri

import (
	"github.com/certen/independant-validator/pkg/finality"
)

// CFA1Magic opens the compact committee chain.
const CFA1Magic = "CFA1"

// KeyBytes is a compressed G2 public key, SigBytes a compressed G1 signature.
const (
	KeyBytes = 96
	SigBytes = 48
)

// NumHash is a (number, hash) checkpoint of an epoch record.
type NumHash struct {
	Number uint64
	Hash   [32]byte
}

// Record is one EpochRecord as CFA1 carries it: what the verifier cannot recompute. The epoch is the position, parent_hash is
// the digest of the previous record, the digest is BLAKE3 of the reconstructed BCS and the Roaring bitmap is the explicit
// signer index list.
type Record struct {
	CommitteeIdx   uint8
	NextIdx        uint8
	FinalState     NumHash
	FinalConsensus NumHash
	Signature      [SigBytes]byte
	Signers        []uint8
}

// CFA1 is the compact committee chain: the distinct committee orderings and records 0..E.
type CFA1 struct {
	Tables  [][][]byte // each table: 1..255 keys of KeyBytes
	Records []Record
}

// Committee returns record i's committee (a table), or nil when the index is out of range.
func (c *CFA1) Committee(i int) [][]byte {
	if i < 0 || i >= len(c.Records) || int(c.Records[i].CommitteeIdx) >= len(c.Tables) {
		return nil
	}
	return c.Tables[c.Records[i].CommitteeIdx]
}

// Next returns record i's next_committee.
func (c *CFA1) Next(i int) [][]byte {
	if i < 0 || i >= len(c.Records) || int(c.Records[i].NextIdx) >= len(c.Tables) {
		return nil
	}
	return c.Tables[c.Records[i].NextIdx]
}

// Encode is the canonical byte form (V2_SPEC_S7 3.3): "CFA1" || u16 n_tables || tables(u8 n || n x 96 B) || u32 n_records ||
// per record (u8 committee_idx, u8 next_idx, u64 final_state.number, B32 final_state.hash, u64 final_consensus.number,
// B32 final_consensus.hash, B48 signature, u8 n_signers, u8[] signers).
func (c *CFA1) Encode() ([]byte, error) {
	if len(c.Tables) > 0xffff || len(c.Records) > 0xffffffff {
		return nil, finality.Malformed("cfa1", finality.ReasonCFA1TooLargeToEncode, len(c.Tables), 0xffff)
	}
	var w finality.Writer
	w.Fixed([]byte(CFA1Magic))
	w.Fixed([]byte{byte(len(c.Tables) >> 8), byte(len(c.Tables))})
	for i, t := range c.Tables {
		if len(t) == 0 || len(t) > 255 {
			return nil, finality.MalformedAt("cfa1.table", i, finality.ReasonCFA1TableSize, len(t), 255)
		}
		w.U8(uint8(len(t)))
		for _, k := range t {
			if len(k) != KeyBytes {
				return nil, finality.MalformedAt("cfa1.table.key", i, finality.ReasonCFA1KeyLength, len(k), KeyBytes)
			}
			w.Fixed(k)
		}
	}
	w.U32(uint32(len(c.Records)))
	for i, r := range c.Records {
		if len(r.Signers) > 255 {
			return nil, finality.MalformedAt("cfa1.record.signers", i, finality.ReasonCFA1SignersTooMany, len(r.Signers), 255)
		}
		w.U8(r.CommitteeIdx)
		w.U8(r.NextIdx)
		w.U64(r.FinalState.Number)
		w.B32(r.FinalState.Hash)
		w.U64(r.FinalConsensus.Number)
		w.B32(r.FinalConsensus.Hash)
		w.Fixed(r.Signature[:])
		w.U8(uint8(len(r.Signers)))
		w.Fixed(r.Signers)
	}
	return w.Bytes(), nil
}

// minRecordBytes is the size of a record without signers.
const minRecordBytes = 1 + 1 + 8 + 32 + 8 + 32 + SigBytes + 1

// DecodeCFA1 decodes strictly: magic, bounded table and record counts (Limits.MaxCFA1Tables / MaxCFA1Records), non-empty
// tables, table indices in range, signer indices strictly increasing and below the committee size, and no trailing byte.
// encode(decode(x)) == x for every x accepted.
func DecodeCFA1(b []byte, lim finality.Limits) (*CFA1, error) {
	r := finality.NewReader(b, lim)
	magic, err := r.Fixed("cfa1.magic", 4)
	if err != nil {
		return nil, err
	}
	if string(magic) != CFA1Magic {
		return nil, finality.Malformed("cfa1.magic", finality.ReasonCFA1BadMagic, 4, 4)
	}
	nt, err := r.Fixed("cfa1.n_tables", 2)
	if err != nil {
		return nil, err
	}
	nTables := int(nt[0])<<8 | int(nt[1])
	if nTables > lim.MaxCFA1Tables {
		return nil, finality.EvidenceTooLarge("cfa1.tables", uint64(nTables), uint64(lim.MaxCFA1Tables))
	}
	if nTables == 0 {
		return nil, finality.Malformed("cfa1.n_tables", finality.ReasonCFA1NoTables, 0, 1)
	}
	c := &CFA1{Tables: make([][][]byte, 0, nTables)}
	for i := 0; i < nTables; i++ {
		n, err := r.U8("cfa1.table.n")
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, finality.MalformedAt("cfa1.table", i, finality.ReasonCFA1TableEmpty, 0, 1)
		}
		keys := make([][]byte, int(n))
		for j := range keys {
			if keys[j], err = r.Fixed("cfa1.table.key", KeyBytes); err != nil {
				return nil, err
			}
		}
		c.Tables = append(c.Tables, keys)
	}
	nRec, err := r.U32("cfa1.n_records")
	if err != nil {
		return nil, err
	}
	if uint64(nRec) > uint64(lim.MaxCFA1Records) {
		return nil, finality.EvidenceTooLarge("cfa1.records", uint64(nRec), uint64(lim.MaxCFA1Records))
	}
	if nRec == 0 {
		return nil, finality.Malformed("cfa1.n_records", finality.ReasonCFA1NoRecords, 0, 1)
	}
	if uint64(nRec)*minRecordBytes > uint64(r.Left()) {
		return nil, finality.Malformed("cfa1.records", finality.ReasonCountExceedsRemaining, r.Left(), int(nRec)*minRecordBytes)
	}
	c.Records = make([]Record, 0, int(nRec))
	for i := 0; i < int(nRec); i++ {
		var rec Record
		if rec.CommitteeIdx, err = r.U8("cfa1.record.committee_idx"); err != nil {
			return nil, err
		}
		if rec.NextIdx, err = r.U8("cfa1.record.next_idx"); err != nil {
			return nil, err
		}
		if err := checkRecordTables(i, rec, nTables); err != nil {
			return nil, err
		}
		if rec.FinalState.Number, err = r.U64("cfa1.record.final_state.number"); err != nil {
			return nil, err
		}
		if rec.FinalState.Hash, err = r.B32("cfa1.record.final_state.hash"); err != nil {
			return nil, err
		}
		if rec.FinalConsensus.Number, err = r.U64("cfa1.record.final_consensus.number"); err != nil {
			return nil, err
		}
		if rec.FinalConsensus.Hash, err = r.B32("cfa1.record.final_consensus.hash"); err != nil {
			return nil, err
		}
		sig, err := r.Fixed("cfa1.record.signature", SigBytes)
		if err != nil {
			return nil, err
		}
		copy(rec.Signature[:], sig)
		ns, err := r.U8("cfa1.record.n_signers")
		if err != nil {
			return nil, err
		}
		if rec.Signers, err = r.Fixed("cfa1.record.signers", int(ns)); err != nil {
			return nil, err
		}
		if err := checkRecordSigners(i, rec.Signers, len(c.Tables[rec.CommitteeIdx])); err != nil {
			return nil, err
		}
		c.Records = append(c.Records, rec)
	}
	if err := r.End("cfa1"); err != nil {
		return nil, err
	}
	return c, nil
}

// checkRecordTables is the table-index rule of record i: both indices name a table. DecodeCFA1 applies it as it reads, and
// VerifyCommitteeChain (which is exported and judges any CFA1) applies it again before it indexes the tables.
func checkRecordTables(i int, rec Record, nTables int) error {
	if int(rec.CommitteeIdx) >= nTables || int(rec.NextIdx) >= nTables {
		return finality.MalformedAt("cfa1.record", i, finality.ReasonCFA1TableIndexOutOfRange, int(max8(rec.CommitteeIdx, rec.NextIdx)), nTables)
	}
	return nil
}

// checkRecordSigners is the signer rule of record i: the indices are strictly increasing and below the committee size, so that no
// signer is counted twice and none names a key outside the committee. Same two callers as checkRecordTables.
func checkRecordSigners(i int, signers []uint8, committeeSize int) error {
	for j, s := range signers {
		if int(s) >= committeeSize || (j > 0 && s <= signers[j-1]) {
			return ChainBroken(uint64(i), CheckSignerIndexInvalid, "index", uint64(j), "signer", uint64(s), "committee_size", uint64(committeeSize))
		}
	}
	return nil
}

func max8(a, b uint8) uint8 {
	if a > b {
		return a
	}
	return b
}
