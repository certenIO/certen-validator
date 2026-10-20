// Copyright 2026 Certen Protocol

package adiri

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"lukechampine.com/blake3"

	"github.com/certen/independant-validator/pkg/finality"
)

// Codec is the one record encoding this verifier implements: the BCS of an EpochRecord, digested with BLAKE3-256, as the
// annex measured it for epochs 0..642 on telcoin-network v0.16.0-adiri (A3). The pins name it (epoch_record_codec); a pin
// that names another codec is epoch_record_codec_unsupported.
const Codec = "telcoin-epoch-record/bcs-blake3/1"

// Name is the evidence kind of this package.
const Name = "adiri/finalized/v1"

// uleb is the unsigned LEB128 of n (BCS length prefix).
func uleb(n int) []byte {
	var out []byte
	v := uint64(n)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// bcsRecord reconstructs the BCS of record `epoch` exactly as V2_SPEC_S7 5.8 O2:
// u32le(epoch) || uleb(n) || (0x60||key)^n || uleb(n') || (0x60||key')^n' || 0x20||parent_digest || u64le(fs.number) ||
// 0x20||fs.hash || u64le(fc.number) || 0x20||fc.hash.
func bcsRecord(epoch uint32, committee, next [][]byte, parent [32]byte, fs, fc NumHash) []byte {
	out := binary.LittleEndian.AppendUint32(nil, epoch)
	out = append(out, uleb(len(committee))...)
	for _, k := range committee {
		out = append(out, 0x60)
		out = append(out, k...)
	}
	out = append(out, uleb(len(next))...)
	for _, k := range next {
		out = append(out, 0x60)
		out = append(out, k...)
	}
	out = append(out, 0x20)
	out = append(out, parent[:]...)
	out = binary.LittleEndian.AppendUint64(out, fs.Number)
	out = append(out, 0x20)
	out = append(out, fs.Hash[:]...)
	out = binary.LittleEndian.AppendUint64(out, fc.Number)
	out = append(out, 0x20)
	out = append(out, fc.Hash[:]...)
	return out
}

// Digest is BLAKE3-256 of the BCS record.
func Digest(bcs []byte) [32]byte { return blake3.Sum256(bcs) }

// SignedMessage is the message the committee signs: 01 00 01 20 || digest (scope EpochBoundary, version V0, app id
// Consensus, then the BCS of a 32-byte digest).
func SignedMessage(digest [32]byte) []byte {
	return append([]byte{0x01, 0x00, 0x01, 0x20}, digest[:]...)
}

// RecordDigests computes digest(i) for every record of the chain (parent_digest(0) = 0^32).
func (c *CFA1) RecordDigests() [][32]byte {
	out := make([][32]byte, len(c.Records))
	var parent [32]byte
	for i := range c.Records {
		r := c.Records[i]
		out[i] = Digest(bcsRecord(uint32(i), c.Tables[r.CommitteeIdx], c.Tables[r.NextIdx], parent, r.FinalState, r.FinalConsensus))
		parent = out[i]
	}
	return out
}

// Params are the Adiri pins of V2_SPEC_S7 4.2.
type Params struct {
	ChainID          uint64
	Codec            string
	GenesisHash      [32]byte
	GenesisCommittee [][]byte
	Epoch0FinalState NumHash
	GenesisLinkSHA   string
	MinCommittee     int
	MaxHeaders       int
	EIP2935Address   common.Address
	EIP2935CodeHash  [32]byte
}

type pinsJSON struct {
	ChainID          uint64   `json:"chain_id"`
	EIP2935          eipJSON  `json:"eip2935"`
	Epoch0FinalState nhJSON   `json:"epoch0_final_state"`
	Codec            string   `json:"epoch_record_codec"`
	GenesisCommittee []string `json:"genesis_committee"`
	GenesisHash      string   `json:"genesis_hash"`
	GenesisLinkSHA   string   `json:"genesis_link_sha256"`
	MaxHeaders       int      `json:"max_headers"`
	MinCommittee     int      `json:"min_committee_size"`
}

type eipJSON struct {
	Address  string `json:"address"`
	Codehash string `json:"runtime_codehash"`
}

type nhJSON struct {
	Hash   string `json:"hash"`
	Number uint64 `json:"number"`
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := decode0x(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%q is not 0x + 32 bytes of hex", s)
	}
	copy(out[:], b)
	return out, nil
}

func decode0x(s string) ([]byte, error) {
	if len(s) < 2 || s[:2] != "0x" {
		return nil, fmt.Errorf("missing 0x prefix")
	}
	return common.FromHex(s), nil
}

// ParsePins reads the adiri section of the pins file. A missing section is finality_pin_unknown; a malformed one is
// finality_pins_corrupt.
func ParsePins(p *finality.Pins) (*Params, error) {
	if p == nil || p.Sections["adiri"] == nil {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainAdiri, "kind", "adiri")
	}
	var j pinsJSON
	dec := json.NewDecoder(bytes.NewReader(p.Sections["adiri"]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, finality.PinsCorrupt("adiri: " + err.Error())
	}
	par := &Params{ChainID: j.ChainID, Codec: j.Codec, GenesisLinkSHA: j.GenesisLinkSHA, MinCommittee: j.MinCommittee, MaxHeaders: j.MaxHeaders}
	var err error
	if par.GenesisHash, err = hex32(j.GenesisHash); err != nil {
		return nil, finality.PinsCorrupt("adiri.genesis_hash: " + err.Error())
	}
	if par.Epoch0FinalState.Hash, err = hex32(j.Epoch0FinalState.Hash); err != nil {
		return nil, finality.PinsCorrupt("adiri.epoch0_final_state.hash: " + err.Error())
	}
	par.Epoch0FinalState.Number = j.Epoch0FinalState.Number
	if par.EIP2935CodeHash, err = hex32(j.EIP2935.Codehash); err != nil {
		return nil, finality.PinsCorrupt("adiri.eip2935.runtime_codehash: " + err.Error())
	}
	a, err := decode0x(j.EIP2935.Address)
	if err != nil || len(a) != 20 {
		return nil, finality.PinsCorrupt("adiri.eip2935.address is not 0x + 20 bytes")
	}
	par.EIP2935Address = common.BytesToAddress(a)
	if len(j.GenesisCommittee) == 0 || len(j.GenesisCommittee) > 255 {
		return nil, finality.PinsCorrupt("adiri.genesis_committee must hold 1..255 keys")
	}
	for i, h := range j.GenesisCommittee {
		k := common.FromHex("0x" + h)
		if len(k) != KeyBytes {
			return nil, finality.PinsCorrupt(fmt.Sprintf("adiri.genesis_committee[%d] is not 96 bytes of hex", i))
		}
		par.GenesisCommittee = append(par.GenesisCommittee, k)
	}
	if par.MinCommittee < 1 || par.MaxHeaders < 1 || par.ChainID == 0 {
		return nil, finality.PinsCorrupt("adiri.min_committee_size, max_headers and chain_id must be positive")
	}
	if len(j.GenesisLinkSHA) != 64 {
		return nil, finality.PinsCorrupt("adiri.genesis_link_sha256 is not 64 hex characters")
	}
	return par, nil
}
