// Copyright 2026 Certen Protocol

package adiri

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// The Adiri genesis link (V2_SPEC_S7 4.2, annex A7): the 290 headers of blocks 1..epoch0 as a concatenation of raw RLP headers
// (176,758 B), published beside the pins file and hash-pinned by the pins file's genesis_link_sha256. It is what binds the pinned
// committee chain to THIS incarnation's genesis block: the first header has number 1 and parentHash = genesis_hash, every header
// links to the previous one, and the last is epoch0_final_state. The link is checked ONCE at load by CheckEmbeddedGenesisLink,
// never per proof (the evidence carries no genesis material and a proof pays nothing for it).

//go:embed testdata/pins/genesis_link_1_290.bin
var embeddedGenesisLink []byte

// EmbeddedGenesisLink returns a copy of the embedded genesis link file.
func EmbeddedGenesisLink() []byte { return append([]byte(nil), embeddedGenesisLink...) }

// SplitHeaders splits a concatenation of raw RLP headers (the genesis link file) into headers. Every header must be a single
// well-formed RLP list; a declared length that does not fit is an error, never a panic.
func SplitHeaders(file []byte) ([][]byte, error) {
	var out [][]byte
	rest := file
	for len(rest) > 0 {
		_, tail, err := rlp.SplitList(rest)
		if err != nil {
			return nil, fmt.Errorf("header %d: %v", len(out), err)
		}
		out = append(out, rest[:len(rest)-len(tail)])
		rest = tail
	}
	return out, nil
}

// VerifyGenesisLink checks a genesis link file: it hashes to wantSHA and holds the headers of blocks 1..epoch0.Number (290
// headers, 176,758 B) as a parentHash chain whose first header has parentHash = the genesis block hash and number 1 and whose last
// is epoch0 (number and hash). The genesis block itself is recomputed from tn_genesis by pinsderive/genesis. It returns the
// number of headers. This is what binds the committee chain to this incarnation's genesis block (annex A7 step 3).
func VerifyGenesisLink(file []byte, wantSHA string, genesisHash [32]byte, epoch0 NumHash) (int, error) {
	sum := sha256.Sum256(file)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return 0, fmt.Errorf("genesis link sha256 %x, want %s", sum, wantSHA)
	}
	hs, err := SplitHeaders(file)
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 {
		return 0, fmt.Errorf("the genesis link is empty")
	}
	var prev finality.HeaderFields
	for i, raw := range hs {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return 0, fmt.Errorf("header %d: %v", i, err)
		}
		if i == 0 && (h.ParentHash != genesisHash || h.Number != 1) {
			return 0, fmt.Errorf("the first header is %d with parent %x, want block 1 with the genesis hash %x", h.Number, h.ParentHash, genesisHash)
		}
		if i > 0 && (h.ParentHash != prev.Hash || h.Number != prev.Number+1) {
			return 0, fmt.Errorf("header %d does not link to header %d", h.Number, prev.Number)
		}
		prev = h
	}
	if prev.Number != epoch0.Number || prev.Hash != epoch0.Hash {
		return 0, fmt.Errorf("the link ends at %d %x, want epoch0_final_state %d %x", prev.Number, prev.Hash, epoch0.Number, epoch0.Hash)
	}
	return len(hs), nil
}

// CheckGenesisLink judges a genesis link file against the adiri section of p: a file whose sha256 is not genesis_link_sha256 is
// finality_pins_corrupt{reason:bad_value, key:"adiri.genesis_link_sha256"}, and a file that hashes right but does not run from
// genesis_hash (block 1) to epoch0_final_state through linked headers is
// finality_pins_corrupt{reason:bad_value, key:"adiri.genesis_link"}. A pins file with no adiri section, or a malformed one, is
// the state ParsePins names.
func CheckGenesisLink(file []byte, p *finality.Pins) error {
	par, err := ParsePins(p)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(file)
	if hex.EncodeToString(sum[:]) != par.GenesisLinkSHA {
		return finality.PinsCorrupt(finality.PinsBadValue, "key", "adiri.genesis_link_sha256")
	}
	if _, err := VerifyGenesisLink(file, par.GenesisLinkSHA, par.GenesisHash, par.Epoch0FinalState); err != nil {
		return finality.PinsCorrupt(finality.PinsBadValue, "key", "adiri.genesis_link")
	}
	return nil
}

// CheckEmbeddedGenesisLink is the load-time check of the embedded pins: the embedded genesis link must be the one the pins file
// hash-pins and must link genesis_hash to epoch0_final_state. It costs one sha256 and 290 header hashes, once per process, and a
// verifier that fails it refuses to start exactly as one whose embedded pins do not hash to PinsSHA256.
func CheckEmbeddedGenesisLink(p *finality.Pins) error {
	return CheckGenesisLink(embeddedGenesisLink, p)
}
