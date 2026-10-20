// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// publicKey is a valid G2 subgroup key derived from a PUBLIC constant seed: a stand-in "other validator" for the mutations.
func publicKey(label string) []byte {
	_, pk, err := bls.GenerateKeyPairFromSeed([]byte("certen-finality-adiri1-public-test-seed/" + label + "/xxxxxxxxxxxx"))
	must(err)
	return pk.Bytes()
}

// nonSubgroupSignature returns the compressed encoding of a point of the BLS12-381 G1 curve that is not in the prime-order
// subgroup (found by trying x = 1, 2, ...).
func nonSubgroupSignature() []byte {
	for i := uint64(1); i < 1000; i++ {
		var x, y, rhs fp.Element
		x.SetUint64(i)
		rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, new(fp.Element).SetUint64(4))
		if y.Sqrt(&rhs) == nil {
			continue
		}
		p := bls12381.G1Affine{X: x, Y: y}
		if p.IsOnCurve() && !p.IsInSubGroup() {
			b := p.Bytes()
			return b[:]
		}
	}
	panic("no non-subgroup point found")
}

// gnarkSigReason classifies a 48-byte signature with gnark directly (not through the verifier under test).
func gnarkSigReason(b []byte) string {
	var p bls12381.G1Affine
	if _, err := p.SetBytes(b); err == nil {
		if p.IsInfinity() {
			return "identity"
		}
		return "valid"
	}
	var q bls12381.G1Affine
	d := bls12381.NewDecoder(bytes.NewReader(b), bls12381.NoSubgroupChecks())
	if err := d.Decode(&q); err != nil || !q.IsOnCurve() {
		return "encoding"
	}
	if q.IsInfinity() {
		return "identity"
	}
	return "subgroup"
}

func embeddedAdiriSection() map[string]any {
	pins, err := finality.EmbeddedPins()
	must(err)
	var m map[string]any
	must(json.Unmarshal(pins.Sections["adiri"], &m))
	return m
}

func cloneSection(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	must(json.Unmarshal(raw, &out))
	return out
}

// adversarial derives the mutants of the real 513643 chain (annex "adversarial cases"). Every expected verdict is a literal.
func adversarial(base vec, baseEv []byte, facts cacheFacts) []vec {
	bp := parse(baseEv)
	n, h := base.Leg.Number, hash32(base.Leg.Hash)
	E := facts.epochOf(n)
	F := facts.finalNumber[E]
	Fh := facts.finalHash[E]
	if F-n+1 != uint64(len(bp.body.Spine)) {
		panic("the base spine is not F..N")
	}
	emb := embeddedAdiriSection()
	var out []vec
	add := func(name, note string, expect string, fn func(p parsed)) {
		p := parse(baseEv)
		fn(p)
		out = append(out, vec{Name: name, Group: "adversarial", Note: note, Leg: base.Leg, Pins: "embedded", Base: base.Name, Edits: diffEdits(baseEv, p.encode()), Expect: expect})
	}
	addPins := func(name, note, expect string, mut func(m map[string]any)) {
		m := cloneSection(emb)
		mut(m)
		out = append(out, vec{Name: name, Group: "adversarial", Note: note, Leg: base.Leg, Pins: m, Base: base.Name, Expect: expect})
	}
	for _, e := range []int{300, 5, 7, 8, 9, 100, 110, 125, 130, 150, 200, 201, 250, 300} {
		if e < len(facts.signers) && facts.signers[e] != 5 {
			panic(fmt.Sprintf("record %d does not have 5 signers", e))
		}
	}
	other := publicKey("other-1")

	// -- signers / quorum
	add("adv-insufficient-signers", "record 300 keeps 3 of its 5 signers (quorum floor(2*5/3)+1 = 4)",
		canon("committee_chain_broken", "epoch", uint64(300), "check", "signers_below_quorum", "got", uint64(3), "need", uint64(4)),
		func(p parsed) { p.cf.Records[300].Signers = p.cf.Records[300].Signers[:3] })
	add("adv-signer-index-out-of-range", "record 5: the last signer index is 5, the committee has 5 members",
		canon("committee_chain_broken", "epoch", uint64(5), "check", "signer_index_invalid", "index", uint64(4), "signer", uint64(5), "committee_size", uint64(5)),
		func(p parsed) { p.cf.Records[5].Signers[4] = 5 })
	add("adv-signer-index-not-increasing", "record 5: signers [1,0,2,3,4] are not strictly increasing",
		canon("committee_chain_broken", "epoch", uint64(5), "check", "signer_index_invalid", "index", uint64(1), "signer", uint64(0), "committee_size", uint64(5)),
		func(p parsed) { p.cf.Records[5].Signers[0], p.cf.Records[5].Signers[1] = 1, 0 })

	// -- committee
	add("adv-committee-not-compatible", "record 7's committee replaces one member with another valid key; next_committee(6) does not list it",
		canon("committee_chain_broken", "epoch", uint64(7), "check", "committee_incompatible", "reason", "set_mismatch", "size", uint64(5), "expected", uint64(5), "min_committee_size", uint64(4)),
		func(p parsed) {
			t := append([][]byte(nil), p.cf.Tables[p.cf.Records[7].CommitteeIdx]...)
			t[4] = other
			p.cf.Tables = append(p.cf.Tables, t)
			p.cf.Records[7].CommitteeIdx = uint8(len(p.cf.Tables) - 1)
		})
	add("adv-committee-duplicate-key", "record 9's committee lists its first key twice",
		canon("committee_chain_broken", "epoch", uint64(9), "check", "committee_duplicate_key", "index", uint64(1)),
		func(p parsed) {
			t := append([][]byte(nil), p.cf.Tables[p.cf.Records[9].CommitteeIdx]...)
			t[1] = t[0]
			p.cf.Tables = append(p.cf.Tables, t)
			p.cf.Records[9].CommitteeIdx = uint8(len(p.cf.Tables) - 1)
		})
	add("adv-genesis-duplicate-key", "record 0's committee lists its first key twice (the genesis list with a duplicate)",
		canon("committee_chain_broken", "epoch", uint64(0), "check", "committee_duplicate_key", "index", uint64(1)),
		func(p parsed) {
			t := append([][]byte(nil), p.cf.Tables[p.cf.Records[0].CommitteeIdx]...)
			t[1] = t[0]
			p.cf.Tables = append(p.cf.Tables, t)
			p.cf.Records[0].CommitteeIdx = uint8(len(p.cf.Tables) - 1)
		})
	add("adv-committee-not-from-genesis", "record 0's committee replaces one genesis key with another valid key: not the pinned set",
		canon("evidence_pin_mismatch", "pin", "genesis_committee", "want", uint64(5), "got", uint64(5)),
		func(p parsed) {
			t := append([][]byte(nil), p.cf.Tables[p.cf.Records[0].CommitteeIdx]...)
			t[4] = other
			p.cf.Tables = append(p.cf.Tables, t)
			p.cf.Records[0].CommitteeIdx = uint8(len(p.cf.Tables) - 1)
		})

	// -- signatures
	add("adv-certificate-for-different-block", "records 200 and 201 swap their signatures: each is a valid certificate for another record",
		canon("committee_chain_broken", "epoch", uint64(200), "check", "signature_invalid", "reason", "pairing"),
		func(p parsed) {
			p.cf.Records[200].Signature, p.cf.Records[201].Signature = p.cf.Records[201].Signature, p.cf.Records[200].Signature
		})
	add("adv-signature-bit-flip", "the last bit of record 300's signature is flipped",
		"", func(p parsed) { p.cf.Records[300].Signature[47] ^= 0x01 })
	flipped := out[len(out)-1]
	_ = flipped
	{
		p := parse(baseEv)
		sig := p.cf.Records[300].Signature
		sig[47] ^= 0x01
		reason := gnarkSigReason(sig[:])
		if reason == "valid" {
			panic("a flipped signature decodes as valid")
		}
		out[len(out)-1].Expect = canon("committee_chain_broken", "epoch", uint64(300), "check", "signature_invalid", "reason", reason)
	}
	ns := nonSubgroupSignature()
	if gnarkSigReason(ns) != "subgroup" {
		panic("the non-subgroup point is not classified subgroup")
	}
	add("adv-signature-not-in-subgroup", "record 125's signature is a point on the G1 curve outside the prime-order subgroup",
		canon("committee_chain_broken", "epoch", uint64(125), "check", "signature_invalid", "reason", "subgroup"),
		func(p parsed) { copy(p.cf.Records[125].Signature[:], ns) })
	ident := make([]byte, 48)
	ident[0] = 0xc0
	if gnarkSigReason(ident) != "identity" {
		panic("the identity encoding is not classified identity")
	}
	add("adv-signature-identity", "record 130's signature is the point at infinity",
		canon("committee_chain_broken", "epoch", uint64(130), "check", "signature_invalid", "reason", "identity"),
		func(p parsed) { copy(p.cf.Records[130].Signature[:], ident) })

	// -- tampered record fields: the digest changes, so the certificate no longer verifies (CFA1 recomputes the digest)
	sigBad := func(e int) string {
		return canon("committee_chain_broken", "epoch", uint64(e), "check", "signature_invalid", "reason", "pairing")
	}
	add("adv-tamper-final-state", "record 100's final_state.number is incremented", sigBad(100),
		func(p parsed) { p.cf.Records[100].FinalState.Number++ })
	add("adv-tamper-final-consensus", "one bit of record 110's final_consensus.hash is flipped", sigBad(110),
		func(p parsed) { p.cf.Records[110].FinalConsensus.Hash[0] ^= 1 })
	add("adv-tamper-committee-order", "record 7 names the committee in the genesis ordering: the same set, a different digest", sigBad(7),
		func(p parsed) { p.cf.Records[7].CommitteeIdx = p.cf.Records[0].CommitteeIdx })
	add("adv-tamper-next-committee-order", "record 8 names its next_committee in the genesis ordering", sigBad(8),
		func(p parsed) { p.cf.Records[8].NextIdx = p.cf.Records[0].CommitteeIdx })
	add("adv-tamper-epoch", "record 100 is removed: every later record sits at the wrong epoch", sigBad(100),
		func(p parsed) { p.cf.Records = append(p.cf.Records[:100:100], p.cf.Records[101:]...) })
	add("adv-tamper-parent-hash", "records 150 and 151 swap places: the digest chain no longer matches", sigBad(150),
		func(p parsed) { p.cf.Records[150], p.cf.Records[151] = p.cf.Records[151], p.cf.Records[150] })
	if t := p0(baseEv); t.cf.Records[100].CommitteeIdx != t.cf.Records[101].CommitteeIdx {
		panic("records 100 and 101 differ in committee table; the epoch tamper expectation assumes they share it")
	}

	// -- pins
	addPins("adv-wrong-incarnation", "the pinned epoch0_final_state hash differs: another incarnation's genesis",
		canon("adiri_incarnation_mismatch", "expected_genesis", hash32("0x"+flipHex(emb["epoch0_final_state"].(map[string]any)["hash"].(string))), "served_genesis", facts.finalHash[0],
			"expected_number", uint64(290), "served_number", uint64(290), "pin", "epoch0_final_state"),
		func(m map[string]any) {
			f := m["epoch0_final_state"].(map[string]any)
			f["hash"] = "0x" + flipHex(f["hash"].(string))
		})
	addPins("adv-pin-mismatch-genesis-committee", "the pinned genesis committee holds a different fifth key",
		canon("evidence_pin_mismatch", "pin", "genesis_committee", "want", uint64(5), "got", uint64(5)),
		func(m map[string]any) {
			c := m["genesis_committee"].([]any)
			c[4] = fmt.Sprintf("%x", other)
		})
	addPins("adv-pin-mismatch-chain-id", "the pins name chain id 2018",
		canon("evidence_pin_mismatch", "pin", "chain_id", "want", uint64(2017), "got", uint64(2018)),
		func(m map[string]any) { m["chain_id"] = float64(2018) })
	addPins("adv-codec-unsupported", "the pins name another record codec",
		canon("epoch_record_codec_unsupported", "epoch", uint64(0), "pinned", "telcoin-epoch-record/bcs-keccak/9", "supported", "telcoin-epoch-record/bcs-blake3/1"),
		func(m map[string]any) { m["epoch_record_codec"] = "telcoin-epoch-record/bcs-keccak/9" })
	addPins("adv-min-committee-size-six", "the pins require a committee of at least 6: the real 5-member committee is below it",
		canon("committee_chain_broken", "epoch", uint64(0), "check", "committee_incompatible", "reason", "below_min_committee_size", "size", uint64(5), "expected", uint64(5), "min_committee_size", uint64(6)),
		func(m map[string]any) { m["min_committee_size"] = float64(6) })

	// -- the link
	spine := bp.body.Spine
	hashOf := func(i int) [32]byte { return [32]byte(crypto.Keccak256Hash(spine[i])) }
	num := func(i int) uint64 { return F - uint64(i) }
	add("adv-spine-bit-flip", "one bit inside header 50 of the spine is flipped",
		canon("finality_header_chain_broken", "spine", "adiri", "at_number", num(49)-1, "want_hash", hashOf(50), "got_hash", func() [32]byte {
			b := append([]byte(nil), spine[50]...)
			b[100] ^= 1
			return [32]byte(crypto.Keccak256Hash(b))
		}(), "reason", "parent_hash_mismatch"),
		func(p parsed) { p.body.Spine[50][100] ^= 1 })
	add("adv-spine-gap", "header 50 is removed from the spine",
		canon("finality_header_chain_broken", "spine", "adiri", "at_number", num(49)-1, "want_hash", hashOf(50), "got_hash", hashOf(51), "reason", "parent_hash_mismatch"),
		func(p parsed) { p.body.Spine = append(p.body.Spine[:50:50], p.body.Spine[51:]...) })
	add("adv-spine-tip-not-final-state", "the seal header F is removed: the spine starts one block below the sealed block",
		canon("finality_link_broken", "from", F, "to", n, "at", F-1, "check", "tip_not_final_state", "want_hash", Fh, "got_hash", hashOf(1)),
		func(p parsed) { p.body.Spine = p.body.Spine[1:] })
	add("adv-spine-truncated", "the leg's own header is removed: the spine ends one block above the leg block",
		canon("finality_block_mismatch", "field", "spineLastNumber", "want", n, "got", n+1),
		func(p parsed) { p.body.Spine = p.body.Spine[:len(p.body.Spine)-1] })
	add("adv-spine-header-decode", "header 3 of the spine is replaced by a non-list",
		canon("finality_link_broken", "from", F, "to", n, "at", F-3, "check", "header_decode", "index", uint64(3)),
		func(p parsed) { p.body.Spine[3][0] = 0x80 })
	{
		v := base
		v.Name, v.Group = "adv-block-after-seal", "adversarial"
		v.Note = "the leg block number is above the sealed block (container header and leg both name block F+1)"
		hh := "0x" + fmt.Sprintf("%x", bytes.Repeat([]byte{0x77}, 32))
		v.Leg = legJSON{finality.ChainAdiri, F + 1, hh, ""}
		p := parse(baseEv)
		p.c.Header.BlockNumber, p.c.Header.BlockHash = F+1, hash32(hh)
		v.Base, v.Evidence = base.Name, ""
		v.Edits = diffEdits(baseEv, p.encode())
		v.Expect = canon("finality_link_broken", "from", F, "to", F+1, "at", F+1, "check", "block_after_seal")
		out = append(out, v)
	}
	{
		v := base
		v.Name, v.Group = "adv-block-hash-mismatch", "adversarial"
		v.Note = "the leg's block hash differs from the container's"
		hh := "0x" + fmt.Sprintf("%x", bytes.Repeat([]byte{0x55}, 32))
		v.Leg = legJSON{finality.ChainAdiri, n, hh, ""}
		v.Base, v.Evidence = base.Name, ""
		v.Expect = canon("finality_block_mismatch", "field", "blockHash", "want", hash32(hh), "got", h)
		out = append(out, v)
	}
	{
		v := base
		v.Name, v.Group = "adv-too-many-records", "adversarial"
		v.Note = "the CFA1 declares 65537 records (limit 65536)"
		v.Base, v.Evidence = base.Name, ""
		mut := append([]byte(nil), baseEv...)
		off := 79 + 4 + 2 // header (75 B), cfa1 length (4), magic (4), n_tables (2)
		for _, t := range bp.cf.Tables {
			off += 1 + len(t)*adiri.KeyBytes
		}
		binary32(mut[off:], 65537)
		v.Edits = diffEdits(baseEv, mut)
		v.Expect = canon("finality_evidence_too_large", "part", "cfa1.records", "count", uint64(65537), "limit", uint64(65536))
		out = append(out, v)
	}
	return out
}

func binary32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func p0(ev []byte) parsed { return parse(ev) }

// flipHex flips the first nibble's low bit of a 0x-prefixed or bare hex string and returns it bare.
func flipHex(s string) string {
	s = s[2:]
	c := s[0]
	if c == '7' {
		c = '6'
	} else {
		c = '7'
	}
	return string(c) + s[1:]
}
