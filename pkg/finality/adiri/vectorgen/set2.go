// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// set2Vectors builds the supplement of finality_adiri1 (published, never edited; now superseded with finality_adiri2 by finality_adiri3) for the boundaries
// and guards that the mutation loop showed set 1 does not pin: the exact 2/3 boundary, a hash-linked spine whose numbers skip,
// a leg that is not on the sealed chain, an empty spine, an unknown linkKind and a trailing byte. All synthetic (test keys in
// the gitignored keys/ directory), self-contained.
func set2Vectors() (map[string][]byte, []vec) {
	kp := loadKeys("pkg/finality/adiri/vectorgen/keys", 8)
	ev := map[string][]byte{}
	var vs []vec
	g5 := seq(0, 5)
	add := func(name, note string, o synthOut, expect string) {
		ev[name] = o.evidence
		vs = append(vs, vec{Name: name, Group: "synthetic", Note: note, Leg: o.leg, Pins: o.pins, Evidence: name + ".bin", Expect: expect})
	}
	addEdit := func(name, note string, base vec, baseEv []byte, mutate func(p *parsed), leg legJSON, expect string) {
		p := parse(baseEv)
		mutate(&p)
		vs = append(vs, vec{Name: name, Group: "adversarial", Note: note, Leg: leg, Pins: base.Pins, Base: base.Name, Edits: diffEdits(baseEv, p.encode()), Expect: expect})
	}

	// the exact 2/3 boundary: 6 -> 4 is 3*4 == 2*6, accepted (and reported); 4 is the minimum size
	g6 := seq(0, 6)
	o := buildSynth(kp, []epochSpec{
		{committee: g6, next: g6, signers: seq(0, 6)},
		{committee: seq(0, 4), next: seq(0, 4), signers: []int{0, 2, 3}},
	}, nil, 21)
	add("syn2-two-thirds-boundary", "6 -> 4: 3*4 == 2*6 sits exactly on the 2/3 bound and is tolerated (reported committee_shrunk); 3 of 4 signers is the quorum", o,
		canon("finalized", "epoch", uint64(1), "chain_len", uint64(2), "committee_size", uint64(4), "signers", uint64(3), "final_number", uint64(1003), "final_hash", fHashOf(o),
			"distance", uint64(3), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{canon("committee_shrunk", "epoch", uint64(1), "size", uint64(4), "expected", uint64(6))}))

	// a hash-linked spine 1003 -> 1001 -> 1000: the numbers skip 1002
	synthNumbers = []uint64{1000, 1001, 1003}
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, nil, 22)
	synthNumbers = nil
	c, err := finality.DecodeContainer(o.evidence, finality.DefaultLimits())
	must(err)
	b, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
	must(err)
	f1, err := finality.ReadHeader(b.Spine[0])
	must(err)
	f2, err := finality.ReadHeader(b.Spine[1])
	must(err)
	add("syn2-spine-number-gap", "the spine is hash-linked but its numbers go 1003, 1001, 1000: the parent of block 1003 claims number 1001", o,
		canon("finality_header_chain_broken", "spine", "adiri", "at_number", uint64(1002), "want_hash", f1.ParentHash, "got_hash", f2.Hash, "reason", "number_gap"))

	// the valid base for the guard mutations: the 4-header spine 1003..1000
	base := buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, nil, 23)
	baseVec := vec{Name: "syn2-spine-4", Group: "synthetic", Note: "the valid base of the guard vectors: one epoch, spine 1003..1000", Leg: base.leg, Pins: base.pins, Evidence: "syn2-spine-4.bin",
		Expect: canon("finalized", "epoch", uint64(0), "chain_len", uint64(1), "committee_size", uint64(5), "signers", uint64(5), "final_number", uint64(1003), "final_hash", fHashOf(base),
			"distance", uint64(3), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{})}
	ev[baseVec.Name] = base.evidence
	vs = append(vs, baseVec)
	realHash := hash32(base.leg.Hash)
	other := "0x" + hex.EncodeToString(append([]byte(nil), repeat(0x55, 32)...))

	// the leg is named consistently in the container and by the caller, but is not the block the sealed chain contains at 1000
	{
		addEdit("syn2-leg-not-on-the-chain", "container and leg both name another block hash at height 1000: the sealed spine ends at a different block", baseVec, base.evidence,
			func(q *parsed) { q.c.Header.BlockHash = hash32(other) }, legJSON{finality.ChainAdiri, 1000, other, ""},
			canon("finality_block_mismatch", "field", "spineLastHash", "want", hash32(other), "got", realHash))
	}
	addEdit("syn2-empty-spine", "linkKind 1 with no header at all", baseVec, base.evidence, func(q *parsed) { q.body.Spine = nil }, base.leg,
		canon("finality_evidence_malformed", "part", "spine", "reason", "spine_empty", "got_len", uint64(0), "want_len", uint64(1)))
	addEdit("syn2-link-kind-3", "linkKind 3 does not exist", baseVec, base.evidence, func(q *parsed) { q.body.LinkKind = 3; q.body.Spine = nil }, base.leg,
		canon("finality_evidence_malformed", "part", "linkKind", "reason", "link_kind_unknown", "got_len", uint64(3), "want_len", uint64(1)))
	addEdit("syn2-body-trailing-byte", "one byte after the last spine header", baseVec, base.evidence, func(q *parsed) { q.c.Body = nil }, base.leg, "")
	// the trailing byte is a raw container edit: append 0x00 to the evidence
	{
		raw := append(append([]byte(nil), base.evidence...), 0)
		last := &vs[len(vs)-1]
		last.Edits = diffEdits(base.evidence, raw)
		last.Expect = canon("finality_evidence_malformed", "part", "body", "reason", "trailing_bytes", "got_len", uint64(1), "want_len", uint64(0))
	}

	addEdit("syn2-duplicate-signer", "signers [0,0,1,2,3]: an index may not repeat (it would count one key twice)", baseVec, base.evidence,
		func(q *parsed) { q.cf.Records[0].Signers = []uint8{0, 0, 1, 2, 3} }, base.leg,
		canon("committee_chain_broken", "epoch", uint64(0), "check", "signer_index_invalid", "index", uint64(1), "signer", uint64(0), "committee_size", uint64(5)))

	// linkKind 2: the seal header must be F
	k2 := buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{}, 24)
	k2Vec := vec{Name: "syn2-kind2", Group: "synthetic", Note: "the valid linkKind 2 base of the seal-header guard vector", Leg: k2.leg, Pins: k2.pins, Evidence: "syn2-kind2.bin",
		Expect: canon("finalized", "epoch", uint64(0), "chain_len", uint64(1), "committee_size", uint64(5), "signers", uint64(5), "final_number", uint64(1003), "final_hash", fHashOf(k2),
			"distance", uint64(3), "link_kind", uint64(2), "consensus_root_matches", true, "committee_shrunk", []string{})}
	ev[k2Vec.Name] = k2.evidence
	vs = append(vs, k2Vec)
	var otherHeaderHash [32]byte
	addEdit("syn2-kind2-final-header-not-the-seal", "the final header differs from F in its last byte: it hashes to another block", k2Vec, k2.evidence,
		func(q *parsed) {
			q.body.FinalHeader[len(q.body.FinalHeader)-1] ^= 1
			otherHeaderHash = [32]byte(crypto.Keccak256Hash(q.body.FinalHeader))
		}, k2.leg, "")
	vs[len(vs)-1].Expect = canon("finality_link_broken", "from", uint64(1003), "to", uint64(1000), "at", uint64(1003), "check", "tip_not_final_state", "want_hash", fHashOf(k2), "got_hash", otherHeaderHash)

	return ev, vs
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
