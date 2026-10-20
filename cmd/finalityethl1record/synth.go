// Copyright 2026 Certen Protocol

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strconv"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The synthetic cases cover rules that no live Sepolia object can reach today (a fork boundary between the attested slot
// and signature_slot - 1, an Electra-era finalized header inside a Gloas-shaped update, the exact 342 boundary with a valid
// signature). They are signed by a four-key test committee whose secret scalars are derived from fixed labels at generation
// time and are never written to the repository; the vectors carry only public keys, roots and signatures.
const (
	synthDST      = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	synthPeriod   = 10
	synthElectraE = 2000
	synthGloasE   = 2570
	synthHezeE    = 2575
)

type synthKeys struct {
	sk [4]*big.Int
	pk [4][48]byte
}

func newSynthKeys() synthKeys {
	var k synthKeys
	for i := range k.sk {
		h := sha256.Sum256([]byte("finality_ethl1_v1/synthetic-test-key/" + strconv.Itoa(i)))
		var e fr.Element
		e.SetBytes(h[:])
		k.sk[i] = e.BigInt(new(big.Int))
		var p bls12381.G1Affine
		p.ScalarMultiplicationBase(k.sk[i])
		k.pk[i] = p.Bytes()
	}
	return k
}

// committee512 returns the SSZ SyncCommittee whose seat i holds key i mod 4, and its aggregate_pubkey.
func (k synthKeys) committee512() []byte {
	b := make([]byte, 0, committeeLen)
	total := new(big.Int)
	for i := 0; i < 512; i++ {
		b = append(b, k.pk[i%4][:]...)
		total.Add(total, k.sk[i%4])
	}
	var agg bls12381.G1Affine
	agg.ScalarMultiplicationBase(total)
	a := agg.Bytes()
	return append(b, a[:]...)
}

// sign returns the aggregate signature of the first n seats over msg.
func (k synthKeys) sign(msg [32]byte, n int) [96]byte {
	total := new(big.Int)
	for i := 0; i < n; i++ {
		total.Add(total, k.sk[i%4])
	}
	h, err := bls12381.HashToG2(msg[:], []byte(synthDST))
	if err != nil {
		panic(err)
	}
	var s bls12381.G2Affine
	s.ScalarMultiplication(&h, total)
	return s.Bytes()
}

func beaconBytes(slot uint64, parent, state, body [32]byte) []byte {
	b := make([]byte, 112)
	binary.LittleEndian.PutUint64(b[0:8], slot)
	binary.LittleEndian.PutUint64(b[8:16], 7)
	copy(b[16:48], parent[:])
	copy(b[48:80], state[:])
	copy(b[80:112], body[:])
	return b
}

func lcHeaderBytes(beacon []byte, exec [32]byte, branch [][32]byte) []byte {
	b := append([]byte(nil), beacon...)
	b = append(b, exec[:]...)
	for _, n := range branch {
		b = append(b, n[:]...)
	}
	return b
}

func nodes(label string, n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sum(label + "/" + strconv.Itoa(i))
	}
	return out
}

// synthFinal builds a finality update: finalized header at finSlot (branch to the execution hash at the gindex of its own
// fork, zero-extended to 11 nodes), attested header at attSlot whose state_root commits to the finalized header, signed by
// n seats under the fork version in force at epoch(sigSlot-1) of the schedule (or at versionEpoch when set).
type synthSpec struct {
	label          string
	attSlot        uint64
	finSlot        uint64
	sigSlot        uint64
	finGindex      uint64 // 2856 for a Gloas finalized header, 812 for an Electra-era one
	finNonZeroXtra bool   // put a non-zero node into the zero-extended part of the finalized branch
	n              int
	version        [4]byte
	gvr            [32]byte
	identitySig    bool
}

func (k synthKeys) final(s synthSpec) []byte {
	exec := sum(s.label + "/finalized-exec")
	var fbranch [][32]byte
	if s.finGindex == 812 {
		fbranch = append([][32]byte{{}, {}}, nodes(s.label+"/fbranch", 9)...)
		if s.finNonZeroXtra {
			fbranch[0] = sum(s.label + "/extra")
		}
	} else {
		fbranch = nodes(s.label+"/fbranch", 11)
	}
	fbody := ethl1.RootFromNormalizedBranch(exec, fbranch, s.finGindex)
	fbeacon := beaconBytes(s.finSlot, sum(s.label+"/fparent"), sum(s.label+"/fstate"), fbody)
	froot, _ := ethl1.HashTreeRootBeaconBlockHeader(fbeacon)
	finBranch := nodes(s.label+"/finbranch", 9)
	state := ethl1.RootFromNormalizedBranch(froot, finBranch, 735)
	aexec := sum(s.label + "/attested-exec")
	abranch := nodes(s.label+"/abranch", 11)
	abody := ethl1.RootFromNormalizedBranch(aexec, abranch, 2856)
	abeacon := beaconBytes(s.attSlot, sum(s.label+"/aparent"), state, abody)

	msg, err := ethl1.SyncCommitteeSigningRoot(abeacon, s.version, s.gvr)
	if err != nil {
		panic(err)
	}
	var sig [96]byte
	if s.identitySig {
		sig[0] = 0xc0
	} else {
		sig = k.sign(msg, s.n)
	}
	out := lcHeaderBytes(abeacon, aexec, abranch)
	out = append(out, lcHeaderBytes(fbeacon, exec, fbranch)...)
	for _, n := range finBranch {
		out = append(out, n[:]...)
	}
	bits := make([]byte, 64)
	for i := 0; i < s.n; i++ {
		bits[i/8] |= 1 << (uint(i) % 8)
	}
	out = append(out, bits...)
	out = append(out, sig[:]...)
	return binary.LittleEndian.AppendUint64(out, s.sigSlot)
}

func (g *gen) synthetic() {
	k := newSynthKeys()
	committee := k.committee512()
	root := sszCommitteeRoot(committee)
	gvr := sum("synthetic-gvr")
	gvrHex := hx(gvr[:])
	rootHex := hx(root[:])
	g.pins["synth"] = pinsFile{
		Format: formatPins, Description: "synthetic network: electra@2000, gloas@2570 (version 0x900000a1), heze@2575 (gloas layout, version 0x900000a2); one anchor, period 10, a 4-key test committee",
		ChainID: "11155111", GVR: gvrHex,
		Forks: []forkFile{
			{"genesis", "0", "0x900000a0", 0}, {"electra", strconv.Itoa(synthElectraE), "0x900000a0", 1},
			{"gloas", strconv.Itoa(synthGloasE), "0x900000a1", 2}, {"heze", strconv.Itoa(synthHezeE), "0x900000a2", 2},
		},
		Anchors:         []anchorFile{{Period: strconv.Itoa(synthPeriod), CommitteeRoot: rootHex, WSPEpochs: strconv.Itoa(wspEpochs)}},
		MinParticipants: minParticipants, MaxLinks: maxLinksPins, MaxSpine: maxSpinePins,
	}
	g.put("pins/synth.json", canonJSON(g.pins["synth"]))
	v := func(h string) [4]byte { var a [4]byte; copy(a[:], []byte{0x90, 0, 0, h[0]}); return a }
	vGloas, vHeze := v("\xa1"), v("\xa2")
	body := ethl1.LB{Layout: ethl1.LayoutNone, SSZ: committee}
	lc := func(final []byte) ethl1.LC {
		return ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: synthPeriod, AnchorRoot: root, AnchorBody: body,
			FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: final}}
	}
	slot := func(epoch, i uint64) uint64 { return epoch*32 + i }
	base := synthSpec{label: "base", attSlot: slot(synthGloasE+2, 5), finSlot: slot(synthGloasE+1, 0), sigSlot: slot(synthGloasE+2, 6), finGindex: 2856, n: 512, version: vGloas, gvr: gvr}
	with := func(label string, f func(*synthSpec)) []byte {
		s := base
		s.label = label
		f(&s)
		return k.final(s)
	}
	ok := func(parts int, crossed int) map[string]string {
		return map[string]string{"participants": strconv.Itoa(parts), "periods_crossed": strconv.Itoa(crossed)}
	}

	g.head("synth_valid_512", "synthetic: 512 of 512 seats under the Gloas version", "synth", lc(with("v512", func(s *synthSpec) {})), "", ok(512, 0))
	g.head("synth_valid_342_exact", "synthetic: exactly 342 seats with a valid signature are accepted", "synth", lc(with("v342", func(s *synthSpec) { s.n = 342 })), "", ok(342, 0))
	g.head("adv_synth_341_valid_signature", "synthetic: 341 seats with a VALID signature are refused by the 342 floor alone", "synth", lc(with("v341", func(s *synthSpec) { s.n = 341 })),
		ethl1.CodeParticipationInsuff, map[string]string{"participants": "341", "required": "342"})
	// a fork boundary lies between the attested slot (last slot of the gloas epoch before heze) and signature_slot-1 (first slot of heze)
	boundary := func(s *synthSpec) {
		s.attSlot, s.sigSlot = slot(synthHezeE-1, 31), slot(synthHezeE, 1)
		s.finSlot = slot(synthGloasE+1, 0)
	}
	g.head("synth_valid_fork_boundary_domain", "synthetic: attested slot in the last epoch before the heze fork, signature_slot-1 in the first heze epoch: the domain version is heze's", "synth",
		lc(with("vfb", func(s *synthSpec) { boundary(s); s.version = vHeze })), "", ok(512, 0))
	g.head("adv_synth_domain_from_attested_epoch", "synthetic: the same update signed under the attested epoch's version (gloas) is refused", "synth",
		lc(with("afb", func(s *synthSpec) { boundary(s); s.version = vGloas })), ethl1.CodeSignatureInvalid, map[string]string{"fork_version": "0x900000a2"})
	g.head("synth_valid_electra_era_finalized_header", "synthetic: a Gloas-shaped update whose finalized header lies in the Electra era is validated at gindex 812 over a zero-extended branch", "synth",
		lc(with("vel", func(s *synthSpec) { s.finSlot = slot(synthElectraE+10, 3); s.finGindex = 812 })), "", ok(512, 0))
	g.head("adv_synth_electra_era_nonzero_extra_node", "synthetic: the same with a non-zero node in the zero-extended part of the finalized branch", "synth",
		lc(with("nzx", func(s *synthSpec) { s.finSlot = slot(synthElectraE+10, 3); s.finGindex = 812; s.finNonZeroXtra = true })),
		ethl1.CodeLinkInvalid, map[string]string{"check": "finalized_header_exec_branch"})
	g.head("adv_synth_finalized_header_in_unsupported_fork", "synthetic: finalized header in an epoch before Electra (no layout): refused as an unsupported fork", "synth",
		lc(with("pre", func(s *synthSpec) { s.finSlot = slot(100, 1); s.finGindex = 812 })), ethl1.CodeForkUnsupported, map[string]string{"epoch": "100", "layout": "gloas"})
	g.head("adv_synth_identity_signature", "synthetic: the point at infinity as the aggregate signature", "synth",
		lc(with("idn", func(s *synthSpec) { s.identitySig = true })), ethl1.CodeSignatureInvalid, nil)
}
