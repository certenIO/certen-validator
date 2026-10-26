// Copyright 2026 Certen Protocol

package ethl1

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// tExec builds an Electra/Deneb ExecutionPayloadHeader (584 fixed bytes, then extra_data) whose every byte is distinct in its
// field, at the SSZ offsets of the consensus specification written out literally here.
func tExec(extra []byte) []byte {
	e := make([]byte, 584)
	for i := range e {
		e[i] = byte(i%251) + 1
	}
	binary.LittleEndian.PutUint32(e[436:], 584)
	return append(e, extra...)
}

func tSha(a, b [32]byte) [32]byte { return sha256.Sum256(append(append([]byte{}, a[:]...), b[:]...)) }

func tMerkle(leaves [][32]byte) [32]byte {
	for len(leaves) > 1 {
		next := make([][32]byte, len(leaves)/2)
		for i := range next {
			next[i] = tSha(leaves[2*i], leaves[2*i+1])
		}
		leaves = next
	}
	return leaves[0]
}

// tExecRoot is hash_tree_root(ExecutionPayloadHeader) from the literal field offsets: 17 fields padded to 32 leaves.
func tExecRoot(e []byte) [32]byte {
	var leaf [32][32]byte
	copy(leaf[0][:], e[0:32])   // parent_hash
	copy(leaf[1][:], e[32:52])  // fee_recipient (20 bytes)
	copy(leaf[2][:], e[52:84])  // state_root
	copy(leaf[3][:], e[84:116]) // receipts_root
	var bloom [][32]byte        // logs_bloom, 256 bytes = 8 chunks
	for i := 0; i < 8; i++ {
		var c [32]byte
		copy(c[:], e[116+32*i:116+32*i+32])
		bloom = append(bloom, c)
	}
	leaf[4] = tMerkle(bloom)
	copy(leaf[5][:], e[372:404]) // prev_randao
	copy(leaf[6][:8], e[404:412])
	copy(leaf[7][:8], e[412:420])
	copy(leaf[8][:8], e[420:428])
	copy(leaf[9][:8], e[428:436])
	extra := e[584:]
	var chunk, length [32]byte
	copy(chunk[:], extra)
	length[0] = byte(len(extra))
	leaf[10] = tSha(chunk, length)
	copy(leaf[11][:], e[440:472]) // base_fee_per_gas
	copy(leaf[12][:], e[472:504]) // block_hash
	copy(leaf[13][:], e[504:536]) // transactions_root
	copy(leaf[14][:], e[536:568]) // withdrawals_root
	copy(leaf[15][:8], e[568:576])
	copy(leaf[16][:8], e[576:584])
	return tMerkle(leaf[:])
}

func TestExecutionHeaderRootHashesEveryFieldAtItsOffset(t *testing.T) {
	for _, extra := range [][]byte{nil, {0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}, tFill(32, 0xcc)} {
		e := tExec(extra)
		if got, want := executionHeaderRoot(e), tExecRoot(e); got != want {
			t.Fatalf("extra_data of %d bytes: %x want %x", len(extra), got, want)
		}
	}
	// every field matters: flipping any single byte of the fixed part changes the root
	base := tExec([]byte{1, 2, 3})
	root := executionHeaderRoot(base)
	for i := 0; i < 584; i++ {
		if i >= 436 && i < 440 {
			continue // the extra_data offset is not hashed (it is checked by decodeElectraHeader)
		}
		m := append([]byte(nil), base...)
		m[i] ^= 0x01
		if executionHeaderRoot(m) == root {
			t.Fatalf("byte %d of the execution header is not hashed", i)
		}
	}
}

func TestDecodeElectraHeaderLengthsOffsetsAndBlockHash(t *testing.T) {
	mk := func(extra []byte) []byte {
		h := make([]byte, 112)
		h = binary.LittleEndian.AppendUint32(h, 244)
		h = append(h, make([]byte, 32*4)...)
		return append(h, tExec(extra)...)
	}
	for _, n := range []int{0, 1, 32} {
		raw := mk(tFill(n, 0x5a))
		h, f := decodeElectraHeader(raw, "p", 3)
		if f != nil || len(raw) != 828+n {
			t.Fatalf("extra of %d bytes: %v (len %d)", n, f, len(raw))
		}
		var wantHash [32]byte
		copy(wantHash[:], tExec(nil)[472:504])
		if h.ExecHash != wantHash || h.Shape != LayoutElectra {
			t.Fatalf("exec hash %x shape %v", h.ExecHash, h.Shape)
		}
	}
	for _, c := range []struct {
		name   string
		raw    []byte
		reason string
		got    int
		want   int
	}{
		{"one byte short", mk(nil)[:827], "header_length", 827, 828},
		{"one byte over the maximum", mk(tFill(33, 1)), "header_length", 861, 828},
	} {
		_, f := decodeElectraHeader(c.raw, "p", 3)
		if f == nil || f.Fields["reason"] != c.reason || f.Fields["got_len"] != c.got || f.Fields["want_len"] != c.want || f.Fields["index"] != 3 || f.Fields["part"] != "p" {
			t.Fatalf("%s: %v", c.name, f)
		}
	}
	bad := mk(nil)
	binary.LittleEndian.PutUint32(bad[112:], 245)
	if _, f := decodeElectraHeader(bad, "p", 0); f == nil || f.Fields["reason"] != "execution_offset" || f.Fields["got_len"] != 245 {
		t.Fatalf("execution offset: %v", f)
	}
	bad = mk(nil)
	binary.LittleEndian.PutUint32(bad[244+436:], 585)
	if _, f := decodeElectraHeader(bad, "p", 0); f == nil || f.Fields["reason"] != "extra_data_offset" || f.Fields["got_len"] != 585 {
		t.Fatalf("extra_data offset: %v", f)
	}
}

func tPat(seed byte, n int) []byte {
	b := make([]byte, n)
	for j := range b {
		b[j] = seed + byte(j%97)
	}
	return b
}

func tElectraHdr(seed byte, number uint64) []byte {
	h := tPat(seed, 112)
	h = binary.LittleEndian.AppendUint32(h, 244)
	h = append(h, tPat(seed+1, 128)...)
	return append(h, tExec([]byte{seed})...)
}

// tBranchOK checks that a decoded branch holds the n consecutive 32-byte nodes of raw.
func tBranchOK(t *testing.T, name string, got [][32]byte, raw []byte, n int) {
	t.Helper()
	if len(got) != n {
		t.Fatalf("%s: %d nodes, want %d", name, len(got), n)
	}
	for i := range got {
		if string(got[i][:]) != string(raw[32*i:32*i+32]) {
			t.Fatalf("%s: node %d differs", name, i)
		}
	}
}

func TestElectraContainersDecodeEveryFieldFromItsOffset(t *testing.T) {
	pr := mainnetPreset()
	committee, cbranch, fbranch := tPat(10, 24624), tPat(50, 6*32), tPat(90, 7*32)
	bits, sig := tPat(130, 64), tPat(170, 96)
	att, fin := tElectraHdr(1, 5), tElectraHdr(2, 6)

	// update: offset | committee | committee branch | finalized offset | finality branch | aggregate | signature slot | headers
	fixed := 4 + 24624 + 6*32 + 4 + 7*32 + 160 + 8
	if fixed != 25216 {
		t.Fatalf("fixed part %d", fixed)
	}
	u := binary.LittleEndian.AppendUint32(nil, uint32(fixed))
	u = append(u, committee...)
	u = append(u, cbranch...)
	u = binary.LittleEndian.AppendUint32(u, uint32(fixed+len(att)))
	u = append(u, fbranch...)
	u = append(u, bits...)
	u = append(u, sig...)
	u = binary.LittleEndian.AppendUint64(u, 0x1122334455667788)
	u = append(u, att...)
	u = append(u, fin...)
	got, f := decodeElectraUpdate(u, 4, pr)
	if f != nil {
		t.Fatal(f)
	}
	if string(got.NextCommittee) != string(committee) || len(got.NextCommittee) != 24624 {
		t.Fatalf("next committee: %d bytes", len(got.NextCommittee))
	}
	tBranchOK(t, "next branch", got.NextBranch, cbranch, 6)
	tBranchOK(t, "finality branch", got.FinalityBranch, fbranch, 7)
	if string(got.Aggregate.Bits) != string(bits) || string(got.Aggregate.Signature[:]) != string(sig) || got.SignatureSlot != 0x1122334455667788 {
		t.Fatalf("aggregate / signature slot misread: %d bits bytes, slot %x", len(got.Aggregate.Bits), got.SignatureSlot)
	}
	if got.Attested.Exec[404-0] != att[244+404] || got.Finalized.Exec[0] != fin[244] || !got.hasNextContainer {
		t.Fatal("attested / finalized headers misplaced")
	}

	// finality update: offset | finalized offset | finality branch | aggregate | signature slot | headers
	ffixed := 4 + 4 + 7*32 + 160 + 8
	if ffixed != 400 {
		t.Fatalf("fixed part %d", ffixed)
	}
	fu := binary.LittleEndian.AppendUint32(nil, uint32(ffixed))
	fu = binary.LittleEndian.AppendUint32(fu, uint32(ffixed+len(att)))
	fu = append(fu, fbranch...)
	fu = append(fu, bits...)
	fu = append(fu, sig...)
	fu = binary.LittleEndian.AppendUint64(fu, 0x0102030405060708)
	fu = append(fu, att...)
	fu = append(fu, fin...)
	gf, f := decodeElectraFinalityUpdate(fu, pr)
	if f != nil {
		t.Fatal(f)
	}
	tBranchOK(t, "final finality branch", gf.FinalityBranch, fbranch, 7)
	if string(gf.Aggregate.Bits) != string(bits) || string(gf.Aggregate.Signature[:]) != string(sig) || gf.SignatureSlot != 0x0102030405060708 {
		t.Fatalf("final aggregate misread: slot %x", gf.SignatureSlot)
	}
	// bootstrap: offset | committee | branch | header
	bfixed := 4 + 24624 + 6*32
	bs := binary.LittleEndian.AppendUint32(nil, uint32(bfixed))
	bs = append(bs, committee...)
	bs = append(bs, cbranch...)
	bs = append(bs, att...)
	bo, f := decodeElectraBootstrap(bs, pr)
	if f != nil {
		t.Fatal(f)
	}
	if string(bo.Committee) != string(committee) || len(bo.Committee) != 24624 {
		t.Fatalf("bootstrap committee: %d bytes", len(bo.Committee))
	}
	tBranchOK(t, "bootstrap branch", bo.CommitteeBranch, cbranch, 6)
}
