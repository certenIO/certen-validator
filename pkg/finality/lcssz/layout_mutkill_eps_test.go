// Copyright 2026 Certen Protocol

package lcssz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// RB12 EPSILON stage 2 (EPS-MUTKILL-1): every function of this package is checked against objects whose every byte is distinct from its
// neighbours (period 251, never zero), with the expected bytes written from the SSZ layouts as literal numbers. A slice that starts or ends
// one byte away, a constant that changed, an arithmetic sign, an offset that moved and a flag that flipped all give a different answer.

func mkPat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%251 + 1)
	}
	return b
}

func mkLE32(v int) []byte          { return binary.LittleEndian.AppendUint32(nil, uint32(v)) }
func mkLE64(v uint64) []byte       { return binary.LittleEndian.AppendUint64(nil, v) }
func mkCat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// mkElectraUpdate is an electra-layout LightClientUpdate: attested header attLen bytes, finalized header finLen bytes, offsets set.
func mkElectraUpdate(attLen, finLen int) []byte {
	u := mkPat(25216 + attLen + finLen)
	copy(u[0:], mkLE32(25216))
	copy(u[24820:], mkLE32(25216+attLen))
	return u
}

// mkElectraFU is an electra-layout LightClientFinalityUpdate of n bytes with the attested header at 400 and the finalized one at finOff.
func mkElectraFU(n, finOff int) []byte {
	fu := mkPat(n)
	copy(fu[0:], mkLE32(400))
	copy(fu[4:], mkLE32(finOff))
	return fu
}

func TestLayoutConstantsAreTheSpecNumbers(t *testing.T) {
	for name, c := range map[string][2]int{
		"CommitteeBytes":             {CommitteeBytes, 24624},
		"beaconHeader":               {beaconHeader, 112},
		"aggregate":                  {aggregate, 160},
		"gloasNextBranch":            {gloasNextBranch, 352},
		"gloasFinalityBranch":        {gloasFinalityBranch, 288},
		"gloasHeader":                {gloasHeader, 496},
		"electraUpdateFixed":         {electraUpdateFixed, 25216},
		"electraFinalityUpdateFixed": {electraFinalityUpdateFixed, 400},
		"electraBootstrapFixed":      {electraBootstrapFixed, 24820},
		"electraHeaderFixed":         {electraHeaderFixed, 244},
		"electraExecFixed":           {electraExecFixed, 584},
		"GloasUpdateSize":            {GloasUpdateSize, 26424},
		"GloasFinalityUpdateSize":    {GloasFinalityUpdateSize, 1448},
		"GloasBootstrapSize":         {GloasBootstrapSize, 25472},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, the SSZ layout says %d", name, c[0], c[1])
		}
	}
	// The Gloas objects are the sum of their parts.
	if 2*496+288+168 != GloasFinalityUpdateSize || 496+24624+352+496+288+168 != GloasUpdateSize || 496+24624+352 != GloasBootstrapSize {
		t.Error("the Gloas sizes are not the sum of their parts")
	}
}

func TestLayoutIsDecidedByTheExactGloasSizeAlone(t *testing.T) {
	for _, c := range []struct {
		name string
		fn   func([]byte) Layout
		size int
	}{
		{"update", LayoutOfUpdate, 26424},
		{"finality update", LayoutOfFinalityUpdate, 1448},
		{"bootstrap", LayoutOfBootstrap, 25472},
	} {
		if got := c.fn(make([]byte, c.size)); got != Gloas {
			t.Errorf("%s of %d bytes = layout %d, want gloas", c.name, c.size, got)
		}
		for _, n := range []int{0, c.size - 1, c.size + 1, 26424 + 1448 + 25472 - c.size} {
			if n == c.size {
				continue
			}
			if got := c.fn(make([]byte, n)); got != Electra {
				t.Errorf("%s of %d bytes = layout %d, want electra", c.name, n, got)
			}
		}
	}
}

func TestCommitteesAreSlicedFromTheirExactPlaceAndTheSizeBoundsAreExact(t *testing.T) {
	type fn func(Layout, []byte) ([]byte, error)
	for _, c := range []struct {
		name         string
		fn           fn
		electraFixed int
		gloasSize    int
	}{
		{"NextCommittee", NextCommittee, 25216, 26424},
		{"BootstrapCommittee", BootstrapCommittee, 24820, 25472},
	} {
		// Electra: the committee follows the 4-byte offset; exactly the fixed size is accepted, one less is refused.
		for _, n := range []int{c.electraFixed, c.electraFixed + 7} {
			b := mkPat(n)
			got, err := c.fn(Electra, b)
			if err != nil || !bytes.Equal(got, b[4:24628]) || len(got) != 24624 {
				t.Errorf("%s electra %d bytes: err %v, committee wrong (len %d)", c.name, n, err, len(got))
			}
		}
		if got, err := c.fn(Electra, mkPat(c.electraFixed-1)); err == nil || got != nil {
			t.Errorf("%s electra one byte short was not refused: %v", c.name, err)
		}
		// Gloas: the committee follows the 496-byte header; only the exact size is accepted.
		b := mkPat(c.gloasSize)
		got, err := c.fn(Gloas, b)
		if err != nil || !bytes.Equal(got, b[496:25120]) || len(got) != 24624 {
			t.Errorf("%s gloas: err %v, committee wrong (len %d)", c.name, err, len(got))
		}
		for _, n := range []int{c.gloasSize - 1, c.gloasSize + 1} {
			if got, err := c.fn(Gloas, mkPat(n)); err == nil || got != nil {
				t.Errorf("%s gloas %d bytes was not refused: %v", c.name, n, err)
			}
		}
		for _, l := range []Layout{0, 3} {
			if got, err := c.fn(l, mkPat(c.gloasSize)); err == nil || got != nil {
				t.Errorf("%s layout %d was not refused: %v", c.name, l, err)
			}
		}
	}
}

func TestGloasUpdateProjectsToItsFinalityUpdateByteForByte(t *testing.T) {
	u := mkPat(26424)
	want := mkCat(u[:496], u[25472:25968], u[25968:26256], u[26256:])
	got, err := UpdateToFinalityUpdate(Gloas, u)
	if err != nil || len(got) != 1448 || !bytes.Equal(got, want) {
		t.Fatalf("gloas projection: err %v len %d, equal %v", err, len(got), bytes.Equal(got, want))
	}
	for _, n := range []int{26423, 26425, 0} {
		if _, err := UpdateToFinalityUpdate(Gloas, mkPat(n)); err == nil {
			t.Errorf("gloas update of %d bytes was not refused", n)
		}
	}
}

func TestElectraUpdateProjectsToItsFinalityUpdateByteForByte(t *testing.T) {
	// Several header sizes, including an attested header larger than the whole fixed part of the result (the capacity must not go negative).
	for _, c := range []struct{ att, fin int }{{828, 828}, {300, 500}, {1000, 10}, {1, 1}, {0, 0}, {5, 0}, {0, 5}} {
		u := mkElectraUpdate(c.att, c.fin)
		want := mkCat(mkLE32(400), mkLE32(400+c.att), u[24824:25216], u[25216:25216+c.att], u[25216+c.att:])
		got, err := UpdateToFinalityUpdate(Electra, u)
		if err != nil || len(got) != 400+c.att+c.fin || !bytes.Equal(got, want) {
			t.Errorf("electra projection att %d fin %d: err %v len %d, equal %v", c.att, c.fin, err, len(got), bytes.Equal(got, want))
		}
	}
}

func TestElectraProjectionRefusesAnyOffsetThatDoesNotFit(t *testing.T) {
	good := mkElectraUpdate(100, 100) // len 25416: attOff 25216, finOff 25316
	if _, err := UpdateToFinalityUpdate(Electra, good[:25215]); err == nil {
		t.Error("an update one byte shorter than the fixed part was accepted")
	}
	badAtt := bytes.Clone(good)
	copy(badAtt[0:], mkLE32(25215))
	if _, err := UpdateToFinalityUpdate(Electra, badAtt); err == nil {
		t.Error("an attested offset other than the fixed size was accepted")
	}
	badAtt2 := bytes.Clone(good)
	copy(badAtt2[0:], mkLE32(25217))
	if _, err := UpdateToFinalityUpdate(Electra, badAtt2); err == nil {
		t.Error("an attested offset past the fixed size was accepted")
	}
	before := bytes.Clone(good)
	copy(before[24820:], mkLE32(25215)) // finalized offset one below the attested one
	if _, err := UpdateToFinalityUpdate(Electra, before); err == nil {
		t.Error("a finalized offset below the attested offset was accepted")
	}
	past := bytes.Clone(good)
	copy(past[24820:], mkLE32(len(good)+1))
	if _, err := UpdateToFinalityUpdate(Electra, past); err == nil {
		t.Error("a finalized offset past the end was accepted")
	}
	// A finalized offset exactly at the attested offset (empty attested header) and exactly at the end (empty finalized header) fit.
	for _, off := range []int{25216, len(good)} {
		ok := bytes.Clone(good)
		copy(ok[24820:], mkLE32(off))
		got, err := UpdateToFinalityUpdate(Electra, ok)
		if err != nil || len(got) != len(ok)-25216+400 {
			t.Errorf("finalized offset %d: err %v len %d", off, err, len(got))
		}
	}
	if _, err := UpdateToFinalityUpdate(Layout(0), good); err == nil {
		t.Error("an unknown layout was accepted")
	}
}

func TestFinalityUpdateSlotsReadsEachSlotFromItsPlace(t *testing.T) {
	// Gloas: attested slot at 0, finalized slot at 496, signature slot in the last 8 bytes.
	g := mkPat(1448)
	copy(g[0:], mkLE64(0x1111))
	copy(g[496:], mkLE64(0x2222))
	copy(g[1440:], mkLE64(0x3333))
	a, f, s, err := FinalityUpdateSlots(Gloas, g)
	if err != nil || a != 0x1111 || f != 0x2222 || s != 0x3333 {
		t.Errorf("gloas slots (%x,%x,%x) %v", a, f, s, err)
	}
	for _, n := range []int{1447, 1449} {
		if _, _, _, err := FinalityUpdateSlots(Gloas, mkPat(n)); err == nil {
			t.Errorf("gloas finality update of %d bytes was accepted", n)
		}
	}
	// Electra: attested slot at 400, finalized slot at finOff, signature slot at 392.
	e := mkElectraFU(2056, 1228)
	copy(e[400:], mkLE64(0x4444))
	copy(e[1228:], mkLE64(0x5555))
	copy(e[392:], mkLE64(0x6666))
	a, f, s, err = FinalityUpdateSlots(Electra, e)
	if err != nil || a != 0x4444 || f != 0x5555 || s != 0x6666 {
		t.Errorf("electra slots (%x,%x,%x) %v", a, f, s, err)
	}
	if _, _, _, err := FinalityUpdateSlots(Electra, mkElectraFU(2055, 1228)); err == nil {
		t.Error("an electra finality update below the minimum size was accepted")
	}
	if _, _, _, err := FinalityUpdateSlots(Layout(9), e); err == nil {
		t.Error("an unknown layout was accepted")
	}
}

func TestUpdateSlotsReadsTheSlotsOfTheProjectionAndRefusesWhatDoesNotProject(t *testing.T) {
	// Gloas update: attested at 0, finalized at 25472, signature slot in the last 8 bytes.
	g := mkPat(26424)
	copy(g[0:], mkLE64(0xA1))
	copy(g[25472:], mkLE64(0xA2))
	copy(g[26416:], mkLE64(0xA3))
	a, f, s, err := UpdateSlots(Gloas, g)
	if err != nil || a != 0xA1 || f != 0xA2 || s != 0xA3 {
		t.Errorf("gloas update slots (%x,%x,%x) %v", a, f, s, err)
	}
	// Electra update: attested header at 25216, finalized header 828 bytes later, signature slot at 25208.
	e := mkElectraUpdate(828, 828)
	copy(e[25216:], mkLE64(0xB1))
	copy(e[25216+828:], mkLE64(0xB2))
	copy(e[25208:], mkLE64(0xB3))
	a, f, s, err = UpdateSlots(Electra, e)
	if err != nil || a != 0xB1 || f != 0xB2 || s != 0xB3 {
		t.Errorf("electra update slots (%x,%x,%x) %v", a, f, s, err)
	}
	// An update that does not project is an error with zero slots, not the slots of nothing.
	if a, f, s, err := UpdateSlots(Gloas, mkPat(26423)); err == nil || a != 0 || f != 0 || s != 0 || !strings.Contains(err.Error(), "a gloas update is 26424 bytes, got 26423") {
		t.Errorf("a short gloas update gave (%x,%x,%x) %v", a, f, s, err)
	}
	if a, f, s, err := UpdateSlots(Electra, mkPat(25215)); err == nil || a != 0 || f != 0 || s != 0 || !strings.Contains(err.Error(), "an electra update is at least 25216 bytes, got 25215") {
		t.Errorf("a short electra update gave (%x,%x,%x) %v", a, f, s, err)
	}
	// An update that projects to a finality update too small to read slots from is refused by the slot reader.
	if _, _, _, err := UpdateSlots(Electra, mkElectraUpdate(10, 10)); err == nil {
		t.Error("a projection below the minimum finality update size gave slots")
	}
}

func TestFinalizedExecOfAGloasUpdateIsTheHashAtItsPlaceWithNoNumber(t *testing.T) {
	fu := mkPat(1448)
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(0xC0 + i)
	}
	copy(fu[496+112:], want)
	hash, number, has, err := FinalizedExec(Gloas, fu)
	if err != nil || has || number != 0 || !bytes.Equal(hash[:], want) {
		t.Fatalf("gloas exec: hash %x number %d has %v err %v", hash, number, has, err)
	}
	for _, n := range []int{1447, 1449} {
		hash, number, has, err := FinalizedExec(Gloas, mkPat(n))
		if err == nil || has || number != 0 || hash != ([32]byte{}) {
			t.Errorf("gloas finality update of %d bytes: hash %x number %d has %v err %v", n, hash, number, has, err)
		}
	}
}

func TestFinalizedExecOfAnElectraUpdateIsTheHashAndNumberAtTheirPlace(t *testing.T) {
	fu := mkElectraFU(2056, 1228)
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(0xD0 + i)
	}
	copy(fu[1228+244+472:], want)
	copy(fu[1228+244+404:], mkLE64(0xE5E5))
	hash, number, has, err := FinalizedExec(Electra, fu)
	if err != nil || !has || number != 0xE5E5 || !bytes.Equal(hash[:], want) {
		t.Fatalf("electra exec: hash %x number %x has %v err %v", hash, number, has, err)
	}

	// An update that FinalityUpdateSlots refuses is refused, with no number reported and no hash.
	hash, number, has, err = FinalizedExec(Electra, mkElectraFU(2055, 1228))
	if err == nil || has || number != 0 || hash != ([32]byte{}) || errors.Is(err, ErrFinalizedHeaderTooShort) {
		t.Errorf("a too-small electra finality update: hash %x number %d has %v err %v", hash, number, has, err)
	}

	// A finalized header that begins one byte too late to hold the execution payload header's fixed part is the named error, and the
	// message says how many bytes there are, where, and how many are needed.
	late := mkElectraFU(2056, 1229)
	hash, number, has, err = FinalizedExec(Electra, late)
	if !errors.Is(err, ErrFinalizedHeaderTooShort) || has || number != 0 || hash != ([32]byte{}) {
		t.Fatalf("a finalized header one byte late: hash %x number %d has %v err %v", hash, number, has, err)
	}
	if got, want := err.Error(), "lcssz: the finalized header is too short for an execution payload header: 827 bytes at offset 1229, need 828"; got != want {
		t.Errorf("the refusal says %q, want %q", got, want)
	}

	// An unknown layout is refused with no number.
	hash, number, has, err = FinalizedExec(Layout(9), fu)
	if err == nil || has || number != 0 || hash != ([32]byte{}) {
		t.Errorf("unknown layout: hash %x number %d has %v err %v", hash, number, has, err)
	}
}

func mkFrame(digest [4]byte, obj []byte) []byte {
	return mkCat(mkLE64(uint64(4+len(obj))), digest[:], obj)
}

func TestSplitFramedUpdatesSplitsEveryFrameAtItsExactBytes(t *testing.T) {
	d1, d2, d3 := [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, [4]byte{9, 10, 11, 12}
	o1, o2, o3 := mkPat(30), mkPat(1), []byte{}
	body := mkCat(mkFrame(d1, o1), mkFrame(d2, o2), mkFrame(d3, o3))
	objs, digests, err := SplitFramedUpdates(body)
	if err != nil || len(objs) != 3 || len(digests) != 3 {
		t.Fatalf("split: %d objects %d digests err %v", len(objs), len(digests), err)
	}
	for i, want := range []struct {
		d [4]byte
		o []byte
	}{{d1, o1}, {d2, o2}, {d3, o3}} {
		if digests[i] != want.d || !bytes.Equal(objs[i], want.o) || len(objs[i]) != len(want.o) {
			t.Errorf("frame %d: digest %v object %x, want %v %x", i, digests[i], objs[i], want.d, want.o)
		}
	}
	// An empty body holds no frames and is not an error.
	if objs, digests, err := SplitFramedUpdates(nil); err != nil || len(objs) != 0 || len(digests) != 0 {
		t.Errorf("empty body: %d %d %v", len(objs), len(digests), err)
	}
	// A frame of exactly 12 bytes (length 4, digest, empty object) fits.
	if objs, _, err := SplitFramedUpdates(mkFrame(d1, nil)); err != nil || len(objs) != 1 || len(objs[0]) != 0 {
		t.Errorf("a 12-byte frame: %d objects, err %v", len(objs), err)
	}
}

func TestSplitFramedUpdatesRefusesWhatDoesNotFrame(t *testing.T) {
	d := [4]byte{1, 2, 3, 4}
	good := mkFrame(d, mkPat(20)) // 8 + 4 + 20 = 32 bytes
	for _, c := range []struct {
		name string
		body []byte
		want string
	}{
		{"11 bytes cannot hold a length and a digest", mkPat(11), "truncated at 0"},
		{"a trailing fragment shorter than a header", mkCat(good, mkPat(11)), "truncated at 32"},
		{"a length below the 4-byte digest", mkCat(mkLE64(3), mkPat(8)), "length 3 at 0 overruns"},
		{"a length one past what is left", mkCat(mkLE64(25), d[:], mkPat(20)), "length 25 at 0 overruns"},
		{"a length of 2^64-1", mkCat(mkLE64(1<<64-1), d[:], mkPat(20)), "overruns"},
		{"a second frame that overruns", mkCat(good, mkLE64(40), d[:], mkPat(8)), "length 40 at 32 overruns"},
	} {
		objs, digests, err := SplitFramedUpdates(c.body)
		if err == nil || objs != nil || digests != nil || !bytes.Contains([]byte(err.Error()), []byte(c.want)) {
			t.Errorf("%s: %d objects, err %v, want an error containing %q", c.name, len(objs), err, c.want)
		}
	}
	// The length exactly equal to what is left is the last frame.
	if objs, _, err := SplitFramedUpdates(mkCat(mkLE64(24), d[:], mkPat(20))); err != nil || len(objs) != 1 || len(objs[0]) != 20 {
		t.Errorf("an exact-fit frame: %d objects, err %v", len(objs), err)
	}
}

func TestFinalityUpdateParticipantsCountsOnlyTheCommitteeBits(t *testing.T) {
	for _, c := range []struct {
		name string
		l    Layout
		size int
		at   int
	}{
		{"gloas", Gloas, 1448, 1280},
		{"electra", Electra, 400, 232},
		{"electra longer", Electra, 2056, 232},
	} {
		fu := make([]byte, c.size)
		// Bits just outside the 64-byte window are never counted.
		fu[c.at-1], fu[c.at+64] = 0xFF, 0xFF
		got, err := FinalityUpdateParticipants(c.l, fu)
		if err != nil || got != 0 {
			t.Errorf("%s: no bits set gave %d, %v", c.name, got, err)
		}
		// Single bits and full bytes at the first byte, a middle byte and the last byte of the window.
		fu[c.at] = 0x01
		fu[c.at+31] = 0x80
		fu[c.at+63] = 0xFF
		fu[c.at+10] = 0x0A
		fu[c.at+11] = 0x7F
		got, err = FinalityUpdateParticipants(c.l, fu)
		if err != nil || got != 1+1+8+2+7 {
			t.Errorf("%s: counted %d, want 19 (err %v)", c.name, got, err)
		}
		for i := 0; i < 64; i++ {
			fu[c.at+i] = 0xFF
		}
		if got, err = FinalityUpdateParticipants(c.l, fu); err != nil || got != 512 {
			t.Errorf("%s: all bits set counted %d, want 512 (err %v)", c.name, got, err)
		}
	}
	// Size bounds: exactly the fixed size of an electra finality update is accepted, one byte less is not; Gloas is exact.
	if _, err := FinalityUpdateParticipants(Electra, make([]byte, 400)); err != nil {
		t.Errorf("electra finality update of exactly 400 bytes: %v", err)
	}
	if n, err := FinalityUpdateParticipants(Electra, make([]byte, 399)); err == nil || n != 0 {
		t.Errorf("electra finality update of 399 bytes: %d %v", n, err)
	}
	for _, n := range []int{1447, 1449} {
		if got, err := FinalityUpdateParticipants(Gloas, make([]byte, n)); err == nil || got != 0 {
			t.Errorf("gloas finality update of %d bytes: %d %v", n, got, err)
		}
	}
	if got, err := FinalityUpdateParticipants(Layout(0), make([]byte, 1448)); err == nil || got != 0 {
		t.Errorf("unknown layout: %d %v", got, err)
	}
}
