// Copyright 2026 Certen Protocol

package baseposted

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

type postedWire struct {
	lim  finality.Limits
	ep   ethl1.Pins
	body Body // the live evidence A body (its LC part is a real one)
}

func loadPostedWire(t *testing.T) postedWire {
	t.Helper()
	set := filepath.Join("testdata", SetName)
	pinsRaw, _ := ReadFile(set, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := ReadFile(set, "evidence/valid_a.bin")
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	ep := EthL1Pins(pins)
	body, err := DecodeBody(c.Body, finality.DefaultLimits(), ep, 32)
	if err != nil {
		t.Fatal(err)
	}
	return postedWire{lim: finality.DefaultLimits(), ep: ep, body: body}
}

// small is a body with the live LC part and one frame carrying one (empty) blob, every other list short.
func (w postedWire) small() Body {
	return Body{LC: w.body.LC, L1Spine: [][]byte{{1}, {2}}, ChannelID: [16]byte{3},
		Frames:   []FrameTx{{L1Block: 5, TxIndex: 2, TxRaw: []byte{9, 9}, Blobs: []Blob{{Raw: make([]byte, BlobSize)}}}},
		Deposits: [][]byte{{7}, {8}}, Nodes: [][]byte{{1}, {2}}}
}

func TestEveryCutOfTheBodyNamesThePartThatRanShortInWireOrder(t *testing.T) {
	w := loadPostedWire(t)
	enc := EncodeBody(w.small())
	if _, err := DecodeBody(enc, w.lim, w.ep, 32); err != nil {
		t.Fatalf("the small body must decode: %v", err)
	}
	// the blob's 131072 bytes end before its commitment (48), proof (48), the two deposits (4+2*5) and the two nodes (4+2*5)
	rawEnd := len(enc) - (48 + 48 + 14 + 14)
	rawStart := rawEnd - BlobSize
	var seen []string
	for cut := 0; cut < len(enc); cut++ {
		// inside the 131072 bytes of the blob only every 997th cut is tried (the part cannot change inside it)
		if cut > rawStart+8 && cut < rawEnd-8 && cut%997 != 0 {
			continue
		}
		_, err := DecodeBody(enc[:cut], w.lim, w.ep, 32)
		se, ok := finality.AsNamed(err)
		if !ok {
			t.Fatalf("cut %d: not a named state: %v", cut, err)
		}
		part := strings.TrimSuffix(fmt.Sprint(se.Fields["part"]), ".len")
		if len(seen) == 0 || seen[len(seen)-1] != part {
			seen = append(seen, part)
		}
	}
	want := []string{"lc.profile", "lc.anchorKind", "lc.anchorPeriod", "lc.anchorRoot", "lc.anchorBody.layout", "lc.anchorBody", "lc.links.count",
		"lc.finalUpdate.layout", "lc.finalUpdate", "l1Spine.count", "l1Spine", "channelId", "frameTxs.count", "frameTxs",
		"frameTx.blobs.count", "frameTx.blobs", "blob.raw", "blob.commitment", "blob.proof", "depositTxs.count", "depositTxs", "nodes.count", "nodes"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("parts in order\n got  %v\n want %v", seen, want)
	}
}

// While the count of frames is checked against the bytes left (20 per frame at least), a frame is cut short only when an earlier frame
// took the bytes: the second of two frames, after a first one with a 20-byte txRaw, is cut at every length up to its minimum.
func TestACutInsideALaterFrameNamesTheFieldThatRanShort(t *testing.T) {
	w := loadPostedWire(t)
	var empty Body
	empty.LC, empty.L1Spine = w.body.LC, [][]byte{{1}}
	base := EncodeBody(empty)
	head := append([]byte(nil), base[:len(base)-12]...)
	head = append(head, 0, 0, 0, 2)           // two frames
	head = append(head, make([]byte, 8+4)...) // l1Block, txIndex
	head = append(head, 0, 0, 0, 20)          // txRaw of 20 bytes
	head = append(head, make([]byte, 20)...)  //
	head = append(head, 0, 0, 0, 0)           // no blobs
	for j := 0; j <= 20; j++ {
		want := "depositTxs.count"
		switch {
		case j < 8:
			want = "frameTx.l1Block"
		case j < 12:
			want = "frameTx.txIndex"
		case j < 16:
			want = "frameTx.txRaw"
		case j < 20:
			want = "frameTx.blobs.count"
		}
		_, err := DecodeBody(append(append([]byte(nil), head...), make([]byte, j)...), w.lim, w.ep, 32)
		se, ok := finality.AsNamed(err)
		if !ok || strings.TrimSuffix(fmt.Sprint(se.Fields["part"]), ".len") != want {
			t.Errorf("second frame cut at %d bytes: %v, want %s", j, err, want)
		}
	}
}

func TestTheBodyCountsAreBoundedByTheirPinsAndByWhatTheRemainingBytesCanHold(t *testing.T) {
	w := loadPostedWire(t)
	items := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = []byte{1}
		}
		return out
	}
	tooLarge := func(what string, err error, part, count, limit string) {
		t.Helper()
		wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": part, "count": count, "limit": limit})
		_ = what
	}
	// L1 spine: bounded by the smaller of the Sepolia pin and the framework limit; an unset pin is the limit
	s2 := w.small()
	s2.L1Spine = items(2)
	ep := w.ep
	ep.MaxSpineHeaders = 1
	_, err := DecodeBody(EncodeBody(s2), w.lim, ep, 32)
	tooLarge("l1 pin 1", err, "l1Spine", "2", "1")
	ep.MaxSpineHeaders = 2
	if _, err = DecodeBody(EncodeBody(s2), w.lim, ep, 32); err != nil {
		t.Fatalf("l1 pin 2 admits 2: %v", err)
	}
	over := w.small()
	over.L1Spine = items(w.lim.MaxSpineHeaders + 1)
	for _, pin := range []int{w.lim.MaxSpineHeaders + 1, 1 << 30, 0, -1} {
		ep.MaxSpineHeaders = pin
		_, err = DecodeBody(EncodeBody(over), w.lim, ep, 32)
		tooLarge(fmt.Sprintf("l1 pin %d", pin), err, "l1Spine", fmt.Sprint(w.lim.MaxSpineHeaders+1), fmt.Sprint(w.lim.MaxSpineHeaders))
	}
	sat := w.small()
	sat.L1Spine = items(w.lim.MaxSpineHeaders)
	for _, pin := range []int{w.lim.MaxSpineHeaders, 0, -1} {
		ep.MaxSpineHeaders = pin
		if _, err = DecodeBody(EncodeBody(sat), w.lim, ep, 32); err != nil {
			t.Fatalf("l1 pin %d admits exactly the limit: %v", pin, err)
		}
	}
	// the total of blobs over all frames is bounded by the pin, each frame's count by it too
	three := func() []Blob {
		return []Blob{{Raw: make([]byte, BlobSize)}, {Raw: make([]byte, BlobSize)}, {Raw: make([]byte, BlobSize)}}
	}
	two := w.small()
	two.Frames = []FrameTx{{L1Block: 5, TxIndex: 0, TxRaw: []byte{9}, Blobs: three()}, {L1Block: 5, TxIndex: 1, TxRaw: []byte{9}, Blobs: three()}}
	if _, err = DecodeBody(EncodeBody(two), w.lim, w.ep, 6); err != nil {
		t.Fatalf("six blobs under a pin of 6: %v", err)
	}
	_, err = DecodeBody(EncodeBody(two), w.lim, w.ep, 5)
	tooLarge("blobs total", err, "blobs", "6", "5")
	_, err = DecodeBody(EncodeBody(two), w.lim, w.ep, 2)
	tooLarge("blobs in one frame", err, "frameTx.blobs", "3", "2")
}

// A count is refused when the bytes after it cannot hold that many of the smallest element, before any element is read.
func TestACountThatTheRemainingBytesCannotHoldIsRefusedBeforeItsElementsAreRead(t *testing.T) {
	w := loadPostedWire(t)
	var empty Body
	empty.LC, empty.L1Spine = w.body.LC, [][]byte{{1}}
	// with no frames, deposits or nodes the tail is the three u32 counts: [frames][deposits][nodes]
	base := EncodeBody(empty)
	tail := len(base) - 12
	frameCount := func(n uint32, filler int) []byte {
		out := append([]byte(nil), base[:tail]...)
		out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		return append(out, make([]byte, filler)...)
	}
	// one frame needs at least 8+4+4+4 = 20 bytes: 19 are not enough, so the count itself is refused
	_, err := DecodeBody(frameCount(1, 19), w.lim, w.ep, 32)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "frameTxs", "reason": string(finality.ReasonCountExceedsRemaining)})
	// 20 bytes of zeros are enough for the count; the frame is then read and its first fields are zero (a txRaw of length 0 and no blobs
	// would be a valid frame, but the deposit and node counts that must follow are missing)
	_, err = DecodeBody(frameCount(1, 20), w.lim, w.ep, 32)
	if se, ok := finality.AsNamed(err); !ok || se.Fields["part"] == "frameTxs" {
		t.Fatalf("20 bytes hold one frame: %v", err)
	}
	// a frame's blobs: each needs 4+48+48 = 100 bytes, so a count of 1 with 99 bytes after it is refused as a count
	frame := func(blobCount uint32, filler int) []byte {
		out := frameCount(1, 0)
		out = append(out, make([]byte, 8+4)...) // l1Block, txIndex
		out = append(out, 0, 0, 0, 0)           // txRaw of length 0
		out = append(out, byte(blobCount>>24), byte(blobCount>>16), byte(blobCount>>8), byte(blobCount))
		return append(out, make([]byte, filler)...)
	}
	_, err = DecodeBody(frame(1, 99), w.lim, w.ep, 32)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "frameTx.blobs", "reason": string(finality.ReasonCountExceedsRemaining)})
	_, err = DecodeBody(frame(1, 100), w.lim, w.ep, 32)
	if se, ok := finality.AsNamed(err); !ok || se.Fields["part"] == "frameTx.blobs" {
		t.Fatalf("100 bytes hold one blob entry's fixed part: %v", err)
	}
}

func TestTheLCExtentWalksEveryLinkAndNamesTheOneThatRunsShort(t *testing.T) {
	lim := finality.DefaultLimits()
	lc := ethl1.LC{Profile: "p", AnchorKind: 1, AnchorPeriod: 7, AnchorBody: ethl1.LB{Layout: 1, SSZ: []byte{1, 2, 3}},
		Links:       []ethl1.LB{{Layout: 1, SSZ: []byte{4, 5}}, {Layout: 2, SSZ: []byte{6}}},
		FinalUpdate: ethl1.LB{Layout: 2, SSZ: []byte{7, 8, 9, 10}}}
	enc := ethl1.EncodeLC(lc)
	n, err := lcExtent(append(append([]byte(nil), enc...), 0xee, 0xee), lim, 64)
	if err != nil || n != len(enc) {
		t.Fatalf("extent %d, %v; want %d", n, err, len(enc))
	}
	_, err = lcExtent(enc, lim, 1)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "lc.links", "count": "2", "limit": "1"})
	for cut := len(enc) - (1 + 4 + 4) - (1 + 4 + 1); cut < len(enc)-(1+4+4); cut++ {
		_, err = lcExtent(enc[:cut], lim, 64)
		se, ok := finality.AsNamed(err)
		part := ""
		if ok {
			part = strings.TrimSuffix(fmt.Sprint(se.Fields["part"]), ".len")
		}
		if !ok || (part != "lc.links.layout" && part != "lc.links") {
			t.Fatalf("cut %d inside the second link: %v", cut, err)
		}
	}
}
