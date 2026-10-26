// Copyright 2026 Certen Protocol

package ethl1

import (
	"fmt"
	"testing"
)

func lcSample(nLinks int) LC {
	lc := LC{Profile: ProfileLC, AnchorKind: 2, AnchorPeriod: 0x0102030405060708, AnchorBody: LB{Layout: LayoutGloas, SSZ: []byte{1, 2, 3}}, FinalUpdate: LB{Layout: LayoutElectra, SSZ: []byte{7, 8, 9}}}
	for i := 0; i < nLinks; i++ {
		lc.Links = append(lc.Links, LB{Layout: LayoutGloas, SSZ: []byte{byte(10 + i), byte(20 + i), byte(30 + i)}})
	}
	lc.AnchorRoot[0], lc.AnchorRoot[31] = 0xaa, 0xbb
	return lc
}

// TestDecodeLCNamesTheFieldAndTheShortfallOfEveryTruncation cuts a two-link container at every byte and expects the part, the
// bytes that were there and the bytes the field needs, from a literal table of the container's regions.
func TestDecodeLCNamesTheFieldAndTheShortfallOfEveryTruncation(t *testing.T) {
	b := EncodeLC(lcSample(2))
	if len(b) != 89 {
		t.Fatalf("encoded container is %d bytes, the region table below assumes 89", len(b))
	}
	regions := []struct {
		part        string
		start, need int
	}{
		{"profile", 0, 4}, {"profile", 4, 8}, {"anchor", 12, 41},
		{"anchor_body", 53, 1}, {"anchor_body", 54, 4}, {"anchor_body", 58, 3},
		{"links", 61, 4},
		{"link", 65, 1}, {"link", 66, 4}, {"link", 70, 3},
		{"link", 73, 1}, {"link", 74, 4}, {"link", 78, 3},
		{"final_update", 81, 1}, {"final_update", 82, 4}, {"final_update", 86, 3},
	}
	for cut := 0; cut < len(b); cut++ {
		var want string
		for _, r := range regions {
			if r.start+r.need > cut {
				want = fmt.Sprintf(`{"code":"finality_evidence_malformed","fields":{"got_len":"%d","index":"0","part":%q,"reason":"truncated","want_len":"%d"}}`, cut-r.start, r.part, r.need)
				break
			}
		}
		_, err := DecodeLC(b[:cut], 8)
		if err == nil || err.Error() != want {
			t.Fatalf("cut at %d:\n got %v\nwant %s", cut, err, want)
		}
	}
	got, err := DecodeLC(b, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != ProfileLC || got.AnchorKind != 2 || got.AnchorPeriod != 0x0102030405060708 || got.AnchorRoot[0] != 0xaa || got.AnchorRoot[31] != 0xbb ||
		got.AnchorBody.Layout != LayoutGloas || len(got.AnchorBody.SSZ) != 3 || len(got.Links) != 2 || got.Links[1].SSZ[2] != 31 ||
		got.FinalUpdate.Layout != LayoutElectra || got.FinalUpdate.SSZ[0] != 7 {
		t.Fatalf("decoded: %+v", got)
	}
}

func TestDecodeLCLinkBoundTrailingBytesAndEmptyParts(t *testing.T) {
	b := EncodeLC(lcSample(2))
	if _, err := DecodeLC(b, 2); err != nil {
		t.Fatalf("exactly max_links links: %v", err)
	}
	if _, err := DecodeLC(b, 1); err == nil || err.Error() != `{"code":"finality_evidence_too_large","fields":{"count":"2","limit":"1","part":"links"}}` {
		t.Fatalf("one over max_links: %v", err)
	}
	if _, err := DecodeLC(append(append([]byte(nil), b...), 0), 8); err == nil ||
		err.Error() != `{"code":"finality_evidence_malformed","fields":{"got_len":"90","index":"0","part":"lc","reason":"trailing_bytes","want_len":"89"}}` {
		t.Fatalf("trailing byte: %v", err)
	}
	// zero-length parts are well-formed: an empty profile and empty blobs
	empty := LC{AnchorKind: 1, AnchorBody: LB{Layout: LayoutNone}, FinalUpdate: LB{Layout: LayoutNone}}
	got, err := DecodeLC(EncodeLC(empty), 0)
	if err != nil || got.Profile != "" || len(got.Links) != 0 || len(got.AnchorBody.SSZ) != 0 || len(got.FinalUpdate.SSZ) != 0 {
		t.Fatalf("empty parts: %+v %v", got, err)
	}
	// the capacity reserved for links is the link count when the bytes left can hold that many five-byte links
	six := lcSample(6)
	for i := range six.Links {
		six.Links[i].SSZ = nil
	}
	six.FinalUpdate.SSZ = nil
	g6, err := DecodeLC(EncodeLC(six), 6)
	if err != nil || len(g6.Links) != 6 || cap(g6.Links) != 6 {
		t.Fatalf("six empty links: len=%d cap=%d %v", len(g6.Links), cap(g6.Links), err)
	}
}
