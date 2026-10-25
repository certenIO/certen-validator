// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// SetName4 is the fourth published vector set of this kind (R12-SPEC-Q1): the streamed-channel shape, where the sequencing-window rule
// is judged on the completing frame alone and a frame below the batch's epoch is not refused. Sets 1 to 3 are never edited.
const SetName4 = "finality_base_posted4"

var setDir4 = filepath.Join("testdata", SetName4)

func TestEveryStreamedChannelVectorOfTheFourthSetIsJudgedAsWritten(t *testing.T) {
	raw, err := ReadFile(setDir4, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir4, "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != FileSHA256(raw) {
		t.Fatalf("MANIFEST.sha256 %s, manifest hashes to %s", strings.TrimSpace(string(want)), FileSHA256(raw))
	}
	var m manifest3
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Set != SetName4 || len(m.Cases) != 8 {
		t.Fatalf("set %q with %d cases", m.Set, len(m.Cases))
	}
	for name, h := range m.Files {
		b, err := ReadFile(setDir4, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
	}
	reg := loadRegistry(t)
	ids := append([]string(nil), m.Cases...)
	sort.Strings(ids)
	okCases, refusals := 0, 0
	for _, id := range ids {
		cr, err := ReadFile(setDir4, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c bindingCase
		if err := json.Unmarshal(cr, &c); err != nil {
			t.Fatal(err)
		}
		if c.ID != id || c.Format != "certen-base-posted-binding/1" || c.L1TimeBase != "1790000000" {
			t.Fatalf("%s: id %q format %q l1_time_base %q", id, c.ID, c.Format, c.L1TimeBase)
		}
		var blocks []uint64
		for _, b := range c.FrameBlocks {
			blocks = append(blocks, u64T(t, id, b))
		}
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: len(blocks), frameBlocks: blocks, rawStream: unhexT(t, id, c.Stream)})
		s.bp.ChannelTimeout = u64T(t, id, c.Pins["channel_timeout"])
		s.bp.GraniteTime = u64T(t, id, c.Pins["granite_time"])
		s.bp.ChannelTimeoutGranite = u64T(t, id, c.Pins["channel_timeout_granite"])
		s.body.Deposits = nil
		for _, d := range c.Deposits {
			s.body.Deposits = append(s.body.Deposits, unhexT(t, id, d))
		}
		var l2txs [][]byte
		for _, x := range c.L2.Txs {
			l2txs = append(l2txs, unhexT(t, id, x))
		}
		s.l2.Timestamp = u64T(t, id, c.L2.Timestamp)
		s.l2.ParentHash = [32]byte(unhexT(t, id, c.L2.ParentHash))
		s.l2.TransactionRoot = [32]byte(ethproof.TrieRoot(l2txs))
		v, verr := s.verify()
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		if got, want := CanonicalVerdict(v, verr), ExpectBytes(e); !bytes.Equal(got, want) {
			t.Errorf("%s:\n want %s\n got  %s", id, want, got)
		}
		if e.Result == "ok" {
			okCases++
			continue
		}
		refusals++
		if _, ok := reg[e.Code]; !ok {
			t.Errorf("%s: code %s is not in the registry", id, e.Code)
		}
	}
	if okCases != 5 || refusals != 3 {
		t.Fatalf("%d accepting and %d refusing cases", okCases, refusals)
	}
}
