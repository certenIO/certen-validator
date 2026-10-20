// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// SetName3 is the third published vector set of this kind (RB11-D2-FIX): the binding cases (what depositTxs and the batch may
// hold) and the channel-timeout cases (Bedrock 300, Granite 50, selected by the L1 block time of each frame). Sets 1 and 2 are
// never edited.
const SetName3 = "finality_base_posted3"

var setDir3 = filepath.Join("testdata", SetName3)

type manifest3 struct {
	Format string            `json:"format"`
	Set    string            `json:"set"`
	Cases  []string          `json:"cases"`
	Files  map[string]string `json:"files"`
}

type bindingCase struct {
	Format      string            `json:"format"`
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Pins        map[string]string `json:"pins"`
	L1TimeBase  string            `json:"l1_time_base"`
	FrameBlocks []string          `json:"frame_l1_blocks"`
	Stream      string            `json:"stream"`
	L2          struct {
		Timestamp  string   `json:"timestamp"`
		ParentHash string   `json:"parent_hash"`
		Txs        []string `json:"txs"`
	} `json:"l2"`
	Deposits []string        `json:"deposits"`
	Expect   json.RawMessage `json:"expect"`
}

func loadManifest3(t *testing.T) manifest3 {
	t.Helper()
	raw, err := ReadFile(setDir3, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir3, "MANIFEST.sha256")
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
	return m
}

func TestVectorSetThreeManifestPinsEveryFileAndNothingElse(t *testing.T) {
	m := loadManifest3(t)
	if m.Set != SetName3 || len(m.Cases) < 20 {
		t.Fatalf("set %q with %d cases", m.Set, len(m.Cases))
	}
	for name, h := range m.Files {
		b, err := ReadFile(setDir3, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
	}
	onDisk := map[string]bool{}
	_ = filepath.WalkDir(setDir3, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(setDir3, p)
			rel = filepath.ToSlash(rel)
			if rel != "manifest.json" && rel != "MANIFEST.sha256" && rel != ".gitattributes" {
				onDisk[rel] = true
			}
		}
		return nil
	})
	for n := range onDisk {
		if _, ok := m.Files[n]; !ok {
			t.Errorf("%s is in the set directory but not in the manifest", n)
		}
	}
	for n := range m.Files {
		if !onDisk[n] {
			t.Errorf("%s is in the manifest but not on disk", n)
		}
	}
	for _, id := range m.Cases {
		if _, ok := m.Files["cases/"+id+".json"]; !ok {
			t.Errorf("case %s has no file in the manifest", id)
		}
	}
}

func unhexT(t *testing.T, id, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return b
}

func u64T(t *testing.T, id, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return v
}

// The world of a case is the synthetic world of synth_test.go (README of the set): a calldata batcher transaction per frame, the
// L1 block of number n timed l1_time_base+n, the batch of the stream judged against an L2 block with the case's timestamp,
// parent hash and transaction list, the case's depositTxs, and the three channel-timeout pins of the case.
func TestEveryBindingVectorOfTheThirdSetIsJudgedAsWritten(t *testing.T) {
	m := loadManifest3(t)
	reg := loadRegistry(t)
	ids := append([]string(nil), m.Cases...)
	sort.Strings(ids)
	okCases, refusals := 0, 0
	for _, id := range ids {
		raw, err := ReadFile(setDir3, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c bindingCase
		if err := json.Unmarshal(raw, &c); err != nil {
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
		s.bp.GraniteTime = u64T(t, id, c.Pins["granite_time"])                      // NEWSYM
		s.bp.ChannelTimeoutGranite = u64T(t, id, c.Pins["channel_timeout_granite"]) // NEWSYM
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
		rs, ok := reg[e.Code]
		if !ok {
			t.Errorf("%s: code %s is not in the registry", id, e.Code)
			continue
		}
		var fields map[string]string
		_ = json.Unmarshal(e.Fields, &fields)
		allowed := map[string]bool{}
		for _, f := range append(append([]string(nil), rs.Required...), rs.Optional...) {
			allowed[f] = true
		}
		for _, f := range rs.Required {
			if _, ok := fields[f]; !ok {
				t.Errorf("%s: %s lacks required field %s", id, e.Code, f)
			}
		}
		for f := range fields {
			if !allowed[f] {
				t.Errorf("%s: %s carries unregistered field %s", id, e.Code, f)
			}
		}
	}
	if okCases < 7 || refusals < 14 {
		t.Fatalf("%d accepting and %d refusing binding cases", okCases, refusals)
	}
}
