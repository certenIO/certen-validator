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
)

// SetName2 is the second published vector set of this kind: the decompressed-channel (stream) cases. The first set is the live
// evidence set; it is never edited.
const SetName2 = "finality_base_posted2"

var setDir2 = filepath.Join("testdata", SetName2)

type manifest2 struct {
	Format string            `json:"format"`
	Set    string            `json:"set"`
	Cases  []string          `json:"cases"`
	Files  map[string]string `json:"files"`
}

type streamParams struct {
	GenesisTime string `json:"l2_genesis_time"`
	BlockTime   string `json:"l2_block_time"`
	ChainID     string `json:"chain_id"`
}

type streamBatch struct {
	Type       string   `json:"type"`
	EpochNum   string   `json:"epoch_num"`
	Timestamp  string   `json:"timestamp"`
	SpanIndex  string   `json:"span_index"`
	SpanBlocks string   `json:"span_blocks"`
	ParentLen  string   `json:"parent_len"`
	EpochLen   string   `json:"epoch_len"`
	Txs        []string `json:"txs"`
}

type streamDecode struct {
	Result  string        `json:"result"`
	Batches []streamBatch `json:"batches,omitempty"`
}

// streamCase is one decompressed-channel vector: the stream the channel inflates to, the decode-level expectation (what
// decodeBatches returns) and the verifier-level expectation (what verifyChannel names for a synthetic channel carrying exactly this
// stream, judged against an L2 block at timestamp 1790000000).
type streamCase struct {
	Format      string          `json:"format"`
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Params      streamParams    `json:"params"`
	Stream      string          `json:"stream"`
	Decode      streamDecode    `json:"decode"`
	Verifier    json.RawMessage `json:"verifier"`
}

func loadManifest2(t *testing.T) manifest2 {
	t.Helper()
	raw, err := ReadFile(setDir2, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir2, "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != FileSHA256(raw) {
		t.Fatalf("MANIFEST.sha256 %s, manifest hashes to %s", strings.TrimSpace(string(want)), FileSHA256(raw))
	}
	var m manifest2
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVectorSetTwoManifestPinsEveryFileAndNothingElse(t *testing.T) {
	m := loadManifest2(t)
	if m.Set != SetName2 || len(m.Cases) < 8 {
		t.Fatalf("set %q with %d cases", m.Set, len(m.Cases))
	}
	for name, h := range m.Files {
		b, err := ReadFile(setDir2, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
	}
	onDisk := map[string]bool{}
	_ = filepath.WalkDir(setDir2, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(setDir2, p)
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
		if _, ok := m.Files["streams/"+id+".json"]; !ok {
			t.Errorf("case %s has no file in the manifest", id)
		}
	}
}

// decodeLevel renders what decodeBatches returned in the form the cases are written in; a panic is reported as an error by the caller.
func decodeLevel(stream []byte, sp spanParams) (out streamDecode, panicked any) {
	defer func() { panicked = recover() }()
	bs, err := decodeBatches(stream, sp)
	if err != nil {
		return streamDecode{Result: "stream_error"}, nil
	}
	out.Result = "ok"
	for _, b := range bs {
		sb := streamBatch{Type: strconv.Itoa(int(b.Type)), EpochNum: strconv.FormatUint(b.EpochNum, 10), Timestamp: strconv.FormatUint(b.Timestamp, 10),
			SpanIndex: strconv.Itoa(b.SpanIndex), SpanBlocks: strconv.Itoa(b.SpanBlocks), ParentLen: strconv.Itoa(b.ParentLen), EpochLen: strconv.Itoa(b.EpochLen), Txs: []string{}}
		for _, tx := range b.Txs {
			sb.Txs = append(sb.Txs, "0x"+hex.EncodeToString(tx))
		}
		out.Batches = append(out.Batches, sb)
	}
	return out, nil
}

// verifierLevel runs verifyChannel over a synthetic calldata channel whose decompressed stream is exactly the case's stream.
func verifierLevel(t *testing.T, stream []byte) (canon []byte, panicked any) {
	t.Helper()
	s := makeSynth(t, synthOpts{calldata: true, compression: "zlib", rawStream: stream})
	defer func() { panicked = recover() }()
	v, err := s.verify()
	return CanonicalVerdict(v, err), nil
}

func TestEveryStreamVectorOfTheSecondSetIsDecodedAndJudgedAsWrittenAndNeverPanics(t *testing.T) {
	m := loadManifest2(t)
	reg := loadRegistry(t)
	ids := append([]string(nil), m.Cases...)
	sort.Strings(ids)
	okCases, refusals := 0, 0
	for _, id := range ids {
		raw, err := ReadFile(setDir2, "streams/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c streamCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if c.ID != id || c.Format != "certen-base-posted-stream/1" {
			t.Fatalf("%s: id %q format %q", id, c.ID, c.Format)
		}
		bp := newPins()
		if c.Params.GenesisTime != strconv.FormatUint(bp.L2GenesisTime, 10) || c.Params.BlockTime != strconv.FormatUint(bp.L2BlockTime, 10) ||
			c.Params.ChainID != strconv.FormatUint(bp.ChainID, 10) {
			t.Fatalf("%s: params %+v are not the pins of the synthetic world", id, c.Params)
		}
		stream, err := hex.DecodeString(strings.TrimPrefix(c.Stream, "0x"))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		got, pan := decodeLevel(stream, spanParams{GenesisTime: bp.L2GenesisTime, BlockTime: bp.L2BlockTime, ChainID: bp.ChainID})
		if pan != nil {
			t.Errorf("%s: decodeBatches panicked: %v", id, pan)
			continue
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(c.Decode)
		if !bytes.Equal(gb, wb) {
			t.Errorf("%s: decode\n want %s\n got  %s", id, wb, gb)
		}
		var e Expect
		if err := json.Unmarshal(c.Verifier, &e); err != nil {
			t.Fatal(err)
		}
		canon, pan := verifierLevel(t, stream)
		if pan != nil {
			t.Errorf("%s: the verifier panicked on a hostile stream: %v", id, pan)
			continue
		}
		if want := ExpectBytes(e); !bytes.Equal(canon, want) {
			t.Errorf("%s: verifier\n want %s\n got  %s", id, want, canon)
		}
		if c.Decode.Result == "ok" {
			okCases++
		} else {
			refusals++
		}
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
	if okCases < 2 || refusals < 6 {
		t.Fatalf("%d accepting and %d refusing stream cases", okCases, refusals)
	}
}
