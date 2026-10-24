// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// specLive is where the orchestrator keeps the specification file. The tests never depend on it: the frozen revision is committed as
// testdata/contractidentity/spec/V2_SPEC_S8.r3.6.md (sha256 SpecSHA256; the r3.1 copy stays beside it as history) and every table comparison below reads that copy, so they run
// identically on a developer machine and in CI.
const specLive = `C:\Accumulate_Stuff\certen\runbooks\2026-10-proof-v2-completion\design\V2_SPEC_S8.md`

// specText returns the committed copy of the frozen specification revision after checking its bytes against the pinned hash.
func specText(t *testing.T) string {
	t.Helper()
	b := readTestdata(t, "spec/V2_SPEC_S8.r3.6.md")
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != SpecSHA256 {
		t.Fatalf("the committed specification copy hashes to %x, the frozen revision is %s", sum, SpecSHA256)
	}
	return string(b)
}

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "contractidentity", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("testdata %s: %v", rel, err)
	}
	return b
}

func hexFile(t *testing.T, rel string) []byte {
	t.Helper()
	s := strings.TrimSpace(string(readTestdata(t, rel)))
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return b
}

var (
	leg0   = BlockRef{Number: 11845679, Hash: bytes32(0x22)}
	chain0 = uint64(11155111)
)

func bytes32(v byte) (out [32]byte) {
	for i := range out {
		out[i] = v
	}
	return
}

type goldenMeta struct {
	ID     string `json:"id"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Digest string `json:"digest"`
}

func loadMeta(t *testing.T, id string) goldenMeta {
	t.Helper()
	var m goldenMeta
	if err := json.Unmarshal(readTestdata(t, "goldens/"+id+".json"), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// g1Container is G-S8-1: two Stated parts, no codes, no nodes.
func g1Container() *Container {
	stated := func(reason string) Part {
		return Part{Tag: TagStated, Stated: &Stated{State: StatedState, Reason: reason, JudgedBlock: 11845679, JudgedHash: bytes32(0x22),
			Failures: []ProviderFailure{{Host: "rpc.example", Error: "no proof window"}}}}
	}
	return &Container{Chain: chain0, Leg: leg0, Settle: stated("capture_not_attempted_in_window"), Attest: stated("attest_block_state_unavailable")}
}

// g2Container is G-S8-2: captured parts, 2 codes, attest link 1 with 2 hops, 2 block txs, 3 nodes (ASCII byte strings).
func g2Container() *Container {
	var a2 [20]byte
	a2[19] = 0x02
	var a1 [20]byte
	for i := range a1 {
		a1[i] = 0x01
	}
	nodes := [][]byte{[]byte("node-A-state"), []byte("node-B-storage"), []byte("node-C-tx")}
	return &Container{
		Chain: chain0, Leg: leg0,
		Codes:  []Code{{Address: a2, Runtime: []byte{0xfe}}, {Address: a1, Runtime: []byte{0x60, 0x01, 0x60, 0x01, 0x55}}},
		Settle: Part{Tag: TagCaptured},
		Attest: Part{Tag: TagCaptured, Attest: &AttestProof{
			Link: LinkHops, HeaderV: []byte("headerV-bytes"), HeaderVParent: []byte("headerVParent-bytes"),
			HopHeaders: [][]byte{[]byte("hop-1"), []byte("hop-2")}, TxIndex: 7, TxLeaf: []byte("txLeaf"), ReceiptLeaf: []byte("receiptLeaf"),
			BlockTxs: [][]byte{[]byte("tx0"), []byte("tx1-typed")},
		}},
		Nodes: finality.EncodeNodes(nodes),
	}
}

func TestGoldenG0Digest(t *testing.T) {
	raw := map[string]any{}
	if err := json.Unmarshal(readTestdata(t, "goldens/G-S8-0.json"), &raw); err != nil {
		t.Fatal(err)
	}
	wantD0, evidence, wantSum, wantDigest := raw["d0"].(string), raw["evidence_ascii"].(string), raw["sha256_evidence"].(string), raw["digest"].(string)
	wantPre := int(raw["preimage_bytes"].(float64))
	d0 := finality.LegBinding(chain0, leg0.Number, leg0.Hash)
	if hex.EncodeToString(d0[:]) != wantD0 {
		t.Fatalf("D0 = %x, golden %s", d0, wantD0)
	}
	ev := []byte(evidence)
	sum := sha256.Sum256(ev)
	if hex.EncodeToString(sum[:]) != wantSum {
		t.Fatalf("sha256(evidence) = %x, golden %s", sum, wantSum)
	}
	pre := DigestPreimage(d0, ev)
	if len(pre) != wantPre {
		t.Fatalf("preimage is %d bytes, golden %d", len(pre), wantPre)
	}
	dg := Digest(d0, ev)
	if hex.EncodeToString(dg[:]) != wantDigest {
		t.Fatalf("digest = %x, golden %s", dg, wantDigest)
	}
	if got := DigestOf(chain0, leg0.Number, leg0.Hash, ev); got != dg {
		t.Fatalf("DigestOf differs from Digest under LegBinding")
	}
	// the domain tag occurs in exactly this one preimage and is the one the specification names
	if DigestDomain != "certen:contract-identity:v1" || bytes.Count(pre, []byte(DigestDomain)) != 1 {
		t.Fatalf("digest domain %q", DigestDomain)
	}
}

func checkContainerGolden(t *testing.T, id string, want *Container) {
	t.Helper()
	meta := loadMeta(t, id)
	fileBytes := hexFile(t, "goldens/"+id+".container.hex")
	if len(fileBytes) != meta.Bytes {
		t.Fatalf("%s file is %d bytes, golden %d", id, len(fileBytes), meta.Bytes)
	}
	sum := sha256.Sum256(fileBytes)
	if hex.EncodeToString(sum[:]) != meta.SHA256 {
		t.Fatalf("%s sha256 = %x, golden %s", id, sum, meta.SHA256)
	}
	dg := DigestOf(chain0, leg0.Number, leg0.Hash, fileBytes)
	if hex.EncodeToString(dg[:]) != meta.Digest {
		t.Fatalf("%s digest = %x, golden %s", id, dg, meta.Digest)
	}
	// 1. the golden decodes and re-encodes to the same bytes
	c, err := Decode(fileBytes, DefaultLimits())
	if err != nil {
		t.Fatalf("%s: decode: %v", id, err)
	}
	again, err := Encode(c, DefaultLimits())
	if err != nil {
		t.Fatalf("%s: encode(decode): %v", id, err)
	}
	if !bytes.Equal(again, fileBytes) {
		t.Fatalf("%s: encode(decode(x)) != x\n got %x\nwant %x", id, again, fileBytes)
	}
	// 2. building it from its described content gives the golden bytes
	built, err := Encode(want, DefaultLimits())
	if err != nil {
		t.Fatalf("%s: encode(described content): %v", id, err)
	}
	if !bytes.Equal(built, fileBytes) {
		t.Fatalf("%s: described content encodes to\n %x\nwant\n %x", id, built, fileBytes)
	}
	if !containersEqual(c, want) {
		t.Fatalf("%s: decoded content differs from the described content", id)
	}
}

func TestGoldenG1Container(t *testing.T) { checkContainerGolden(t, "G-S8-1", g1Container()) }
func TestGoldenG2Container(t *testing.T) { checkContainerGolden(t, "G-S8-2", g2Container()) }

// The G-S8-2 nodes are ordered by keccak256 and the specification names that order: node-B-storage < node-A-state < node-C-tx.
func TestGoldenG2NodeOrderIsByKeccak(t *testing.T) {
	c := g2Container()
	var names []string
	for _, n := range c.Nodes {
		names = append(names, string(n))
	}
	if strings.Join(names, ",") != "node-B-storage,node-A-state,node-C-tx" {
		t.Fatalf("nodes sorted by keccak256: %v", names)
	}
	if h := crypto.Keccak256Hash([]byte("node-B-storage")).Hex(); !strings.HasPrefix(h, "0x50f036ed") {
		t.Fatalf("keccak(node-B-storage) = %s", h)
	}
}

// The golden hex in the specification text equals the committed file (a test fails if the spec text and the file differ).
func TestGoldensEqualSpecText(t *testing.T) {
	spec := specText(t)
	g2 := regexp.MustCompile("G-S8-2 hex: `([0-9a-f]+)`").FindStringSubmatch(spec)
	g1 := regexp.MustCompile("reference for the codec\\):\\s*`([0-9a-f]+)`").FindStringSubmatch(spec)
	if g1 == nil || g2 == nil {
		t.Fatal("the golden hex strings are not where the spec places them")
	}
	if got := strings.TrimSpace(string(readTestdata(t, "goldens/G-S8-1.container.hex"))); got != g1[1] {
		t.Fatalf("G-S8-1: committed file differs from the spec text\n file %s\n spec %s", got, g1[1])
	}
	if got := strings.TrimSpace(string(readTestdata(t, "goldens/G-S8-2.container.hex"))); got != g2[1] {
		t.Fatalf("G-S8-2: committed file differs from the spec text\n file %s\n spec %s", got, g2[1])
	}
	for _, want := range []string{
		"3ead3c1527420fcc681037f621f0d9362ce452f3496162d92fd47ab5e23d6923", "d7070fd59481084db1d6c97caf4cfb18865d4400a7a324a93799b39db7511edf",
		"d009d115af904ed12afed394efb75040986863137151d6d1ef05494d36793937", "1102d40eacc348fce94b4995b4fe12f8b09e7770e4f7d7bdb972f4a9b58cd1d9",
		"8cf32b725e1c4ed69930f182012a7035a6d9ed2e68d4a5b931d7460e8bd1cab1", "934aa97bcb306db1a15243b3b0552fdf1d20656be77ee3d236ccf121612684d1",
		"1cea0a369d4a4167f9f3b9be09de1670dfb5718a866bbf7d2a6519b540643445",
	} {
		if !strings.Contains(spec, want) {
			t.Fatalf("the spec text no longer contains golden value %s", want)
		}
	}
	for _, id := range []string{"G-S8-1", "G-S8-2"} {
		row := loadMeta(t, id)
		if !strings.Contains(spec, row.SHA256) || !strings.Contains(spec, row.Digest) {
			t.Fatalf("%s metadata is not in the spec text", id)
		}
	}
}

// The live specification file, when this machine has it, must still carry the frozen tables; a difference is reported (a changed table is
// a new freeze), never silently ignored. Its absence (CI) is a log line: the frozen copy is then the only reference of this run.
func TestLiveSpecStillMatchesFrozenCopy(t *testing.T) {
	live, err := os.ReadFile(specLive)
	if err != nil {
		t.Logf("live specification not readable here (%v): the frozen copy %s is the only reference in this run", err, SpecSHA256)
		return
	}
	sum := sha256.Sum256(live)
	if hex.EncodeToString(sum[:]) == SpecSHA256 {
		return
	}
	// a later text-only revision is allowed, but the frozen tables must be identical in it
	frozen := specText(t)
	for _, h := range []string{"### Item 1 - ", "### Item 3 - ", "### Item 4 - ", "### Item 5 - "} {
		if section(frozen, h) != section(string(live), h) {
			t.Errorf("the live specification (sha256 %x) changed the frozen section %q: re-freeze (new spec revision, new lift, SUPERSEDED note)", sum, h)
		}
	}
}

// section returns the text from the heading that starts with h to the next heading of level 2 or 3.
func section(spec, h string) string {
	i := strings.Index(spec, "\n"+h)
	if i < 0 {
		return ""
	}
	rest := spec[i+1:]
	end := len(rest)
	for _, m := range []string{"\n### ", "\n## "} {
		if x := strings.Index(rest[len(h):], m); x >= 0 && x+len(h) < end {
			end = x + len(h)
		}
	}
	return rest[:end]
}

// containersEqual compares two containers by value, treating nil and empty byte strings and lists as equal.
func containersEqual(a, b *Container) bool {
	return bytes.Equal(EncodeUnvalidated(a), EncodeUnvalidated(b))
}
