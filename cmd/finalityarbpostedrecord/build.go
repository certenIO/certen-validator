// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

const (
	setName     = "finality_arb_posted1"
	formatCase  = "certen-finality-arbposted-case/1"
	formatMan   = "certen-finality-manifest/1"
	registryRel = "testdata/finality/states.json"
)

type legFile struct {
	Chain     string `json:"chain"`
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	HeaderRLP string `json:"header_rlp"`
}

type patch struct {
	At  int    `json:"at"`
	Del int    `json:"del"`
	Ins string `json:"ins"`
}

type caseFile struct {
	Format      string  `json:"format"`
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Pins        string  `json:"pins"`
	Leg         legFile `json:"leg"`
	// Evidence is the recorded base with one patch applied: bytes[:at] || ins || bytes[at+del:].
	Base   string `json:"evidence_base"`
	Patch  patch  `json:"evidence_patch"`
	Expect string `json:"expect_canonical"`
}

type builder struct {
	out     string
	files   map[string][]byte
	cases   []string
	base    []byte
	baseLeg legFile
	legHdr  []byte
	pinsRaw map[string][]byte
	pinsObj map[string]*finality.Pins
	reg     *finality.Registry
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func canonState(code string, kv ...any) string {
	return string(finality.NewState(code, kv...).Canonical())
}

func canonOK(v finality.Verdict) string {
	f := map[string]any{}
	for k, x := range v.Fields {
		f[k] = x
	}
	f["kind"] = v.Kind
	f["level"] = v.Level
	return string((&finality.StateError{Code: "verified", Fields: f}).Canonical())
}

// diff returns the single patch turning old into new (common prefix and suffix removed).
func diff(old, new []byte) patch {
	p := 0
	for p < len(old) && p < len(new) && old[p] == new[p] {
		p++
	}
	s := 0
	for s < len(old)-p && s < len(new)-p && old[len(old)-1-s] == new[len(new)-1-s] {
		s++
	}
	return patch{At: p, Del: len(old) - p - s, Ins: hx(new[p : len(new)-s])}
}

func applyPatch(base []byte, p patch) []byte {
	ins, _ := hex.DecodeString(strings.TrimPrefix(p.Ins, "0x"))
	out := append([]byte(nil), base[:p.At]...)
	out = append(out, ins...)
	return append(out, base[p.At+p.Del:]...)
}

func (b *builder) put(path string, data []byte) { b.files[path] = data }

// add runs the case through the verifier and refuses it unless the verdict equals the literal written here.
func (b *builder) add(id, desc, pinsName string, leg legFile, ev []byte, want string) error {
	pins := b.pinsObj[pinsName]
	num, hash, hdr := uint64(0), [32]byte{}, unhexb(leg.HeaderRLP)
	fmt.Sscan(leg.Number, &num)
	copy(hash[:], unhexb(leg.Hash))
	ref := finality.BlockRef{Chain: 421614, Number: num, Hash: hash, HeaderRLP: hdr}
	var got string
	if k, ok := kindOf(); ok {
		v, err := k.Verify(pins, ref, ev)
		if err != nil {
			if s, named := finality.AsNamed(err); named {
				got = string(s.Canonical())
			} else {
				return fmt.Errorf("case %s: unnamed error %v", id, err)
			}
		} else {
			got = canonOK(v)
		}
	}
	if got != want {
		return fmt.Errorf("case %s: verdict differs from its literal\n got  %s\n want %s", id, got, want)
	}
	cf := caseFile{Format: formatCase, ID: id, Description: desc, Pins: "pins/" + pinsName + ".json", Leg: leg,
		Base: "raw/evidence.bin", Patch: diff(b.base, ev), Expect: want}
	if !bytes.Equal(applyPatch(b.base, cf.Patch), ev) {
		return fmt.Errorf("case %s: patch does not reproduce the evidence", id)
	}
	j, err := json.MarshalIndent(cf, "", " ")
	if err != nil {
		return err
	}
	b.put("cases/"+id+".json", append(j, '\n'))
	b.cases = append(b.cases, id)
	return nil
}

func kindOf() (*arbposted.Kind, bool) { return arbposted.New(), true }

func unhexb(s string) []byte {
	out, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return out
}

func encodePins(d map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func parsePinsMap(raw []byte) map[string]any {
	var d map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&d); err != nil {
		panic(err)
	}
	return d
}

func (b *builder) addPins(name string, mut func(d map[string]any)) error {
	d := parsePinsMap(b.pinsRaw["main"])
	mut(d)
	raw := encodePins(d)
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		return fmt.Errorf("pins %s: %w", name, err)
	}
	b.pinsRaw[name] = raw
	b.pinsObj[name] = p
	b.put("pins/"+name+".json", raw)
	return nil
}

func arbSection(d map[string]any) map[string]any { return d["arb_sepolia"].(map[string]any) }

// legWith returns a synthetic leg: the real block header with its transactionsRoot replaced by the root of txs, and that header's
// hash. The evidence is unchanged; the vector says "the leg block holds THESE transactions".
func legWith(base legFile, hdr []byte, txs [][]byte) legFile {
	items, err := splitItems(hdr)
	if err != nil {
		panic(err)
	}
	root := ethproof.TrieRoot(txs)
	items[4] = mustRLP(root.Bytes())
	nh, err := rlp.EncodeToBytes(rawList(items))
	if err != nil {
		panic(err)
	}
	h := crypto.Keccak256Hash(nh)
	return legFile{Chain: base.Chain, Number: base.Number, Hash: hx(h[:]), HeaderRLP: hx(nh)}
}

type rawList []rlp.RawValue

func splitItems(hdr []byte) ([]rlp.RawValue, error) {
	content, _, err := rlp.SplitList(hdr)
	if err != nil {
		return nil, err
	}
	var items []rlp.RawValue
	for len(content) > 0 {
		_, _, rest, err := rlp.Split(content)
		if err != nil {
			return nil, err
		}
		items = append(items, rlp.RawValue(content[:len(content)-len(rest)]))
		content = rest
	}
	return items, nil
}

func mustRLP(v any) rlp.RawValue {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return b
}

// header returns the container header bytes and the body of an evidence container.
func splitEvidence(ev []byte) (hdr []byte, body []byte) {
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		panic(err)
	}
	return ev[:len(ev)-len(c.Body)], c.Body
}

func build(rawDir, out string) error {
	b := &builder{out: out, files: map[string][]byte{}, pinsRaw: map[string][]byte{}, pinsObj: map[string]*finality.Pins{}}
	rd := func(n string) []byte {
		x, err := os.ReadFile(filepath.Join(rawDir, n))
		if err != nil {
			panic(err)
		}
		return x
	}
	b.base = rd("evidence.bin")
	var leg rawLeg
	if err := json.Unmarshal(rd("leg.json"), &leg); err != nil {
		return err
	}
	b.baseLeg = legFile{Chain: leg.Chain, Number: leg.Number, Hash: leg.Hash, HeaderRLP: leg.HeaderRLP}
	b.legHdr = unhexb(leg.HeaderRLP)
	var txs [][]byte
	for _, t := range leg.Txs {
		txs = append(txs, unhexb(t))
	}
	var capt struct {
		Batch        uint64 `json:"batch"`
		MessageIndex int    `json:"message_index"`
	}
	if err := json.Unmarshal(rd("capture.json"), &capt); err != nil {
		return err
	}
	b.put("raw/evidence.bin", b.base)
	b.put("raw/leg.json", rd("leg.json"))
	b.put("raw/capture.json", rd("capture.json"))
	b.put("raw/pins.json", rd("pins.json"))
	b.pinsRaw["main"] = rd("pins.json")
	main, err := finality.ParsePinsOverride(b.pinsRaw["main"])
	if err != nil {
		return err
	}
	b.pinsObj["main"] = main
	b.put("pins/main.json", b.pinsRaw["main"])

	e, err := arbposted.Decode(mustBody(b.base), arbposted.DefaultBounds())
	if err != nil {
		return fmt.Errorf("the recorded evidence does not decode: %w", err)
	}
	hdrBytes, _ := splitEvidence(b.base)
	reencode := func(m arbposted.Evidence) []byte { return append(append([]byte(nil), hdrBytes...), m.Encode()...) }
	if !bytes.Equal(reencode(e), b.base) {
		return fmt.Errorf("encode(decode(evidence)) differs from the recorded bytes")
	}
	clone := func() arbposted.Evidence {
		m, err := arbposted.Decode(mustBody(b.base), arbposted.DefaultBounds())
		if err != nil {
			panic(err)
		}
		return m
	}
	flip := func(x []byte, i int) []byte { y := append([]byte(nil), x...); y[i] ^= 1; return y }
	N := e.BatchSeq
	spineTop, _ := finality.ReadHeader(e.L1Spine[0])
	spineBot, _ := finality.ReadHeader(e.L1Spine[len(e.L1Spine)-1])
	S := e.StateBlock
	if spineBot.Number != S {
		return fmt.Errorf("the recorded spine ends at %d, the state block is %d", spineBot.Number, S)
	}
	acc := canonState("l1_posted_content_not_found", "reason", "accumulator_mismatch", "batch", N)
	blobBad := canonState("blob_commitment_mismatch")
	root := b.baseLeg

	// ---- pins variants
	pv := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"no_bridge_impl_pin", func(d map[string]any) {
			delete(arbSection(d)["logic_pins"].(map[string]any), "0x3bd9637547d75e5b4539449e14c759b86b9d37a7c1f2b47a1524f857e4ff1a0c")
		}},
		{"kzg_setup_wrong", func(d map[string]any) {
			d["eth_sepolia"].(map[string]any)["kzg_setup_sha256"] = strings.Repeat("a", 64)
		}},
		{"max_uncompressed_1000", func(d map[string]any) { arbSection(d)["max_uncompressed_batch"] = json.Number("1000") }},
		{"max_segments_100", func(d map[string]any) { arbSection(d)["max_segments"] = json.Number("100") }},
		{"max_blobs_2", func(d map[string]any) { arbSection(d)["max_blobs"] = json.Number("2") }},
		{"bold_genesis_at_block", func(d map[string]any) { arbSection(d)["bold_genesis_l2_block"] = json.Number(root.Number) }},
		{"no_arb_section", func(d map[string]any) { delete(d, "arb_sepolia") }},
		{"bridge_other_address", func(d map[string]any) { arbSection(d)["bridge"] = "0x0000000000000000000000000000000000000001" }},
		{"chain_id_wrong", func(d map[string]any) { arbSection(d)["chain_id"] = json.Number("421615") }},
	}
	for _, p := range pv {
		if err := b.addPins(p.name, p.mut); err != nil {
			return err
		}
	}

	nBlobs := uint64(len(e.Blobs))
	stateHash := crypto.Keccak256Hash(e.L1Spine[len(e.L1Spine)-1])
	okWant := canonState("verified",
		"batch_sequence_number", N, "blobs", nBlobs, "kind", arbposted.KindName, "l1_state_block", S,
		"l1_state_block_hash", [32]byte(stateHash), "level", finality.LevelL1Posted, "message_ordinal", uint64(capt.MessageIndex),
		"messages", uint64(countMessages(e)), "statement", arbposted.Statement)

	type c struct {
		id, desc, pins string
		leg            legFile
		ev             []byte
		want           string
	}
	var cs []c
	add := func(id, desc, pins string, leg legFile, ev []byte, want string) {
		cs = append(cs, c{id, desc, pins, leg, ev, want})
	}
	add("valid_live", "a live Arbitrum Sepolia block whose batch is in finalized L1 state: Bridge account, implementation, accumulator and three KZG-verified blobs, decoded to the block's own transactions", "main", root, b.base, okWant)

	// ---- accumulator preimage
	m := clone()
	m.Header40[2]++
	add("adv_header40_min_block_altered", "header40.minBlockNumber + 1: the recomputed accumulator is not the proven one", "main", root, reencode(m), acc)
	m = clone()
	m.BeforeAcc[0] ^= 1
	add("adv_before_acc_altered", "beforeAcc flipped", "main", root, reencode(m), acc)
	m = clone()
	m.DelayedAcc[31] ^= 1
	add("adv_delayed_acc_altered", "delayedAcc flipped", "main", root, reencode(m), acc)
	m = clone()
	m.VersionedHashes[0][5] ^= 1
	add("adv_versioned_hash_altered", "a versioned hash flipped: the data hash, hence the accumulator, differs", "main", root, reencode(m), acc)
	m = clone()
	m.BatchSeq++
	add("adv_batch_sequence_other", "batchSeq + 1: the proven slot is another batch's accumulator", "main", root, reencode(m), acc)

	// ---- blobs
	m = clone()
	m.Blobs[0].Commitment[3] ^= 1
	add("adv_blob_commitment_flipped", "blob 0 commitment flipped: it no longer hashes to the versioned hash", "main", root, reencode(m), blobBad)
	m = clone()
	m.Blobs[1].Proof[7] ^= 1
	add("adv_blob_proof_flipped", "blob 1 proof flipped: the versioned hash matches, the KZG blob proof does not verify", "main", root, reencode(m), blobBad)
	m = clone()
	m.Blobs[2%len(m.Blobs)].Raw = flip(m.Blobs[2%len(m.Blobs)].Raw, 1000)
	add("adv_blob_raw_flipped", "one byte of a raw blob flipped: the KZG proof does not verify", "main", root, reencode(m), blobBad)
	m = clone()
	m.Blobs = m.Blobs[:len(m.Blobs)-1]
	add("adv_blob_missing", "the last blob dropped: fewer blobs than versioned hashes", "main", root, reencode(m), blobBad)

	// ---- Bridge identity and storage proofs
	impl := common.HexToAddress("0xed26e46f38957763f83f2c45f6fb6702cfebc7d8")
	codeHash := common.HexToHash("0x3bd9637547d75e5b4539449e14c759b86b9d37a7c1f2b47a1524f857e4ff1a0c")
	add("adv_bridge_impl_not_pinned", "the pins do not hold the Bridge implementation code hash", "no_bridge_impl_pin", root, b.base,
		canonState("contract_identity_unproven", "role", "bridge_impl", "address", impl[:], "code_hash", codeHash[:], "judged_at", S))
	add("adv_bridge_not_the_pinned_address", "the pinned Bridge address has no account in the proof", "bridge_other_address", root, b.base,
		canonState("contract_identity_unproven", "role", "bridge_impl", "address", common.HexToAddress("0x0000000000000000000000000000000000000001").Bytes(), "code_hash", make([]byte, 32), "judged_at", S))
	for _, which := range []string{"account", "slot"} {
		want := canonState("l1_state_proof_invalid", "which", which)
		found := false
		for i := range e.Nodes {
			m = clone()
			m.Nodes = append(append([][]byte(nil), e.Nodes[:i]...), e.Nodes[i+1:]...)
			ev := reencode(m)
			_, verr := arbposted.New().Verify(main, blockRef(root), ev)
			if s, ok := finality.AsNamed(verr); ok && string(s.Canonical()) == want {
				add("adv_bridge_"+which+"_proof_node_missing", "one trie node removed from the shared NODES set: the "+which+" proof no longer resolves", "main", root, ev, want)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no node removal yields l1_state_proof_invalid{%s}", which)
		}
	}
	m = clone()
	m.Nodes = nil
	add("adv_nodes_empty", "no trie nodes at all", "main", root, reencode(m), canonState("l1_state_proof_invalid", "which", "account"))

	// ---- L1 finality and the spine
	m = clone()
	m.LC.FinalUpdate.SSZ = flip(m.LC.FinalUpdate.SSZ, len(m.LC.FinalUpdate.SSZ)-8-20)
	add("adv_lc_signature_flipped", "a byte of the finality update's aggregate signature flipped", "main", root, reencode(m),
		canonState("l1_finality_unproven", "reason", "lc_refused", "inner", "finality_signature_invalid"))
	m = clone()
	m.LC.AnchorRoot[0] ^= 1
	add("adv_lc_anchor_root_altered", "anchorRoot differs from the committee's root", "main", root, reencode(m),
		canonState("l1_finality_unproven", "reason", "lc_refused", "inner", "finality_pin_mismatch"))
	if len(e.L1Spine) > 1 {
		m = clone()
		m.L1Spine[1] = flip(m.L1Spine[1], 8)
		add("adv_spine_header_altered", "a spine header altered: it no longer hashes to its child's parentHash", "main", root, reencode(m),
			canonState("l1_finality_unproven", "reason", "spine_refused", "inner", "finality_header_chain_broken"))
	}
	m = clone()
	m.L1Spine = nil
	add("adv_spine_empty", "no spine headers", "main", root, reencode(m),
		canonState("l1_finality_unproven", "reason", "spine_refused", "inner", "finality_evidence_malformed"))
	m = clone()
	m.StateBlock = S + 1000
	add("adv_state_block_above_spine", "stateBlock above the finalized head", "main", root, reencode(m),
		canonState("finality_block_not_covered", "block_number", S+1000, "finalized_exec_number", spineTop.Number))
	m = clone()
	m.StateBlock = S - 1
	add("adv_state_block_below_spine", "stateBlock below the spine's last header", "main", root, reencode(m),
		canonState("finality_block_not_covered", "block_number", S-1, "finalized_exec_number", spineTop.Number))

	// ---- the leg's transactions (synthetic leg headers over the same real evidence)
	std := []int{}
	for i, t := range txs {
		if ethproof.TxType(t) <= 4 {
			std = append(std, i)
		}
	}
	notFound := func(r string) string {
		return canonState("l1_posted_content_not_found", "reason", r, "batch", N)
	}
	mism := func(r string) string {
		return canonState("l1_posted_content_not_found", "reason", r, "batch", N, "messages_scanned", uint64(countMessages(e)), "segments", uint64(countSegments(e)))
	}
	altered := append([][]byte(nil), txs...)
	altered[std[0]] = flip(altered[std[0]], len(altered[std[0]])-3)
	add("adv_block_txs_root_mismatch", "the carried transactions are altered but the leg header is the real one: their trie root is not the header's", "main", root, reencode(withTxs(clone(), altered)), notFound("block_txs_root_mismatch"))
	add("adv_tx_altered", "the leg block holds a transaction with one byte altered (header root recomputed): no message carries it", "main", legWith(root, b.legHdr, altered), reencode(withTxs(clone(), altered)), mism("no_matching_message"))
	if len(std) >= 2 {
		swapped := append([][]byte(nil), txs...)
		swapped[std[0]], swapped[std[1]] = swapped[std[1]], swapped[std[0]]
		add("adv_tx_order_swapped", "two signed transactions of the block swapped: the message lists them in the other order", "main", legWith(root, b.legHdr, swapped), reencode(withTxs(clone(), swapped)), mism("no_matching_message"))
		missing := append(append([][]byte(nil), txs[:std[len(std)-1]]...), txs[std[len(std)-1]+1:]...)
		add("adv_tx_missing", "the last signed transaction dropped from the block", "main", legWith(root, b.legHdr, missing), reencode(withTxs(clone(), missing)), mism("no_matching_message"))
	}
	extra := append(append([][]byte(nil), txs...), txs[std[0]])
	add("adv_tx_extra", "an extra signed transaction (a duplicate) appended to the block", "main", legWith(root, b.legHdr, extra), reencode(withTxs(clone(), extra)), mism("no_matching_message"))
	only := [][]byte{txs[0]}
	if ethproof.TxType(only[0]) <= 4 {
		only = nil
	}
	add("adv_no_standard_transactions", "a block with no signed standard transaction", "main", legWith(root, b.legHdr, only), reencode(withTxs(clone(), only)), notFound("no_standard_transactions"))
	odd := append(append([][]byte(nil), txs...), []byte{0x6b, 0xc0})
	add("adv_unsupported_tx_type", "a transaction of type 0x6b in the block", "main", legWith(root, b.legHdr, odd), reencode(withTxs(clone(), odd)),
		canonState("l1_posted_content_not_found", "reason", "unsupported_tx_type", "batch", N, "tx_type", uint64(0x6b)))
	nonce := headerNonce(b.legHdr)
	dep := append(append([][]byte(nil), txs...), []byte{0x64, 0xc0})
	types := []uint64{}
	for _, t := range dep {
		types = append(types, uint64(ethproof.TxType(t)))
	}
	add("adv_delayed_origin_without_proof", "a delayed-origin (0x64) transaction in the block and no Delayed section", "main", legWith(root, b.legHdr, dep), reencode(withTxs(clone(), dep)),
		canonState("l1_posted_delayed_origin_unproven", "block_tx_types", types, "header_nonce", nonce))
	bold, _ := finality.ReadHeader(b.legHdr)
	add("adv_pre_bold_block", "the pins put the BoLD genesis at the leg's own block number", "bold_genesis_at_block", root, b.base,
		canonState("pre_bold_block", "n", bold.Number, "bold_genesis_l2_block", bold.Number))

	// ---- data kind and container shape
	m = clone()
	m.DataKind, m.VersionedHashes, m.Blobs = arbposted.DataNone, nil, nil
	add("adv_data_kind_none", "dataKind 3: a batch without data cannot contain a block", "main", root, reencode(m), notFound("no_data_batch"))
	dkOff, dfOff := offsets(clone())
	ev := append([]byte(nil), b.base...)
	ev[len(hdrBytes)+dkOff] = 7
	add("adv_data_kind_unknown", "dataKind 7", "main", root, ev,
		canonState("finality_evidence_malformed", "part", "dataKind", "reason", "bad_enum_value", "got_len", uint64(7), "want_len", uint64(3)))
	ev = append([]byte(nil), b.base...)
	ev[len(hdrBytes)+dfOff] = 2
	add("adv_delayed_flag_unknown", "delayedFlag 2", "main", root, ev,
		canonState("finality_evidence_malformed", "part", "delayedFlag", "reason", "bad_enum_value", "got_len", uint64(2), "want_len", uint64(1)))
	add("adv_trailing_byte", "one byte after the container body", "main", root, append(append([]byte(nil), b.base...), 0),
		canonState("finality_evidence_malformed", "part", "body", "reason", "trailing_bytes", "got_len", uint64(1), "want_len", uint64(0)))
	add("adv_truncated_in_nodes", "the container cut in the middle of the node set", "main", root, b.base[:len(b.base)-10],
		canonState("finality_evidence_malformed", "part", "nodes", "reason", "length_exceeds_remaining", "got_len", uint64(len(lastNodeTail(e))-10), "want_len", uint64(len(lastNodeTail(e))), "index", uint64(len(e.Nodes)-1)))
	if len(e.Nodes) >= 2 {
		pre2 := append(append([]byte(nil), hdrBytes...), func() []byte { z := clone(); z.Nodes = nil; return z.Encode() }()...)
		pre2 = pre2[:len(pre2)-4]
		var w finality.Writer
		w.Fixed(pre2)
		unsorted := append([][]byte(nil), e.Nodes...)
		unsorted[0], unsorted[1] = unsorted[1], unsorted[0]
		w.LPList(unsorted)
		add("adv_nodes_unsorted", "the first two trie nodes swapped: NODES is not strictly ascending", "main", root, w.Bytes(),
			canonState("finality_evidence_malformed", "part", "nodes", "reason", "nodes_not_ascending_unique", "got_len", uint64(0), "want_len", uint64(0), "index", uint64(1)))
	}
	// blockTxs count above its bound: overwrite the u32 count that follows the spine and stateBlock
	cntOff := countOffset(clone())
	ev = append([]byte(nil), b.base...)
	ev[len(hdrBytes)+cntOff], ev[len(hdrBytes)+cntOff+1], ev[len(hdrBytes)+cntOff+2], ev[len(hdrBytes)+cntOff+3] = 0, 1, 0, 1
	add("adv_block_txs_count_over_bound", "blockTxs claims 65,537 entries (the bound is 65,536)", "main", root, ev,
		canonState("finality_evidence_too_large", "part", "blockTxs", "count", uint64(65537), "limit", uint64(65536)))
	add("adv_blobs_over_pinned_max", "the pins bound blobs at 2; the batch carries 3 versioned hashes", "max_blobs_2", root, b.base,
		canonState("finality_evidence_too_large", "part", "versionedHashes", "count", nBlobs, "limit", uint64(2)))
	add("adv_uncompressed_batch_over_bound", "the pins bound the decompressed batch at 1000 bytes: a brotli stream larger than the bound is refused, never truncated", "max_uncompressed_1000", root, b.base,
		canonState("finality_evidence_too_large", "part", "uncompressed_batch", "count", uint64(1001), "limit", uint64(1000)))
	add("adv_segments_over_bound", "the pins bound segments at 100; the batch holds more", "max_segments_100", root, b.base,
		canonState("finality_evidence_too_large", "part", "segments", "count", uint64(101), "limit", uint64(100)))
	add("adv_kzg_setup_pin_wrong", "the pinned KZG setup hash is not the setup this verifier uses", "kzg_setup_wrong", root, b.base,
		canonState("pin_mismatch", "field", "kzg_setup_sha256"))
	add("adv_arb_section_absent", "the pins file has no arb_sepolia section", "no_arb_section", root, b.base,
		canonState("finality_pin_unknown", "chain", uint64(421614), "kind", "arb_sepolia"))
	add("adv_pins_chain_id_wrong", "arb_sepolia.chain_id is not 421614", "chain_id_wrong", root, b.base, canonState("pin_mismatch", "field", "chain_id"))
	// container header: another kind string
	hk := append([]byte(nil), b.base...)
	i := bytes.Index(hk, []byte("arb-sepolia/l1_posted/v1"))
	hk[i+len("arb-sepolia/l1_posted/v")] = '2'
	add("adv_container_kind_other_version", "the container's kind string is arb-sepolia/l1_posted/v2", "main", root, hk, canonState("finality_evidence_unrecognised", "kind", "arb-sepolia/l1_posted/v2", "version", ""))

	for _, k := range cs {
		if err := b.add(k.id, k.desc, k.pins, k.leg, k.ev, k.want); err != nil {
			return err
		}
	}
	return b.flush(rawDir)
}

func mustBody(ev []byte) []byte { _, body := splitEvidence(ev); return body }

func withTxs(e arbposted.Evidence, txs [][]byte) arbposted.Evidence { e.BlockTxs = txs; return e }

// offsets returns the body offsets of the dataKind byte and the delayedFlag byte of the recorded evidence.
func offsets(e arbposted.Evidence) (dataKind, delayedFlag int) {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(e.LC))
	w.LPList(e.L1Spine)
	w.U64(e.StateBlock)
	w.LPList(e.BlockTxs)
	w.U64(e.BatchSeq)
	for range e.Header40 {
		w.U64(0)
	}
	w.B32(e.BeforeAcc)
	w.B32(e.DelayedAcc)
	dataKind = len(w.Bytes())
	w.U8(e.DataKind)
	w.Count(len(e.VersionedHashes))
	for _, h := range e.VersionedHashes {
		w.B32(h)
	}
	w.Count(len(e.Blobs))
	for _, bl := range e.Blobs {
		w.LP(bl.Raw)
		w.Fixed(bl.Commitment[:])
		w.Fixed(bl.Proof[:])
	}
	delayedFlag = len(w.Bytes())
	return
}

// countOffset is the body offset of the u32 count of blockTxs.
func countOffset(e arbposted.Evidence) int {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(e.LC))
	w.LPList(e.L1Spine)
	w.U64(e.StateBlock)
	return len(w.Bytes())
}

func lastNodeTail(e arbposted.Evidence) []byte {
	n := finality.EncodeNodes(e.Nodes)
	return n[len(n)-1]
}

func blockRef(l legFile) finality.BlockRef {
	var num uint64
	fmt.Sscan(l.Number, &num)
	var h [32]byte
	copy(h[:], unhexb(l.Hash))
	return finality.BlockRef{Chain: 421614, Number: num, Hash: h, HeaderRLP: unhexb(l.HeaderRLP)}
}

func headerNonce(hdr []byte) uint64 {
	items, _ := splitItems(hdr)
	content, _, _ := rlp.SplitString(items[14])
	var n uint64
	for _, c := range content {
		n = n<<8 | uint64(c)
	}
	return n
}

func countMessages(e arbposted.Evidence) int {
	raws := make([][]byte, len(e.Blobs))
	for i := range e.Blobs {
		raws[i] = e.Blobs[i].Raw
	}
	p, err := arbposted.PayloadFromBlobs(raws)
	if err != nil {
		return 0
	}
	m, err := arbposted.MessageTxs(p, 16777216, 102400)
	if err != nil {
		return 0
	}
	return len(m)
}

func countSegments(e arbposted.Evidence) int {
	raws := make([][]byte, len(e.Blobs))
	for i := range e.Blobs {
		raws[i] = e.Blobs[i].Raw
	}
	p, _ := arbposted.PayloadFromBlobs(raws)
	return arbposted.SegmentCount(p, 16777216, 102400)
}

func (b *builder) flush(rawDir string) error {
	regPath := filepath.Join(rawDir, "..", registryRel)
	_ = regPath
	files := map[string]string{}
	paths := make([]string, 0, len(b.files))
	for p := range b.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		dst := filepath.Join(b.out, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, b.files[p], 0o644); err != nil {
			return err
		}
		s := sha256.Sum256(b.files[p])
		files[p] = hex.EncodeToString(s[:])
	}
	man := map[string]any{"format": formatMan, "set": setName, "files": files, "cases": b.cases}
	mj, err := json.MarshalIndent(man, "", " ")
	if err != nil {
		return err
	}
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(b.out, "MANIFEST.json"), mj, 0o644); err != nil {
		return err
	}
	s := sha256.Sum256(mj)
	return os.WriteFile(filepath.Join(b.out, "MANIFEST.json.sha256"), []byte(hex.EncodeToString(s[:])+"\n"), 0o644)
}
