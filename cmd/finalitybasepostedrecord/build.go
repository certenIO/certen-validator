// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

type vPins struct {
	ChainID string `json:"chain_id"`
	GVR     string `json:"genesis_validators_root"`
	Forks   []struct {
		Name    string `json:"name"`
		Epoch   string `json:"epoch"`
		Version string `json:"version"`
		Layout  int    `json:"layout"`
	} `json:"forks"`
	Anchors []struct {
		Period        string  `json:"period"`
		CommitteeRoot string  `json:"committee_root"`
		BlockRoot     *string `json:"block_root"`
		WSPEpochs     string  `json:"wsp_epochs"`
	} `json:"anchors"`
}

// composePins writes the finality-pins override of the set: the embedded base_sepolia section plus the Sepolia network section
// whose ledger is the one the captured light-client chain derived (ethl1 recorder output).
func composePins(rawDir string) (map[string]any, ethl1.LC, error) {
	var lc ethl1.LC
	emb := finality.EmbeddedPinsBytes()
	var m map[string]any
	if err := json.Unmarshal(emb, &m); err != nil {
		return nil, lc, err
	}
	var capt struct {
		SigPeriod uint64 `json:"final_signature_period"`
	}
	cb, err := os.ReadFile(filepath.Join(rawDir, "capture.json"))
	if err != nil {
		return nil, lc, err
	}
	if err := json.Unmarshal(cb, &capt); err != nil {
		return nil, lc, err
	}
	P := capt.SigPeriod
	fu, err := os.ReadFile(filepath.Join(rawDir, "finality_update.ssz"))
	if err != nil {
		return nil, lc, err
	}
	linkRaw, err := os.ReadFile(filepath.Join(rawDir, "updates", fmt.Sprintf("%d.ssz", P-1)))
	if err != nil {
		return nil, lc, err
	}
	const offNext, committeeLen = 496, 24624
	comm := linkRaw[offNext : offNext+committeeLen]
	root, err := ethl1.HashTreeRootSyncCommittee(comm)
	if err != nil {
		return nil, lc, err
	}
	ls := sha256.Sum256(linkRaw)
	eth := m["eth_sepolia"].(map[string]any)
	eth["anchors"] = []any{map[string]any{"period": P, "committee_root": hx(root[:]), "wsp_epochs": 279, "link_sha256": hex.EncodeToString(ls[:]),
		"derived_by": []any{"vector-set pin: next_sync_committee of the Lodestar light_client update of period " + strconv.FormatUint(P-1, 10) + " captured " + time.Now().UTC().Format("2006-01-02") + " (single source; not a published ledger entry)"}}}
	lc = ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: P, AnchorRoot: root, AnchorBody: ethl1.LB{Layout: ethl1.LayoutNone, SSZ: append([]byte(nil), comm...)},
		FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: fu}}
	return m, lc, nil
}

func writeJSON(path string, v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, os.WriteFile(path, b, 0o644)
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

type fileLC struct{ lc ethl1.LC }

func (f fileLC) Finalized(context.Context) (ethl1.LC, error) { return f.lc, nil }

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

// ---- the build command ----

func buildSet(capDir, rawDir, outDir string) error {
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(outDir, "pins"), 0o755); err != nil {
		return err
	}
	for _, d := range []string{"legs", "evidence", "cases"} {
		if err := os.MkdirAll(filepath.Join(outDir, d), 0o755); err != nil {
			return err
		}
	}
	files := map[string][]byte{}
	pinsMain, lc, err := composePins(rawDir)
	if err != nil {
		return err
	}
	put := func(name string, v any) error {
		b, err := writeJSON(filepath.Join(outDir, filepath.FromSlash(name)), v)
		files[name] = b
		return err
	}
	if err := put("pins/main.json", pinsMain); err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(files["pins/main.json"])
	if err != nil {
		return fmt.Errorf("the composed pins do not parse: %w", err)
	}
	ep := epins(pins)
	src := &baseposted.JSONRPCSource{BlockURLs: []string{"https://ethereum-sepolia-rpc.publicnode.com"}}
	l2 := &baseposted.L2JSONRPC{URLs: []string{"https://sepolia.base.org"}}
	br := &baseposted.Builder{Pins: pins, Store: baseposted.DirStore{Dir: capDir}, L1: src, Headers: src, L2: l2, LC: fileLC{lc}}
	chans, err := br.Channels(ctx)
	if err != nil {
		return err
	}
	if len(chans) < 2 {
		return fmt.Errorf("need two complete captured channels, have %d", len(chans))
	}
	bp, _ := baseposted.ParsePins(pins)
	// pick, per channel, an interior L2 block
	type leg struct {
		num uint64
		hdr []byte
		hsh [32]byte
		ts  uint64
	}
	pick := func(c baseposted.ChannelInfo) (leg, error) {
		ts := c.Timestamps[len(c.Timestamps)/2]
		num := (ts - bp.L2GenesisTime) / bp.L2BlockTime
		hdr, hash, hts, err := l2Header(ctx, num)
		if err != nil {
			return leg{}, err
		}
		if hts != ts {
			return leg{}, fmt.Errorf("L2 block %d has timestamp %d, the batch says %d", num, hts, ts)
		}
		return leg{num, hdr, hash, ts}, nil
	}
	// the channel A: the earliest complete channel whose frames were captured; B: the next
	a, err := pick(chans[0])
	if err != nil {
		return err
	}
	bLeg, err := pick(chans[1])
	if err != nil {
		return err
	}
	build := func(l leg) ([]byte, error) {
		ad, pend, err := br.Build(ctx, &ethproof.Settlement{Header: l.hdr}, 0, finality.LevelL1Posted)
		if err != nil {
			return nil, err
		}
		if pend != nil {
			return nil, fmt.Errorf("pending: %s", pend.Error())
		}
		return ad.Evidence, nil
	}
	t0 := time.Now()
	evA, err := build(a)
	if err != nil {
		return fmt.Errorf("build A: %w", err)
	}
	buildDur := time.Since(t0)
	evB, err := build(bLeg)
	if err != nil {
		return fmt.Errorf("build B: %w", err)
	}
	fmt.Printf("built evidence A %d bytes (%s), B %d bytes\n", len(evA), buildDur.Round(time.Millisecond), len(evB))
	files["evidence/valid_a.bin"], files["evidence/valid_b.bin"] = evA, evB
	for n, b := range map[string][]byte{"evidence/valid_a.bin": evA, "evidence/valid_b.bin": evB} {
		if err := os.WriteFile(filepath.Join(outDir, filepath.FromSlash(n)), b, 0o644); err != nil {
			return err
		}
	}
	writeLeg := func(name string, num uint64, hash [32]byte, hdr []byte) error {
		return put("legs/"+name+".json", baseposted.Leg{Chain: "84532", Number: strconv.FormatUint(num, 10), Hash: hx(hash[:]), Header: hx(hdr)})
	}
	if err := writeLeg("a", a.num, a.hsh, a.hdr); err != nil {
		return err
	}
	if err := writeLeg("b", bLeg.num, bLeg.hsh, bLeg.hdr); err != nil {
		return err
	}

	// decode A for the structural mutations and the independent expectations
	cA, err := finality.DecodeContainer(evA, finality.DefaultLimits())
	if err != nil {
		return err
	}
	epr := ep
	bodyA, err := baseposted.DecodeBody(cA.Body, finality.DefaultLimits(), epr, 32)
	if err != nil {
		return err
	}
	var cases []baseposted.Case
	var failures []string
	addCase := func(id, desc, pinsName, legName, base string, baseBytes, mut []byte, code string, fields map[string]string, okFields map[string]string) {
		exp := baseposted.Expect{Result: "state", Code: code}
		fb := canonMap(fields)
		exp.Fields = fb
		if code == "" {
			exp.Result = "ok"
			exp.Fields = canonMap(okFields)
		}
		c := baseposted.Case{Format: "certen-base-posted-case/1", ID: id, Description: desc, Pins: "pins/" + pinsName + ".json", Leg: "legs/" + legName + ".json",
			Base: base, Splice: baseposted.Diff(baseBytes, mut)}
		eb, _ := json.Marshal(exp)
		c.Expect = eb
		got, err := c.Run(outDir)
		if err != nil {
			failures = append(failures, id+": "+err.Error())
			return
		}
		want := baseposted.ExpectBytes(exp)
		if !bytes.Equal(got, want) {
			failures = append(failures, fmt.Sprintf("%s:\n  want %s\n  got  %s", id, want, got))
		}
		cases = append(cases, c)
		b, _ := json.MarshalIndent(c, "", "  ")
		files["cases/"+id+".json"] = append(b, '\n')
		_ = os.WriteFile(filepath.Join(outDir, "cases", id+".json"), append(b, '\n'), 0o644)
	}

	frameBlocks := distinct(bodyA.Frames)
	first := frameBlocks[0]
	enc := func(mod func(*baseposted.Body)) []byte {
		bd := cloneBody(bodyA)
		mod(&bd)
		cc := finality.Container{Header: cA.Header, Body: baseposted.EncodeBody(bd)}
		out, err := cc.Encode()
		if err != nil {
			panic(err)
		}
		return out
	}
	const batcher = "0xfc56e7272eebbba5bc6c544e159483c4a38f8ba3" // R11-base-sepolia Q2: SystemConfig.batcherHash on 2026-10-17, not read from this code
	okA := map[string]string{"batch_type": "0", "batcher": batcher, "span_blocks": "1", "span_index": "0", "parent_hash_bits": "256", "epoch_hash_bits": "256"}
	_ = okA
	// pins variants
	variant := func(name string, f func(base map[string]any)) {
		m := deepCopy(pinsMain)
		f(m["base_sepolia"].(map[string]any))
		if err := put("pins/"+name+".json", m); err != nil {
			panic(err)
		}
	}
	variant("channel_cap_1mb", func(b map[string]any) { b["max_rlp_bytes_per_channel"] = 1000000 })
	variant("seq_window_1", func(b map[string]any) { b["seq_window_size"] = 1 })
	variant("denim_at_block_a", func(b map[string]any) { b["denim_time"] = a.ts })
	variant("denim_after_block_a", func(b map[string]any) { b["denim_time"] = a.ts + 1 })
	variant("syscfg_impl_other", func(b map[string]any) {
		b["impl_pins"] = map[string]any{"0x" + strings.Repeat("11", 32): map[string]any{"role": "syscfg_impl"}}
	})
	variant("kzg_setup_other", func(b map[string]any) { b["kzg_setup_sha256"] = strings.Repeat("22", 32) })

	// okFields: everything but the hand-checked invariants comes from the run; the invariants are asserted here
	okFor := func(ev []byte, l leg) map[string]string {
		v, verr := baseposted.Kind{}.Verify(pins, finality.BlockRef{Chain: 84532, Number: l.num, Hash: l.hsh, HeaderRLP: l.hdr}, ev)
		if verr != nil {
			failures = append(failures, fmt.Sprintf("valid case does not verify: %v", verr))
			return nil
		}
		var cv struct {
			Fields map[string]json.RawMessage `json:"fields"`
		}
		_ = json.Unmarshal(baseposted.CanonicalVerdict(v, nil), &cv)
		out := map[string]string{}
		for k, raw := range cv.Fields {
			out[k] = string(raw)
		}
		for k, want := range map[string]string{"batch_type": "0", "span_blocks": "1", "span_index": "0", "parent_hash_bits": "256", "epoch_hash_bits": "256"} {
			if strings.Trim(out[k], `"`) != want {
				failures = append(failures, fmt.Sprintf("valid case field %s = %s, want %s", k, out[k], want))
			}
		}
		if strings.Trim(out["batcher"], `"`) != batcher {
			failures = append(failures, fmt.Sprintf("batcher %s, annex says %s", out["batcher"], batcher))
		}
		return out
	}
	rawOK := func(m map[string]string) map[string]string { return stripQuotes(m) }
	okAF := rawOK(okFor(evA, a))
	okBF := rawOK(okFor(evB, bLeg))
	addCase("valid_a", "an interior L2 block of the first captured channel, 6-7 raw blobs, Brotli, singular batches, L1 finality by the live light-client chain", "main", "a", "evidence/valid_a.bin", evA, evA, "", nil, okAF)
	addCase("valid_b", "an interior L2 block of the second captured channel", "main", "b", "evidence/valid_b.bin", evB, evB, "", nil, okBF)
	addCase("valid_a_denim_after_block", "the Denim guard is a strict >=: denim_time one second after the block is accepted", "denim_after_block_a", "a", "evidence/valid_a.bin", evA, evA, "", nil, okAF)

	// ---- mutations of the real bytes
	flip := func(b []byte, i int) []byte { c := append([]byte(nil), b...); c[i] ^= 1; return c }
	_ = flip
	addCase("blob_commitment_flipped", "one byte of blob 0's commitment flipped: the versioned hash no longer matches the transaction", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { b.Frames[0].Blobs[0].Commitment[5] ^= 1 }), "blob_commitment_mismatch", map[string]string{}, nil)
	addCase("blob_kzg_proof_flipped", "one byte of blob 0's KZG proof flipped: versioned hash holds, verify_blob_kzg_proof fails", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { b.Frames[0].Blobs[0].Proof[5] ^= 1 }), "blob_commitment_mismatch", map[string]string{}, nil)
	addCase("blob_raw_flipped", "one byte of blob 0 flipped: the commitment and proof no longer open to the blob", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { b.Frames[0].Blobs[0].Raw[100] ^= 1 }), "blob_commitment_mismatch", map[string]string{}, nil)
	if len(bodyA.Frames[0].Blobs) >= 2 {
		addCase("blob_commitments_swapped", "the commitments of blobs 0 and 1 of the first frame transaction exchanged: each versioned hash mismatches", "main", "a", "evidence/valid_a.bin", evA,
			enc(func(b *baseposted.Body) {
				x, y := b.Frames[0].Blobs[0], b.Frames[0].Blobs[1]
				b.Frames[0].Blobs[0].Commitment, b.Frames[0].Blobs[0].Proof = y.Commitment, y.Proof
				b.Frames[0].Blobs[1].Commitment, b.Frames[0].Blobs[1].Proof = x.Commitment, x.Proof
			}), "blob_commitment_mismatch", map[string]string{}, nil)
		addCase("blob_dropped", "the last blob of the first frame transaction removed: fewer blobs than the transaction's versioned hashes", "main", "a", "evidence/valid_a.bin", evA,
			enc(func(b *baseposted.Body) { b.Frames[0].Blobs = b.Frames[0].Blobs[:len(b.Frames[0].Blobs)-1] }), "blob_commitment_mismatch", map[string]string{}, nil)
	}
	if len(bodyA.Frames) >= 2 {
		addCase("frame_tx_missing_last", "the last frame transaction removed: the closing frame is absent", "main", "a", "evidence/valid_a.bin", evA,
			enc(func(b *baseposted.Body) { b.Frames = b.Frames[:len(b.Frames)-1] }), "channel_incomplete", map[string]string{}, nil)
		addCase("frame_tx_duplicated", "the first frame transaction listed twice", "main", "a", "evidence/valid_a.bin", evA,
			enc(func(b *baseposted.Body) { b.Frames = append([]baseposted.FrameTx{b.Frames[0]}, b.Frames...) }), "channel_incomplete", map[string]string{}, nil)
		addCase("frame_txs_swapped", "the first two frame transactions in the wrong order", "main", "a", "evidence/valid_a.bin", evA,
			enc(func(b *baseposted.Body) { b.Frames[0], b.Frames[1] = b.Frames[1], b.Frames[0] }), "channel_incomplete", map[string]string{}, nil)
	}
	stateRoot := stateRootOf(bodyA, first)
	addCase("systemconfig_state_node_missing", "the root node of the frame block's state trie removed: the SystemConfig account cannot be proven", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { b.Nodes = dropNode(b.Nodes, stateRoot) }), "l1_state_proof_invalid", map[string]string{"which": "account"}, nil)
	txRoot := txRootOf(bodyA, first)
	addCase("tx_trie_node_missing", "the root node of the frame block's transaction trie removed: the frame transaction is not proven in the block", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { b.Nodes = dropNode(b.Nodes, txRoot) }), "l1_tx_proof_invalid", map[string]string{}, nil)
	addCase("frame_l1_block_not_on_spine", "the spine cut off below the frame block: its header is not covered", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) {
			n := 0
			for i, h := range b.L1Spine {
				if hd, _ := finality.ReadHeader(h); hd.Number == first {
					n = i
				}
			}
			b.L1Spine = b.L1Spine[:n]
		}), "finality_block_not_covered", map[string]string{"block_number": strconv.FormatUint(first, 10), "finalized_exec_number": strconv.FormatUint(topNumber(bodyA), 10)}, nil)
	addCase("lc_finality_signature_flipped", "a bit of the finality update's sync-committee signature flipped: L1 finality is refused, the inner code is carried", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) {
			ssz := append([]byte(nil), b.LC.FinalUpdate.SSZ...)
			ssz[1344+20] ^= 1
			b.LC.FinalUpdate.SSZ = ssz
		}), "l1_finality_unproven", map[string]string{"reason": "lc_refused", "inner": "finality_signature_invalid"}, nil)
	addCase("frame_count_over_bound", "the frame count field set to 257: finality_evidence_too_large before anything is read", "main", "a", "evidence/valid_a.bin", evA,
		setFrameCount(evA, bodyA, cA, 257), "finality_evidence_too_large", map[string]string{"count": "257", "limit": "256", "part": "frameTxs"}, nil)
	addCase("trailing_byte", "one byte appended to the container", "main", "a", "evidence/valid_a.bin", evA,
		append(append([]byte(nil), evA...), 0), "finality_evidence_malformed", map[string]string{"got_len": "1", "part": "body", "reason": "trailing_bytes", "want_len": "0"}, nil)
	// deposits: locate the L1-info data inside the deposit
	dep := append([]byte(nil), bodyA.Deposits[0]...)
	hi := bytes.Index(dep, depositHash(dep))
	if hi < 100 {
		return fmt.Errorf("could not locate the L1-info hash in the deposit")
	}
	dataStart := hi - 100
	numOff := dataStart + 28 + 7
	addCase("deposit_epoch_number_altered", "the L1-info deposit's epoch number changed by one: it no longer equals the batch's epoch", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { d := append([]byte(nil), dep...); d[numOff] ^= 1; b.Deposits[0] = d }), "batch_binding_mismatch", map[string]string{"field": "epoch_num"}, nil)
	addCase("deposit_epoch_hash_altered", "the L1-info deposit's epoch hash changed", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { d := append([]byte(nil), dep...); d[hi] ^= 1; b.Deposits[0] = d }), "batch_binding_mismatch", map[string]string{"field": "epoch_hash"}, nil)
	addCase("deposit_data_tail_altered", "the last byte of the L1-info deposit changed: transactionsRoot over deposits and batch transactions differs from the header's", "main", "a", "evidence/valid_a.bin", evA,
		enc(func(b *baseposted.Body) { d := append([]byte(nil), dep...); d[len(d)-1] ^= 1; b.Deposits[0] = d }), "batch_binding_mismatch", map[string]string{"field": "transactions_root"}, nil)
	// the leg: a header with another parent hash (hash recomputed), and a header of a block in the other channel
	forged := forgeParent(a.hdr)
	fh := crypto.Keccak256Hash(forged)
	if err := writeLeg("a_parent_forged", a.num, fh, forged); err != nil {
		return err
	}
	fc := cA.Header
	fc.BlockHash = fh
	evF, _ := finality.Container{Header: fc, Body: cA.Body}.Encode()
	if err := os.WriteFile(filepath.Join(outDir, "evidence", "valid_a_parent_forged.bin"), evF, 0o644); err != nil {
		return err
	}
	files["evidence/valid_a_parent_forged.bin"] = evF
	addCase("leg_parent_hash_altered", "the leg's header has another parentHash: the batch for its timestamp commits the real one", "main", "a_parent_forged", "evidence/valid_a_parent_forged.bin", evF, evF,
		"batch_binding_mismatch", map[string]string{"field": "parent_hash"}, nil)
	// leg of channel B against the evidence of channel A: the container names block A, the leg is B -> finality_block_mismatch
	addCase("leg_is_another_block", "the leg is a block of the second channel but the container is about the first: finality_block_mismatch", "main", "b", "evidence/valid_a.bin", evA, evA,
		"finality_block_mismatch", map[string]string{"field": "blockNumber", "got": strconv.FormatUint(a.num, 10), "want": strconv.FormatUint(bLeg.num, 10)}, nil)
	// the evidence of channel B re-labelled for the leg of channel A's timestamp: build a container for B's channel with a header timestamp not in it
	otherHdr, otherHash := timestampOutside(a.hdr, int(chans[0].Timestamps[len(chans[0].Timestamps)-1])+2)
	if err := writeLeg("a_timestamp_outside", a.num, otherHash, otherHdr); err != nil {
		return err
	}
	fc2 := cA.Header
	fc2.BlockHash = otherHash
	evO, _ := finality.Container{Header: fc2, Body: cA.Body}.Encode()
	if err := os.WriteFile(filepath.Join(outDir, "evidence", "valid_a_timestamp_outside.bin"), evO, 0o644); err != nil {
		return err
	}
	files["evidence/valid_a_timestamp_outside.bin"] = evO
	addCase("batch_not_found_for_timestamp", "the leg's timestamp lies after the last batch of the channel", "main", "a_timestamp_outside", "evidence/valid_a_timestamp_outside.bin", evO, evO,
		"batch_not_found", map[string]string{"n_batches": strconv.Itoa(len(chans[0].Timestamps)), "timestamp": strconv.FormatUint(timestampOf(otherHdr), 10)}, nil)
	// pins variants over the real evidence
	addCase("channel_bomb_over_cap", "max_rlp_bytes_per_channel = 1,000,000 while the channel decompresses to about 2 MB", "channel_cap_1mb", "a", "evidence/valid_a.bin", evA, evA, "channel_malformed", map[string]string{}, nil)
	addCase("batch_outside_sequencing_window", "seq_window_size = 1 while the frames sit more than one block above the epoch", "seq_window_1", "a", "evidence/valid_a.bin", evA, evA, "batch_outside_sequencing_window", map[string]string{}, nil)
	addCase("post_denim_block", "denim_time equals the block's timestamp: the post-Denim guard refuses before anything else is judged", "denim_at_block_a", "a", "evidence/valid_a.bin", evA, evA, "batch_format_unsupported", map[string]string{"type": "post_denim"}, nil)
	addCase("systemconfig_impl_unpinned", "the SystemConfig implementation's code hash is not a pinned syscfg_impl", "syscfg_impl_other", "a", "evidence/valid_a.bin", evA, evA,
		"contract_identity_unproven", map[string]string{"address": "0xaeb75e200b9bcf9343ff1a2d2b1b3976e7339ca4", "code_hash": "0x35c04acf3bb541d90092bf3e328475377142f70760fa82f372ac0c4e4b3ff4f6",
			"judged_at": strconv.FormatUint(first, 10), "role": "syscfg_impl"}, nil)
	addCase("kzg_setup_pin_other", "kzg_setup_sha256 is not the setup this verifier carries", "kzg_setup_other", "a", "evidence/valid_a.bin", evA, evA, "finality_pins_corrupt", map[string]string{"key": "base_sepolia.kzg_setup_sha256", "reason": "bad_value"}, nil)

	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Println("FAIL", f)
		}
		return fmt.Errorf("%d case(s) do not yield the hand-written verdict", len(failures))
	}
	// README + manifest
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	files["README.md"] = []byte(readme(len(cases), buildDur))
	if err := os.WriteFile(filepath.Join(outDir, "README.md"), files["README.md"], 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, ".gitattributes"), []byte("* -text\n"), 0o644); err != nil {
		return err
	}
	manifest := map[string]any{"format": "certen-base-posted-vectors/1", "set": baseposted.SetName, "spec": "V2_SPEC_S7 r2 section 5.4",
		"pins_sha256_embedded": finality.PinsSHA256, "cases": caseIDs(cases)}
	fm := map[string]string{}
	for n, b := range files {
		fm[n] = baseposted.FileSHA256(b)
	}
	manifest["files"] = fm
	mb, err := writeJSON(filepath.Join(outDir, "manifest.json"), manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "MANIFEST.sha256"), []byte(baseposted.FileSHA256(mb)+"\n"), 0o644)
}

func caseIDs(cs []baseposted.Case) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func readme(n int, build time.Duration) string {
	return fmt.Sprintf("# %s - published conformance vectors for base-sepolia/l1_posted/v1\n\nSpec: V2_SPEC_S7 r2 section 5.4, 3.3, 7. The Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must return the same canonical bytes on every case (%d cases).\n\n`manifest.json` lists the SHA-256 of every other file; `MANIFEST.sha256` is the SHA-256 of `manifest.json`.\n\n- `evidence/valid_a.bin`, `valid_b.bin`: real evidence (live Base Sepolia channels posted to the batch inbox, real KZG proofs, a real Sepolia light-client finality chain). A case other than these stores only a `splice` over a named evidence file.\n- `pins/*.json`: finality pins override files (`--pins`): `main` is the embedded base_sepolia section plus a Sepolia ledger derived from the captured light-client chain; the others alter exactly one pin.\n- `legs/*.json`: the L2 block header (Settlement.Header) the evidence is judged against.\n- `cases/*.json`: `{pins, leg, evidence, splice?, expect}`; `expect` is `{result:ok, fields}` or `{result:state, code, fields}`; the comparison is on canonical bytes (sorted keys, integers as decimal strings, bytes 0x lower-case hex).\n\nSynthetic cases (calldata-mode batcher transaction, zlib channels, span batches, wrong batcher sender, transaction not to the inbox, channel timeout, malformed channel) need a synthetic L1 and are covered by Go unit tests in `synth_test.go` / `verify_test.go`; they are not part of this set yet.\n\nRegenerate: `finalitybasepostedrecord watch` (live capture), `finalityethl1record record|build` (light-client chain), `finalitybasepostedrecord build`. Build time of evidence A from the capture: %s.\n", baseposted.SetName, n, build.Round(time.Second))
}

// ---- helpers ----

func epins(p *finality.Pins) ethl1.Pins { return baseposted.EthL1Pins(p) }

func canonMap(m map[string]string) json.RawMessage {
	if m == nil {
		m = map[string]string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		v := m[k]
		if strings.HasPrefix(v, "[") || strings.HasPrefix(v, `"`) {
			b.WriteString(v)
		} else {
			vb, _ := json.Marshal(v)
			b.Write(vb)
		}
	}
	b.WriteByte('}')
	return b.Bytes()
}

func stripQuotes(m map[string]string) map[string]string { return m }

func distinct(fr []baseposted.FrameTx) []uint64 {
	seen := map[uint64]bool{}
	var out []uint64
	for _, f := range fr {
		if !seen[f.L1Block] {
			seen[f.L1Block] = true
			out = append(out, f.L1Block)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneBody(b baseposted.Body) baseposted.Body {
	c := b
	c.L1Spine = append([][]byte(nil), b.L1Spine...)
	c.Nodes = append([][]byte(nil), b.Nodes...)
	c.Deposits = append([][]byte(nil), b.Deposits...)
	c.Frames = make([]baseposted.FrameTx, len(b.Frames))
	for i, f := range b.Frames {
		f.Blobs = make([]baseposted.Blob, len(b.Frames[i].Blobs))
		for j, bl := range b.Frames[i].Blobs {
			bl.Raw = append([]byte(nil), bl.Raw...)
			f.Blobs[j] = bl
		}
		f.TxRaw = append([]byte(nil), b.Frames[i].TxRaw...)
		c.Frames[i] = f
	}
	return c
}

func dropNode(nodes [][]byte, hash [32]byte) [][]byte {
	var out [][]byte
	for _, n := range nodes {
		if [32]byte(crypto.Keccak256Hash(n)) != hash {
			out = append(out, n)
		}
	}
	return out
}

func spineHeader(b baseposted.Body, number uint64) finality.HeaderFields {
	for _, h := range b.L1Spine {
		hd, err := finality.ReadHeader(h)
		if err == nil && hd.Number == number {
			return hd
		}
	}
	panic("block not on the spine")
}

func stateRootOf(b baseposted.Body, n uint64) [32]byte { return spineHeader(b, n).StateRoot }
func txRootOf(b baseposted.Body, n uint64) [32]byte    { return spineHeader(b, n).TransactionRoot }
func topNumber(b baseposted.Body) uint64 {
	hd, _ := finality.ReadHeader(b.L1Spine[0])
	return hd.Number
}

// setFrameCount rewrites the u32 frame count of the body (it follows the 16-byte channel id).
func setFrameCount(ev []byte, b baseposted.Body, c finality.Container, n uint32) []byte {
	out := append([]byte(nil), ev...)
	body := c.Body
	i := bytes.Index(body, b.ChannelID[:])
	off := len(ev) - len(body) + i + 16
	binary.BigEndian.PutUint32(out[off:], n)
	return out
}

func depositHash(dep []byte) []byte {
	// the epoch hash is the 32 bytes at data[100:132]; find the data string by scanning for the L1-info selector region: the
	// deposit's data is the last RLP item, a string of at least 132 bytes
	for i := len(dep) - 164; i >= 0; i-- {
		if dep[i] == 0xb8 || dep[i] == 0xb9 {
			continue
		}
	}
	// the data string is the tail: its payload starts after its RLP header; take the last len-? bytes
	// a string header of 0xb8 0xa4 (164 bytes) precedes it in every post-Ecotone L1-info deposit
	j := bytes.LastIndex(dep, []byte{0xb8, 0xa4})
	if j < 0 {
		panic("L1-info data header not found")
	}
	data := dep[j+2:]
	return data[100:132]
}
