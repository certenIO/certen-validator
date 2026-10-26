// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// setName5 is the vector set this command writes.
const setName5 = "finality_base_posted5"

type dLeg struct {
	id   string
	num  uint64
	hdr  []byte
	hsh  [32]byte
	ts   uint64
	ch   baseposted.ChannelInfo
	ev   []byte
	what string
}

// frameTxsOf lists the L1 blocks of a channel's frame transactions as frame entries, so that distinct() (sorted, once each) applies.
func frameTxsOf(blocks []uint64) []baseposted.FrameTx {
	out := make([]baseposted.FrameTx, len(blocks))
	for i, n := range blocks {
		out[i].L1Block = n
	}
	return out
}

func countTs(ts []uint64, s uint64) (n int) {
	for _, t := range ts {
		if t == s {
			n++
		}
	}
	return n
}

// buildDenim writes finality_base_posted5 from live-captured post-Denim Base Sepolia channels: real legs of a timestamp second that
// holds five blocks, of a second that straddles two channels and of another channel, with mutants of the bytes and of the pins. Every
// expected verdict is written here by hand (the run only supplies the figures that depend on the live chain: finalized_slot and
// finalized_epoch; the batcher, channel id and L1 blocks are asserted against the capture).
func buildDenim(capDir, rawDir, outDir string) error {
	ctx := context.Background()
	for _, d := range []string{"pins", "legs", "evidence", "cases"} {
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
		return err
	}
	bp, err := baseposted.ParsePins(pins)
	if err != nil {
		return err
	}
	if bp.PostDenim == nil {
		return fmt.Errorf("the embedded pins carry no post_denim row")
	}
	src := &baseposted.JSONRPCSource{BlockURLs: []string{"https://ethereum-sepolia-rpc.publicnode.com"}}
	l2 := &baseposted.L2JSONRPC{URLs: []string{"https://sepolia.base.org"}}
	br := &baseposted.Builder{Pins: pins, Store: baseposted.DirStore{Dir: capDir}, L1: src, Headers: src, L2: l2, LC: fileLC{lc}}
	chans, err := br.Channels(ctx)
	if err != nil {
		return err
	}
	dt := bp.DenimTime
	first := (dt - bp.L2GenesisTime + 1) / 2 // ceil: the first block with a 200 ms schedule
	blockOf := func(s, j uint64) uint64 { return first + 5*(s-dt) + j }
	mk := func(id, what string, num uint64, ch baseposted.ChannelInfo, wantTs uint64) (*dLeg, error) {
		hdr, hash, ts, err := l2Header(ctx, num)
		if err != nil {
			return nil, err
		}
		if ts != wantTs {
			return nil, fmt.Errorf("L2 block %d has timestamp %d, the schedule says %d", num, ts, wantTs)
		}
		ad, pend, err := br.Build(ctx, &ethproof.Settlement{Header: hdr}, 0, finality.LevelL1Posted)
		if err != nil {
			return nil, err
		}
		if pend != nil {
			return nil, fmt.Errorf("block %d pending: %s", num, pend.Error())
		}
		return &dLeg{id: id, num: num, hdr: hdr, hsh: hash, ts: ts, ch: ch, ev: ad.Evidence, what: what}, nil
	}
	// the straddled second: the last batch of a channel and the first batch of the next hold the same timestamp
	var st1, st2 *dLeg
	for k := 0; k+1 < len(chans) && st1 == nil; k++ {
		a, b := chans[k], chans[k+1]
		s := a.Timestamps[len(a.Timestamps)-1]
		if s < dt || s != b.Timestamps[0] || countTs(a.Timestamps, s)+countTs(b.Timestamps, s) != 5 {
			continue
		}
		j := uint64(countTs(a.Timestamps, s) - 1)
		x, e1 := mk("straddle_last_of_first_channel", "the last block of a channel whose second continues in the next channel", blockOf(s, j), a, s)
		y, e2 := mk("straddle_first_of_next_channel", "the first block of the next channel, the same timestamp second", blockOf(s, j+1), b, s)
		if e1 != nil || e2 != nil {
			fmt.Println("straddle candidate", k, "unusable:", e1, e2)
			continue
		}
		st1, st2 = x, y
	}
	if st1 == nil {
		return fmt.Errorf("no straddled second among %d captured channels", len(chans))
	}
	// a second of five blocks inside one channel, and the next second
	var g0, g1, g2, o1 *dLeg
	for _, c := range chans {
		if g0 != nil {
			break
		}
		for _, s := range c.Timestamps {
			if s < dt || s == c.Timestamps[0] || countTs(c.Timestamps, s) != 5 || countTs(c.Timestamps, s+1) != 5 {
				continue
			}
			a, e1 := mk("second_block_last_of_its_second", "the fifth block of a second (800 ms part)", blockOf(s, 4), c, s)
			b, e2 := mk("second_block_first_of_its_second", "the first block of the next second", blockOf(s+1, 0), c, s+1)
			d, e3 := mk("second_block_second_of_its_second", "the second block of that second: the batch a timestamp-only lookup does not select", blockOf(s+1, 1), c, s+1)
			if e1 != nil || e2 != nil || e3 != nil {
				fmt.Println("group candidate unusable:", e1, e2, e3)
				continue
			}
			g0, g1, g2 = a, b, d
			break
		}
	}
	if g0 == nil {
		return fmt.Errorf("no two full seconds inside one captured channel")
	}
	for i := len(chans) - 1; i >= 0 && o1 == nil; i-- {
		c := chans[i]
		if c.ID == g0.ch.ID || c.ID == st1.ch.ID || c.ID == st2.ch.ID {
			continue
		}
		for _, s := range c.Timestamps {
			if s < dt || s == c.Timestamps[0] || countTs(c.Timestamps, s) != 5 {
				continue
			}
			if x, err := mk("another_channel_fourth_block", "the fourth block of a second in a channel of its own", blockOf(s, 3), c, s); err == nil {
				o1 = x
				break
			}
		}
	}
	if o1 == nil {
		return fmt.Errorf("no further channel with a full second")
	}
	legs := []*dLeg{g0, g1, g2, st1, st2, o1}
	for _, l := range legs {
		fmt.Printf("leg %-34s block %d ts %d channel %x L1 %v evidence %d B\n", l.id, l.num, l.ts, l.ch.ID, l.ch.L1Blocks, len(l.ev))
		if err := os.WriteFile(filepath.Join(outDir, "evidence", l.id+".bin"), l.ev, 0o644); err != nil {
			return err
		}
		files["evidence/"+l.id+".bin"] = l.ev
		if err := put("legs/"+l.id+".json", baseposted.Leg{Chain: "84532", Number: strconv.FormatUint(l.num, 10), Hash: hx(l.hsh[:]), Header: hx(l.hdr)}); err != nil {
			return err
		}
	}
	// pins variants: one change each
	variant := func(name string, f func(base map[string]any)) error {
		m := deepCopy(pinsMain)
		f(m["base_sepolia"].(map[string]any))
		return put("pins/"+name+".json", m)
	}
	if err := variant("without_post_denim", func(b map[string]any) { delete(b, "post_denim") }); err != nil {
		return err
	}
	if err := variant("denim_time_after_block_g2", func(b map[string]any) { b["denim_time"] = g2.ts + 1 }); err != nil {
		return err
	}
	if err := variant("post_denim_span_type", func(b map[string]any) { b["post_denim"].(map[string]any)["batch_types"] = []any{0, 1} }); err != nil {
		return err
	}
	var cases []baseposted.Case
	var failures []string
	addCase := func(id, desc, pinsName string, l *dLeg, legFile string, mut []byte, exp baseposted.Expect) {
		c := baseposted.Case{Format: "certen-base-posted-case/1", ID: id, Description: desc, Pins: "pins/" + pinsName + ".json", Leg: "legs/" + legFile + ".json",
			Base: "evidence/" + l.id + ".bin", Splice: baseposted.Diff(l.ev, mut)}
		eb, _ := json.Marshal(exp)
		c.Expect = eb
		got, err := c.Run(outDir)
		if err != nil {
			failures = append(failures, id+": "+err.Error())
			return
		}
		if want := baseposted.ExpectBytes(exp); !bytes.Equal(got, want) {
			failures = append(failures, fmt.Sprintf("%s:\n  want %s\n  got  %s", id, want, got))
		}
		cases = append(cases, c)
		b, _ := json.MarshalIndent(c, "", "  ")
		files["cases/"+id+".json"] = append(b, '\n')
		_ = os.WriteFile(filepath.Join(outDir, "cases", id+".json"), append(b, '\n'), 0o644)
	}
	state := func(code string, f map[string]string) baseposted.Expect {
		return baseposted.Expect{Result: "state", Code: code, Fields: canonMap(f)}
	}
	const batcher = "0xfc56e7272eebbba5bc6c544e159483c4a38f8ba3" // R11-base-denim: SystemConfig.batcherHash on 2026-10-26, not read from this code
	okFields := func(l *dLeg) map[string]string {
		v, verr := baseposted.Kind{}.Verify(pins, finality.BlockRef{Chain: 84532, Number: l.num, Hash: l.hsh, HeaderRLP: l.hdr}, l.ev)
		if verr != nil {
			failures = append(failures, fmt.Sprintf("%s does not verify: %v", l.id, verr))
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
		var l1 []string
		for _, n := range distinct(frameTxsOf(l.ch.L1Blocks)) {
			l1 = append(l1, strconv.Quote(strconv.FormatUint(n, 10)))
		}
		for k, want := range map[string]string{"batch_type": `"0"`, "span_blocks": `"1"`, "span_index": `"0"`, "parent_hash_bits": `"256"`, "epoch_hash_bits": `"256"`,
			"batcher": strconv.Quote(batcher), "channel_id": strconv.Quote("0x" + hex.EncodeToString(l.ch.ID[:])), "l1_blocks": "[" + strings.Join(l1, ",") + "]"} {
			if out[k] != want {
				failures = append(failures, fmt.Sprintf("%s: field %s = %s, the capture says %s", l.id, k, out[k], want))
			}
		}
		return out
	}
	for _, l := range legs {
		addCase("valid_"+l.id, l.what+fmt.Sprintf(" (Base Sepolia block %d, timestamp %d)", l.num, l.ts), "main", l, l.id, l.ev,
			baseposted.Expect{Result: "ok", Fields: canonMap(okFields(l))})
	}
	// ---- mutants of the leg header (the container is repointed at the altered header)
	cG2, err := finality.DecodeContainer(g2.ev, finality.DefaultLimits())
	if err != nil {
		return err
	}
	repoint := func(base *dLeg, number uint64, hash [32]byte) []byte {
		c, err := finality.DecodeContainer(base.ev, finality.DefaultLimits())
		if err != nil {
			panic(err)
		}
		c.Header.BlockNumber, c.Header.BlockHash = number, hash
		out, err := finality.Container{Header: c.Header, Body: c.Body}.Encode()
		if err != nil {
			panic(err)
		}
		return out
	}
	altered := func(name string, base *dLeg, hdr []byte) ([]byte, error) {
		h := [32]byte(crypto.Keccak256Hash(hdr))
		if err := put("legs/"+name+".json", baseposted.Leg{Chain: "84532", Number: strconv.FormatUint(base.num, 10), Hash: hx(h[:]), Header: hx(hdr)}); err != nil {
			return nil, err
		}
		return repoint(base, base.num, h), nil
	}
	forged := forgeParent(g2.hdr)
	evF, err := altered("g2_parent_altered", g2, forged)
	if err != nil {
		return err
	}
	addCase("denim_leg_parent_hash_altered", "a block of a five-block second whose header has another parent hash: no batch of the second commits it", "main", g2, "g2_parent_altered", evF,
		state("batch_binding_mismatch", map[string]string{"field": "parent_hash"}))
	var parentOfG1 []byte
	if err := rlp.DecodeBytes(headerItems(g1.hdr)[0], &parentOfG1); err != nil {
		return err
	}
	evC, err := altered("g2_names_the_previous_batch", g2, setItem(g2.hdr, 0, parentOfG1))
	if err != nil {
		return err
	}
	addCase("denim_leg_names_the_previous_batch_of_its_second", "the header of the second block of a second carries the parent hash of the first: the previous block's batch is selected and its transactions do not rebuild this header's root", "main", g2, "g2_names_the_previous_batch", evC,
		state("batch_binding_mismatch", map[string]string{"field": "transactions_root"}))
	// the straddled second's later block judged with the earlier channel's evidence
	addCase("denim_straddle_leg_with_the_other_channel", "the first block of the next channel judged with the evidence of the previous channel, which holds the same timestamp second with other parent hashes", "main", st1, st2.id,
		repoint(st1, st2.num, st2.hsh), state("batch_binding_mismatch", map[string]string{"field": "parent_hash"}))
	// ---- mutants of the deposits
	bodyG2, err := baseposted.DecodeBody(cG2.Body, finality.DefaultLimits(), baseposted.EthL1Pins(pins), 32)
	if err != nil {
		return err
	}
	if len(bodyG2.Deposits) != 2 {
		return fmt.Errorf("a post-Denim block holds %d deposits, the research says 2 (L1 info and BaseTime)", len(bodyG2.Deposits))
	}
	enc := func(mod func(*baseposted.Body)) []byte {
		bd := cloneBody(bodyG2)
		mod(&bd)
		out, err := finality.Container{Header: cG2.Header, Body: baseposted.EncodeBody(bd)}.Encode()
		if err != nil {
			panic(err)
		}
		return out
	}
	addCase("denim_basetime_deposit_dropped", "the BaseTime deposit (transaction 1) removed from the deposit list: the transaction root of the header no longer rebuilds", "main", g2, g2.id,
		enc(func(b *baseposted.Body) { b.Deposits = b.Deposits[:1] }), state("batch_binding_mismatch", map[string]string{"field": "transactions_root"}))
	addCase("denim_basetime_deposit_altered", "the last byte of the BaseTime deposit changed", "main", g2, g2.id,
		enc(func(b *baseposted.Body) {
			d := append([]byte(nil), b.Deposits[1]...)
			d[len(d)-1] ^= 1
			b.Deposits[1] = d
		}), state("batch_binding_mismatch", map[string]string{"field": "transactions_root"}))
	// ---- the pins
	addCase("denim_pins_without_post_denim", "pins without the post_denim capability row: the post-Denim block keeps the named refusal", "without_post_denim", g2, g2.id, g2.ev,
		state("batch_format_unsupported", map[string]string{"type": "post_denim"}))
	addCase("denim_time_after_the_block_is_timestamp_keyed", "denim_time one second after the block: the block is judged as before the fork, by its timestamp alone, which selects the first batch of the second", "denim_time_after_block_g2", g2, g2.id, g2.ev,
		state("batch_binding_mismatch", map[string]string{"field": "parent_hash"}))
	addCase("denim_pins_post_denim_row_names_span_batches", "a post_denim row that lists batch type 1: the pins are corrupt", "post_denim_span_type", g2, g2.id, g2.ev,
		state("finality_pins_corrupt", map[string]string{"reason": "bad_value", "key": "base_sepolia.post_denim"}))
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Println("FAIL", f)
		}
		return fmt.Errorf("%d case(s) do not yield the hand-written verdict", len(failures))
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	files["README.md"] = []byte(readme5(len(cases), legs))
	if err := os.WriteFile(filepath.Join(outDir, "README.md"), files["README.md"], 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, ".gitattributes"), []byte("* -text\n"), 0o644); err != nil {
		return err
	}
	manifest := map[string]any{"format": "certen-base-posted-vectors/1", "set": setName5, "spec": "V2_SPEC_S7 r2 section 5.4, RB11-D-POST (R11-base-denim)",
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
	fmt.Printf("%d cases, MANIFEST %s\n", len(cases), baseposted.FileSHA256(mb))
	return os.WriteFile(filepath.Join(outDir, "MANIFEST.sha256"), []byte(baseposted.FileSHA256(mb)+"\n"), 0o644)
}

func readme5(n int, legs []*dLeg) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s - post-Denim vectors for base-sepolia/l1_posted/v1 (RB11-D-POST)\n\n", setName5)
	b.WriteString("Companion of `finality_base_posted1` to `4` (never edited). Same case format `certen-base-posted-case/1`; the Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must judge every case the same way.\n\n")
	b.WriteString("`manifest.json` lists the SHA-256 of every other file (this README included) and `pins_sha256_embedded`, the SHA-256 of the pins file embedded in the verifier that judged the set (`pkg/finality/pins/finality-pins.json`); `MANIFEST.sha256` is the SHA-256 of `manifest.json`. `pins/main.json` is the embedded pins file whose `eth_sepolia` section is the one derived from the captured light-client chain; its `base_sepolia` section, `post_denim` row included, is byte-identical to the embedded one (a Go test asserts it).\n\n")
	fmt.Fprintf(&b, "%d cases. Real evidence, captured live from Base Sepolia and Ethereum Sepolia on 2026-10-26: the legs below, each in a Brotli channel of EIP-4844 blobs posted by the batcher to the inbox, real KZG proofs, a real light-client finality chain, five L2 blocks per timestamp second (200 ms blocks), a BaseTime deposit as transaction 1.\n\n", n)
	b.WriteString("| leg | Base Sepolia block | timestamp | channel | L1 block(s) |\n|---|---|---|---|---|\n")
	for _, l := range legs {
		fmt.Fprintf(&b, "| `%s` | %d | %d | `%x` | %v |\n", l.id, l.num, l.ts, l.ch.ID, l.ch.L1Blocks)
	}
	b.WriteString("\n## What the cases pin\n\n")
	b.WriteString("- Valid cases: a block is bound to the singular batch of its channel whose timestamp AND full 32-byte parent hash are the block's (`second_block_second_of_its_second` is a block a timestamp-only lookup judges `batch_binding_mismatch{parent_hash}`; the straddled second is found in the right one of two channels).\n")
	b.WriteString("- `denim_leg_parent_hash_altered`, `denim_leg_names_the_previous_batch_of_its_second`, `denim_straddle_leg_with_the_other_channel`: the batch is selected by parent hash, never by position or by timestamp.\n")
	b.WriteString("- `denim_basetime_deposit_dropped`, `denim_basetime_deposit_altered`: the BaseTime deposit is bound only through `transactionsRoot` (no BaseTime or schedule predicate: tech debt O6).\n")
	b.WriteString("- `denim_pins_without_post_denim` (a new binary on old pins fails closed), `denim_time_after_the_block_is_timestamp_keyed` (before the fork the lookup is by timestamp), `denim_pins_post_denim_row_names_span_batches` (the row is corrupt).\n\n")
	b.WriteString("Not in this set: a span batch carrying a Denim block (`batch_format_unsupported{type:span_post_denim}`) and a wrong batcher sender (`batcher_sender_mismatch`). Both need a fabricated L1 (the sender is bound by the L1 transaction trie and the SystemConfig state proof, so any byte change of real evidence is refused earlier with another code); they are judged by Go unit tests over the synthetic world (`denim_rb12_test.go`).\n\n")
	b.WriteString("Regenerate (live data; the public providers serve state proofs only near the head, so the channels must be captured while they are posted): `finalitybasepostedrecord capture -dir CAP -from <head-100> -for 24m`, then `finalityethl1record record -out RAW` after the last captured block is finalized, then `finalitybasepostedrecord build-denim -cap CAP -raw RAW -out <set directory>`.\n")
	return b.String()
}
