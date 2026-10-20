// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func q(s string) string     { return strconv.Quote(s) }
func dec(v uint64) string   { return q(strconv.FormatUint(v, 10)) }
func hexq(b []byte) string  { return q("0x" + hex.EncodeToString(b)) }
func h32(h [32]byte) string { return hexq(h[:]) }

// frozen is the state of a resolved game read from the live chain: an independent source for the expected verdict (slots 0 and
// 7 and the prover keys of a resolved game never change again).
type frozen struct {
	created, resolved uint64
	status            uint8
	expRes, proofs    uint64
	tee, zk           bool
}

func readFrozen(ctx context.Context, game [20]byte) (frozen, error) {
	rpc := liveRPC()
	var f frozen
	w0, err := rpc.StorageAtLatest(ctx, game, [32]byte{})
	if err != nil {
		return f, err
	}
	f.created, f.resolved, f.status = binary.BigEndian.Uint64(w0[24:]), binary.BigEndian.Uint64(w0[16:24]), w0[15]
	var s7 [32]byte
	s7[31] = 7
	w7, err := rpc.StorageAtLatest(ctx, game, s7)
	if err != nil {
		return f, err
	}
	f.expRes, f.proofs = binary.BigEndian.Uint64(w7[24:]), binary.BigEndian.Uint64(w7[16:24])
	key := func(k byte) [32]byte {
		var kk, six [32]byte
		kk[31], six[31] = k, 6
		return [32]byte(crypto.Keccak256Hash(kk[:], six[:]))
	}
	t, err := rpc.StorageAtLatest(ctx, game, key(0))
	if err != nil {
		return f, err
	}
	z, err := rpc.StorageAtLatest(ctx, game, key(1))
	if err != nil {
		return f, err
	}
	f.tee, f.zk = t != [32]byte{}, z != [32]byte{}
	return f, nil
}

func (g *gen) finish(ctx context.Context, bp *basefinal.Pins, pins *finality.Pins, ev map[string][]byte, legOf map[string]string,
	bodies map[string]basefinal.Body, legBlocks map[string]finality.BlockRef, lc ethl1.LC) error {
	head, err := ethl1.VerifyFinalizedHead(basefinal.EthL1Pins(pins), lc)
	if err != nil {
		return fmt.Errorf("the recorded light-client update does not verify: %w", err)
	}
	hdrOf := func(raw []byte) finality.HeaderFields { h, _ := finality.ReadHeader(raw); return h }
	lay := bp.Layouts[basefinal.LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)

	okWant := func(name string) (string, error) {
		body := bodies[name]
		f, err := readFrozen(ctx, body.GameProxy)
		if err != nil {
			return "", err
		}
		if f.status != 2 {
			return "", fmt.Errorf("%s: the live game status is %d, a positive case needs DEFENDER_WINS", name, f.status)
		}
		ps := "tee"
		switch {
		case f.tee && f.zk:
			ps = "tee+zk"
		case f.zk:
			ps = "zk"
		}
		path := "slow"
		if d := f.expRes - f.created; d > 432000 {
			path = "extended"
		} else if d < 432000 {
			path = "fast"
		}
		var a finality.HeaderFields
		for _, raw := range body.L1Spine {
			if h := hdrOf(raw); h.Number == body.StateBlock {
				a = h
			}
		}
		l2seq := binary.BigEndian.Uint64(body.GameCode[tl+84+24 : tl+84+32])
		start := l2seq - 600
		outBlock, kind := l2seq, "root_claim"
		if body.OutputRootIndex > 0 {
			outBlock, kind = start+30*uint64(body.OutputRootIndex), "intermediate"
		}
		fields := `{"a_hash":` + h32(a.Hash) + `,"a_number":` + dec(a.Number) + `,"a_timestamp":` + dec(a.Timestamp) +
			`,"created_at":` + dec(f.created) + `,"expected_resolution":` + dec(f.expRes) + `,"finalization_path":` + q(path) +
			`,"game":` + hexq(body.GameProxy[:]) + `,"game_type":"621","game_version":"0.2.0","l1_finalized_slot":` + dec(head.Slot) +
			`,"l1_participants":` + dec(uint64(head.Participants)) + `,"output_root_block":` + dec(outBlock) +
			`,"output_root_index":` + dec(uint64(body.OutputRootIndex)) + `,"proof_count":` + dec(f.proofs) + `,"proof_system":` + q(ps) +
			`,"resolved_at":` + dec(f.resolved) + `,"root_kind":` + q(kind) + `,"status":"2"}`
		return `{"fields":` + fields + `,"result":"ok"}`, nil
	}
	state := func(code, fields string) string { return `{"code":` + q(code) + `,"fields":` + fields + `}` }

	main := "leg_47604755"
	mainEv, mainLeg := ev[main], legOf[main]
	mainBody, mainBlock := bodies[main], legBlocks[main]
	baseFile := "evidence/valid_" + main + ".bin"
	judgedAt := dec(mainBody.StateBlock)

	// ---- the live cases ----
	for _, name := range []string{"leg_47604755", "leg_47898494"} {
		w, err := okWant(name)
		if err != nil {
			return err
		}
		c := bcase{id: "valid_" + name, desc: "live: a resolved DEFENDER_WINS 0.2.0 game (TEE proof, slow path) past its delay as of finalized L1 block A, an intermediate-root anchor and the L2 spine down to the leg block",
			pins: "pins/main.json", ev: ev[name], leg: legOf[name], want: w}
		if err := g.add(c); err != nil {
			return err
		}
	}
	for _, name := range []string{"g030_28495", "g020_28494_inprogress"} {
		if err := g.add(bcase{id: "pending_" + name, desc: "live: an unresolved game (implementation and graph proven, status 0 at A): refused, never a weaker level",
			pins: "pins/main.json", ev: ev[name], leg: legOf[name], want: state("game_not_resolved", `{"status":"0"}`)}); err != nil {
			return err
		}
	}

	// ---- byte mutations of the first live case ----
	mutate := func(id, desc, want string, f func(b *basefinal.Body)) error {
		b := mainBody
		b.L1Spine = append([][]byte(nil), mainBody.L1Spine...)
		b.L2Spine = append([][]byte(nil), mainBody.L2Spine...)
		b.Nodes = append([][]byte(nil), mainBody.Nodes...)
		f(&b)
		return g.add(bcase{id: id, desc: desc, pins: "pins/main.json", ev: container(b, hdrOf(mainBlock.HeaderRLP)), base: mainEv, baseFile: baseFile, leg: mainLeg, want: want})
	}
	top := hdrOf(mainBody.L2Spine[0])
	k := mainBody.OutputRootIndex
	root := func(i uint32) []byte { // intermediate root i of the recorded game code
		off := tl + lay.ArgsBaseLen + 32*int(i)
		return mainBody.GameCode[off : off+32]
	}
	topRoot := crypto.Keccak256(make([]byte, 32), top.StateRoot[:], top.WithdrawalsRoot[:], top.Hash[:])
	if !strings.EqualFold(hex.EncodeToString(topRoot), hex.EncodeToString(root(k-1))) {
		return fmt.Errorf("the recorded game's intermediate root %d is not the output root of the recorded header", k-1)
	}
	if err := mutate("adv_output_root_index_points_at_another_root", "the index selects the next intermediate root; the header at the output-root block does not commit to it",
		state("output_root_mismatch", `{"claimed":`+hexq(root(k))+`,"computed":`+hexq(topRoot)+`}`),
		func(b *basefinal.Body) { b.OutputRootIndex = k + 1 }); err != nil {
		return err
	}
	if err := mutate("adv_output_root_index_above_n", "an index above the 20 intermediate roots is a bound, not a root",
		state("finality_evidence_too_large", `{"count":"21","limit":"20","part":"outputRootIndex"}`),
		func(b *basefinal.Body) { b.OutputRootIndex = 21 }); err != nil {
		return err
	}
	h1, h3 := hdrOf(mainBody.L2Spine[1]), hdrOf(mainBody.L2Spine[3])
	if err := mutate("adv_l2_spine_gap", "a header of the L2 spine removed: the hash link breaks",
		state("finality_header_chain_broken", `{"at_number":`+dec(h1.Number-1)+`,"got_hash":`+h32(h3.Hash)+`,"reason":"hash","spine":"l2","want_hash":`+h32(h1.ParentHash)+`}`),
		func(b *basefinal.Body) { b.L2Spine = append(append([][]byte(nil), b.L2Spine[:2]...), b.L2Spine[3:]...) }); err != nil {
		return err
	}
	if err := mutate("adv_l2_spine_stops_before_the_leg", "the spine ends one block above the leg: the leg is not the end of the proven chain",
		state("l2_block_not_canonical", `{}`),
		func(b *basefinal.Body) { b.L2Spine = b.L2Spine[:len(b.L2Spine)-1] }); err != nil {
		return err
	}
	if err := mutate("adv_state_block_below_the_l1_spine", "stateBlock names a block under the carried L1 spine",
		state("finality_block_not_covered", `{"block_number":`+dec(mainBody.StateBlock-1)+`,"finalized_exec_number":`+dec(hdrOf(mainBody.L1Spine[0]).Number)+`}`),
		func(b *basefinal.Body) { b.StateBlock-- }); err != nil {
		return err
	}
	if err := mutate("adv_game_proxy_not_proven", "the game proxy address is not one of the proven accounts",
		state("l1_state_proof_invalid", `{"which":"account"}`),
		func(b *basefinal.Body) { b.GameProxy[19] ^= 1 }); err != nil {
		return err
	}
	if err := mutate("adv_game_code_byte_flipped", "a byte of the carried game code flipped: it is no longer the code of the proven account",
		state("l1_state_proof_invalid", `{"which":"account"}`),
		func(b *basefinal.Body) {
			b.GameCode = append([]byte(nil), b.GameCode...)
			b.GameCode[300] ^= 1
		}); err != nil {
		return err
	}
	if err := mutate("adv_lc_signature_flipped", "a bit of the finality update's sync-committee signature flipped: L1 finality is refused and the inner code is carried",
		state("l1_finality_unproven", `{"inner":"finality_signature_invalid","reason":"lc_refused"}`),
		func(b *basefinal.Body) {
			ssz := append([]byte(nil), b.LC.FinalUpdate.SSZ...)
			ssz[len(ssz)-8-96] ^= 1
			b.LC.FinalUpdate.SSZ = ssz
		}); err != nil {
		return err
	}
	// a node dropped from the proof set: the first one whose removal is a slot (not an account) refusal
	for i := range mainBody.Nodes {
		b := mainBody
		b.Nodes = append(append([][]byte(nil), mainBody.Nodes[:i]...), mainBody.Nodes[i+1:]...)
		var a ethl1.L1Block
		for _, raw := range b.L1Spine {
			if h := hdrOf(raw); h.Number == b.StateBlock {
				a = ethl1.L1Block{Hash: h.Hash, Number: h.Number, StateRoot: h.StateRoot, Timestamp: h.Timestamp}
			}
		}
		_, jerr := basefinal.Judge(bp, a, b, mainBlock, head)
		if s, ok := finality.AsNamed(jerr); ok && s.Code == "l1_state_proof_invalid" && s.Fields["which"] == "slot" {
			if err := g.add(bcase{id: "adv_storage_node_dropped", desc: "one trie node of a storage proof removed from NODES: the slot cannot be proven", pins: "pins/main.json",
				ev: container(b, hdrOf(mainBlock.HeaderRLP)), base: mainEv, baseFile: baseFile, leg: mainLeg, want: state("l1_state_proof_invalid", `{"which":"slot"}`)}); err != nil {
				return err
			}
			break
		}
	}
	trail := append(append([]byte(nil), mainEv...), 0)
	if err := g.add(bcase{id: "adv_trailing_byte", desc: "one byte after the NODES set", pins: "pins/main.json", ev: trail, base: mainEv, baseFile: baseFile, leg: mainLeg,
		want: state("finality_evidence_malformed", `{"got_len":"1","part":"body","reason":"trailing_bytes","want_len":"0"}`)}); err != nil {
		return err
	}

	// ---- pins variants of the first live case ----
	variant := func(id, desc, want string, edit func(base map[string]any)) error {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(string(g.files["pins/main.json"])))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			return err
		}
		edit(m["base_sepolia"].(map[string]any))
		b, _ := json.MarshalIndent(m, "", "  ")
		name := "pins/" + id + ".json"
		g.put(name, append(b, '\n'))
		return g.add(bcase{id: id, desc: desc, pins: name, ev: mainEv, base: mainEv, baseFile: baseFile, leg: mainLeg, want: want})
	}
	const hash020 = "0xf7f8a640ea3ffadf55e9f425a039e879471a1cda9988e92e2c96d423e08869c7"
	const hashASR = "0xd01ffe5bb9bdf9cb1e42b2dd12188f9bc2a163e8301b24451d7d8485280148b7"
	const hashProxy = "0xfa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998"
	impl := func(m map[string]any) map[string]any { return m["impl_pins"].(map[string]any) }
	identity020 := state("contract_identity_unproven", `{"address":"0xd702aae6221f36dfe7e8ebc4315d64344a9db4cb","code_hash":"`+hash020+`","judged_at":`+judgedAt+`,"role":"game_impl"}`)
	if err := variant("adv_pins_game_implementation_not_pinned", "the pins do not hold the 0.2.0 game implementation: the game cannot be recognised", identity020,
		func(b map[string]any) { delete(impl(b), hash020) }); err != nil {
		return err
	}
	if err := variant("adv_pins_game_implementation_row_incomplete", "the 0.2.0 row lacks its interval pairs: an incomplete row is treated as absent", identity020,
		func(b map[string]any) { delete(impl(b)[hash020].(map[string]any), "interval_pairs") }); err != nil {
		return err
	}
	if err := variant("adv_pins_proxy_runtime_not_pinned", "the OP proxy runtime hash is not pinned: the Portal proxy is unproven",
		state("contract_identity_unproven", `{"address":"0x49f53e41452c74589e85ca1677426ba426459e85","code_hash":"`+hashProxy+`","judged_at":`+judgedAt+`,"role":"portal_proxy"}`),
		func(b map[string]any) { delete(b["proxy_pins"].(map[string]any), hashProxy) }); err != nil {
		return err
	}
	f, err := readFrozen(ctx, mainBody.GameProxy)
	if err != nil {
		return err
	}
	var aTS uint64
	for _, raw := range mainBody.L1Spine {
		if h := hdrOf(raw); h.Number == mainBody.StateBlock {
			aTS = h.Timestamp
		}
	}
	if err := variant("adv_pins_synthetic_finality_delay", "the pinned AnchorStateRegistry implementation carries a 10-billion-second finality delay: the game is within it",
		state("game_within_finality_delay", `{"T":`+dec(aTS)+`,"delay":"10000000000","resolvedAt":`+dec(f.resolved)+`}`),
		func(b map[string]any) {
			impl(b)[hashASR].(map[string]any)["finality_delay_seconds"] = json.Number("10000000000")
		}); err != nil {
		return err
	}
	if err := variant("adv_pins_interval_pair_removed", "the 0.2.0 row only knows a 6000/300 pair: the game's 600-block total is not a pinned pair",
		state("game_unrecognised", `{"n":"20","reason":"interval_pair","total":"600"}`),
		func(b map[string]any) { impl(b)[hash020].(map[string]any)["interval_pairs"] = [][2]int{{6000, 300}} }); err != nil {
		return err
	}
	return g.writeManifest()
}
