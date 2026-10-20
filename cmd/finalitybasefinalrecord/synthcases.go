// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
)

const (
	synthHash020  = "0xf7f8a640ea3ffadf55e9f425a039e879471a1cda9988e92e2c96d423e08869c7"
	synthHash030  = "0x80e5c0bb48b8a222e8883e2f0729264857211cc906da8971fe8309466981ecaf"
	synthHashASR  = "0xd01ffe5bb9bdf9cb1e42b2dd12188f9bc2a163e8301b24451d7d8485280148b7"
	synthBad      = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	synthPortal   = "0x49f53e41452c74589e85ca1677426ba426459e85"
	synthSysCfg   = "0xf272670eb55e895584501d564afeb048bed26194"
	synthASRAddr  = "0x2ff5cc82dbf333ea30d8ee462178ab1707315355"
	synthDGFAddr  = "0xd6e6dbf4f7ea0ac412fd8b65ed297e64bb7a06e1"
	synthSUPAddr  = "0xe4401eb53ae90a5335a51fe1828d7becaf7a63508"
	synthJudgedAt = "11954148"
)

func u8p(v uint8) *uint8    { return &v }
func u64p(v uint64) *uint64 { return &v }
func boolp(v bool) *bool    { return &v }

// judgeCases writes the synthetic-world judge vectors (judge/*.json) and the pins variants they use.
func (g *gen) judgeCases(bp *basefinal.Pins) error {
	var ids []string
	add := func(id, desc, pinsFile string, o *basefinal.SynthOut, want string) error {
		var e basefinal.Expect
		var w struct {
			Code   string          `json:"code"`
			Fields json.RawMessage `json:"fields"`
			Result string          `json:"result"`
		}
		if err := json.Unmarshal([]byte(want), &w); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		e = basefinal.Expect{Result: w.Result, Code: w.Code, Fields: w.Fields}
		if e.Result == "" {
			e.Result = "state"
		}
		jc := basefinal.NewJudgeCase(id, desc, pinsFile, o, basefinal.ExpectBytes(e))
		b, _ := json.MarshalIndent(jc, "", "  ")
		g.put("judge/"+id+".json", append(b, '\n'))
		ids = append(ids, id)
		return nil
	}
	build := func(s basefinal.SynthSpec) *basefinal.SynthOut {
		o, err := basefinal.BuildSynth(bp, s)
		if err != nil {
			panic(err)
		}
		return o
	}
	state := func(code, fields string) string { return `{"code":` + q(code) + `,"fields":` + fields + `}` }
	main := "pins/main.json"

	okFields := func(o *basefinal.SynthOut, kv map[string]string) string {
		m := map[string]string{
			"a_hash": h32(o.A.Hash), "a_number": dec(o.A.Number), "a_timestamp": dec(o.A.Timestamp), "created_at": dec(1790980536),
			"expected_resolution": dec(1790980536 + 432000), "finalization_path": q("slow"), "game": hexq(o.GameAddr[:]), "game_type": q("621"),
			"game_version": q("0.2.0"), "l1_finalized_slot": q("0"), "l1_participants": q("0"), "output_root_block": dec(47604773),
			"output_root_index": q("0"), "proof_count": q("1"), "proof_system": q("tee"), "resolved_at": dec(1790980536 + 432288), "root_kind": q("root_claim"), "status": q("2"),
		}
		for k, v := range kv {
			m[k] = v
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, q(k)+":"+m[k])
		}
		return `{"fields":{` + strings.Join(parts, ",") + `},"result":"ok"}`
	}

	// ---- accepted worlds ----
	type okCase struct {
		id, desc string
		spec     basefinal.SynthSpec
		kv       map[string]string
	}
	created := uint64(1790980536)
	for _, c := range []okCase{
		{"synth_ok_root_claim_anchor", "a healthy resolved 0.2.0 game, the rootClaim anchor (index 0)", basefinal.SynthSpec{Depth: 2}, nil},
		{"synth_ok_intermediate_root_3", "the same game anchored at intermediate root 2 (index 3), L2 spine of 5 headers", basefinal.SynthSpec{K: 3, Depth: 4}, map[string]string{"output_root_index": q("3"), "root_kind": q("intermediate")}},
		{"synth_ok_last_intermediate_root", "index 20, the last intermediate root (equal to the rootClaim)", basefinal.SynthSpec{K: 20, Depth: 1}, map[string]string{"output_root_index": q("20"), "root_kind": q("intermediate")}},
		{"synth_ok_zk_only", "ZK proof only: proof_system zk is an attribute, not a predicate", basefinal.SynthSpec{Depth: 1, TEE: boolp(false), ZK: boolp(true)}, map[string]string{"proof_system": q("zk")}},
		{"synth_ok_tee_and_zk_fast", "TEE+ZK, second proof within the window: the fast path (expectedResolution - createdAt = 86400)", basefinal.SynthSpec{Depth: 1, ZK: boolp(true), ProofCount: u64p(2), ExpectedRes: u64p(created + 86400), ResolvedAt: created + 90000},
			map[string]string{"proof_system": q("tee+zk"), "proof_count": q("2"), "finalization_path": q("fast"), "expected_resolution": dec(created + 86400), "resolved_at": dec(created + 90000)}},
		{"synth_ok_tee_and_zk_second_proof_too_late", "two proofs but the second landed after createdAt+4d: still the slow delay", basefinal.SynthSpec{Depth: 1, ZK: boolp(true), ProofCount: u64p(2)}, map[string]string{"proof_system": q("tee+zk"), "proof_count": q("2")}},
		{"synth_ok_extended_after_nullify", "a proof was nullified and the delay extended past 5 days", basefinal.SynthSpec{Depth: 1, ExpectedRes: u64p(created + 500000), ResolvedAt: created + 500100},
			map[string]string{"finalization_path": q("extended"), "expected_resolution": dec(created + 500000), "resolved_at": dec(created + 500100)}},
	} {
		o := build(c.spec)
		kv := map[string]string{"output_root_block": dec(47604773)}
		for k, v := range c.kv {
			kv[k] = v
		}
		if err := add(c.id, c.desc, main, o, okFields(o, kv)); err != nil {
			return err
		}
	}
	for _, pr := range []struct {
		id    string
		pair  [2]uint64
		block uint64
	}{{"synth_ok_030_fast_pair_6000_300", [2]uint64{6000, 300}, 48500000}, {"synth_ok_030_slow_pair_600_30", [2]uint64{600, 30}, 48500000}} {
		pair := pr.pair
		o := build(basefinal.SynthSpec{Version: "0.3.0", Pair: &pair, K: 5, Depth: 3, OutBlock: pr.block})
		kv := map[string]string{"game_version": q("0.3.0"), "output_root_block": dec(pr.block), "output_root_index": q("5"), "root_kind": q("intermediate")}
		if err := add(pr.id, "the 0.3.0 implementation with the "+fmt.Sprint(pr.pair)+" interval pair", main, o, okFields(o, kv)); err != nil {
			return err
		}
	}

	// ---- claim validity (isGameClaimValid as of A) ----
	for _, c := range []struct {
		id, desc string
		spec     basefinal.SynthSpec
		want     string
	}{
		{"synth_blacklisted", "ASR.disputeGameBlacklist[game] is set", basefinal.SynthSpec{Blacklisted: true}, state("game_blacklisted", `{}`)},
		{"synth_retired", "createdAt equals retirementTimestamp: retired (createdAt must be strictly greater)", basefinal.SynthSpec{Retirement: u64p(created)}, state("game_retired", `{"createdAt":`+dec(created)+`,"retirementTimestamp":`+dec(created)+`}`)},
		{"synth_retired_by_one_second", "retirementTimestamp one second after createdAt", basefinal.SynthSpec{Retirement: u64p(created + 1)}, state("game_retired", `{"createdAt":`+dec(created)+`,"retirementTimestamp":`+dec(created+1)+`}`)},
		{"synth_paused_on_address_zero", "SuperchainConfig.pauseTimestamps[address(0)] is non-zero (any non-zero value is refused; PAUSE_EXPIRY is not interpreted)", basefinal.SynthSpec{PauseZero: 1790000000},
			state("l1_system_paused", `{"identifier":"0x0000000000000000000000000000000000000000","pauseTimestamp":"1790000000"}`)},
		{"synth_paused_on_portal", "SuperchainConfig.pauseTimestamps[portal] is non-zero", basefinal.SynthSpec{PausePort: 7}, state("l1_system_paused", `{"identifier":`+q(synthPortal)+`,"pauseTimestamp":"7"}`)},
		{"synth_not_respected", "wasRespectedGameTypeWhenCreated is 0", basefinal.SynthSpec{Respected: u8p(0)}, state("game_not_respected", `{}`)},
		{"synth_in_progress", "status 0 at A", basefinal.SynthSpec{Status: u8p(0)}, state("game_not_resolved", `{"status":"0"}`)},
		{"synth_within_delay_by_equality", "T equals resolvedAt (delay 0): the comparison is strict", basefinal.SynthSpec{ATimestamp: created + 432288}, state("game_within_finality_delay", `{"T":`+dec(created+432288)+`,"delay":"0","resolvedAt":`+dec(created+432288)+`}`)},
		{"synth_challenger_wins", "status 1", basefinal.SynthSpec{Status: u8p(1)}, state("game_challenger_wins", `{}`)},
		{"synth_countered_but_defender_wins", "slot 5 (counteredByIntermediateRootIndexPlusOne) is non-zero with status 2: inconsistent evidence", basefinal.SynthSpec{Countered: 4}, state("l1_state_proof_invalid", `{"which":"slot"}`)},
		{"synth_resolved_before_expected_resolution", "resolvedAt < expectedResolution with status 2: inconsistent evidence", basefinal.SynthSpec{ExpectedRes: u64p(created + 432288 + 1)}, state("l1_state_proof_invalid", `{"which":"slot"}`)},
		{"synth_no_prover_key", "neither the TEE nor the ZK prover key is set on a resolved game", basefinal.SynthSpec{TEE: boolp(false)}, state("l1_state_proof_invalid", `{"which":"slot"}`)},
		{"synth_fast_path_without_second_proof", "expectedResolution - createdAt = 86400 with proofCount 1: not a path the contract can take", basefinal.SynthSpec{ExpectedRes: u64p(created + 86400), ProofCount: u64p(1)}, state("l1_state_proof_invalid", `{"which":"slot"}`)},
	} {
		if err := add(c.id, c.desc, main, build(c.spec), c.want); err != nil {
			return err
		}
	}

	// ---- the clone template (exact 98-byte template, args, trailer) ----
	flip := func(i int) basefinal.SynthSpec {
		return basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, code *[]byte) { (*code)[i] ^= 1 }}
	}
	unrec := func(r string) string { return state("game_unrecognised", `{"reason":`+q(r)+`}`) }
	for _, c := range []struct {
		id, desc string
		spec     basefinal.SynthSpec
		reason   string
	}{
		{"synth_template_head_byte", "byte 3 of the clone head flipped", flip(3), "prefix"},
		{"synth_template_length_field", "byte 54 (the embedded be16(args_len+2)) flipped", flip(54), "prefix"},
		{"synth_template_mid_byte", "byte 60 (inside 806062363936013d73) flipped", flip(60), "prefix"},
		{"synth_template_tail_byte", "byte 90 (inside the 13-byte tail) flipped", flip(90), "prefix"},
		{"synth_trailer", "the last byte (the trailer be16) flipped", flip(875), "trailer"},
		{"synth_code_one_byte_longer", "one byte appended to the code", basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) { *c = append(*c, 0) }}, "args_len"},
		{"synth_code_one_byte_shorter", "the last byte removed", basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) { *c = (*c)[:len(*c)-1] }}, "args_len"},
		{"synth_19_intermediate_roots", "one 32-byte root removed from the args", basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) {
			*c = append((*c)[:98+136], (*c)[98+136+32:]...)
		}}, "n_mismatch"},
		{"synth_21_intermediate_roots", "one 32-byte root added to the args", basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) {
			*c = append(append(append([]byte{}, (*c)[:len(*c)-2]...), make([]byte, 32)...), (*c)[len(*c)-2:]...)
		}}, "n_mismatch"},
		{"synth_code_shorter_than_the_template", "60 bytes of code", basefinal.SynthSpec{Tweak: func(_ *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) { *c = (*c)[:60] }}, "prefix"},
	} {
		if err := add(c.id, c.desc, main, build(c.spec), unrec(c.reason)); err != nil {
			return err
		}
	}

	// ---- interval pairs ----
	for _, c := range []struct {
		id, desc string
		spec     basefinal.SynthSpec
		total    string
	}{
		{"synth_interval_500", "a 500-block game", basefinal.SynthSpec{Pair: &[2]uint64{500, 25}}, "500"},
		{"synth_interval_start_off_by_one", "the game's starting block one above: total 599", basefinal.SynthSpec{StartDelta: 1}, "599"},
		{"synth_interval_6000_on_020", "0.2.0 does not know the 6000/300 pair", basefinal.SynthSpec{Pair: &[2]uint64{6000, 300}}, "6000"},
	} {
		if err := add(c.id, c.desc, main, build(c.spec), state("game_unrecognised", `{"n":"20","reason":"interval_pair","total":`+q(c.total)+`}`)); err != nil {
			return err
		}
	}

	// ---- the output root and the L2 spine ----
	o := build(basefinal.SynthSpec{K: 3, Depth: 5})
	hdr := func(raw []byte) finality.HeaderFields { h, _ := finality.ReadHeader(raw); return h }
	top, h1, h3 := hdr(o.Body.L2Spine[0]), hdr(o.Body.L2Spine[1]), hdr(o.Body.L2Spine[3])
	topRoot := crypto.Keccak256(make([]byte, 32), top.StateRoot[:], top.WithdrawalsRoot[:], top.Hash[:])
	root := func(i int) []byte { return o.Body.GameCode[98+136+32*i : 98+136+32*i+32] }
	if !bytes.Equal(topRoot, root(2)) {
		return fmt.Errorf("the synthetic world's intermediate root 2 is not the output root of its top header")
	}
	withBody := func(f func(b *basefinal.Body, leg *finality.BlockRef)) *basefinal.SynthOut {
		c := *o
		c.Body.L2Spine = append([][]byte(nil), o.Body.L2Spine...)
		c.Body.Nodes = append([][]byte(nil), o.Body.Nodes...)
		f(&c.Body, &c.Leg)
		return &c
	}
	for _, c := range []struct {
		id, desc string
		o        *basefinal.SynthOut
		want     string
	}{
		{"synth_output_root_other_index", "the index selects a root the header does not commit to", withBody(func(b *basefinal.Body, _ *finality.BlockRef) { b.OutputRootIndex = 4 }),
			state("output_root_mismatch", `{"claimed":`+hexq(root(3))+`,"computed":`+hexq(topRoot)+`}`)},
		{"synth_output_root_index_above_n", "index 21 above the 20 roots is a bound", withBody(func(b *basefinal.Body, _ *finality.BlockRef) { b.OutputRootIndex = 21 }),
			state("finality_evidence_too_large", `{"count":"21","limit":"20","part":"outputRootIndex"}`)},
		{"synth_l2_spine_gap", "a header removed from the middle of the L2 spine", withBody(func(b *basefinal.Body, _ *finality.BlockRef) {
			b.L2Spine = append(append([][]byte(nil), b.L2Spine[:2]...), b.L2Spine[3:]...)
		}), state("finality_header_chain_broken", `{"at_number":`+dec(h1.Number-1)+`,"got_hash":`+h32(h3.Hash)+`,"reason":"hash","spine":"l2","want_hash":`+h32(h1.ParentHash)+`}`)},
		{"synth_l2_spine_stops_short", "the spine ends one block above the leg", withBody(func(b *basefinal.Body, _ *finality.BlockRef) { b.L2Spine = b.L2Spine[:len(b.L2Spine)-1] }), state("l2_block_not_canonical", `{}`)},
		{"synth_l2_spine_empty", "no L2 header at all", withBody(func(b *basefinal.Body, _ *finality.BlockRef) { b.L2Spine = nil }), state("l2_block_not_canonical", `{}`)},
		{"synth_leg_is_another_block", "the leg block's hash is not the spine's last header", withBody(func(_ *basefinal.Body, leg *finality.BlockRef) { leg.Hash[0] ^= 1 }), state("l2_block_not_canonical", `{}`)},
	} {
		if err := add(c.id, c.desc, main, c.o, c.want); err != nil {
			return err
		}
	}
	skip := build(basefinal.SynthSpec{K: 2, Depth: 3, L2NumberSkipAt: 2})
	sh := hdr(skip.Body.L2Spine[1])
	sh2 := hdr(skip.Body.L2Spine[2])
	if err := add("synth_l2_spine_number_skips", "every hash link is right but the third header's number skips one", main, skip,
		state("finality_header_chain_broken", `{"at_number":`+dec(sh.Number-1)+`,"got_hash":`+h32(sh2.Hash)+`,"reason":"number","spine":"l2","want_hash":`+h32(sh.ParentHash)+`}`)); err != nil {
		return err
	}

	// ---- the contract graph: every link is read from the proven state and pinned ----
	other := [20]byte{0xaa}
	otherHex := hexq(other[:])
	ident := func(role, addr string, ch [32]byte) string {
		return state("contract_identity_unproven", `{"address":`+addr+`,"code_hash":`+h32(ch)+`,"judged_at":`+q(synthJudgedAt)+`,"role":`+q(role)+`}`)
	}
	var opProxy [32]byte
	for h, r := range bp.Proxy {
		if r == basefinal.RoleOPProxy {
			opProxy = h
		}
	}
	bad := basefinal.SynthBadHash
	A := basefinal.SynthAddrs
	setImpl := func(a [20]byte) basefinal.SynthSpec {
		return basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, _ *basefinal.Pins, _ *[]byte) { w.SetCodeHash(a, bad) }}
	}
	setProxy := func(a [20]byte) basefinal.SynthSpec { return setImpl(a) }
	hexAddr := func(a [20]byte) string { return hexq(a[:]) }
	portalA, sysA := addr20(synthPortal), addr20(synthSysCfg)
	for _, c := range []struct {
		id, desc string
		spec     basefinal.SynthSpec
		want     string
	}{
		{"synth_graph_portal_names_another_system_config", "Portal slot 55 is not the pinned SystemConfig", basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, p *basefinal.Pins, _ *[]byte) {
			var x [32]byte
			copy(x[12:], other[:])
			w.Set(p.Portal, slotWord(55), x)
		}}, ident("portal.systemConfig", otherHex, opProxy)},
		{"synth_graph_system_config_names_another_portal", "SystemConfig OPTIMISM_PORTAL_SLOT is not the pinned Portal", basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, p *basefinal.Pins, _ *[]byte) {
			var x [32]byte
			copy(x[12:], other[:])
			w.Set(p.SystemConfig, [32]byte(common.HexToHash("0x4b6c74f9e688cb39801f2112c14a8c57232a3fc5202e1444126d4bce86eb19ac")), x)
		}}, ident("systemconfig.portal", otherHex, opProxy)},
		{"synth_graph_asr_names_another_system_config", "ASR slot 0 (bytes 10..30) is not the pinned SystemConfig", basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, _ *basefinal.Pins, _ *[]byte) {
			var x [32]byte
			copy(x[10:30], other[:])
			w.Set(A.ASR, slotWord(0), x)
		}}, ident("asr.systemConfig", otherHex, opProxy)},
		{"synth_proxy_portal_runtime_unknown", "the Portal proxy runtime hash is not pinned", setProxy(portalA), ident("portal_proxy", hexAddr(portalA), bad)},
		{"synth_proxy_system_config_runtime_unknown", "the SystemConfig proxy runtime hash is not pinned", setProxy(sysA), ident("system_config_proxy", hexAddr(sysA), bad)},
		{"synth_proxy_asr_runtime_unknown", "the ASR proxy runtime hash is not pinned", setProxy(A.ASR), ident("asr_proxy", hexAddr(A.ASR), bad)},
		{"synth_proxy_dgf_runtime_unknown", "the DGF proxy runtime hash is not pinned", setProxy(A.DGF), ident("dgf_proxy", hexAddr(A.DGF), bad)},
		{"synth_proxy_superchain_runtime_unknown", "the SuperchainConfig proxy runtime hash is not pinned", setProxy(A.SUP), ident("superchain_proxy", hexAddr(A.SUP), bad)},
		{"synth_impl_portal_unknown", "the Portal implementation is not pinned", setImpl(A.PortalImpl), ident("portal_impl", hexAddr(A.PortalImpl), bad)},
		{"synth_impl_system_config_unknown", "the SystemConfig implementation is not pinned", setImpl(A.SysCfgImpl), ident("syscfg_impl", hexAddr(A.SysCfgImpl), bad)},
		{"synth_impl_asr_unknown", "the ASR implementation is not pinned", setImpl(A.ASRImpl), ident("asr_impl", hexAddr(A.ASRImpl), bad)},
		{"synth_impl_dgf_unknown", "the DGF implementation is not pinned", setImpl(A.DGFImpl), ident("dgf_impl", hexAddr(A.DGFImpl), bad)},
		{"synth_impl_superchain_unknown", "the SuperchainConfig implementation is not pinned", setImpl(A.SupImpl), ident("superchain_impl", hexAddr(A.SupImpl), bad)},
		{"synth_impl_pinned_under_another_role", "the Portal implementation carries the DGF implementation's pinned hash: right hash, wrong role", basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, _ *basefinal.Pins, _ *[]byte) {
			var dgfImpl [32]byte
			dgfImpl = mustHash("0x910d7bf9e11f1a95aab4e3fceb71f647c8db0431b4510e2155c54dca2b50e444")
			w.SetCodeHash(A.PortalImpl, dgfImpl)
		}}, ident("portal_impl", hexAddr(A.PortalImpl), mustHash("0x910d7bf9e11f1a95aab4e3fceb71f647c8db0431b4510e2155c54dca2b50e444"))},
		{"synth_game_implementation_unknown", "the implementation embedded in the game's clone code is a contract the pins do not hold", basefinal.SynthSpec{Tweak: func(w *basefinal.SynthWorld, _ *basefinal.Pins, c *[]byte) {
			copy((*c)[65:85], other[:])
			w.SetCodeHash(other, [32]byte{0xcc})
		}}, ident("game_impl", otherHex, [32]byte{0xcc})},
	} {
		if err := add(c.id, c.desc, main, build(c.spec), c.want); err != nil {
			return err
		}
	}

	// ---- the registration in DisputeGameFactory._disputeGames[uuid] ----
	for _, c := range []struct {
		id, desc string
		reg      func(r *[32]byte)
		want     string
	}{
		{"synth_registration_absent", "the factory has no entry for the game's uuid", func(r *[32]byte) { *r = [32]byte{} }, state("game_not_registered", `{}`)},
		{"synth_registration_other_type", "the entry names game type 620", func(r *[32]byte) { r[3] ^= 1 }, state("game_type_unsupported", `{"type":"620"}`)},
		{"synth_registration_type_zero", "the entry names game type 0 (and nothing else)", func(r *[32]byte) { *r = [32]byte{31: 1} }, state("game_type_unsupported", `{"type":"0"}`)},
		{"synth_registration_other_creation_time", "the entry's createdAt is not the game's", func(r *[32]byte) { r[11] ^= 1 }, state("game_not_registered", `{}`)},
		{"synth_registration_other_proxy", "the entry names another proxy", func(r *[32]byte) { r[31] ^= 1 }, state("game_not_registered", `{}`)},
	} {
		if err := add(c.id, c.desc, main, build(basefinal.SynthSpec{RegTweak: c.reg}), c.want); err != nil {
			return err
		}
	}

	// ---- the proofs ----
	flipCode := withBody(func(b *basefinal.Body, _ *finality.BlockRef) {
		b.GameCode = append([]byte(nil), o.Body.GameCode...)
		b.GameCode[200] ^= 1
	})
	if err := add("synth_game_code_differs_from_the_proven_account", "a byte of the carried game code flipped", main, flipCode, state("l1_state_proof_invalid", `{"which":"account"}`)); err != nil {
		return err
	}
	noNodes := withBody(func(b *basefinal.Body, _ *finality.BlockRef) { b.Nodes = nil })
	if err := add("synth_no_proof_nodes", "NODES is empty: the first account cannot be proven", main, noNodes, state("l1_state_proof_invalid", `{"which":"account"}`)); err != nil {
		return err
	}
	wrongRoot := *o
	wrongRoot.A.StateRoot[0] ^= 1
	if err := add("synth_a_state_root_differs", "the covered header's state root is not the one the proofs commit to", main, &wrongRoot, state("l1_state_proof_invalid", `{"which":"account"}`)); err != nil {
		return err
	}

	// ---- pins variants ----
	variant := func(id, desc string, edit func(base map[string]any), o *basefinal.SynthOut, want string) error {
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
		return add(id, desc, name, o, want)
	}
	impl := func(m map[string]any) map[string]any { return m["impl_pins"].(map[string]any) }
	healthy := build(basefinal.SynthSpec{Depth: 1})
	if err := variant("synth_pins_finality_delay_86400", "the pinned ASR implementation has a one-day finality delay: T = resolvedAt+1000 is within it",
		func(b map[string]any) {
			impl(b)[synthHashASR].(map[string]any)["finality_delay_seconds"] = json.Number("86400")
		}, healthy,
		state("game_within_finality_delay", `{"T":`+dec(healthy.A.Timestamp)+`,"delay":"86400","resolvedAt":`+dec(created+432288)+`}`)); err != nil {
		return err
	}
	identity020 := ident("game_impl", `"0xd702aae6221f36dfe7e8ebc4315d64344a9db4cb"`, mustHash(synthHash020))
	if err := variant("synth_pins_game_row_absent", "the 0.2.0 game implementation row is not pinned", func(b map[string]any) { delete(impl(b), synthHash020) }, healthy, identity020); err != nil {
		return err
	}
	for _, key := range []string{"interval_pairs", "slow_finalization_delay", "cwia", "impl", "n_intermediate", "args_len"} {
		key := key
		if err := variant("synth_pins_game_row_without_"+key, "the 0.2.0 row lacks "+key+": an incomplete row is treated as absent", func(b map[string]any) { delete(impl(b)[synthHash020].(map[string]any), key) }, healthy, identity020); err != nil {
			return err
		}
	}
	g.judgeIDs = ids
	return nil
}

func slotWord(n uint64) (w [32]byte) {
	binary.BigEndian.PutUint64(w[24:], n)
	return w
}

func mustHash(s string) (h [32]byte) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		panic("bad hash " + s)
	}
	copy(h[:], b)
	return h
}
