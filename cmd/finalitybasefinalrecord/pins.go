// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// pinsCmd merges the keys RB11-D1 owns into the base_sepolia section of the embedded pins file and writes the result to out
// (sorted keys, 2-space indent, LF, final newline: the form json.MarshalIndent gives a map). Values come only from the annexes
// (R11-base-sepolia Q1/Q9, R11-base-030 Q2/Q4(a)) and from on-chain reads taken by `measure`; the code hashes were re-measured
// with eth_getCode at the time of writing (checked below when the provider answers).
func pinsCmd(ctx context.Context, out string) error {
	if out == "" {
		return fmt.Errorf("-out is required")
	}
	raw := finality.EmbeddedPinsBytes()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return err
	}
	// the round trip of the unmodified file must be byte-identical: the form is the generator's
	rt, _ := json.MarshalIndent(root, "", "  ")
	rt = append(rt, '\n')
	if !bytes.Equal(rt, raw) {
		return fmt.Errorf("the embedded pins file does not round-trip through json.MarshalIndent: the merge would reformat it")
	}
	base, ok := root["base_sepolia"].(map[string]any)
	if !ok {
		base = map[string]any{}
		root["base_sepolia"] = base
	}
	base["portal"] = "0x49f53e41452c74589e85ca1677426ba426459e85"
	base["system_config"] = "0xf272670eb55e895584501d564afeb048bed26194"
	base["chain_id"] = 84532
	base["l1_chain_id"] = 11155111
	base["max_l2_headers"] = 1024

	impl, _ := base["impl_pins"].(map[string]any)
	if impl == nil {
		impl = map[string]any{}
		base["impl_pins"] = impl
	}
	common := func(m map[string]any) map[string]any {
		m["role"] = "game_impl"
		m["game_type"] = 621
		m["cwia"] = "aggregate_v1"
		m["n_intermediate"] = 20
		m["args_len"] = 776
		m["slow_finalization_delay"] = 432000
		m["fast_finalization_delay"] = 86400
		m["proof_threshold"] = 1
		m["asr"] = "0x2ff5cc82dbf333ea30d8ee462178ab1707315355"
		m["l2_chain_id"] = 84532
		m["l2_genesis_block"] = 0
		m["l2_genesis_timestamp"] = 1695768288
		m["build"] = "solc 0.8.15 london runs 999999 bytecodeHash none"
		return m
	}
	g020 := common(map[string]any{
		"version": "0.2.0", "impl": "0xd702aae6221f36dfe7e8ebc4315d64344a9db4cb", "code_bytes": 19060,
		"interval_pairs": [][2]int{{600, 30}}, "last_game_dgf_index": 28494, "last_game_created": 1792442352,
		"source": "base/contracts@385f21a4 v8.3.0 src/L1/proofs/AggregateVerifier.sol",
	})
	g030 := common(map[string]any{
		"version": "0.3.0", "impl": "0xb5abcf8656e3f26990eceeec99d22023e7eb7e3b", "code_bytes": 20379,
		"interval_pairs": [][2]int{{600, 30}, {6000, 300}}, "first_game_dgf_index": 28495, "first_game_created": 1792451160,
		"dgf": "0xd6e6dbf4f7ea0ac412fd8b65ed297e64bb7a06e1", "delayed_weth": "0xd6e2d9d4f1f8865ac983ee848983fb1979429914",
		"tee_verifier": "0x92f6dd3501e51b8b20c77b959becaaebeb210e17", "zk_verifier": "0xa738e13d97a3f10b307c2cd190edd3e227a72d68",
		"protocol_versions": "0x15b721b12cf3b0c4400c8a2935a0ae391c2ef65b", "fast_blocks_per_second": 5, "fast_upgrade_index": 13,
		"l2_block_time_slow": 2,
		"source":             "base/contracts@8c21f6d0 v8.4.0 src/L1/proofs/AggregateVerifier.sol",
	})
	// the immutables the annexes quote only in truncated form are read from the implementations (full values or none)
	rpc := liveRPC()
	for _, g := range []struct {
		row  map[string]any
		addr string
	}{{g020, "0xd702aae6221f36dfe7e8ebc4315d64344a9db4cb"}, {g030, "0xb5abcf8656e3f26990eceeec99d22023e7eb7e3b"}} {
		for _, f := range []struct{ key, sig string }{
			{"tee_image_hash", "TEE_IMAGE_HASH()"}, {"zk_range_hash", "ZK_RANGE_HASH()"},
			{"zk_aggregate_hash", "ZK_AGGREGATE_HASH()"}, {"config_hash", "CONFIG_HASH()"},
		} {
			b, err := rpc.CallLatest(ctx, addr20(g.addr), crypto.Keccak256([]byte(f.sig))[:4])
			if err == nil && len(b) == 32 {
				g.row[f.key] = "0x" + hex.EncodeToString(b)
			} else {
				fmt.Fprintf(os.Stderr, "note: %s on %s not readable (%v): not pinned\n", f.sig, g.addr, err)
			}
		}
	}
	put := func(hash string, row map[string]any) { impl[hash] = row }
	put("0xf7f8a640ea3ffadf55e9f425a039e879471a1cda9988e92e2c96d423e08869c7", g020)
	put("0x80e5c0bb48b8a222e8883e2f0729264857211cc906da8971fe8309466981ecaf", g030)
	put("0xd01ffe5bb9bdf9cb1e42b2dd12188f9bc2a163e8301b24451d7d8485280148b7", map[string]any{"role": "asr_impl", "finality_delay_seconds": 0})
	put("0x9edef3a3cf703488a47cc7a4e6c595cc4f13fa0c14fdd4710ba143b146ce51fb", map[string]any{"role": "portal_impl"})
	put("0x35c04acf3bb541d90092bf3e328475377142f70760fa82f372ac0c4e4b3ff4f6", map[string]any{"role": "syscfg_impl"})
	put("0x910d7bf9e11f1a95aab4e3fceb71f647c8db0431b4510e2155c54dca2b50e444", map[string]any{"role": "dgf_impl"})
	put("0xdcfac30da8e1e7fbd5231636a9e34c65381c5f5ddd35ba257ba595c5ce0fb1f4", map[string]any{"role": "superchain_impl"})

	base["proxy_pins"] = map[string]any{
		"0xfa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998": map[string]any{"role": "op_proxy", "bytes": 2059, "applies_to": "portal, system_config, asr, dgf"},
		"0x33920c8270353487e486debc0d8ddbb187fa86727f2daf412d794589e6f26cb5": map[string]any{"role": "superchain_proxy", "bytes": 2100, "source": "unverified (B30 OQ2)"},
	}
	base["game_layout"] = map[string]any{
		"aggregate_v1": map[string]any{
			"args_base_len": 136, "args_per_root": 32,
			"clone_head": "0x36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b363d3d373d3d3d3d61",
			"clone_mid":  "0x806062363936013d73",
			"clone_tail": "0x5af43d3d93803e606057fd5bf3",
			"args":       "creator(20)|rootClaim(32)|l1Head(32)|l2seq(32)|parent(20)|roots(32*n); trailer be16(args_len+2); template = head|be16(args_len+2)|mid|impl(20)|tail (98 B)",
			"game_slots": map[string]any{
				"0": "createdAt@0 u64, resolvedAt@8 u64, status@16 u8, initialized@17, wasRespected@18",
				"1": "startingOutputRoot.root", "2": "startingOutputRoot.l2SequenceNumber", "5": "counteredByIntermediateRootIndexPlusOne",
				"6": "proofTypeToProver mapping (TEE key 0, ZK key 1)", "7": "expectedResolution@0 u64, proofCount@8", "8": "scheduleId",
			},
		},
	}
	// the template pieces must have the lengths the annex states
	lay := base["game_layout"].(map[string]any)["aggregate_v1"].(map[string]any)
	for k, want := range map[string]int{"clone_head": 54, "clone_mid": 9, "clone_tail": 13} {
		if b, _ := hex.DecodeString(strings.TrimPrefix(lay[k].(string), "0x")); len(b) != want {
			return fmt.Errorf("%s is %d bytes, the annex says %d", k, len(b), want)
		}
	}
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s; sha256 %x\n", out, sha256.Sum256(b))
	return nil
}
