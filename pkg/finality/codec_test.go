// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func limitsFrom(t testing.TB, m map[string]uint64) Limits {
	t.Helper()
	l := DefaultLimits()
	for k, v := range m {
		switch k {
		case "max_evidence_bytes":
			l.MaxEvidenceBytes = int(v)
		case "max_string_bytes":
			l.MaxStringBytes = int(v)
		case "max_nodes":
			l.MaxNodes = int(v)
		case "max_node_bytes":
			l.MaxNodeBytes = int(v)
		default:
			t.Fatalf("unknown limit %q in a vector", k)
		}
	}
	return l
}

func TestContainerVectorsDecodeStrictly(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string            `json:"name"`
			Hex    string            `json:"hex"`
			Limits map[string]uint64 `json:"limits"`
			Expect string            `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readVectors(t, "containers.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) < 10 {
		t.Fatalf("only %d container vectors", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			c, err := DecodeContainer(raw, limitsFrom(t, v.Limits))
			got := ""
			if err != nil {
				got = canonOf(err)
			} else {
				got = string(canonValue(map[string]any{
					"kind": c.Header.Kind, "chain": c.Header.Chain, "level": uint64(c.Header.Level), "blockNumber": c.Header.BlockNumber,
					"blockHash": c.Header.BlockHash, "body": c.Body,
				}))
				// encode(decode(x)) == x
				again, eerr := c.Encode()
				if eerr != nil || !bytes.Equal(again, raw) {
					t.Fatalf("encode(decode(x)) != x: %v", eerr)
				}
			}
			if got != supersededExpect(v.Expect) {
				t.Fatalf("\n got  %s\n want %s", got, supersededExpect(v.Expect))
			}
		})
	}
}

// probeDecode is the test grammar of codec_probe.json: LIST<LP> || NODES || u64 || end.
func probeDecode(raw []byte, lim Limits) error {
	r := NewReader(raw, lim)
	if _, err := r.LPList("probe.list", 4, 16); err != nil {
		return err
	}
	if _, err := r.Nodes("probe.nodes", 8); err != nil {
		return err
	}
	if _, err := r.U64("probe.n"); err != nil {
		return err
	}
	return r.End("probe.end")
}

func probeEncode(t testing.TB, raw []byte) []byte {
	t.Helper()
	r := NewReader(raw, DefaultLimits())
	items, _ := r.LPList("probe.list", 4, 16)
	nodes, _ := r.Nodes("probe.nodes", 8)
	n, _ := r.U64("probe.n")
	var w Writer
	w.LPList(items)
	w.Nodes(nodes)
	w.U64(n)
	return w.Bytes()
}

func TestCodecProbeVectorsAreStrict(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string            `json:"name"`
			Hex    string            `json:"hex"`
			Limits map[string]uint64 `json:"limits"`
			Expect string            `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readVectors(t, "codec_probe.json"), &set); err != nil {
		t.Fatal(err)
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			err := probeDecode(raw, limitsFrom(t, v.Limits))
			if got := canonOf(err); got != supersededExpect(v.Expect) {
				t.Fatalf("\n got  %s\n want %s", got, supersededExpect(v.Expect))
			}
			if err == nil && !bytes.Equal(probeEncode(t, raw), raw) {
				t.Fatal("encode(decode(x)) != x")
			}
		})
	}
}

func TestNodesAreCanonicallySortedAndUnique(t *testing.T) {
	in := [][]byte{[]byte("zz"), []byte("a"), []byte("zz"), []byte("mm")}
	out := EncodeNodes(in)
	if len(out) != 3 {
		t.Fatalf("duplicates kept: %d", len(out))
	}
	for i := 1; i < len(out); i++ {
		if bytes.Compare(crypto.Keccak256(out[i-1]), crypto.Keccak256(out[i])) >= 0 {
			t.Fatal("not ascending by keccak256")
		}
	}
	var w Writer
	w.Nodes(out)
	if _, err := NewReader(w.Bytes(), DefaultLimits()).Nodes("n", 8); err != nil {
		t.Fatal(err)
	}
}

func TestEveryBoundOfSection82IsTheSpecValueAndRefusesWithTheNumber(t *testing.T) {
	l := DefaultLimits()
	got := map[string]int{
		"MaxEvidenceBytes": l.MaxEvidenceBytes, "MaxLinks": l.MaxLinks, "MaxSpineHeaders": l.MaxSpineHeaders, "MaxHeaderChain": l.MaxHeaderChain,
		"MaxL2Headers": l.MaxL2Headers, "MaxBlobsBase": l.MaxBlobsBase, "MaxBlobsArbitrum": l.MaxBlobsArbitrum, "MaxFrameTxs": l.MaxFrameTxs,
		"MaxDepositTxs": l.MaxDepositTxs, "MaxBlockTxs": l.MaxBlockTxs, "MaxNodes": l.MaxNodes, "MaxNodeBytes": l.MaxNodeBytes,
		"MaxTxLeafBytes": l.MaxTxLeafBytes, "MaxCodeBytes": l.MaxCodeBytes, "MaxCFA1Tables": l.MaxCFA1Tables, "MaxCFA1Records": l.MaxCFA1Records,
		"MaxSigners": l.MaxSigners, "MaxSegments": l.MaxSegments, "MaxUncompressedBatch": l.MaxUncompressedBatch,
	}
	// MaxEvidenceBytes (64 MiB) is the validator end of three linked figures: proofs_service MaxFinalityEvidenceBytes (134217728, two 64 MiB
	// containers) and the gateway PROOF_V2_MAX_BYTES (285212672, two of those plus the rest-of-document allowance); spec V2_SPEC_S7 8.2 (line 299).
	// Change them together.
	for k, v := range map[string]int{
		"MaxEvidenceBytes": 64 << 20, "MaxLinks": 64, "MaxSpineHeaders": 16384, "MaxHeaderChain": 32768, "MaxL2Headers": 1024,
		"MaxBlobsBase": 32, "MaxBlobsArbitrum": 16, "MaxFrameTxs": 256, "MaxDepositTxs": 4096, "MaxBlockTxs": 65536,
		"MaxNodes": 8192, "MaxNodeBytes": 4096, "MaxTxLeafBytes": 2097152, "MaxCodeBytes": 262144, "MaxCFA1Tables": 64,
		"MaxCFA1Records": 65536, "MaxSigners": 255, "MaxSegments": 102400, "MaxUncompressedBatch": 16777216,
	} {
		if got[k] != v {
			t.Errorf("%s is %d, section 8.2 says %d", k, got[k], v)
		}
	}
	// a count over its limit is refused with the number and the limit
	var w Writer
	w.U32(uint32(l.MaxNodes + 1))
	_, err := NewReader(w.Bytes(), l).Nodes("nodes", l.MaxNodeBytes)
	st := stateOf(t, err)
	if st.Code != CodeEvidenceTooLarge || st.Fields["count"] != uint64(l.MaxNodes+1) || st.Fields["limit"] != uint64(l.MaxNodes) || st.Fields["part"] != "nodes" {
		t.Fatalf("%v", err)
	}
	// a tx/receipt trie node may be as large as max_tx_leaf_bytes, a state node only max_node_bytes
	var big Writer
	big.Count(1)
	big.LP(make([]byte, l.MaxNodeBytes+1))
	if _, err := NewReader(big.Bytes(), l).Nodes("state", l.MaxNodeBytes); err == nil || stateOf(t, err).Code != CodeEvidenceTooLarge {
		t.Fatalf("an over-size state node was accepted: %v", err)
	}
	if _, err := NewReader(big.Bytes(), l).Nodes("tx", l.MaxTxLeafBytes); err != nil {
		t.Fatalf("a transaction-trie node of %d bytes was refused: %v", l.MaxNodeBytes+1, err)
	}
	huge := make([]byte, l.MaxEvidenceBytes+1)
	if _, err := DecodeContainer(huge, l); err == nil || stateOf(t, err).Code != CodeEvidenceTooLarge {
		t.Fatalf("an over-size container was not refused as too large: %v", err)
	}
}

// rlpList encodes byte strings as one RLP list (test helper; every item is a short string).
func rlpList(items [][]byte) []byte {
	var body []byte
	for _, it := range items {
		switch {
		case len(it) == 1 && it[0] < 0x80:
			body = append(body, it...)
		case len(it) <= 55:
			body = append(append(body, 0x80+byte(len(it))), it...)
		default:
			panic("test items are short")
		}
	}
	if len(body) <= 55 {
		return append([]byte{0xc0 + byte(len(body))}, body...)
	}
	return append([]byte{0xf8, byte(len(body))}, body...)
}

func TestHeadersAreReadPositionallyNotDecodedIntoATypedHeader(t *testing.T) {
	// a 23-item header (Sepolia since 2026-10-06) and a 17-item one: both read; the item count is not fixed
	build := func(items int) []byte {
		var parts [][]byte
		for i := 0; i < items; i++ {
			switch i {
			case 8:
				parts = append(parts, []byte{0x01, 0x02})
			case 11:
				parts = append(parts, []byte{0x65, 0x00, 0x00, 0x01})
			case 0, 3, 4, 5, 16:
				h := fill(byte(0x10 + i))
				parts = append(parts, h[:])
			default:
				parts = append(parts, []byte{byte(i)})
			}
		}
		return rlpList(parts)
	}
	for _, n := range []int{15, 17, 21, 23} {
		raw := build(n)
		h, err := ReadHeader(raw)
		if err != nil {
			t.Fatalf("%d items: %v", n, err)
		}
		if h.Items != n || h.Number != 0x0102 || h.Timestamp != 0x65000001 || h.StateRoot != fill(0x13) || h.ParentHash != fill(0x10) {
			t.Fatalf("%d items: %+v", n, h)
		}
		if (n >= 17) != (h.WithdrawalsRoot != nil) {
			t.Fatalf("%d items: withdrawalsRoot presence is %v", n, h.WithdrawalsRoot != nil)
		}
		if h.Hash != [32]byte(crypto.Keccak256Hash(raw)) {
			t.Fatal("hash is not keccak256 of the raw header")
		}
	}
	for name, raw := range map[string][]byte{
		"not a list":    {0x01},
		"too few items": rlpList([][]byte{{1}, {2}}),
		"trailing":      append(build(15), 0),
	} {
		if _, err := ReadHeader(raw); err == nil || stateOf(t, err).Code != CodeEvidenceMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
}
