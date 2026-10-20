// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// record2 captures the Electra/Fulu-layout objects of the finality_ethl1_v2 set once: the Fulu period-1378 update (already in
// the v1 raw capture, fetched again from both clients for byte comparison), the period-1377 update (which learns the committee
// that signs period 1378), the Fulu bootstrap of the period-start checkpoint, and the long execution spine of the legacy leg.
// Every provider text that reaches stderr or storage goes through pkg/ethrpc.RedactText.
const (
	lighthouse        = "https://ethereum-sepolia-beacon-api.publicnode.com"
	fuluCheckpoint    = "0x5f71d7f650f9252b48749b5f062c0c234e01afd69f364ab600e2b6051494b20d"
	legacyLegBlock    = 11845679
	electraUpdFixed   = 25216 // fixed part of an Electra-layout LightClientUpdate
	electraHeaderFix  = 244   // beacon(112) + offset(4) + execution_branch(4*32)
	execBlockNumberAt = 404   // block_number inside the ExecutionPayloadHeader
	execBlockHashAt   = 472
)

func redactedErr(format string, a ...any) error {
	return ethrpc.RedactError(fmt.Errorf(format, a...))
}

func getBoth(path, accept string) (lode, light []byte, err error) {
	var code int
	lode, code, err = get(lodestar+path, accept)
	if err != nil || code != 200 {
		return nil, nil, redactedErr("lodestar %s: status %d: %v: %.200s", path, code, err, lode)
	}
	light, code, err = get(lighthouse+path, accept)
	if err != nil || code != 200 {
		return nil, nil, redactedErr("lighthouse %s: status %d: %v: %.200s", path, code, err, light)
	}
	return lode, light, nil
}

// splitUpdates parses the framed /updates response: u64le length, then 4 bytes of fork digest and the SSZ object.
func splitUpdates(body []byte) ([][]byte, error) {
	var out [][]byte
	pos := 0
	for pos < len(body) {
		if pos+12 > len(body) {
			return nil, fmt.Errorf("updates frame truncated at %d", pos)
		}
		n := int(binary.LittleEndian.Uint64(body[pos : pos+8]))
		if n < 4 || pos+8+n > len(body) {
			return nil, fmt.Errorf("updates frame length %d at %d overruns", n, pos)
		}
		out = append(out, body[pos+12:pos+8+n])
		pos += 8 + n
	}
	return out, nil
}

type capture2 struct {
	CapturedUTC       string `json:"captured_utc"`
	Lodestar          string `json:"lodestar"`
	Lighthouse        string `json:"lighthouse"`
	ExecEndpoint      string `json:"exec_endpoint"`
	FuluCheckpoint    string `json:"fulu_bootstrap_block_root"`
	BootstrapBytes    int    `json:"fulu_bootstrap_bytes"`
	BootstrapSlot     uint64 `json:"fulu_bootstrap_header_slot"`
	Update1377Bytes   int    `json:"update_1377_bytes"`
	Update1378Bytes   int    `json:"update_1378_bytes"`
	LodestarEqLight   bool   `json:"lighthouse_fields_equal_lodestar_ssz"`
	Update1378EqV1    bool   `json:"update_1378_equals_v1_capture"`
	FinalizedExecNum  uint64 `json:"update_1378_finalized_exec_number"`
	FinalizedExecHash string `json:"update_1378_finalized_exec_hash"`
	LegBlock          uint64 `json:"legacy_leg_block"`
	SpineHeaders      int    `json:"legacy_spine_headers"`
	SpineBytes        int    `json:"legacy_spine_rlp_bytes"`
	SpineFileBytes    int    `json:"legacy_spine_file_bytes"`
}

// electraFinalizedExec reads the finalized header's execution number and hash from an Electra-layout LightClientUpdate.
func electraFinalizedExec(upd []byte) (num uint64, hash [32]byte, err error) {
	if len(upd) < electraUpdFixed+2*(electraHeaderFix+584) {
		return 0, hash, fmt.Errorf("update of %d bytes is not electra-layout", len(upd))
	}
	attOff := int(binary.LittleEndian.Uint32(upd[0:4]))
	finOff := int(binary.LittleEndian.Uint32(upd[electraUpdFixed-4-224-160-8 : electraUpdFixed-224-160-8]))
	if attOff != electraUpdFixed || finOff <= attOff || finOff+electraHeaderFix+584 > len(upd) {
		return 0, hash, fmt.Errorf("offsets %d,%d do not fit %d bytes", attOff, finOff, len(upd))
	}
	h := upd[finOff:]
	ex := h[electraHeaderFix:]
	num = binary.LittleEndian.Uint64(ex[execBlockNumberAt:])
	copy(hash[:], ex[execBlockHashAt:execBlockHashAt+32])
	return num, hash, nil
}

func record2(rawDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	c := capture2{CapturedUTC: time.Now().UTC().Format(time.RFC3339), Lodestar: lodestar, Lighthouse: lighthouse, ExecEndpoint: publicnode, FuluCheckpoint: fuluCheckpoint, LegBlock: legacyLegBlock}

	lo, li, err := getBoth("/eth/v1/beacon/light_client/bootstrap/"+fuluCheckpoint, "application/octet-stream")
	if err != nil {
		return err
	}
	if err := crossCheckBootstrap(lo, li); err != nil {
		return err
	}
	c.BootstrapBytes = len(lo)
	c.BootstrapSlot = binary.LittleEndian.Uint64(lo[4+24624+192 : 4+24624+192+8]) // the header follows the fixed part
	if err := os.WriteFile(filepath.Join(outDir, "bootstrap_fulu.ssz"), lo, 0o644); err != nil {
		return err
	}

	lo, li, err = getBoth("/eth/v1/beacon/light_client/updates?start_period=1377&count=2", "application/octet-stream")
	if err != nil {
		return err
	}
	parts, err := splitUpdates(lo)
	if err != nil || len(parts) != 2 {
		return redactedErr("updates 1377-1378: %d parts: %v", len(parts), err)
	}
	if err := crossCheckUpdates(parts, li); err != nil {
		return err
	}
	c.LodestarEqLight = true
	for i, name := range []string{"update_1377.ssz", "update_1378.ssz"} {
		if err := os.WriteFile(filepath.Join(outDir, name), parts[i], 0o644); err != nil {
			return err
		}
	}
	c.Update1377Bytes, c.Update1378Bytes = len(parts[0]), len(parts[1])
	if v1, err := os.ReadFile(filepath.Join(rawDir, "updates", "1378.ssz")); err == nil {
		c.Update1378EqV1 = bytes.Equal(v1, parts[1])
	}
	num, hash, err := electraFinalizedExec(parts[1])
	if err != nil {
		return err
	}
	c.FinalizedExecNum, c.FinalizedExecHash = num, "0x"+hex.EncodeToString(hash[:])
	if num < legacyLegBlock {
		return fmt.Errorf("period 1378 update finalizes execution block %d, below the legacy leg %d", num, legacyLegBlock)
	}

	// the long spine, newest first, in JSON-RPC batches of 50 by number; each rebuilt RLP must hash to the node's hash and the
	// parent links must close.
	count := int(num-legacyLegBlock) + 1
	var rlpBytes int
	want := c.FinalizedExecHash
	var n uint64 = num
	var blob bytes.Buffer
	blob.Write(binary.BigEndian.AppendUint32(nil, uint32(count)))
	for done := 0; done < count; {
		batch := 20
		if count-done < batch {
			batch = count - done
		}
		var reqs []map[string]any
		for k := 0; k < batch; k++ {
			reqs = append(reqs, map[string]any{"jsonrpc": "2.0", "id": k, "method": "eth_getBlockByNumber", "params": []any{fmt.Sprintf("0x%x", n-uint64(k)), false}})
		}
		var results []struct {
			ID     int            `json:"id"`
			Result map[string]any `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		var rerr error
		for try := 0; try < 12; try++ {
			body, _ := json.Marshal(reqs)
			resp, err := httpc.Post(publicnode, "application/json", bytes.NewReader(body))
			if err != nil {
				rerr = redactedErr("batch at %d: %v", n, err)
				time.Sleep(time.Duration(try+1) * 2 * time.Second)
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			results = nil
			if err := json.Unmarshal(b, &results); err != nil || len(results) != batch {
				rerr = redactedErr("batch at %d: status %d: decode: %v: %.200s", n, resp.StatusCode, err, b)
				time.Sleep(time.Duration(try+1) * 2 * time.Second)
				continue
			}
			rerr = nil
			for _, r := range results {
				if r.Error != nil || r.Result == nil {
					msg := "null result"
					if r.Error != nil {
						msg = r.Error.Message
					}
					rerr = redactedErr("block %d not served: %s", n-uint64(r.ID), msg)
					break
				}
			}
			if rerr != nil {
				time.Sleep(time.Duration(try+1) * 4 * time.Second)
				continue
			}
			break
		}
		if rerr != nil {
			return rerr
		}
		byID := map[int]map[string]any{}
		for _, r := range results {
			if r.Error != nil || r.Result == nil {
				msg := ""
				if r.Error != nil {
					msg = r.Error.Message
				}
				return redactedErr("block %d not served: %s", n-uint64(r.ID), msg)
			}
			byID[r.ID] = r.Result
		}
		for k := 0; k < batch; k++ {
			m := byID[k]
			raw, err := headerFromBlock(m)
			if err != nil {
				return err
			}
			got := "0x" + hex.EncodeToString(keccak(raw))
			if got != want || got != m["hash"] {
				return fmt.Errorf("block %d: rebuilt header hashes to %s, expected %s (node says %v)", n-uint64(k), got, want, m["hash"])
			}
			blob.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw))))
			blob.Write(raw)
			rlpBytes += len(raw)
			want, _ = m["parentHash"].(string)
		}
		n -= uint64(batch)
		time.Sleep(400 * time.Millisecond)
		done += batch
	}
	c.SpineHeaders, c.SpineBytes, c.SpineFileBytes = count, rlpBytes, blob.Len()
	if err := os.WriteFile(filepath.Join(outDir, "spine_legacy.bin"), blob.Bytes(), 0o644); err != nil {
		return err
	}
	cj, _ := json.MarshalIndent(c, "", " ")
	return os.WriteFile(filepath.Join(outDir, "capture2.json"), cj, 0o644)
}
