// Copyright 2026 Certen Protocol

package lcssz

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The lcssz cases of the published set finality_eth_sepolia3 (review V-C2-A1 D3): a shape is a length and two offsets, the rest zero,
// with the execution hash and number planted where an electra finalized header carries them.
func TestEverySet3LcsszCaseGivesItsVerdict(t *testing.T) {
	dir := filepath.Join("..", "ethsepolia", "testdata", "finality_eth_sepolia3", "lcssz")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, en.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			ID         string `json:"id"`
			Len        int    `json:"len"`
			AttOff     int    `json:"att_off"`
			FinOff     int    `json:"fin_off"`
			ExecHash   string `json:"exec_hash"`
			ExecNumber uint64 `json:"exec_number"`
			Expect     string `json:"expect"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		fu := make([]byte, c.Len)
		binary.LittleEndian.PutUint32(fu, uint32(c.AttOff))
		binary.LittleEndian.PutUint32(fu[4:], uint32(c.FinOff))
		if c.ExecHash != "" {
			h, err := hex.DecodeString(strings.TrimPrefix(c.ExecHash, "0x"))
			if err != nil {
				t.Fatal(err)
			}
			ex := fu[c.FinOff+electraHeaderFixed:]
			copy(ex[electraExecHashAt:], h)
			binary.LittleEndian.PutUint64(ex[electraExecNumberAt:], c.ExecNumber)
		}
		mustNotPanic(t, c.ID, func() {
			hash, number, has, err := FinalizedExec(Electra, fu)
			switch c.Expect {
			case "ok":
				if err != nil || !has || number != c.ExecNumber || "0x"+hex.EncodeToString(hash[:]) != c.ExecHash {
					t.Errorf("%s: %x %d %v %v", c.ID, hash, number, has, err)
				}
			case "finalized_header_too_short":
				if !errors.Is(err, ErrFinalizedHeaderTooShort) {
					t.Errorf("%s: %v", c.ID, err)
				}
				if _, _, _, serr := FinalityUpdateSlots(Electra, fu); serr != nil {
					t.Errorf("%s: the shape must be one FinalityUpdateSlots accepts: %v", c.ID, serr)
				}
			case "invalid":
				if err == nil || errors.Is(err, ErrFinalizedHeaderTooShort) {
					t.Errorf("%s: %v", c.ID, err)
				}
			default:
				t.Errorf("%s: expect %q", c.ID, c.Expect)
			}
		})
	}
	if len(ents) != 5 {
		t.Fatalf("%d lcssz cases, want 5", len(ents))
	}
}
