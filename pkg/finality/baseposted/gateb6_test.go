// Copyright 2026 Certen Protocol

package baseposted

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func baseSection(t *testing.T) map[string]any {
	t.Helper()
	fp, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(fp.Sections["base_sepolia"], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func pinsWith(t *testing.T, m map[string]any) *finality.Pins {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return &finality.Pins{Sections: map[string]json.RawMessage{"base_sepolia": raw}}
}

func TestParsePinsReadsTheBaseSectionAndNamesTheKeyOfEveryBadValue(t *testing.T) {
	good := baseSection(t)
	bp, err := ParsePins(pinsWith(t, good))
	if err != nil {
		t.Fatal(err)
	}
	num := func(k string) uint64 { return uint64(good[k].(float64)) }
	if bp.ChainID != num("chain_id") || bp.L1ChainID != num("l1_chain_id") || bp.SeqWindowSize != num("seq_window_size") || bp.ChannelTimeout != num("channel_timeout") ||
		bp.MaxRLPBytesPerChannel != num("max_rlp_bytes_per_channel") || bp.IsthmusTime != num("isthmus_time") || bp.DenimTime != num("denim_time") ||
		uint64(bp.MaxBlobs) != num("max_blobs") || bp.L2GenesisTime != num("l2_genesis_time") || bp.L2BlockTime != num("l2_block_time") ||
		bp.KZGSetupSHA256 != good["kzg_setup_sha256"].(string) || len(bp.SystemConfigImplHashes) == 0 {
		t.Fatalf("%+v", bp)
	}
	if "0x"+common20(bp.SystemConfig) != strings.ToLower(good["system_config"].(string)) || "0x"+common20(bp.BatchInbox) != strings.ToLower(good["batch_inbox"].(string)) {
		t.Fatalf("addresses %x %x", bp.SystemConfig, bp.BatchInbox)
	}
	// a section that is absent, and no pins at all
	_, err = ParsePins(&finality.Pins{})
	wantCode(t, err, finality.CodePinUnknown, map[string]string{"kind": "base_sepolia"})
	_, err = ParsePins(nil)
	wantCode(t, err, finality.CodePinUnknown, map[string]string{"kind": "base_sepolia"})
	// a section that is not an object
	_, err = ParsePins(&finality.Pins{Sections: map[string]json.RawMessage{"base_sepolia": json.RawMessage(`[1]`)}})
	wantCode(t, err, finality.CodePinsCorrupt, map[string]string{"key": "base_sepolia"})
	// upper-case hex is read as the same address, a mixed-case one too
	up := baseSection(t)
	up["system_config"] = "0x" + strings.ToUpper(good["system_config"].(string)[2:])
	up["batch_inbox"] = "0x" + strings.ToUpper(good["batch_inbox"].(string)[2:])
	if bp2, err := ParsePins(pinsWith(t, up)); err != nil || bp2.SystemConfig != bp.SystemConfig || bp2.BatchInbox != bp.BatchInbox {
		t.Fatalf("upper-case addresses: %v", err)
	}
	cases := []struct {
		key  string
		edit func(m map[string]any)
	}{
		{"chain_id", func(m map[string]any) { m["chain_id"] = 1 }},
		{"l1_chain_id", func(m map[string]any) { m["l1_chain_id"] = 1 }},
		{"system_config", func(m map[string]any) { m["system_config"] = "0x1234" }},
		{"system_config", func(m map[string]any) { m["system_config"] = "f272670eb55e895584501d564afeb048bed26194" }},
		{"system_config", func(m map[string]any) { m["system_config"] = "0xzz72670eb55e895584501d564afeb048bed26194" }},
		{"batch_inbox", func(m map[string]any) { m["batch_inbox"] = "0x12" }},
		{"seq_window_size", func(m map[string]any) { m["seq_window_size"] = 0 }},
		{"channel_timeout", func(m map[string]any) { m["channel_timeout"] = 0 }},
		{"max_rlp_bytes_per_channel", func(m map[string]any) { m["max_rlp_bytes_per_channel"] = 0 }},
		{"l2_genesis_time", func(m map[string]any) { m["l2_genesis_time"] = 0 }},
		{"l2_block_time", func(m map[string]any) { m["l2_block_time"] = 0 }},
		{"isthmus_time", func(m map[string]any) { m["isthmus_time"] = 0 }},
		{"denim_time", func(m map[string]any) { m["denim_time"] = 0 }},
		{"max_blobs", func(m map[string]any) { m["max_blobs"] = 0 }},
		{"max_blobs", func(m map[string]any) { m["max_blobs"] = -1 }},
		{"kzg_setup_sha256", func(m map[string]any) { m["kzg_setup_sha256"] = "ab" }},
		{"kzg_setup_sha256", func(m map[string]any) { m["kzg_setup_sha256"] = strings.ToUpper(good["kzg_setup_sha256"].(string)) }},
		{"kzg_setup_sha256", func(m map[string]any) { m["kzg_setup_sha256"] = strings.Repeat("zz", 32) }},
		{"impl_pins", func(m map[string]any) { m["impl_pins"] = map[string]any{"0x12": map[string]any{"role": "syscfg_impl"}} }},
		{"impl_pins", func(m map[string]any) {
			m["impl_pins"] = map[string]any{"0x" + strings.Repeat("ab", 32): 7}
		}},
		{"impl_pins", func(m map[string]any) {
			m["impl_pins"] = map[string]any{"0x" + strings.Repeat("ab", 32): map[string]any{"role": "something_else"}}
		}},
		{"impl_pins", func(m map[string]any) { delete(m, "impl_pins") }},
	}
	for i, c := range cases {
		m := baseSection(t)
		c.edit(m)
		_, err := ParsePins(pinsWith(t, m))
		wantCode(t, err, finality.CodePinsCorrupt, map[string]string{"key": "base_sepolia." + c.key})
		_ = i
	}
	// max_blobs of 1 is a pin, and an impl row of another role is not counted
	m := baseSection(t)
	m["max_blobs"] = 1
	rows := m["impl_pins"].(map[string]any)
	rows["0x"+strings.Repeat("cd", 32)] = map[string]any{"role": "other_role"}
	bp3, err := ParsePins(pinsWith(t, m))
	if err != nil || bp3.MaxBlobs != 1 || len(bp3.SystemConfigImplHashes) != len(bp.SystemConfigImplHashes) || bp3.SystemConfigImplHashes[[32]byte{0xcd, 0xcd}] {
		t.Fatalf("%+v %v", bp3, err)
	}
}

func common20(a [20]byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 40)
	for i, b := range a {
		out[2*i], out[2*i+1] = hexd[b>>4], hexd[b&0xf]
	}
	return string(out)
}

func TestTheFrameworkSepoliaPinsBecomeTheL1HeadVerifiersPinsFieldForField(t *testing.T) {
	pinsRaw, err := ReadFile(setDir, "pins/main.json") // the Sepolia ledger of the published set has anchors
	if err != nil {
		t.Fatal(err)
	}
	fp, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	es, err := fp.Sepolia()
	if err != nil {
		t.Fatal(err)
	}
	got := EthL1Pins(fp)
	if got.Network.ChainID != es.ChainID || got.MinParticipants != es.MinParticipants || got.MaxLinks != es.MaxLinks || got.MaxSpineHeaders != es.MaxSpineHeaders ||
		len(got.Network.Forks) != len(es.Forks) || len(got.Anchors) != len(es.Anchors) || len(es.Forks) == 0 || len(es.Anchors) == 0 {
		t.Fatalf("%+v", got)
	}
	hx := func(b []byte) string { return "0x" + common20Bytes(b) }
	if hx(got.Network.GenesisValidatorsRoot[:]) != es.GenesisValidatorsRoot {
		t.Fatalf("genesis validators root %s", hx(got.Network.GenesisValidatorsRoot[:]))
	}
	layouts := map[string]ethl1.Layout{"electra": ethl1.LayoutElectra, "gloas": ethl1.LayoutGloas}
	var sawLayout, sawNone bool
	for i, f := range es.Forks {
		g := got.Network.Forks[i]
		if g.Name != f.Name || g.Epoch != f.Epoch || hx(g.Version[:]) != f.Version {
			t.Errorf("fork %d: %+v vs %+v", i, g, f)
		}
		want := ethl1.LayoutNone
		if f.Layout != nil {
			want = layouts[*f.Layout]
			sawLayout = true
		} else {
			sawNone = true
		}
		if g.Layout != want {
			t.Errorf("fork %s: layout %v, want %v", f.Name, g.Layout, want)
		}
	}
	if !sawLayout || !sawNone {
		t.Fatalf("test assumption: the embedded forks include forks with and without a layout (%v %v)", sawLayout, sawNone)
	}
	var sawBlock, sawNoBlock bool
	for i, a := range es.Anchors {
		g := got.Anchors[i]
		if g.Period != a.Period || g.WSPEpochs != a.WspEpochs || hx(g.CommitteeRoot[:]) != a.CommitteeRoot {
			t.Errorf("anchor %d: %+v vs %+v", i, g, a)
		}
		if a.BlockRoot != "" {
			sawBlock = true
			if g.BlockRoot == nil || hx(g.BlockRoot[:]) != a.BlockRoot {
				t.Errorf("anchor %d block root", i)
			}
		} else {
			sawNoBlock = true
			if g.BlockRoot != nil {
				t.Errorf("anchor %d: a block root where there is none", i)
			}
		}
	}
	if !sawBlock && !sawNoBlock {
		t.Fatal("no anchors")
	}
	// pins without a Sepolia section give the zero pins
	if z := EthL1Pins(&finality.Pins{}); z.Network.ChainID != 0 || len(z.Anchors) != 0 {
		t.Fatalf("%+v", z)
	}
}

func common20Bytes(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, x := range b {
		out[2*i], out[2*i+1] = hexd[x>>4], hexd[x&0xf]
	}
	return string(out)
}

func TestStateOfKeepsTheCodeAndFieldsOfAnL1FaultAndPassesOtherErrorsThrough(t *testing.T) {
	f := ethl1.BlockNotCovered(7, 9)
	err := stateOf(f)
	se, ok := finality.AsNamed(err)
	if !ok || se.Code != f.Code || len(se.Fields) != len(f.Fields) {
		t.Fatalf("%v", err)
	}
	for k, v := range f.Fields {
		if se.Fields[k] != v {
			t.Errorf("field %s: %v vs %v", k, se.Fields[k], v)
		}
	}
	other := errors.New("not a fault")
	if got := stateOf(other); got != other {
		t.Fatalf("%v", got)
	}
}
