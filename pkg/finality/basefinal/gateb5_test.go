// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/hex"
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

func hexOf(a [20]byte) string { return "0x" + hex.EncodeToString(a[:]) }

func wantPinsCorrupt(t *testing.T, name string, err error, key string) {
	t.Helper()
	want := string(finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia."+key).Canonical())
	if key == "" {
		want = string(finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia").Canonical())
	}
	if got := canonOf(t, err); got != want {
		t.Errorf("%s:\n got %s\nwant %s", name, got, want)
	}
}

func TestParsePinsReadsTheBaseSectionAndNamesTheKeyOfEveryBadValue(t *testing.T) {
	good := baseSection(t)
	bp, err := ParsePins(pinsWith(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if bp.ChainID != uint64(good["chain_id"].(float64)) || bp.L1ChainID != uint64(good["l1_chain_id"].(float64)) || bp.MaxL2Headers != int(good["max_l2_headers"].(float64)) ||
		hexOf(bp.Portal) != good["portal"].(string) || hexOf(bp.SystemConfig) != good["system_config"].(string) ||
		len(bp.Impl) != len(good["impl_pins"].(map[string]any)) || len(bp.Proxy) != len(good["proxy_pins"].(map[string]any)) || len(bp.Layouts) != len(good["game_layout"].(map[string]any)) {
		t.Fatalf("%+v", bp)
	}
	// an absent section, no pins at all, a section that is no object
	canonUnknown := string(finality.NewState(finality.CodePinUnknown, "chain", uint64(Chain), "kind", "base_sepolia").Canonical())
	for name, p := range map[string]*finality.Pins{"empty": {}, "nil": nil} {
		_, err := ParsePins(p)
		if got := canonOf(t, err); got != canonUnknown {
			t.Errorf("%s: %s", name, got)
		}
	}
	_, err = ParsePins(&finality.Pins{Sections: map[string]json.RawMessage{"base_sepolia": json.RawMessage(`[1]`)}})
	wantPinsCorrupt(t, "section not an object", err, "")

	row := func(m map[string]any, k string) map[string]any {
		return m["impl_pins"].(map[string]any)[k].(map[string]any)
	}
	var gameKey, proxyKey string
	for k, v := range good["impl_pins"].(map[string]any) {
		if v.(map[string]any)["role"] == RoleGameImpl {
			gameKey = k
		}
	}
	for k := range good["proxy_pins"].(map[string]any) {
		proxyKey = k
	}
	layName := ""
	for k := range good["game_layout"].(map[string]any) {
		layName = k
	}
	lay := func(m map[string]any) map[string]any {
		return m["game_layout"].(map[string]any)[layName].(map[string]any)
	}
	upper := func(s string) string { return "0x" + strings.ToUpper(s[2:]) }
	cases := []struct {
		key  string
		edit func(m map[string]any)
	}{
		{"chain_id", func(m map[string]any) { m["chain_id"] = 1 }},
		{"l1_chain_id", func(m map[string]any) { m["l1_chain_id"] = 1 }},
		{"portal", func(m map[string]any) { m["portal"] = "0x12" }},
		{"portal", func(m map[string]any) { m["portal"] = good["portal"].(string)[2:] }},
		{"portal", func(m map[string]any) { m["portal"] = upper(good["portal"].(string)) }},
		{"portal", func(m map[string]any) { m["portal"] = "0x" + strings.Repeat("zz", 20) }},
		{"system_config", func(m map[string]any) { m["system_config"] = "0x12" }},
		{"system_config", func(m map[string]any) { m["system_config"] = upper(good["system_config"].(string)) }},
		{"max_l2_headers", func(m map[string]any) { m["max_l2_headers"] = 0 }},
		{"max_l2_headers", func(m map[string]any) { m["max_l2_headers"] = -1 }},
		{"impl_pins", func(m map[string]any) { m["impl_pins"].(map[string]any)["0x12"] = map[string]any{"role": "x"} }},
		{"impl_pins", func(m map[string]any) { m["impl_pins"].(map[string]any)[upper(gameKey)] = map[string]any{"role": "x"} }},
		{"impl_pins", func(m map[string]any) { m["impl_pins"].(map[string]any)["0x"+strings.Repeat("ab", 32)] = 7 }},
		{"impl_pins", func(m map[string]any) {
			m["impl_pins"].(map[string]any)["0x"+strings.Repeat("ab", 32)] = map[string]any{"version": "1"}
		}},
		{"proxy_pins", func(m map[string]any) { m["proxy_pins"].(map[string]any)["0x12"] = map[string]any{"role": "x"} }},
		{"proxy_pins", func(m map[string]any) { m["proxy_pins"].(map[string]any)["0x"+strings.Repeat("ab", 32)] = 7 }},
		{"proxy_pins", func(m map[string]any) {
			m["proxy_pins"].(map[string]any)["0x"+strings.Repeat("ab", 32)] = map[string]any{"version": "1"}
		}},
		{"game_layout", func(m map[string]any) { lay(m)["clone_head"] = "ab" }},
		{"game_layout", func(m map[string]any) { lay(m)["clone_head"] = upper(lay(m)["clone_head"].(string)) }},
		{"game_layout", func(m map[string]any) { lay(m)["clone_mid"] = "0xzz" }},
		{"game_layout", func(m map[string]any) { lay(m)["clone_tail"] = "0xabc" }},
		{"game_layout", func(m map[string]any) { lay(m)["args_base_len"] = 0 }},
		{"game_layout", func(m map[string]any) { lay(m)["args_per_root"] = 0 }},
		{"game_layout", func(m map[string]any) { lay(m)["args_per_root"] = -1 }},
		// the judge and the builder index the fixed args up to byte 136 (the parent address at [116,136)) and read a 32-byte root per
		// intermediate root: a layout that cannot hold them is refused when the pins are read, not when a game is judged
		{"game_layout", func(m map[string]any) { lay(m)["args_base_len"] = 135 }},
		{"game_layout", func(m map[string]any) { lay(m)["args_base_len"] = 1 }},
		{"game_layout", func(m map[string]any) { lay(m)["args_per_root"] = 31 }},
		{"game_layout", func(m map[string]any) { lay(m)["args_per_root"] = 1 }},
	}
	for i, c := range cases {
		m := baseSection(t)
		c.edit(m)
		_, err := ParsePins(pinsWith(t, m))
		wantPinsCorrupt(t, "case "+string(rune('a'+i)), err, c.key)
	}
	// what is accepted: a max of 1, a row whose impl address is unreadable (the row is then incomplete, not an error), a row without
	// a game type, an empty layout part
	m := baseSection(t)
	m["max_l2_headers"] = 1
	row(m, gameKey)["impl"] = "garbage"
	delete(row(m, gameKey), "game_type")
	m["proxy_pins"].(map[string]any)[proxyKey] = map[string]any{"role": "renamed"}
	lay(m)["clone_mid"] = "0x"
	bp2, err := ParsePins(pinsWith(t, m))
	if err != nil || bp2.MaxL2Headers != 1 {
		t.Fatalf("%v", err)
	}
	var k [32]byte
	kb, _ := hex.DecodeString(gameKey[2:])
	copy(k[:], kb)
	if r := bp2.Impl[k]; r.Impl != [20]byte{} || r.GameType != 0 || r.Role != RoleGameImpl || r.Complete(bp2.Layouts) {
		t.Errorf("%+v", r)
	}
	var pk [32]byte
	pb, _ := hex.DecodeString(proxyKey[2:])
	copy(pk[:], pb)
	if bp2.Proxy[pk] != "renamed" || len(bp2.Layouts[layName].CloneMid) != 0 {
		t.Errorf("%v %+v", bp2.Proxy[pk], bp2.Layouts[layName])
	}
	// every field of a row is carried over
	r0 := bp.Impl[k]
	rr := row(good, gameKey)
	if r0.Version != rr["version"].(string) || r0.CWIA != rr["cwia"].(string) || r0.NIntermediate != int(rr["n_intermediate"].(float64)) || r0.ArgsLen != int(rr["args_len"].(float64)) ||
		r0.SlowDelay != uint64(rr["slow_finalization_delay"].(float64)) || r0.FastDelay != uint64(rr["fast_finalization_delay"].(float64)) || r0.GameType != uint32(rr["game_type"].(float64)) ||
		len(r0.IntervalPairs) != len(rr["interval_pairs"].([]any)) || hexOf(r0.Impl) != rr["impl"].(string) {
		t.Errorf("%+v", r0)
	}
}

func TestACompleteGameRowNeedsEveryDecodedImmutableTheLayoutAndSoundIntervalPairs(t *testing.T) {
	p := loadPins(t)
	var row ImplRow
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Complete(p.Layouts) {
			row = r
		}
	}
	if row.Role == "" {
		t.Fatal("no complete game row in the pins")
	}
	mod := func(f func(r *ImplRow)) bool {
		r := row
		r.IntervalPairs = append([][2]uint64(nil), row.IntervalPairs...)
		f(&r)
		return r.Complete(p.Layouts)
	}
	for name, f := range map[string]func(r *ImplRow){
		"another role":        func(r *ImplRow) { r.Role = RolePortalImpl },
		"no game type":        func(r *ImplRow) { r.GameType = 0 },
		"no version":          func(r *ImplRow) { r.Version = "" },
		"no impl address":     func(r *ImplRow) { r.Impl = [20]byte{} },
		"no intermediate":     func(r *ImplRow) { r.NIntermediate = 0 },
		"negative":            func(r *ImplRow) { r.NIntermediate = -1 },
		"no pairs":            func(r *ImplRow) { r.IntervalPairs = nil },
		"no slow delay":       func(r *ImplRow) { r.SlowDelay = 0 },
		"no fast delay":       func(r *ImplRow) { r.FastDelay = 0 },
		"unknown layout":      func(r *ImplRow) { r.CWIA = "nope" },
		"args one too long":   func(r *ImplRow) { r.ArgsLen++ },
		"args one too short":  func(r *ImplRow) { r.ArgsLen-- },
		"pair total zero":     func(r *ImplRow) { r.IntervalPairs[0][0] = 0 },
		"pair interval zero":  func(r *ImplRow) { r.IntervalPairs[0][1] = 0 },
		"pair not a multiple": func(r *ImplRow) { r.IntervalPairs[0][0]++ },
		"a later bad pair":    func(r *ImplRow) { r.IntervalPairs = append(r.IntervalPairs, [2]uint64{0, 5}) },
	} {
		if mod(f) {
			t.Errorf("%s: the row is still complete", name)
		}
	}
	if !mod(func(r *ImplRow) {}) || !mod(func(r *ImplRow) { r.GameType = 1 }) || !mod(func(r *ImplRow) { r.IntervalPairs = append(r.IntervalPairs, [2]uint64{10, 5}) }) {
		t.Error("a complete row was refused")
	}
}

func TestTheFrameworkSepoliaPinsBecomeTheL1HeadVerifiersPinsFieldForField(t *testing.T) {
	pinsRaw, err := ReadFile(setDir, "pins/main.json")
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
	hx := func(b []byte) string { return "0x" + hex.EncodeToString(b) }
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
		t.Fatalf("test assumption: the forks include some with and some without a layout (%v %v)", sawLayout, sawNone)
	}
	for i, a := range es.Anchors {
		g := got.Anchors[i]
		if g.Period != a.Period || g.WSPEpochs != a.WspEpochs || hx(g.CommitteeRoot[:]) != a.CommitteeRoot {
			t.Errorf("anchor %d: %+v vs %+v", i, g, a)
		}
		if a.BlockRoot != "" {
			if g.BlockRoot == nil || hx(g.BlockRoot[:]) != a.BlockRoot {
				t.Errorf("anchor %d block root", i)
			}
		} else if g.BlockRoot != nil {
			t.Errorf("anchor %d: a block root where there is none", i)
		}
	}
	if z := EthL1Pins(&finality.Pins{}); z.Network.ChainID != 0 || len(z.Anchors) != 0 {
		t.Fatalf("%+v", z)
	}
	// stateOf keeps the code and fields of an L1 fault and passes any other error through
	f := ethl1.BlockNotCovered(7, 9)
	se, ok := finality.AsNamed(stateOf(f))
	if !ok || se.Code != f.Code || len(se.Fields) != len(f.Fields) {
		t.Fatalf("%v", se)
	}
	for k, v := range f.Fields {
		if se.Fields[k] != v {
			t.Errorf("field %s: %v vs %v", k, se.Fields[k], v)
		}
	}
	other := errors.New("not a fault")
	if stateOf(other) != other {
		t.Fatal("a plain error is passed through")
	}
	// the hash order of the pins writer
	hs := sortedImplHashes(loadPins(t).Impl)
	for i := 1; i < len(hs); i++ {
		if string(hs[i-1][:]) >= string(hs[i][:]) {
			t.Fatalf("not ascending at %d", i)
		}
	}
	if len(hs) != len(loadPins(t).Impl) {
		t.Fatal("every row is listed once")
	}
	// hex parsing: lower-case 0x only
	for _, c := range []struct {
		s  string
		n  int
		ok bool
	}{{"0x00", 1, true}, {"0x00", 2, false}, {"00", 1, false}, {"0xAB", 1, false}, {"0xzz", 1, false}, {"", 0, false}, {"0x", 0, true}} {
		if _, ok := unhex(c.s, c.n); ok != c.ok {
			t.Errorf("unhex(%q, %d) = %v", c.s, c.n, ok)
		}
	}
	for _, c := range []struct {
		s  string
		ok bool
	}{{"0x00ff", true}, {"0x", true}, {"00", false}, {"0xAB", false}, {"0xz", false}, {"0xabc", false}} {
		if _, ok := hexBytes(c.s); ok != c.ok {
			t.Errorf("hexBytes(%q) = %v", c.s, ok)
		}
	}
}
