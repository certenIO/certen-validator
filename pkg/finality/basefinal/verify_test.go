// Copyright 2026 Certen Protocol

package basefinal

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func loadPins(t *testing.T) *Pins {
	t.Helper()
	fp, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePins(fp)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// clonePins copies the maps so a test can drop or edit a row without touching the shared pins.
func clonePins(p *Pins) *Pins {
	q := *p
	q.Impl = map[[32]byte]ImplRow{}
	for k, v := range p.Impl {
		q.Impl[k] = v
	}
	q.Proxy = map[[32]byte]string{}
	for k, v := range p.Proxy {
		q.Proxy[k] = v
	}
	return &q
}

func u8(v uint8) *uint8    { return &v }
func u64(v uint64) *uint64 { return &v }
func bl(v bool) *bool      { return &v }

func run(t *testing.T, p *Pins, s SynthSpec, edit func(o *SynthOut)) (map[string]any, error) {
	t.Helper()
	o, err := BuildSynth(p, s)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(o)
	}
	return Judge(p, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
}

func canonOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected a named state, got nil")
	}
	s, ok := finality.AsNamed(err)
	if !ok {
		t.Fatalf("not a named state: %v", err)
	}
	return string(s.Canonical())
}

const zeroAddr = "0x0000000000000000000000000000000000000000"

func TestAHealthyGameIsFinalizedAsOfA(t *testing.T) {
	p := loadPins(t)
	f, err := run(t, p, SynthSpec{K: 3, Depth: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"output_root_index": uint32(3), "root_kind": "intermediate", "proof_system": "tee", "finalization_path": "slow", "game_version": "0.2.0", "status": uint8(2)}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, f[k], f[k], v)
		}
	}
	if f["output_root_block"] != uint64(47604773-0) || f["created_at"] != uint64(1790980536) {
		t.Errorf("fields %v", f)
	}
	// the rootClaim anchor (index 0) and the last intermediate root (index n) are both accepted
	for _, k := range []uint32{0, 20} {
		if f, err = run(t, p, SynthSpec{K: k, Depth: 2}, nil); err != nil {
			t.Fatalf("K=%d: %v", k, err)
		} else if k == 0 && f["root_kind"] != "root_claim" {
			t.Errorf("root kind %v", f["root_kind"])
		}
	}
}

func TestEveryClaimValidityRefusalIsItsOwnNamedState(t *testing.T) {
	p := loadPins(t)
	created := uint64(1790980536)
	for _, c := range []struct {
		name string
		spec SynthSpec
		want string
	}{
		{"blacklisted", SynthSpec{Blacklisted: true}, `{"code":"game_blacklisted","fields":{}}`},
		{"retired", SynthSpec{Retirement: u64(created)}, `{"code":"game_retired","fields":{"createdAt":"1790980536","retirementTimestamp":"1790980536"}}`},
		{"retired by one second", SynthSpec{Retirement: u64(created + 1)}, `{"code":"game_retired","fields":{"createdAt":"1790980536","retirementTimestamp":"1790980537"}}`},
		{"pause on address zero", SynthSpec{PauseZero: 1790000000}, `{"code":"l1_system_paused","fields":{"identifier":"` + zeroAddr + `","pauseTimestamp":"1790000000"}}`},
		{"pause on the portal", SynthSpec{PausePort: 7}, `{"code":"l1_system_paused","fields":{"identifier":"0x49f53e41452c74589e85ca1677426ba426459e85","pauseTimestamp":"7"}}`},
		{"not respected", SynthSpec{Respected: u8(0)}, `{"code":"game_not_respected","fields":{}}`},
		{"in progress", SynthSpec{Status: u8(0)}, `{"code":"game_not_resolved","fields":{"status":"0"}}`},
		{"within the finality delay", SynthSpec{ATimestamp: created + 432288}, `{"code":"game_within_finality_delay","fields":{"T":"1791412824","delay":"0","resolvedAt":"1791412824"}}`},
		{"challenger wins", SynthSpec{Status: u8(1)}, `{"code":"game_challenger_wins","fields":{}}`},
		{"countered yet DEFENDER_WINS", SynthSpec{Countered: 4}, `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`},
		{"resolved before expectedResolution", SynthSpec{ExpectedRes: u64(created + 432288 + 1)}, `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`},
		{"no prover at all", SynthSpec{TEE: bl(false)}, `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`},
		{"fast path without a second proof", SynthSpec{ExpectedRes: u64(created + 86400), ProofCount: u64(1)}, `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := run(t, p, c.spec, nil)
			if got := canonOf(t, err); got != c.want {
				t.Fatalf("\n got %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestTheFinalizationAttributesAreReportedNotGated(t *testing.T) {
	p := loadPins(t)
	created := uint64(1790980536)
	for _, c := range []struct {
		name         string
		spec         SynthSpec
		system, path string
	}{
		{"tee only slow", SynthSpec{}, "tee", "slow"},
		{"zk only slow", SynthSpec{TEE: bl(false), ZK: bl(true)}, "zk", "slow"},
		{"tee and zk fast", SynthSpec{ZK: bl(true), ProofCount: u64(2), ExpectedRes: u64(created + 86400), ResolvedAt: created + 90000}, "tee+zk", "fast"},
		{"tee and zk slow (second proof too late)", SynthSpec{ZK: bl(true), ProofCount: u64(2)}, "tee+zk", "slow"},
		{"a nullified proof extended the delay", SynthSpec{ExpectedRes: u64(created + 500000), ResolvedAt: created + 500100}, "tee", "extended"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := run(t, p, c.spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			if f["proof_system"] != c.system || f["finalization_path"] != c.path {
				t.Fatalf("got %v / %v", f["proof_system"], f["finalization_path"])
			}
		})
	}
}

func TestACustomFinalityDelayInTheAsrImplementationPinIsEnforced(t *testing.T) {
	p := clonePins(loadPins(t))
	h := hashOfRole(p, RoleASRImpl)
	row := p.Impl[h]
	row.FinalityDelaySeconds = u64(86400)
	p.Impl[h] = row
	_, err := run(t, p, SynthSpec{}, nil) // T = resolvedAt + 1000 <= resolvedAt + 86400
	want := `{"code":"game_within_finality_delay","fields":{"T":"1791413824","delay":"86400","resolvedAt":"1791412824"}}`
	if got := canonOf(t, err); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	// and the strict inequality: T == resolvedAt+delay is still within, T == resolvedAt+delay+1 is past
	if _, err := run(t, p, SynthSpec{ATimestamp: 1791412824 + 86400 + 1}, nil); err != nil {
		t.Fatalf("one second past the delay: %v", err)
	}
	if _, err := run(t, p, SynthSpec{ATimestamp: 1791412824 + 86400}, nil); err == nil {
		t.Fatal("T == resolvedAt+delay must still be within the delay")
	}
}

func TestACloneThatIsNotTheExactTemplateIsGameUnrecognised(t *testing.T) {
	p := loadPins(t)
	flip := func(i int) SynthSpec {
		return SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, code *[]byte) { (*code)[i] ^= 1 }}
	}
	for _, c := range []struct {
		name   string
		spec   SynthSpec
		reason string
	}{
		{"head byte flipped", flip(3), "prefix"},
		{"the embedded length flipped", flip(54), "prefix"},
		{"mid byte flipped", flip(60), "prefix"},
		{"tail byte flipped", flip(90), "prefix"},
		{"trailer flipped", flip(875), "trailer"},
		{"one byte too long", SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, c *[]byte) { *c = append(*c, 0) }}, "args_len"},
		{"one byte too short", SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, c *[]byte) { *c = (*c)[:len(*c)-1] }}, "args_len"},
		{"19 intermediate roots", SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, c *[]byte) { *c = append((*c)[:100+136], (*c)[100+136+32:]...) }}, "n_mismatch"},
		{"21 intermediate roots", SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, c *[]byte) {
			*c = append(append(append([]byte{}, (*c)[:len(*c)-2]...), make([]byte, 32)...), (*c)[len(*c)-2:]...)
		}}, "n_mismatch"},
		{"shorter than the template", SynthSpec{Tweak: func(_ *SynthWorld, _ *Pins, c *[]byte) { *c = (*c)[:60] }}, "prefix"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := run(t, p, c.spec, nil)
			want := `{"code":"game_unrecognised","fields":{"reason":"` + c.reason + `"}}`
			if got := canonOf(t, err); got != want {
				t.Fatalf("\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestTheIntervalPairMustBeOneOfThePinnedPairs(t *testing.T) {
	p := loadPins(t)
	for _, c := range []struct {
		name string
		spec SynthSpec
		want string
	}{
		{"a 500-block game", SynthSpec{Pair: &[2]uint64{500, 25}}, `{"code":"game_unrecognised","fields":{"n":"20","reason":"interval_pair","total":"500"}}`},
		{"a start block off by one", SynthSpec{StartDelta: 1}, `{"code":"game_unrecognised","fields":{"n":"20","reason":"interval_pair","total":"599"}}`},
		{"0.2.0 does not know the 6000/300 pair", SynthSpec{Pair: &[2]uint64{6000, 300}}, `{"code":"game_unrecognised","fields":{"n":"20","reason":"interval_pair","total":"6000"}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := run(t, p, c.spec, nil)
			if got := canonOf(t, err); got != c.want {
				t.Fatalf("\n got %s\nwant %s", got, c.want)
			}
		})
	}
	// both pairs of 0.3.0 are accepted; the interval decides the block of an intermediate root
	for _, pr := range [][2]uint64{{600, 30}, {6000, 300}} {
		f, err := run(t, p, SynthSpec{Version: "0.3.0", Pair: &pr, K: 5, Depth: 3, OutBlock: 48500000}, nil)
		if err != nil {
			t.Fatalf("0.3.0 pair %v: %v", pr, err)
		}
		if f["game_version"] != "0.3.0" || f["output_root_block"] != uint64(48500000) {
			t.Errorf("%v", f)
		}
	}
	// a pair whose total matches but whose root count does not
	q := clonePins(p)
	for h, r := range q.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.2.0" {
			r.IntervalPairs = [][2]uint64{{600, 20}}
			q.Impl[h] = r
		}
	}
	_, err := run(t, q, SynthSpec{Pair: &[2]uint64{600, 30}}, func(o *SynthOut) {})
	if got, want := canonOf(t, err), `{"code":"game_unrecognised","fields":{"n":"30","reason":"interval_pair","total":"600"}}`; got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestTheOutputRootIsRecomputedFromTheL2HeaderAlone(t *testing.T) {
	p := loadPins(t)
	o, _ := BuildSynth(p, SynthSpec{K: 3, Depth: 2})
	top, _ := finality.ReadHeader(o.Body.L2Spine[0])
	// the wrong index selects another root
	body := o.Body
	body.OutputRootIndex = 4
	_, err := Judge(p, o.A, body, o.Leg, ethl1.FinalizedHead{})
	s, _ := finality.AsNamed(err)
	if s == nil || s.Code != CodeOutputRootMismatch {
		t.Fatalf("%v", err)
	}
	if s.Fields["computed"] != [32]byte(crypto.Keccak256Hash(make([]byte, 32), top.StateRoot[:], top.WithdrawalsRoot[:], top.Hash[:])) {
		t.Errorf("computed %v", s.Fields["computed"])
	}
	// a header without withdrawalsRoot cannot give an output root
	noW := rlpDropItem(t, o.Body.L2Spine[0], 16)
	body = o.Body
	body.L2Spine = append([][]byte{noW}, o.Body.L2Spine[1:]...)
	_, err = Judge(p, o.A, body, o.Leg, ethl1.FinalizedHead{})
	want := `{"code":"output_root_mismatch","fields":{"claimed":"0x` + fmt.Sprintf("%x", outputRoot(top)) + `","computed":"0x0000000000000000000000000000000000000000000000000000000000000000"}}`
	if got := canonOf(t, err); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	// an index above n is a bound, not a root
	body = o.Body
	body.OutputRootIndex = 21
	_, err = Judge(p, o.A, body, o.Leg, ethl1.FinalizedHead{})
	if got, w := canonOf(t, err), `{"code":"finality_evidence_too_large","fields":{"count":"21","limit":"20","part":"outputRootIndex"}}`; got != w {
		t.Fatalf("\n got %s\nwant %s", got, w)
	}
}

func TestTheL2SpineMustReachTheLegAndBeUnbroken(t *testing.T) {
	p := loadPins(t)
	o, _ := BuildSynth(p, SynthSpec{K: 2, Depth: 5})
	if len(o.Body.L2Spine) != 6 {
		t.Fatalf("%d headers", len(o.Body.L2Spine))
	}
	mut := func(f func(b *Body, leg *finality.BlockRef)) error {
		b, leg := o.Body, o.Leg
		b.L2Spine = append([][]byte(nil), o.Body.L2Spine...)
		f(&b, &leg)
		_, err := Judge(p, o.A, b, leg, ethl1.FinalizedHead{})
		return err
	}
	code := func(err error) string { s, _ := finality.AsNamed(err); return s.Code }
	if c := code(mut(func(b *Body, _ *finality.BlockRef) { b.L2Spine = append(b.L2Spine[:2], b.L2Spine[3:]...) })); c != "finality_header_chain_broken" {
		t.Errorf("a gap: %s", c)
	}
	err := mut(func(b *Body, _ *finality.BlockRef) { b.L2Spine = append(b.L2Spine[:2], b.L2Spine[3:]...) })
	s, _ := finality.AsNamed(err)
	if s.Fields["spine"] != "l2" || s.Fields["reason"] != "hash" {
		t.Errorf("gap fields %v", s.Fields)
	}
	h1, _ := finality.ReadHeader(o.Body.L2Spine[1])
	if s.Fields["want_hash"] != h1.ParentHash || s.Fields["at_number"] != h1.Number-1 {
		t.Errorf("gap fields %v", s.Fields)
	}
	// a forged link: a header of the right number whose content differs
	forged := SynthL2Header(h1.Number-1, [32]byte{9}, [32]byte{1}, [32]byte{2})
	err = mut(func(b *Body, _ *finality.BlockRef) { b.L2Spine[2] = forged })
	if s, _ = finality.AsNamed(err); s == nil || s.Code != "finality_header_chain_broken" || s.Fields["reason"] != "hash" {
		t.Errorf("forged link: %v", err)
	}
	// a header that is not RLP at all
	err = mut(func(b *Body, _ *finality.BlockRef) { b.L2Spine[2] = []byte{1, 2, 3} })
	if s, _ = finality.AsNamed(err); s == nil || s.Code != "finality_header_chain_broken" || s.Fields["reason"] != "rlp" {
		t.Errorf("garbage header: %v", err)
	}
	// the spine stops short of the leg / continues past it / the leg is another block
	for name, f := range map[string]func(b *Body, leg *finality.BlockRef){
		"stops short": func(b *Body, _ *finality.BlockRef) { b.L2Spine = b.L2Spine[:4] },
		"continues below": func(b *Body, leg *finality.BlockRef) {
			leg.Number++
			leg.Hash = h1.Hash
			leg.HeaderRLP = o.Body.L2Spine[1]
		},
		"another leg": func(_ *Body, leg *finality.BlockRef) { leg.Hash[0] ^= 1 },
		"empty spine": func(b *Body, _ *finality.BlockRef) { b.L2Spine = nil },
		"leg header bytes differ": func(_ *Body, leg *finality.BlockRef) {
			leg.HeaderRLP = SynthL2Header(leg.Number, [32]byte{}, [32]byte{3}, [32]byte{4})
		},
	} {
		if got := canonOf(t, mut(f)); got != `{"code":"l2_block_not_canonical","fields":{}}` {
			t.Errorf("%s: %s", name, got)
		}
	}
	// a link whose hash matches but whose number skips one
	o2, _ := BuildSynth(p, SynthSpec{K: 2, Depth: 3, L2NumberSkipAt: 2})
	_, err = Judge(p, o2.A, o2.Body, o2.Leg, ethl1.FinalizedHead{})
	if s, _ = finality.AsNamed(err); s == nil || s.Code != "finality_header_chain_broken" || s.Fields["reason"] != "number" {
		t.Errorf("number skip: %v", err)
	}
}

func TestEveryLinkOfTheContractGraphIsProvenAndPinned(t *testing.T) {
	p := loadPins(t)
	other := [20]byte{0xaa}
	badHash := [32]byte{0xbb}
	for _, c := range []struct {
		name  string
		tweak func(w *SynthWorld, p *Pins, c *[]byte)
		role  string
	}{
		{"portal does not name the system config", func(w *SynthWorld, p *Pins, _ *[]byte) {
			w.Set(p.Portal, be32(slotPortalSystemConfig), addrToWord(other))
		}, "portal.systemConfig"},
		{"system config does not name the portal", func(w *SynthWorld, p *Pins, _ *[]byte) { w.Set(p.SystemConfig, optimismPortalSlot, addrToWord(other)) }, "systemconfig.portal"},
		{"asr does not name the system config", func(w *SynthWorld, _ *Pins, _ *[]byte) {
			var x [32]byte
			copy(x[10:30], other[:])
			w.Set(synthASR, be32(slotASRSystemConfig), x)
		}, "asr.systemConfig"},
		{"portal proxy code unknown", func(w *SynthWorld, p *Pins, _ *[]byte) { w.SetCodeHash(p.Portal, badHash) }, "portal_proxy"},
		{"system config proxy code unknown", func(w *SynthWorld, p *Pins, _ *[]byte) { w.SetCodeHash(p.SystemConfig, badHash) }, "system_config_proxy"},
		{"asr proxy code unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthASR, badHash) }, "asr_proxy"},
		{"dgf proxy code unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthDGF, badHash) }, "dgf_proxy"},
		{"superchain proxy code unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthSUP, badHash) }, "superchain_proxy"},
		{"portal implementation unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthPImpl, badHash) }, RolePortalImpl},
		{"system config implementation unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthSImpl, badHash) }, RoleSysCfgImpl},
		{"asr implementation unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthAImpl, badHash) }, RoleASRImpl},
		{"dgf implementation unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthDImpl, badHash) }, RoleDGFImpl},
		{"superchain implementation unknown", func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetCodeHash(synthUImpl, badHash) }, RoleSuperchainImpl},
		{"an implementation pinned under another role", func(w *SynthWorld, p *Pins, _ *[]byte) { w.SetCodeHash(synthPImpl, hashOfRole(p, RoleDGFImpl)) }, RolePortalImpl},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := run(t, p, SynthSpec{Tweak: c.tweak}, nil)
			s, ok := finality.AsNamed(err)
			if !ok || s.Code != CodeContractIdentity || s.Fields["role"] != c.role || s.Fields["judged_at"] != uint64(11954148) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestTheGameImplementationMustBeACompletePinnedRowAndTheRegistrationMustMatch(t *testing.T) {
	p := loadPins(t)
	// the embedded implementation is another contract
	unknown := [20]byte{0xde, 0xad}
	_, err := run(t, p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, c *[]byte) {
		copy((*c)[65:85], unknown[:])
		w.SetCodeHash(unknown, [32]byte{0xcc})
	}}, nil)
	s, _ := finality.AsNamed(err)
	if s == nil || s.Code != CodeContractIdentity || s.Fields["role"] != RoleGameImpl || s.Fields["address"] != unknown {
		t.Fatalf("%v", err)
	}
	// an incomplete row is treated as absent (V2_SPEC_S7 4.2)
	for name, edit := range map[string]func(r *ImplRow){
		"no interval pairs": func(r *ImplRow) { r.IntervalPairs = nil },
		"no slow delay":     func(r *ImplRow) { r.SlowDelay = 0 },
		"no cwia":           func(r *ImplRow) { r.CWIA = "" },
		"wrong args_len":    func(r *ImplRow) { r.ArgsLen++ },
		"no impl address":   func(r *ImplRow) { r.Impl = [20]byte{} },
	} {
		q := clonePins(p)
		for h, r := range q.Impl {
			if r.Role == RoleGameImpl && r.Version == "0.2.0" {
				edit(&r)
				q.Impl[h] = r
			}
		}
		_, err := run(t, p, SynthSpec{}, func(o *SynthOut) {
			if _, err := Judge(q, o.A, o.Body, o.Leg, ethl1.FinalizedHead{}); err == nil {
				t.Errorf("%s: an incomplete row was used", name)
			} else if s, _ := finality.AsNamed(err); s.Code != CodeContractIdentity || s.Fields["role"] != RoleGameImpl {
				t.Errorf("%s: %v", name, err)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// the registration: absent, another game type, another creation time, another proxy
	for name, reg := range map[string]func(r *[32]byte){
		"absent":        func(r *[32]byte) { *r = [32]byte{} },
		"another type":  func(r *[32]byte) { r[3] ^= 1 },
		"another time":  func(r *[32]byte) { r[11] ^= 1 },
		"another proxy": func(r *[32]byte) { r[31] ^= 1 },
		"type zero":     func(r *[32]byte) { *r = [32]byte{31: 1} },
	} {
		_, err := run(t, p, SynthSpec{RegTweak: reg}, nil)
		want := `{"code":"game_not_registered","fields":{}}`
		switch name {
		case "another type":
			want = `{"code":"game_type_unsupported","fields":{"type":"620"}}`
		case "type zero":
			want = `{"code":"game_type_unsupported","fields":{"type":"0"}}`
		}
		if got := canonOf(t, err); got != want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
}

func TestAProofThatIsNotInTheNodeSetIsAStateProofRefusal(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for i := range o.Body.Nodes {
		b := o.Body
		b.Nodes = append(append([][]byte(nil), o.Body.Nodes[:i]...), o.Body.Nodes[i+1:]...)
		_, jerr := Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
		if jerr == nil {
			continue // a node shared by no proof of this world is not possible; a duplicate would still verify
		}
		seen[canonOf(t, jerr)]++
	}
	for _, want := range []string{`{"code":"l1_state_proof_invalid","fields":{"which":"account"}}`, `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}`} {
		if seen[want] == 0 {
			t.Errorf("removing a node never gave %s: %v", want, seen)
		}
	}
	// the code the evidence carries must be the code of the proven account
	b := o.Body
	b.GameCode = append([]byte(nil), o.Body.GameCode...)
	b.GameCode[200] ^= 1
	_, jerr := Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
	if got := canonOf(t, jerr); got != `{"code":"l1_state_proof_invalid","fields":{"which":"account"}}` {
		t.Errorf("%s", got)
	}
	// an A with another state root proves nothing
	a := o.A
	a.StateRoot[0] ^= 1
	_, jerr = Judge(p, a, o.Body, o.Leg, ethl1.FinalizedHead{})
	if got := canonOf(t, jerr); got != `{"code":"l1_state_proof_invalid","fields":{"which":"account"}}` {
		t.Errorf("%s", got)
	}
}

// rlpDropItem re-encodes a header RLP list without its item idx.
func rlpDropItem(t *testing.T, raw []byte, idx int) []byte {
	t.Helper()
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil {
		t.Fatal(err)
	}
	items = append(items[:idx], items[idx+1:]...)
	out, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
