// Copyright 2026 Certen Protocol

package basefinal

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func rlpBytes(v any) []byte {
	b, err := rlp.EncodeToBytes(v)
	if err != nil {
		panic(err)
	}
	return b
}

type slotRef struct {
	addr [20]byte
	slot [32]byte
}

// worldRefs lists every slot of the world a spec builds (the proven ones, present or absent) and every account.
func worldRefs(t *testing.T, p *Pins, spec SynthSpec) ([]slotRef, [][20]byte) {
	t.Helper()
	o, err := BuildSynth(p, spec)
	if err != nil {
		t.Fatal(err)
	}
	var refs []slotRef
	var accts [][20]byte
	for a, x := range o.World.Accts {
		accts = append(accts, a)
		seen := map[[32]byte]bool{}
		for s := range x.Slots {
			seen[s] = true
		}
		for _, s := range x.Prove {
			seen[s] = true
		}
		for s := range seen {
			refs = append(refs, slotRef{a, s})
		}
	}
	return refs, accts
}

func judgeSpec(t *testing.T, p *Pins, spec SynthSpec) (map[string]any, error) {
	t.Helper()
	o, err := BuildSynth(p, spec)
	if err != nil {
		t.Fatal(err)
	}
	return Judge(p, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
}

// Every storage word the judge reads is read from a proof: a leaf that is not a word (a 33-byte value, the empty string, a list) is
// the state-proof refusal of that slot, wherever in the contract graph the word is. A read whose failure were ignored would
// carry on with zero and accept or refuse for another reason.
func TestEverySlotTheJudgeReadsRefusesAValueThatIsNotAWord(t *testing.T) {
	p := loadPins(t)
	base := SynthSpec{K: 3, Depth: 4}
	if _, err := judgeSpec(t, p, base); err != nil {
		t.Fatalf("the base world must be accepted: %v", err)
	}
	refs, _ := worldRefs(t, p, base)
	if len(refs) < 20 {
		t.Fatalf("%d slots in the world", len(refs))
	}
	bad := map[string][]byte{
		"33 bytes":     rlpBytes(make([]byte, 33)),
		"empty string": {0x80},
		"a list":       {0xc0},
	}
	for _, r := range refs {
		for name, leaf := range bad {
			r, leaf := r, leaf
			spec := base
			spec.Tweak = func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetRaw(r.addr, r.slot, leaf) }
			_, err := judgeSpec(t, p, spec)
			if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}` {
				t.Errorf("slot %x of %x as %s: %s", r.slot, r.addr, name, got)
			}
		}
	}
}

// Every account the judge reads is a leaf of the state trie: a leaf that is no account is the state-proof refusal of that account,
// and an account that is proven absent is refused by the check that needed it (an identity for a contract of the graph, the state
// proof for the game and the factory).
func TestEveryAccountTheJudgeReadsIsRefusedWhenMalformedOrProvenAbsent(t *testing.T) {
	p := loadPins(t)
	base := SynthSpec{K: 3, Depth: 4}
	_, accts := worldRefs(t, p, base)
	o, err := BuildSynth(p, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) < 12 {
		t.Fatalf("%d accounts", len(accts))
	}
	for _, a := range accts {
		a := a
		spec := base
		spec.Tweak = func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetRawAccount(a, rlpBytes([]byte("not an account"))) }
		_, err := judgeSpec(t, p, spec)
		if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"account"}}` {
			t.Errorf("account %x malformed: %s", a, got)
		}
	}
	// the contract each address is, by the role the judge names when that contract is missing
	role := map[[20]byte]string{
		p.Portal: "portal_proxy", p.SystemConfig: "system_config_proxy", SynthAddrs.ASR: "asr_proxy", SynthAddrs.DGF: "dgf_proxy",
		SynthAddrs.SUP: "superchain_proxy", SynthAddrs.PortalImpl: "portal_impl", SynthAddrs.SysCfgImpl: "syscfg_impl",
		SynthAddrs.ASRImpl: "asr_impl", SynthAddrs.DGFImpl: "dgf_impl", SynthAddrs.SupImpl: "superchain_impl", o.Row.Impl: "game_impl",
	}
	for _, a := range accts {
		a := a
		spec := base
		spec.Tweak = func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetAbsent(a) }
		_, err := judgeSpec(t, p, spec)
		se, ok := finality.AsNamed(err)
		if !ok {
			t.Errorf("account %x absent: %v", a, err)
			continue
		}
		if a == SynthAddrs.Game {
			if string(se.Canonical()) != `{"code":"l1_state_proof_invalid","fields":{"which":"account"}}` {
				t.Errorf("the game proxy absent: %s", se.Canonical())
			}
			continue
		}
		if se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != role[a] || role[a] == "" {
			t.Errorf("account %x absent: %s, want an identity refusal of %q", a, se.Canonical(), role[a])
		}
	}
}
