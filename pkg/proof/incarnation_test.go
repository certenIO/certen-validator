package proof

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The pinned incarnations (docs/l4/INCARNATION_ANCHOR.md), re-derived offline from evidence recorded 2026-09-29.
const (
	kermitIncarnation  = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"
	mainnetIncarnation = "90721b40a0114a1c6d1a22b95d47e168e8c5d8c4fbc885f7cd36c6fe07fc91c0"
)

func loadIncarnationEvidence(t *testing.T, name string) *IncarnationEvidence {
	t.Helper()
	b, err := os.ReadFile("testdata/incarnation/" + name)
	if err != nil {
		t.Fatalf("the committed evidence %s is required: %v", name, err)
	}
	e := new(IncarnationEvidence)
	if err := json.Unmarshal(b, e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestIncarnation_PinnedVectorsReDeriveOffline(t *testing.T) {
	for name, want := range map[string]string{"kermit.json": kermitIncarnation, "mainnet.json": mainnetIncarnation} {
		rep, err := loadIncarnationEvidence(t, name).Verify()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := hex.EncodeToString(rep.Incarnation[:]); got != want {
			t.Fatalf("%s: incarnation %s, pinned %s", name, got, want)
		}
		if rep.GenesisSigners < int(rep.GenesisThreshold) || rep.GenesisThreshold == 0 {
			t.Fatalf("%s: genesis quorum %d of %d", name, rep.GenesisSigners, rep.GenesisThreshold)
		}
	}
}

func TestIncarnation_KermitInputs(t *testing.T) {
	rep, err := loadIncarnationEvidence(t, "kermit.json").Verify()
	if err != nil {
		t.Fatal(err)
	}
	in := rep.Inputs
	if hex.EncodeToString(in.GenesisRootChainAnchor[:]) != "e3f3119213a1ead44647659d67e47f4269a2affb13f150aa87b20baacf93cf81" ||
		hex.EncodeToString(in.GenesisStateTreeAnchor[:]) != "5cd146ba4ba40712ab002936d29ef213a7e2ff4ebc0b5ec4183b1ae8af00d5ff" ||
		in.GenesisTimeUnix != 1769910286 || rep.NetworkName != "DevNet" || len(rep.Validators) != 3 ||
		rep.Threshold.Numerator != 2 || rep.Threshold.Denominator != 3 {
		t.Fatalf("unexpected Kermit genesis: %+v name=%s validators=%d threshold=%v", in, rep.NetworkName, len(rep.Validators), rep.Threshold)
	}
}

// Every input moves the identity; nothing that cannot describe a genesis is accepted.
func TestComputeIncarnation_EveryInputBinds(t *testing.T) {
	rep, err := loadIncarnationEvidence(t, "kermit.json").Verify()
	if err != nil {
		t.Fatal(err)
	}
	base := rep.Inputs
	want, err := ComputeIncarnation(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*IncarnationInputs){
		"root":    func(in *IncarnationInputs) { in.GenesisRootChainAnchor[31] ^= 1 },
		"state":   func(in *IncarnationInputs) { in.GenesisStateTreeAnchor[0] ^= 1 },
		"time":    func(in *IncarnationInputs) { in.GenesisTimeUnix++ },
		"network": func(in *IncarnationInputs) { in.NetworkRecord = append(append([]byte{}, in.NetworkRecord...), 0) },
		"globals": func(in *IncarnationInputs) {
			in.GlobalsRecord = append([]byte{}, in.GlobalsRecord[:len(in.GlobalsRecord)-1]...)
		},
		"swap-rec": func(in *IncarnationInputs) { in.NetworkRecord, in.GlobalsRecord = in.GlobalsRecord, in.NetworkRecord },
	}
	for name, mut := range mutations {
		in := base
		mut(&in)
		got, err := ComputeIncarnation(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == want {
			t.Errorf("%s: changing the input did not change the incarnation", name)
		}
	}
	refused := map[string]func(*IncarnationInputs){
		"block 0":    func(in *IncarnationInputs) { in.GenesisMinorBlockIndex = 0 },
		"block 2":    func(in *IncarnationInputs) { in.GenesisMinorBlockIndex = 2 },
		"no root":    func(in *IncarnationInputs) { in.GenesisRootChainAnchor = [32]byte{} },
		"no state":   func(in *IncarnationInputs) { in.GenesisStateTreeAnchor = [32]byte{} },
		"no time":    func(in *IncarnationInputs) { in.GenesisTimeUnix = 0 },
		"no network": func(in *IncarnationInputs) { in.NetworkRecord = nil },
		"no globals": func(in *IncarnationInputs) { in.GlobalsRecord = nil },
	}
	for name, mut := range refused {
		in := base
		mut(&in)
		if _, err := ComputeIncarnation(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Tampering with any piece of the evidence is refused - never a different value, never a weaker answer.
func TestIncarnationEvidence_TamperingIsRefused(t *testing.T) {
	flipHex := func(s string, at int) string {
		b := []byte(s)
		if b[at] == '0' {
			b[at] = '1'
		} else {
			b[at] = '0'
		}
		return string(b)
	}
	tampers := map[string]func(e *IncarnationEvidence){
		"anchor tx bytes": func(e *IncarnationEvidence) { e.GenesisAnchorTx = flipHex(e.GenesisAnchorTx, len(e.GenesisAnchorTx)-2) },
		"anchor entry":    func(e *IncarnationEvidence) { e.GenesisAnchorEntry = flipHex(e.GenesisAnchorEntry, 5) },
		"root entry":      func(e *IncarnationEvidence) { e.RootAnchor.Entry = flipHex(e.RootAnchor.Entry, 3) },
		"root receipt": func(e *IncarnationEvidence) {
			e.RootAnchor.Receipt.Entries[0].Hash = flipHex(e.RootAnchor.Receipt.Entries[0].Hash, 2)
		},
		"root index": func(e *IncarnationEvidence) { e.RootAnchor.Index = 1 },
		"bpt entry":  func(e *IncarnationEvidence) { e.BptAnchor.Entry = flipHex(e.BptAnchor.Entry, 3) },
		"network state": func(e *IncarnationEvidence) {
			e.Network.AccountState = flipHex(e.Network.AccountState, len(e.Network.AccountState)-4)
		},
		"globals state": func(e *IncarnationEvidence) {
			e.Globals.AccountState = flipHex(e.Globals.AccountState, len(e.Globals.AccountState)-4)
		},
		"ledger state": func(e *IncarnationEvidence) {
			e.Ledger1.AccountState = flipHex(e.Ledger1.AccountState, len(e.Ledger1.AccountState)-4)
		},
		"network main count":  func(e *IncarnationEvidence) { e.Network.Chains[0].Count = 2 },
		"network main0 tx":    func(e *IncarnationEvidence) { e.NetworkTx0 = flipHex(e.NetworkTx0, len(e.NetworkTx0)-2) },
		"globals main0 entry": func(e *IncarnationEvidence) { e.GlobalsMain0.Entry = flipHex(e.GlobalsMain0.Entry, 1) },
		"swapped accounts":    func(e *IncarnationEvidence) { e.Network, e.Globals = e.Globals, e.Network },
		"leg signature":       func(e *IncarnationEvidence) { s := &e.GenesisLeg.Signatures[0]; s.Signature = flipHex(s.Signature, 4) },
		"leg set": func(e *IncarnationEvidence) {
			v := &e.GenesisLeg.ValidatorSet[0]
			v.PublicKey = flipHex(v.PublicKey, 4)
		},
		"leg threshold":  func(e *IncarnationEvidence) { e.GenesisLeg.AcceptThreshold.Numerator = 1 },
		"leg block":      func(e *IncarnationEvidence) { e.GenesisLeg.MinorBlockIndex = 2 },
		"no leg":         func(e *IncarnationEvidence) { e.GenesisLeg = nil },
		"restated value": func(e *IncarnationEvidence) { e.Incarnation = flipHex(e.Incarnation, 7) },
	}
	for name, tamper := range tampers {
		e := loadIncarnationEvidence(t, "kermit.json")
		tamper(e)
		if rep, err := e.Verify(); err == nil {
			t.Errorf("%s: accepted, incarnation %x", name, rep.Incarnation)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: refused without a reason", name)
		}
	}
}
