// Copyright 2026 Certen Protocol

package proofv2

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The fixture is a live Kermit transaction (rb4-phase-c-09282125.acme/data, 7dec3f82...) built by cmd/proofv2build on
// 2026-10-04, with the Directory's 491 major records and the Kermit incarnation evidence RB5 Phase A published.
const kermitPin = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

func gunzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	ev  *Evidence
	ar  *Archive
	inc *proof.IncarnationEvidence
	pin [32]byte
}

func load(t *testing.T) fixture {
	t.Helper()
	var fx fixture
	var err error
	if fx.ar, err = UnmarshalArchive(gunzip(t, "testdata/archive.json.gz")); err != nil {
		t.Fatal(err)
	}
	fx.ev = new(Evidence)
	if err := json.Unmarshal(gunzip(t, "testdata/evidence_7dec3f82.json.gz"), fx.ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	fx.inc = new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, fx.inc); err != nil {
		t.Fatal(err)
	}
	b, _ := hex.DecodeString(kermitPin)
	copy(fx.pin[:], b)
	return fx
}

func TestVerifyLiveKermitProof(t *testing.T) {
	fx := load(t)
	rep, err := Verify(fx.ev, fx.ar, fx.inc, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SetVerdict != proof.VerdictVerified {
		t.Fatalf("set verdict %s, want verified", rep.SetVerdict)
	}
	if rep.Majors == 0 || rep.CertifiedBlock == 0 || rep.CheckBlock < rep.CertifiedBlock || rep.Validators != 3 || rep.Threshold != 2 {
		t.Fatalf("unexpected report %+v", rep)
	}
}

// mutate re-encodes one minor-root record of the evidence after f changes it.
func mutateMinorRoot(t *testing.T, h *string, f func(*api.MinorRootRecord)) {
	t.Helper()
	r, err := decodeMinorRoot(*h)
	if err != nil {
		t.Fatal(err)
	}
	f(r)
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	*h = hex.EncodeToString(b)
}

func flipHexByte(s string, at int) string {
	b, _ := hex.DecodeString(s)
	b[at] ^= 0x01
	return hex.EncodeToString(b)
}

// Each case is an attack a lying server or a tampered store could mount; each must be refused.
func TestVerifyRefusesTampering(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*testing.T, *fixture)
		want string
	}{
		{"a receipt step changed", func(t *testing.T, fx *fixture) {
			r, _ := decodeReceipt(fx.ev.Receipt)
			r.Entries[3].Hash[0] ^= 1
			b, _ := r.MarshalBinary()
			fx.ev.Receipt = hex.EncodeToString(b)
		}, "receipt does not validate"},
		{"a different transaction claimed", func(t *testing.T, fx *fixture) {
			fx.ev.TxHash = flipHexByte(fx.ev.TxHash, 0)
		}, "not the transaction"},
		{"the certified anchor's signatures stripped (a signature-less anchor presented as certified)", func(t *testing.T, fx *fixture) {
			mutateMinorRoot(t, &fx.ev.Certify, func(r *api.MinorRootRecord) { r.Signatures = nil })
		}, "quorum not met"},
		{"one signature forged", func(t *testing.T, fx *fixture) {
			mutateMinorRoot(t, &fx.ev.Certify, func(r *api.MinorRootRecord) {
				ed := r.Signatures[0].(*protocol.ED25519Signature)
				ed.Signature[0] ^= 1
			})
		}, "invalid signature"},
		{"the certified anchor forked off the verified root", func(t *testing.T, fx *fixture) {
			// The root a run starts from is computed from Pending alone (Count is metadata the verifier never reads), so
			// a fork is a different Pending.
			mutateMinorRoot(t, &fx.ev.Certify, func(r *api.MinorRootRecord) {
				for _, p := range r.RootProof.MerkleState.Pending {
					if p != nil {
						p[0] ^= 1
						return
					}
				}
			})
		}, "root proof"},
		{"a major block skipped", func(t *testing.T, fx *fixture) {
			fx.ar.Majors[5] = fx.ar.Majors[6]
		}, "expected major block"},
		{"the evidence built on more major blocks than the archive holds", func(t *testing.T, fx *fixture) {
			fx.ar.Majors = fx.ar.Majors[:fx.ev.Majors-1]
		}, "archive has"},
		{"a validator added to the proven network definition", func(t *testing.T, fx *fixture) {
			fx.ev.Check.Set.Network.AccountState = flipHexByte(fx.ev.Check.Set.Network.AccountState, len(fx.ev.Check.Set.Network.AccountState)/2-4)
		}, "set check"},
		{"the network account's main chain height understated (an update omitted)", func(t *testing.T, fx *fixture) {
			for i := range fx.ev.Check.Set.Network.Chains {
				if fx.ev.Check.Set.Network.Chains[i].Name == "main" {
					fx.ev.Check.Set.Network.Chains[i].Count++
				}
			}
		}, "set check"},
		{"the set check run dropped", func(t *testing.T, fx *fixture) {
			fx.ev.Check.Hops = nil
		}, "no minor-root run"},
		{"another incarnation pinned", func(t *testing.T, fx *fixture) {
			fx.pin[0] ^= 1
		}, "not the pinned"},
		{"a version the verifier does not know", func(t *testing.T, fx *fixture) {
			fx.ev.Version = "1.0"
		}, "not a v2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := load(t)
			c.mut(t, &fx)
			_, err := Verify(fx.ev, fx.ar, fx.inc, fx.pin)
			if err == nil {
				t.Fatal("tampered evidence verified")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for the wrong reason: %v (want %q)", err, c.want)
			}
		})
	}
}
