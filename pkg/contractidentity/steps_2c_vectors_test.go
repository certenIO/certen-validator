// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/finality"
)

// The vector set s8_2c_1: the VS8 rows of steps 21, 23 and 24 that the closed mutation vocabulary can express (V2_SPEC_S8 r3.2, Freeze item 5).
// Each vector is a few mutation lines on H0 (Sepolia, h0) and an expectation DERIVED FROM THE SPECIFICATION TEXT (the row of item 5 and the
// step it names) before the verifier was run. The expectations name the parts of package 2c and the headline the FULL verifier yields when the
// other packages judge their parts of H0 as verified (no vector below touches anything those packages judge). The sets are run by the REAL
// composed verifier (NewDefaultVerifier) since the integration of the four step packages; the test-only stand-ins of build2c remain only in the
// tests that isolate one step of package 2c by editing a fact.

const vectorSet2c = "s8_2c_1"

type author2c struct {
	t *testing.T
	f *fixture
}

func (a *author2c) vectors() []ci.Vector {
	f := a.f
	sp := f.spec
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		if muts == nil {
			muts = []ci.Mutation{}
		}
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	anchor, verifier, owner := hexAddr(sp.Roles.Anchor), hexAddr(sp.Roles.Verifier), hexAddr(sp.Roles.Owner)
	decoy := hexAddr("0x1111111111111111111111111111111111111111")
	hv, err := finality.ReadHeader(f.built.World.Container.Attest.Attest.HeaderV)
	if err != nil {
		a.t.Fatal(err)
	}
	both := func(who common.Address, slot uint64, w common.Hash) []ci.Mutation {
		return []ci.Mutation{setWord(world.StationPre, who, slot, w), setWord(world.StationPost, who, slot, w)}
	}
	mismatch := func(field string, onchain, want common.Address) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedAuthorizationAttest, "refused"),
			est(ci.JudgedAuthorizationAttest, "authorization_mismatch", map[string]any{"field": field, "onchain": onchain, "want": want, "at": ci.AtAttestPre}))
	}
	// VS8-150 (step 21b): the owners read in step 18 equal a policy.owner row covering B_v, else R authorization_mismatch (equal at pre and post,
	// rule IB verified); a word that differs between the stations is U state_changed_in_block
	add("VS8-150.anchor_owner", mismatch("anchor_owner", decoy, owner), both(anchor, 27, word(decoy))...)
	add("VS8-150.verifier_owner", mismatch("verifier_owner", decoy, owner), both(verifier, 2, word(decoy))...)
	add("VS8-150.anchor_owner_changed_after", exp(ci.HeadlineUnproven, only(ci.JudgedAuthorizationAttest, "unproven"),
		est(ci.JudgedAuthorizationAttest, "unproven", map[string]any{"reason": "state_changed_in_block", "field": "A16", "pre": word(owner), "post": word(decoy), "block": hv.Number})),
		setWord(world.StationPost, anchor, 27, word(decoy)))

	// VS8-151 (step 21c): Registry9 against the proven registry; the field is the first difference in the order of the specification text
	r9 := sp.Context.Registry9
	mis := func(field string) ci.Expected {
		return exp(ci.HeadlineRefused, only(ci.JudgedRegistryLink, "refused"), est(ci.JudgedRegistryLink, "registry_mismatch", map[string]any{"field": field}))
	}
	k := []byte(r9.Members[2].BLSKey)
	if k[5] == '0' {
		k[5] = '1'
	} else {
		k[5] = '0'
	}
	add("VS8-151.member_key", mis("member_key"), ctxSet("registry9.members.2.bls_key", string(k)))
	add("VS8-151.member_power", mis("member_power"), ctxSet("registry9.members.1.power", r9.Members[1].Power+1))
	add("VS8-151.member_address", mis("member_address"), ctxSet("registry9.members.0.address", "0x0000000000000000000000000000000000000001"))
	add("VS8-151.count_missing", mis("count"), ctxSet("registry9.members", r9.Members[:len(r9.Members)-1]))
	add("VS8-151.threshold", mis("threshold"), ctxSet("registry9.num", 1))
	add("VS8-151.certen_set_root", mis("certen_set_root"), ctxSet("registry9.certen_set_root", "0x"+strings.Repeat("ab", 32)))
	add("VS8-151.set_root", mis("set_root"), both(anchor, 17, common.HexToHash("0xabc"))...)
	add("VS8-151.message_root", a.supersededByF17()["VS8-151.message_root"], setWord(world.StationPre, anchor, 17, common.HexToHash("0xabc")))

	// VS8-153: no Registry9, no setRootHistory row for the proven root
	e153 := exp(ci.HeadlineVerifiedCore, only(ci.JudgedRegistryLink, "open"))
	e153.Open = []ci.ExpectedOpen{{Part: ci.JudgedRegistryLink, Kind: ci.OpenNotChecked, Code: ci.Prefix + "not_checked", Fields: cf(map[string]any{"part": "registry_link", "reason": "no_registry_in_file"})}}
	add("VS8-153", e153, ci.Mutation{Op: "unset_field", Target: "context", Path: "registry9"})

	// VS8-160 / VS8-161 (step 21d)
	pkc := common.HexToHash(sp.Attestation.Blob[13])
	other := pkc
	other[31] ^= 1
	add("VS8-160", exp(ci.HeadlineRefused, only(ci.JudgedRegistryLink, "refused"), est(ci.JudgedRegistryLink, "pkc_mismatch", map[string]any{"s9": other, "onchain": pkc})),
		ctxSet("registry9.signer_commitment", strings.ToLower(other.Hex())))
	e161 := exp(ci.HeadlineVerifiedCore, only(ci.JudgedRegistryLink, "verified"))
	e161.Open = []ci.ExpectedOpen{{Part: ci.JudgedRegistryLink, Kind: ci.OpenNotChecked, Code: ci.Prefix + "not_checked", Fields: cf(map[string]any{"part": "pkc_signer_check", "reason": "no_s9_commitment"})}}
	add("VS8-161", e161, ctxSet("registry9.signer_commitment", "0x"+strings.Repeat("00", 32)))

	// VS8-180 (step 23): all core parts verified plus one alert, plus one drift, plus both -> verified_core{open}, never verified
	alert := func(field string, onchain, want any) ci.ExpectedOpen {
		return ci.ExpectedOpen{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenAlert, Code: ci.Prefix + "alert", Fields: cf(map[string]any{"field": field, "at": "settle", "onchain": onchain, "want": want})}
	}
	au := &author{a.t, f}
	root := au.storedWord(anchor, ci.SlotIndex(17))
	drift := ci.ExpectedOpen{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenDrift, Code: ci.Prefix + "drift", Fields: cf(map[string]any{"field": "A14", "attest": root, "settle": common.HexToHash("0xabc")})}
	vc := func(o ...ci.ExpectedOpen) ci.Expected {
		e := exp(ci.HeadlineVerifiedCore, map[string]string{ci.JudgedAuthorizationAttest: "verified", ci.JudgedRegistryLink: "verified"})
		e.Open = o
		return e
	}
	add("VS8-180.alert", vc(alert("paused", uint64(1), uint64(0))), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(0), common.BigToHash(big.NewInt(1))))
	// a root changed at N only is a drift of A14 AND (the root commits to the validators) a set_root alert: "plus both"
	add("VS8-180.drift_and_alert", vc(alert("set_root", common.HexToHash("0xabc"), root), drift), world.SetStorage(world.StationSettle, anchor, ci.SlotIndex(17), common.HexToHash("0xabc")))
	return out
}

func TestVectors2cAgainstTheVerifier(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	wj := worldJSON(t, f)
	ver := f.verifier2c()
	for _, v := range a.vectors() {
		t.Run(v.ID, func(t *testing.T) {
			in, err := world.Builder{Manifest: f.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("the world cannot build the vector: %v", err)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, f.m)
			if err != nil {
				t.Fatalf("verifier error: %v", err)
			}
			if err := ci.MatchExpected(v.Expected, rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// verifier2c is the REAL composed verifier (steps of 2a, 2b-1, 2b-2 and 2c): the sets of package 2c are judged by the facts the real steps 16-22
// produce. The stand-ins of build2c remain only in the tests that deliberately isolate one step of package 2c by editing a fact (c2Hook).
func (f *fixture) verifier2c() ci.Verifier {
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

// The published set: loaded from disk (hash-checked), run WITHOUT the world builder on the materialised inputs, regenerated byte-identically.
// Written once with CERTEN_WRITE_S8_2C=1.
func TestVectorSet2cIsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	vectors := a.vectors()
	if _, err := os.Stat(setDir(vectorSet2c)); err != nil && os.Getenv("CERTEN_WRITE_S8_2C") == "1" {
		if err := world.WriteSet(setDir(vectorSet2c), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSet2c))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSet2c, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	for _, r := range ci.RunSet(set, nil, f.verifier2c()) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	checkPublishedBytes(t, f, vectorSet2c, vectors)
}

// checkPublishedBytes regenerates the set into a temporary directory, which must be byte-identical to the published one (the world builder and the
// author did not drift).
func checkPublishedBytes(t *testing.T, f *fixture, name string, vectors []ci.Vector) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "again")
	if err := world.WriteSet(tmp, f.spec, vectors); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	published, _ := os.ReadDir(setDir(name))
	if len(entries) != len(published) {
		t.Fatalf("regenerated %d files, published %d", len(entries), len(published))
	}
	for _, e := range entries {
		x, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
		y, _ := os.ReadFile(filepath.Join(setDir(name), e.Name()))
		if !bytes.Equal(x, y) {
			t.Errorf("file %s differs from the published one", e.Name())
		}
	}
}

var _ = fmt.Sprint
