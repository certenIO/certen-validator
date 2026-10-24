// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/finality"
)

// The vector set s8_2c_3 (V2_SPEC_S8 r3.2 + F16/F17, sha256 3c637e4f...): the manifest_history exactness rows VS8-154..159 (step 21c without a
// Registry9: an extension row of policy.setRootHistory for the world's own set root, the commitments of its pkcList read at both attestation
// stations through the world member attestation.pkc_list) and the F17 verdict-precedence rows of registry_mismatch / pkc_mismatch. It SUPERSEDES
// VS8-151.message_root of s8_2c_1, whose r3.2 expectation (R registry_mismatch) is replaced by F17 (U state_changed_in_block on A14); before the
// sets were published s8_2c_1 was regenerated with the F17 expectation (supersededByF17), and the same vector stays here. Expectations are derived from the spec
// text before the verifier is run; the key digest is computed here independently of the verifier.

const vectorSet2c3 = "s8_2c_3"

// refKeysDigest is keccak256(lp("certen:validator-keys:v1") || u32(n) || for each address ascending: B20 || lp(key)), written from the spec text.
func refKeysDigest(addrs []common.Address, keys [][]byte) common.Hash {
	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return bytes.Compare(addrs[idx[a]][:], addrs[idx[b]][:]) < 0 })
	u32 := func(n int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }
	tag := []byte("certen:validator-keys:v1")
	pre := append(u32(len(tag)), tag...)
	pre = append(pre, u32(len(addrs))...)
	for _, i := range idx {
		pre = append(pre, addrs[i][:]...)
		pre = append(pre, u32(len(keys[i]))...)
		pre = append(pre, keys[i]...)
	}
	return crypto.Keccak256Hash(pre)
}

func hexOf(h common.Hash) string { return strings.ToLower(h.Hex()) }

func (a *author2c) supersededByF17() map[string]ci.Expected {
	f := a.f
	sp := f.spec
	anchor := hexAddr(sp.Roles.Anchor)
	hv := a.header()
	root := (&author{a.t, f}).storedWord(anchor, ci.SlotIndex(17))
	return map[string]ci.Expected{
		"VS8-151.message_root": a.stateChanged(root, hv.Number, "A14", common.HexToHash("0xabc"), root),
	}
}

func (a *author2c) header() finality.HeaderFields {
	hv, err := finality.ReadHeader(a.f.built.World.Container.Attest.Attest.HeaderV)
	if err != nil {
		a.t.Fatal(err)
	}
	return hv
}

func (a *author2c) stateChanged(_ common.Hash, block uint64, field string, pre, post common.Hash) ci.Expected {
	return exp(ci.HeadlineUnproven, only(ci.JudgedRegistryLink, "unproven"),
		est(ci.JudgedRegistryLink, "unproven", map[string]any{"reason": "state_changed_in_block", "field": field, "pre": pre, "post": post, "block": block}))
}

func (a *author2c) vectors3() []ci.Vector {
	f := a.f
	sp := f.spec
	au := &author{a.t, f}
	anchor, owner := hexAddr(sp.Roles.Anchor), hexAddr(sp.Roles.Owner)
	hv := a.header()
	if hv.Number <= 11832592 {
		a.t.Fatalf("B_v %d does not follow the last embedded setRootHistory row of Sepolia", hv.Number)
	}
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	jv := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			a.t.Fatal(err)
		}
		return b
	}
	root := au.storedWord(anchor, ci.SlotIndex(17))
	members := sp.Context.Registry9.Members
	var addrs []common.Address
	var keys [][]byte
	for _, m := range members {
		addrs = append(addrs, hexAddr(m.Address))
		k, err := hexDecode(m.BLSKey)
		if err != nil {
			a.t.Fatal(err)
		}
		keys = append(keys, k)
	}
	good := refKeysDigest(addrs, keys)
	pkcs := world.WorldPKCs(11155111)
	hexList := func(l []common.Hash) []string {
		out := make([]string, len(l))
		for i, h := range l {
			out[i] = hexOf(h)
		}
		return out
	}
	// the honest setRootHistory row for the world's own set root, and the mutations that install it (no Registry9, the row's commitments read)
	baseRow := func() map[string]any {
		return map[string]any{"chainId": uint64(11155111), "root": hexOf(root), "validFromBlock": hv.Number, "validToBlock": nil,
			"thresholdNumerator": 2, "thresholdDenominator": 3, "keysDigest": hexOf(good), "pkcCount": 29, "pkcList": hexList(pkcs)}
	}
	install := func(row map[string]any, readList bool, extra ...ci.Mutation) []ci.Mutation {
		ms := []ci.Mutation{{Op: "unset_field", Target: "context", Path: "registry9"}}
		if readList {
			ms = append(ms, ci.Mutation{Op: "set_field", Target: "world", Path: "attestation.pkc_list", Value: jv(hexList(pkcs))})
		}
		ms = append(ms, ci.Mutation{Op: "set_field", Target: "extension", Path: "policy", Value: jv(map[string]any{"setRootHistory": []any{row}})})
		return append(ms, extra...)
	}
	keysNC := func(reason string, f map[string]any, extra ...ci.ExpectedOpen) ci.Expected {
		fields := map[string]any{"part": "registry_keys", "reason": reason}
		for k, v := range f {
			fields[k] = v
		}
		e := exp(ci.HeadlineVerifiedCore, only(ci.JudgedRegistryLink, "open"))
		e.Open = append([]ci.ExpectedOpen{{Part: ci.JudgedRegistryLink, Kind: ci.OpenNotChecked, Code: ci.Prefix + "not_checked", Fields: cf(fields)}}, extra...)
		return e
	}
	drift := func(field string, attest, settle common.Hash) ci.ExpectedOpen {
		return ci.ExpectedOpen{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenDrift, Code: ci.Prefix + "drift", Fields: cf(map[string]any{"field": field, "attest": attest, "settle": settle})}
	}
	word64 := func(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n)) }
	both := func(slot common.Hash, w common.Hash) []ci.Mutation {
		return []ci.Mutation{world.SetStorage(world.StationPre, anchor, slot, w), world.SetStorage(world.StationPost, anchor, slot, w)}
	}
	without := func(k string) map[string]any { r := baseRow(); delete(r, k); return r }

	// VS8-154: the honest row proves keys and the authorized set exactly: registry_link verified via manifest_history, headline verified
	add("VS8-154", exp(ci.HeadlineVerified, only(ci.JudgedRegistryLink, "verified")), install(baseRow(), true)...)
	// VS8-155: the owner swaps one BLS key (the root does not commit to keys): not_checked{registry_keys, keys_digest_mismatch}, never verified
	m2 := hexAddr(members[2].Address)
	dataSlot := ci.DynDataSlot(ci.MemberSlot(ci.MappingSlotAt(ci.KeyAddress(m2), 12), 2), 0)
	swapped := append([]byte(nil), keys[2]...)
	nw := common.HexToHash("0x5a5a")
	copy(swapped[:32], nw[:])
	keys2 := append([][]byte(nil), keys...)
	keys2[2] = swapped
	add("VS8-155", keysNC("keys_digest_mismatch", map[string]any{"want": good, "got": refKeysDigest(addrs, keys2)}), install(baseRow(), true, both(dataSlot, nw)...)...)
	// VS8-156: the owner authorizes one extra commitment (slot 5 = 30, the row says 29); the root drifts nothing, A07 drifts at N
	add("VS8-156", keysNC("pkc_count_mismatch", map[string]any{"want": uint64(29), "got": uint64(30)}, drift("A07", word64(30), word64(29))),
		install(baseRow(), true, both(ci.SlotIndex(5), word64(30))...)...)
	// VS8-157: the owner replaces one authorized commitment (count equal): the first listed entry that is 0 is named
	used := common.HexToHash(sp.Attestation.Blob[13])
	pick := pkcs[10]
	if pick == used {
		pick = pkcs[11]
	}
	add("VS8-157", keysNC("pkc_set_mismatch", map[string]any{"entry": pick}), install(baseRow(), true, both(ci.MappingSlotAt(ci.KeyBytes32(pick), 4), common.Hash{})...)...)
	// VS8-158: a row without keysDigest / pkcCount / pkcList; keysDigest in another address order; another threshold
	add("VS8-158.row_without_keys_digest", keysNC("row_without_keys_digest", nil), install(without("keysDigest"), true)...)
	add("VS8-158.row_without_pkc_count", keysNC("row_without_pkc_count", nil), install(without("pkcCount"), false)...)
	add("VS8-158.pkc_list_absent", keysNC("pkc_list_absent", nil), install(without("pkcList"), false)...)
	rev := make([]common.Address, len(addrs))
	for i := range addrs {
		rev[len(addrs)-1-i] = addrs[i]
	}
	revKeys := make([][]byte, len(keys))
	for i := range keys {
		revKeys[len(keys)-1-i] = keys[i]
	}
	// the digest of the addresses listed in descending order WITHOUT the sort the spec requires (the owner\x27s "other address order")
	wrong := unsortedDigest(rev, revKeys)
	r := baseRow()
	r["keysDigest"] = hexOf(wrong)
	add("VS8-158.keys_digest_other_order", keysNC("keys_digest_mismatch", map[string]any{"want": wrong, "got": good}), install(r, true)...)
	r = baseRow()
	r["thresholdNumerator"], r["thresholdDenominator"] = 1, 3
	add("VS8-158.threshold", keysNC("threshold_mismatch", map[string]any{"want": "1/3", "got": "2/3"}), install(r, true)...)
	// VS8-159: the list unsorted (a swap), with a duplicate, and 257 entries
	r = baseRow()
	l := hexList(pkcs)
	l[3], l[4] = l[4], l[3]
	r["pkcList"] = l
	add("VS8-159.unsorted", keysNC("pkc_list_malformed", map[string]any{"index": uint64(4)}), install(r, false)...)
	r = baseRow()
	l = hexList(pkcs)
	l[5] = l[4]
	r["pkcList"] = l
	add("VS8-159.duplicate", keysNC("pkc_list_malformed", map[string]any{"index": uint64(5)}), install(r, false)...)
	big257 := append([]common.Hash(nil), pkcs...)
	for i := 0; len(big257) < 257; i++ {
		big257 = append(big257, crypto.Keccak256Hash([]byte(fmt.Sprintf("synthetic-pkc-%d", i))))
	}
	sort.Slice(big257, func(i, j int) bool { return bytes.Compare(big257[i][:], big257[j][:]) < 0 })
	r = baseRow()
	r["pkcCount"], r["pkcList"] = 257, hexList(big257)
	add("VS8-159.too_large", keysNC("pkc_list_too_large", map[string]any{"count": uint64(257), "limit": uint64(256)}, drift("A07", word64(257), word64(29))),
		install(r, false, both(ci.SlotIndex(5), word64(257))...)...)

	// F17: registry_mismatch / pkc_mismatch obey the verdict precedence
	m1 := hexAddr(members[1].Address)
	powerSlot := ci.MemberSlot(ci.MappingSlotAt(ci.KeyAddress(m1), 12), 1)
	badPower := ctxSet("registry9.members.1.power", members[1].Power+1)
	add("VS8-151.message_root", a.stateChanged(root, hv.Number, "A14", common.HexToHash("0xabc"), root), world.SetStorage(world.StationPre, anchor, ci.SlotIndex(17), common.HexToHash("0xabc")))
	add("VS8-151.roster_changed_in_block", a.stateChanged(root, hv.Number, "A09:"+strings.ToLower(m1.Hex())+":1", word64(members[1].Power), word64(members[1].Power+1)),
		world.SetStorage(world.StationPost, anchor, powerSlot, word64(members[1].Power+1)))
	add("VS8-151.owner_active_in_block", exp(ci.HeadlineUnproven, only(ci.JudgedRegistryLink, "unproven")), badPower, world.SetNonce(world.StationPost, owner, 7777))
	other := used
	other[31] ^= 1
	pkcSlot := ci.MappingSlotAt(ci.KeyBytes32(used), 4)
	add("VS8-160.a05_changed_in_block", a.stateChanged(root, hv.Number, "A05", word64(1), common.Hash{}),
		ctxSet("registry9.signer_commitment", hexOf(other)), world.SetStorage(world.StationPost, anchor, pkcSlot, common.Hash{}))
	add("VS8-160.owner_active_in_block", exp(ci.HeadlineUnproven, only(ci.JudgedRegistryLink, "unproven")),
		ctxSet("registry9.signer_commitment", hexOf(other)), world.SetNonce(world.StationPost, owner, 7777))
	return out
}

// unsortedDigest is the digest preimage of the formula WITHOUT the ascending address sort (the faulty digest of VS8-158).
func unsortedDigest(addrs []common.Address, keys [][]byte) common.Hash {
	u32 := func(n int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }
	tag := []byte("certen:validator-keys:v1")
	pre := append(u32(len(tag)), tag...)
	pre = append(pre, u32(len(addrs))...)
	for i := range addrs {
		pre = append(pre, addrs[i][:]...)
		pre = append(pre, u32(len(keys[i]))...)
		pre = append(pre, keys[i]...)
	}
	return crypto.Keccak256Hash(pre)
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func TestVectors2c3AgainstTheVerifier(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	wj := worldJSON(t, f)
	ver := f.verifier2c()
	for _, v := range a.vectors3() {
		t.Run(v.ID, func(t *testing.T) {
			in, err := world.Builder{Manifest: f.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatalf("the world cannot build the vector: %v", err)
			}
			rep, err := ver.Verify(in.Ctx, in.Container, in.Manifest)
			if err != nil {
				t.Fatalf("verifier error: %v", err)
			}
			if err := ci.MatchExpected(v.Expected, rep); err != nil {
				t.Fatal(err)
			}
			if v.ID == "VS8-154" && rep.Headline.RegistryLink != "via manifest_history{keys:digest,pkc:exact_set}" {
				t.Fatalf("registry_link %q", rep.Headline.RegistryLink)
			}
			if _, err := rep.Canonical(); err != nil {
				t.Fatalf("canonical form: %v", err)
			}
		})
	}
}

func TestVectorSet2c3IsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	vectors := a.vectors3()
	if _, err := os.Stat(setDir(vectorSet2c3)); err != nil && os.Getenv("CERTEN_WRITE_S8_2C3") == "1" {
		if err := world.WriteSet(setDir(vectorSet2c3), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSet2c3))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSet2c3, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	for _, r := range ci.RunSet(set, nil, f.verifier2c()) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	checkPublishedBytes(t, f, vectorSet2c3, vectors)
}
