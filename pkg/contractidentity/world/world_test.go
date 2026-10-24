// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

const sepolia = 11155111

var allChains = []uint64{11155111, 84532, 421614, 2017}
var allVariants = []string{VariantH0, VariantS6Silent, VariantHops}

func manifest(t testing.TB) *ci.Manifest {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func derive(t testing.TB, chain uint64, variant string) *World {
	t.Helper()
	m := manifest(t)
	sp, err := Generate(m, chain, variant)
	if err != nil {
		t.Fatalf("generate %d/%s: %v", chain, variant, err)
	}
	w, err := Derive(m, sp)
	if err != nil {
		t.Fatalf("derive %d/%s: %v", chain, variant, err)
	}
	return w
}

func TestTemplatesAreThePinnedRuntime(t *testing.T) {
	m := manifest(t)
	for _, key := range []string{"CertenAnchorV8_2/r5", "BLSZKVerifierV2_1/r5", "BLSZKVerifierV2Generated/r5", "BLSZKVerifierV2Generated/r7", "CertenAccountFactoryV11/r5", "CertenAccountV7_3/r5"} {
		b, ok := m.Build(key)
		if !ok {
			t.Fatalf("no build %s", key)
		}
		tpl, err := Template(key)
		if err != nil {
			t.Fatal(err)
		}
		if len(tpl) != b.Runtime.Bytes {
			t.Fatalf("%s: %d bytes, manifest %d", key, len(tpl), b.Runtime.Bytes)
		}
		got, err := MaskedKeccak(tpl, b)
		if err != nil || got.Hex() != b.Runtime.MaskedKeccak {
			t.Fatalf("%s: masked keccak %s (%v), manifest %s", key, got.Hex(), err, b.Runtime.MaskedKeccak)
		}
		// the committed file IS masked: filling the references with non-zero values changes the hash only through the masked ranges
		vals := map[string]common.Hash{}
		for _, imm := range b.Immutables {
			vals[imm.Name] = common.HexToHash("0xabcdef")
		}
		filled, err := Fill(tpl, b, vals)
		if err != nil {
			t.Fatal(err)
		}
		if g, _ := MaskedKeccak(filled, b); g != got {
			t.Fatalf("%s: filling changed the masked hash", key)
		}
		if len(b.Immutables) > 0 && bytes.Equal(filled, tpl) {
			t.Fatalf("%s: Fill wrote nothing", key)
		}
	}
	// Fill refuses a missing and an extra immutable
	b, _ := m.Build("CertenAnchorV8_2/r5")
	tpl, _ := Template("CertenAnchorV8_2/r5")
	if _, err := Fill(tpl, b, map[string]common.Hash{}); err == nil {
		t.Fatal("Fill accepted a missing immutable")
	}
	if _, err := Fill(tpl, b, map[string]common.Hash{"DEPLOYMENT_CHAIN_ID": {}, "nope": {}}); err == nil {
		t.Fatal("Fill accepted an unknown immutable")
	}
	// the account creation code is the manifest's artifact
	cc, err := CreationCode("CertenAccountV7_3/r5")
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := m.Build("CertenAccountV7_3/r5")
	if len(cc) != ab.Creation.Bytes || crypto.Keccak256Hash(cc).Hex() != ab.Creation.Keccak {
		t.Fatalf("creation code %d bytes keccak %s, manifest %d %s", len(cc), crypto.Keccak256Hash(cc).Hex(), ab.Creation.Bytes, ab.Creation.Keccak)
	}
}

func TestEveryProfileAndVariantDerivesCleanAndDeterministic(t *testing.T) {
	m := manifest(t)
	for _, chain := range allChains {
		for _, v := range allVariants {
			w1 := derive(t, chain, v)
			if w1.PlanErr != nil || w1.CheckErr != nil {
				t.Fatalf("%d/%s: plan %v check %v", chain, v, w1.PlanErr, w1.CheckErr)
			}
			if w1.Planned != len(w1.Container.Nodes) || w1.Planned == 0 {
				t.Fatalf("%d/%s: planned %d nodes, container %d", chain, v, w1.Planned, len(w1.Container.Nodes))
			}
			w2 := derive(t, chain, v)
			if !bytes.Equal(w1.ContainerBytes, w2.ContainerBytes) {
				t.Fatalf("%d/%s: two derivations differ", chain, v)
			}
			s1, _ := w1.Spec.MarshalIndent()
			s2, _ := w2.Spec.MarshalIndent()
			if !bytes.Equal(s1, s2) {
				t.Fatalf("%d/%s: two specs differ", chain, v)
			}
			// the container decodes and re-encodes byte-identically
			c, err := ci.Decode(w1.ContainerBytes, ci.DefaultLimits())
			if err != nil {
				t.Fatalf("%d/%s: %v", chain, v, err)
			}
			if re, err := ci.Encode(c, ci.DefaultLimits()); err != nil || !bytes.Equal(re, w1.ContainerBytes) {
				t.Fatalf("%d/%s: encode(decode(x)) != x (%v)", chain, v, err)
			}
			// the context is complete
			if err := w1.Ctx.ValidateContext(); err != nil {
				t.Fatalf("%d/%s: %v", chain, v, err)
			}
			t.Logf("%d/%-8s container %6d B, %2d nodes, world.json %6d B, container sha256 %x spec sha256 %x", chain, v, len(w1.ContainerBytes), w1.Planned, len(s1),
				sha256.Sum256(w1.ContainerBytes), sha256.Sum256(s1))
		}
	}
	_ = m
}

// testReads re-reads a world's container with the strict reads, as a verifier does.
type testReads struct {
	t  *testing.T
	w  *World
	ns *ci.NodeSet
}

func newReads(t *testing.T, w *World) *testReads {
	ns, err := ci.NewNodeSet(w.Container.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	return &testReads{t: t, w: w, ns: ns}
}

func (r *testReads) acct(station string, a common.Address) ci.AccountState {
	r.t.Helper()
	acc, err := ci.ReadAccount(r.w.StateRoots[station], r.ns, a)
	if err != nil {
		r.t.Fatalf("%s %s: %v", station, a.Hex(), err)
	}
	return acc
}

func (r *testReads) slot(station string, a common.Address, s common.Hash) common.Hash {
	r.t.Helper()
	acc := r.acct(station, a)
	v, err := ci.ReadSlot(acc.StorageRoot, r.ns, s)
	if err != nil {
		r.t.Fatalf("%s %s slot %s: %v", station, a.Hex(), s.Hex(), err)
	}
	return v
}

func addrOf(t *testing.T, s string) common.Address {
	a, err := parseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func rpcWord(t *testing.T, s string) common.Hash {
	h, err := parseHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func parentOf(t *testing.T, raw []byte) common.Hash {
	f, err := finality.ReadHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return common.Hash(f.ParentHash)
}

// checkWorld verifies the facts the steps of the algorithm will judge, with the strict reads over the container's own nodes.
func checkWorld(t *testing.T, w *World) {
	t.Helper()
	m := w.Manifest
	sp := w.Spec
	rd := newReads(t, w)
	A, V, G, F := addrOf(t, sp.Roles.Anchor), addrOf(t, sp.Roles.Verifier), addrOf(t, sp.Roles.Groth16), addrOf(t, sp.Roles.Factory)
	acct, O, hist := addrOf(t, sp.Roles.Account), addrOf(t, sp.Roles.Owner), addrOf(t, sp.Roles.History)
	lim := ci.DefaultLimits()

	// headers: positional reads, hashes, state roots, links
	for name, raw := range w.HeaderRLP {
		f, err := finality.ReadHeader(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if common.Hash(f.Hash) != w.BlockHashes[name] || crypto.Keccak256Hash(raw) != w.BlockHashes[name] {
			t.Fatalf("%s: hash", name)
		}
	}
	stateOf := map[string]string{BlockAttestParent: StationPre, BlockAttest: StationPost, BlockSettle: StationSettle}
	for blk, st := range stateOf {
		f, _ := finality.ReadHeader(w.HeaderRLP[blk])
		if common.Hash(f.StateRoot) != w.StateRoots[st] {
			t.Fatalf("%s: header state root %x is not the %s root %s", blk, f.StateRoot, st, w.StateRoots[st])
		}
	}
	att := w.Container.Attest.Attest
	if att.Link != ci.LinkSpine && att.Link != ci.LinkHops {
		t.Fatalf("link %d", att.Link)
	}
	if crypto.Keccak256Hash(att.HeaderVParent) != parentOf(t, att.HeaderV) {
		t.Fatal("headerVParent is not the parent of headerV")
	}
	fv, _ := finality.ReadHeader(att.HeaderV)
	fp, _ := finality.ReadHeader(att.HeaderVParent)
	fs, _ := finality.ReadHeader(w.HeaderRLP[BlockSettle])
	if fp.Number+1 != fv.Number || fv.Number >= fs.Number {
		t.Fatalf("numbers: parent %d, B_v %d, N %d", fp.Number, fv.Number, fs.Number)
	}
	e29, _ := m.EIP2935(sp.Chain)
	if att.Link == ci.LinkSpine {
		if len(att.Spine) != int(fs.Number-fv.Number) || crypto.Keccak256Hash(att.Spine[0]) != common.Hash(fs.ParentHash) || !bytes.Equal(att.Spine[len(att.Spine)-1], att.HeaderV) {
			t.Fatal("the spine does not run from parentHash(N) down to headerV")
		}
		for i := 1; i < len(att.Spine); i++ {
			if crypto.Keccak256Hash(att.Spine[i]) != parentOf(t, att.Spine[i-1]) {
				t.Fatalf("spine break at %d", i)
			}
		}
	} else {
		hs := append([][]byte{att.HeaderV}, att.HopHeaders...)
		hs = append(hs, w.HeaderRLP[BlockSettle])
		stations := []string{}
		for i := range att.HopHeaders {
			stations = append(stations, HopStation(i+1))
		}
		stations = append(stations, StationSettle)
		for i := 0; i+1 < len(hs); i++ {
			a, _ := finality.ReadHeader(hs[i])
			b, _ := finality.ReadHeader(hs[i+1])
			if b.Number <= a.Number || b.Number-a.Number > e29.Window {
				t.Fatalf("hop %d: gap %d against window %d", i, int64(b.Number)-int64(a.Number), e29.Window)
			}
			ha := rd.acct(stations[i], hist)
			if ha.CodeHash.Hex() != e29.CodeHash {
				t.Fatalf("hop %d: history code hash %s, manifest %s", i, ha.CodeHash.Hex(), e29.CodeHash)
			}
			if got := rd.slot(stations[i], hist, wordU(a.Number%e29.Window)); got != crypto.Keccak256Hash(hs[i]) {
				t.Fatalf("hop %d: ring slot holds %s, not the hash of H_%d", i, got.Hex(), i)
			}
		}
	}

	// the settlement the S6 verifier would accept, and the attestation block's own transactions
	if _, _, err := w.Ctx.Settlement.Verify(); err != nil {
		t.Fatalf("settlement: %v", err)
	}
	cen, err := ci.VerifyBlockTxs(common.BytesToHash(mustField(t, att.HeaderV, 4)), att.BlockTxs, int(att.TxIndex), att.TxLeaf, lim)
	if err != nil {
		t.Fatalf("block txs: %v", err)
	}
	ts, _ := m.TxScan(sp.Chain)
	want := map[byte]bool{2: true}
	for _, ty := range append(append([]int{}, ts.CoveredTypes...), ts.SystemTypes...) {
		want[byte(ty)] = true
	}
	var wantTypes []byte
	for ty := range want {
		wantTypes = append(wantTypes, ty)
	}
	sort.Slice(wantTypes, func(i, j int) bool { return wantTypes[i] < wantTypes[j] })
	if !bytes.Equal(cen.Distinct, wantTypes) {
		t.Fatalf("census %x, manifest lists %x", cen.Distinct, wantTypes)
	}
	// strict walks of the transaction and receipt under the header roots
	for i, root := range []common.Hash{common.BytesToHash(mustField(t, att.HeaderV, 4)), common.BytesToHash(mustField(t, att.HeaderV, 5))} {
		leaf, err := ci.ReadIndexedLeaf(root, rd.ns, uint64(att.TxIndex), lim.MaxNodeBytes)
		if err != nil || !bytes.Equal(leaf, [][]byte{att.TxLeaf, att.ReceiptLeaf}[i]) {
			t.Fatalf("indexed leaf %d: %v", i, err)
		}
	}

	// the carried code is the pinned build, filled for this chain and this account
	byAddr := map[common.Address][]byte{}
	for _, c := range w.Container.Codes {
		byAddr[c.Address] = c.Runtime
	}
	for a, key := range map[common.Address]string{A: "CertenAnchorV8_2/r5", V: "BLSZKVerifierV2_1/r5", F: "CertenAccountFactoryV11/r5", acct: "CertenAccountV7_3/r5"} {
		b, _ := m.Build(key)
		got, err := MaskedKeccak(byAddr[a], b)
		if err != nil || got.Hex() != b.Runtime.MaskedKeccak || len(byAddr[a]) != b.Runtime.Bytes {
			t.Fatalf("%s: carried code masked keccak %s (%v)", key, got.Hex(), err)
		}
		if h := crypto.Keccak256Hash(byAddr[a]); rd.acct(StationSettle, a).CodeHash != h {
			t.Fatalf("%s: account code hash is not the carried code's", key)
		}
	}
	gd, _ := m.Deployment(sp.Chain, "groth16Verifier")
	gb, _ := m.Build(gd.Build)
	if g, _ := MaskedKeccak(byAddr[G], gb); g.Hex() != gb.Runtime.MaskedKeccak {
		t.Fatalf("generated verifier masked keccak %s", g.Hex())
	}
	// immutables: the chain id nine times, the account's three immutables, the verifier's three groth16 references
	ab, _ := m.Build("CertenAnchorV8_2/r5")
	for _, imm := range ab.Immutables {
		for _, r := range imm.References {
			if got := common.BytesToHash(byAddr[A][r.Start : r.Start+32]); got != wordU(sp.Chain) {
				t.Fatalf("anchor DEPLOYMENT_CHAIN_ID reference at %d holds %s", r.Start, got.Hex())
			}
		}
	}
	vb, _ := m.Build("BLSZKVerifierV2_1/r5")
	for _, r := range vb.Immutables[0].References {
		if common.BytesToAddress(byAddr[V][r.Start:r.Start+32]) != G {
			t.Fatal("verifier groth16Verifier reference is not the generated verifier")
		}
	}

	// step 8: the account is the CREATE2 of the factory (creation code, salt, constructor arguments), and the factory registers it
	adi := sp.Context.ADIURL
	row, _ := m.Account(sp.Chain, strings.ToLower(acct.Hex()))
	if row.ADIURL != adi {
		t.Fatalf("adi %q, manifest %q", adi, row.ADIURL)
	}
	creation, _ := CreationCode("CertenAccountV7_3/r5")
	ownerW := crypto.Keccak256([]byte(adi))[12:]
	args, err := abiPack([]string{"address", "address", "string", "string"}, EntryPoint, common.BytesToAddress(ownerW), adi, row.GoverningBook)
	if err != nil {
		t.Fatal(err)
	}
	initHash := crypto.Keccak256(append(append([]byte{}, creation...), args...))
	if common.BytesToHash(initHash).Hex() != row.Create2.InitcodeKeccak {
		t.Fatalf("initcode keccak %x, manifest %s", initHash, row.Create2.InitcodeKeccak)
	}
	salt := crypto.Keccak256([]byte(adi))
	if got := crypto.CreateAddress2(F, [32]byte(salt), initHash); got != acct {
		t.Fatalf("CREATE2 address %s, account %s", got.Hex(), acct.Hex())
	}
	if rd.slot(StationSettle, F, ci.MappingSlotAt(ci.KeyAddress(acct), 2)) != wordU(1) {
		t.Fatal("factory _deployedAccounts")
	}

	// steps 9-11: the pointer, the record and the bundle id
	if p, _ := ci.WordAddress(rd.slot(StationSettle, acct, ci.SlotIndex(2))); p != A {
		t.Fatal("anchor pointer")
	}
	anchorID := rpcWord(t, sp.Settlement.AnchorID)
	rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
	var rw [13]common.Hash
	for k := range rw {
		rw[k] = rd.slot(StationSettle, A, ci.MemberSlot(rec, uint64(k)))
	}
	if rw[0] != anchorID {
		t.Fatal("record bundleId")
	}
	if v, _ := ci.PackedBool(rw[10], 20); !v {
		t.Fatal("record not valid")
	}
	if v, _ := ci.PackedBool(rw[10], 21); !v {
		t.Fatal("record not proofExecuted at N")
	}
	b := w.Ctx.Batch
	if rw[1] != common.Hash(b.BatchRoot) || rw[7] != common.Hash(b.OperationID) || rw[11] != common.Hash(b.AccSetRoot) || rw[12] != common.Hash(b.Incarnation) {
		t.Fatal("record binding to the batch facts")
	}
	leafCount := rd.slot(StationSettle, A, ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3))
	packed := append([]byte("certen:batchbundle:v2"), wordU(sp.Chain).Bytes()...)
	packed = append(packed, b.BatchRoot[:]...)
	packed = append(packed, leafCount.Bytes()...)
	packed = append(packed, b.OperationID[:]...)
	packed = append(packed, rw[8].Bytes()...)
	packed = append(packed, b.AccSetRoot[:]...)
	packed = append(packed, b.Incarnation[:]...)
	if crypto.Keccak256Hash(packed) != anchorID {
		t.Fatal("bundle id derivation")
	}

	// the attestation: calldata, the blob tie, the flips between pre and post, the thresholds and the set root
	var attTx types.Transaction
	if err := attTx.UnmarshalBinary(att.TxLeaf); err != nil {
		t.Fatal(err)
	}
	if attTx.To() == nil || *attTx.To() != A {
		t.Fatal("attestation tx.to")
	}
	call, err := ci.DecodeComprehensiveProofCall(attTx.Data(), ci.DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ci.DecodeZKBlob(call.BLS.AggregateSignature)
	if err != nil {
		t.Fatal(err)
	}
	opID := common.Hash(b.OperationID)
	setRoot := rd.slot(StationPre, A, ci.SlotIndex(17))
	enc, _ := abiPack([]string{"bytes32", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"}, [32]byte(common.RightPadBytes([]byte("certen:bls:v2:pre"), 32)),
		new(big.Int).SetUint64(sp.Chain), [32]byte(anchorID), [32]byte(rw[6]), [32]byte(opID), [32]byte(setRoot), [32]byte(b.AccSetRoot), [32]byte(b.Incarnation))
	msg := crypto.Keccak256Hash(enc)
	if call.AnchorID != [32]byte(anchorID) || common.Hash(blob.MessageHash) != msg || call.BLS.MessageHash != [32]byte(msg) || common.Hash(call.Commitments.OperationCommitment) != opID {
		t.Fatal("message hash / blob tie / operation commitment")
	}
	if pk := rd.slot(StationPre, A, ci.MappingSlotAt(ci.KeyBytes32(blob.PubkeyCommitment), 4)); pk != wordU(1) {
		t.Fatal("pkc not authorized")
	}
	if w.Ctx.Registry9 != nil && w.Ctx.Registry9.SignerCommitment != blob.PubkeyCommitment {
		t.Fatal("Registry9.SignerCommitment is not the blob pkc")
	}
	if rd.slot(StationPre, A, ci.MappingSlotAt(ci.KeyBytes32(opID), 18)) != (common.Hash{}) || rd.slot(StationPost, A, ci.MappingSlotAt(ci.KeyBytes32(opID), 18)) != wordU(1) {
		t.Fatal("flip F1")
	}
	pre10 := rd.slot(StationPre, A, ci.MemberSlot(rec, 10))
	post10 := rd.slot(StationPost, A, ci.MemberSlot(rec, 10))
	preExec, _ := ci.PackedBool(pre10, 21)
	postExec, _ := ci.PackedBool(post10, 21)
	lvl, _ := ci.PackedUint64(post10, 23, 1)
	if preExec || !postExec || lvl != uint64(call.Governance.AuthorityLevel) {
		t.Fatalf("flip F2: pre %v post %v level %d, decoded %d", preExec, postExec, lvl, call.Governance.AuthorityLevel)
	}
	for k := uint64(0); k < 13; k++ {
		if k != 10 && rd.slot(StationPre, A, ci.MemberSlot(rec, k)) != rd.slot(StationPost, A, ci.MemberSlot(rec, k)) {
			t.Fatalf("record word %d differs pre/post", k)
		}
	}
	num, den := rd.slot(StationPre, A, ci.SlotIndex(15)).Big().Uint64(), rd.slot(StationPre, A, ci.SlotIndex(16)).Big().Uint64()
	total := rd.slot(StationPre, A, ci.SlotIndex(14)).Big().Uint64()
	signed := uint64(0)
	for _, p := range call.BLS.VotingPowers {
		signed += p.Uint64()
	}
	if call.BLS.SignedVotingPower.Uint64() != signed || call.BLS.TotalVotingPower.Uint64() != total || signed < total*num/den || blob.SignedVotingPower.Uint64()*3 < blob.TotalVotingPower.Uint64()*2 {
		t.Fatalf("thresholds: signed %d total %d inner %v/%v", signed, total, blob.SignedVotingPower, blob.TotalVotingPower)
	}
	if vnum, vden := rd.slot(StationPre, V, ci.SlotIndex(0)).Big().Uint64(), rd.slot(StationPre, V, ci.SlotIndex(1)).Big().Uint64(); vnum != 2 || vden != 3 {
		t.Fatal("verifier thresholds")
	}
	// the set root recomputed from the validators the registry holds
	n := int(rd.slot(StationPre, A, ci.SlotIndex(13)).Big().Uint64())
	type vi struct {
		addr  common.Address
		power *big.Int
	}
	var vs []vi
	for i := 0; i < n; i++ {
		el, _, _ := ci.ArrayElementSlot(13, uint64(i), 20)
		a, _ := ci.WordAddress(rd.slot(StationPre, A, el))
		base := ci.MappingSlotAt(ci.KeyAddress(a), 12)
		if rd.slot(StationPre, A, base) != wordU(1) {
			t.Fatal("validator not registered")
		}
		key, err := ci.ReadBytes(rd.acct(StationPre, A).StorageRoot, rd.ns, ci.MemberSlot(base, 2), 256)
		if err != nil || len(key) != 96 {
			t.Fatalf("validator key: %d bytes %v", len(key), err)
		}
		vs = append(vs, vi{a, rd.slot(StationPre, A, ci.MemberSlot(base, 1)).Big()})
	}
	sort.Slice(vs, func(i, j int) bool {
		return new(big.Int).SetBytes(vs[i].addr[:]).Cmp(new(big.Int).SetBytes(vs[j].addr[:])) < 0
	})
	var sa []common.Address
	var sp2 []*big.Int
	for _, v := range vs {
		sa, sp2 = append(sa, v.addr), append(sp2, v.power)
	}
	renc, _ := abiPack([]string{"address[]", "uint256[]", "uint256", "uint256"}, sa, sp2, new(big.Int).SetUint64(num), new(big.Int).SetUint64(den))
	if crypto.Keccak256Hash(renc) != setRoot {
		t.Fatal("currentValidatorSetRoot is not the contract's own formula over the registry")
	}
	if r9 := w.Ctx.Registry9; r9 != nil {
		if r9.CertenSetRoot != [32]byte(setRoot) || len(r9.Members) != n {
			t.Fatal("Registry9 does not match the chain registry")
		}
		for i, mem := range r9.Members {
			if mem.Address != vs[i].addr || mem.Power != vs[i].power.Uint64() || len(mem.BLSKey) != 192 || mem.BLSKey != strings.ToLower(mem.BLSKey) {
				t.Fatalf("Registry9 member %d", i)
			}
		}
	}
	// owners: pinned, code-empty and nonce-stable across the attestation block (rule IB)
	ow, _ := ci.WordAddress(rd.slot(StationPre, A, ci.SlotIndex(27)))
	if ow != O || rd.acct(StationPre, O).CodeHash != types.EmptyCodeHash || rd.acct(StationPre, O).Nonce != rd.acct(StationPost, O).Nonce {
		t.Fatal("owner pin / code / nonce")
	}
	// step 12: the verifier slot of the anchor
	s30 := rd.slot(StationSettle, A, ci.SlotIndex(30))
	if pv, _ := ci.PackedAddress(s30, 0); pv != V {
		t.Fatal("anchor slot 30 verifier")
	}

	// the settlement call and its logs
	sc, err := ci.DecodeSettlementCall(w.Ctx.Tx.Data(), ci.DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	if *w.Ctx.Tx.To() != acct || sc.Proof.AnchorID != [32]byte(anchorID) || sc.Proof.OperationID != b.OperationID || common.Hash(sc.Proof.AuthorityBook) != crypto.Keccak256Hash([]byte(row.GoverningBook)) {
		t.Fatal("settlement call binding")
	}
	var sawLeaf, sawOp bool
	for _, lg := range w.Ctx.Receipt.Logs {
		if lg.Address != acct {
			continue
		}
		switch lg.Topics[0] {
		case ci.TopicOf(ci.SigLeafConsumed):
			sawLeaf = lg.Topics[1] == anchorID && w.Ctx.S6Status != ci.S6Proven || (lg.Topics[1] == anchorID && lg.Topics[2] == common.Hash(w.Ctx.S6.LeafKey))
		case ci.TopicOf(ci.SigGovernanceOperation):
			d, err := ci.DecodeGovernanceOperationData(lg.Data)
			sawOp = err == nil && d.Level == 4
		}
	}
	if !sawLeaf || !sawOp {
		t.Fatal("settlement receipt logs")
	}
	if w.Ctx.S6 != nil && w.Ctx.S6.CodeHash != rd.acct(StationSettle, acct).CodeHash {
		t.Fatal("S6 code hash")
	}
	if w.Ctx.S7 == nil || w.Ctx.S7.Headline != finality.LevelFinalized {
		t.Fatal("S7 report")
	}
}

func mustField(t *testing.T, header []byte, idx int) []byte {
	f, err := finality.ReadHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	switch idx {
	case 4:
		return f.TransactionRoot[:]
	case 5:
		return f.ReceiptsRoot[:]
	}
	return f.StateRoot[:]
}

func TestH0IsInternallyConsistentOnEveryProfile(t *testing.T) {
	for _, chain := range allChains {
		for _, v := range allVariants {
			t.Run(fmt.Sprintf("%d_%s", chain, v), func(t *testing.T) {
				checkWorld(t, derive(t, chain, v))
			})
		}
	}
}

func TestInclusionProofsOfTheSettlementAreEthproofs(t *testing.T) {
	w := derive(t, sepolia, VariantH0)
	hdr, rcpt, err := w.Ctx.Settlement.Verify()
	if err != nil || hdr.Number.Uint64() != w.Container.Leg.Number || !rcpt.Succeeded() {
		t.Fatalf("settlement %v", err)
	}
	if _, err := ethproof.VerifyInclusion(w.Ctx.Settlement.Tx, hdr.TxHash, w.Ctx.Settlement.Tx.LeafIndex); err != nil {
		t.Fatal(err)
	}
}
