// Copyright 2026 Certen Protocol

package capture

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The read plan: every proof read of steps 5-22 of V2_SPEC_S8 r3.2 for one leg, in the roots settle, attest_pre, attest_post and hop.<i>.
// Step 22b says NODES are exactly the nodes these reads visit, so the capture derives its reads from this one plan and the assembler
// re-runs the SAME plan with the strict reads of package contractidentity over the container's nodes (nothing missing, nothing left
// unvisited). The plan is a pure function of the values the reads return: a read that depends on a proven value (the validators, the
// key bytes, the verifier and generated-verifier addresses, the owners) takes that value from the reader.

// Stations. A hop station is HopStation(i), i >= 1.
const (
	StationSettle = "settle"
	StationPre    = "attest_pre"
	StationPost   = "attest_post"
)

// HopStation names the station of hop header H_i (the root of hopHeaders[i-1]).
func HopStation(i int) string { return fmt.Sprintf("hop.%d", i) }

// errPending is returned by a collecting reader for a read it has not served yet: the plan goes on with the zero value and the collector
// asks for everything pending in one call per contract before it runs the plan again.
var errPending = errors.New("capture: read pending")

// Reader serves the reads of the plan.
type Reader interface {
	Account(station string, a common.Address) (ci.AccountState, error)
	Slot(station string, a common.Address, s common.Hash) (common.Hash, error)
	// Indexed reads the attestation transaction (kind "tx") or receipt ("receipt") leaf at index under the attestation header.
	Indexed(kind string, index uint32) ([]byte, error)
	// Code returns the runtime code of the account at the station: nil, nil for an account with no code.
	Code(station string, a common.Address) ([]byte, error)
}

// Facts are the inputs of the plan that no read produces: the leg's identity and what the settlement and the attestation say.
type Facts struct {
	Chain       uint64
	Manifest    *ci.Manifest
	Account     common.Address // the emitter of the selected LeafConsumed log
	AnchorID    common.Hash    // topic1 of that log
	OperationID common.Hash    // the batch operation id (the usedCommitments key); attest stations only
	PKC         common.Hash    // blob word 13 of the attestation call
	Book        common.Hash    // ADIGovernanceProof.authorityBook
	Page        uint64         // ADIGovernanceProof.authorityPage
	Selectors   [][4]byte      // the first four bytes of every leg's data, bytes4(0) for a leg shorter than four bytes
	Link        uint8          // ci.LinkSameBlock | LinkHops | LinkSpine
	HopNumbers  []uint64       // link 1: the numbers of H_0 (= B_v), H_1 .. H_k; H_{k+1} is the settlement block
	TxIndex     uint32         // attestation transaction index in B_v
}

// PlanError is a plan that cannot be derived from the chain's own values (the chain contradicts a pin); nothing is stored for it.
type PlanError struct {
	Station string
	Reason  string
	Err     error
}

func (e *PlanError) Error() string {
	s := fmt.Sprintf("capture plan at %s: %s", e.Station, e.Reason)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}
func (e *PlanError) Unwrap() error { return e.Err }

type planner struct {
	rd      Reader
	f       *Facts
	err     error
	pending bool
}

func (p *planner) fail(st, reason string, err error) {
	if p.err == nil {
		p.err = &PlanError{Station: st, Reason: reason, Err: err}
	}
}

func (p *planner) take(st, what string, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errPending):
		p.pending = true
	default:
		p.fail(st, what, err)
	}
	return false
}

func (p *planner) account(st string, a common.Address) ci.AccountState {
	if p.err != nil {
		return ci.AccountState{}
	}
	acc, err := p.rd.Account(st, a)
	if !p.take(st, "account "+a.Hex(), err) {
		return ci.AccountState{}
	}
	return acc
}

func (p *planner) slot(st string, a common.Address, s common.Hash) common.Hash {
	if p.err != nil {
		return common.Hash{}
	}
	v, err := p.rd.Slot(st, a, s)
	if !p.take(st, "slot "+s.Hex()+" of "+a.Hex(), err) {
		return common.Hash{}
	}
	return v
}

func (p *planner) code(st string, a common.Address) []byte {
	if p.err != nil {
		return nil
	}
	c, err := p.rd.Code(st, a)
	if !p.take(st, "code "+a.Hex(), err) {
		return nil
	}
	return c
}

// dyn reads a bytes/string variable by the step 6 rule: the head word, then exactly the data words it implies.
func (p *planner) dyn(st string, a common.Address, slot common.Hash, max uint64) []byte {
	head := p.slot(st, a, slot)
	if p.err != nil || p.pending {
		return nil
	}
	h, err := ci.ParseDynHead(head, max)
	if err != nil {
		p.fail(st, "string_invalid", err)
		return nil
	}
	words := make([]common.Hash, 0, h.DynWordCount())
	for i := uint64(0); i < h.DynWordCount(); i++ {
		words = append(words, p.slot(st, a, ci.DynDataSlot(slot, i)))
	}
	if p.err != nil || p.pending {
		return nil
	}
	out, err := h.Assemble(words)
	if err != nil {
		p.fail(st, "string_invalid", err)
	}
	return out
}

func (p *planner) addrWord(st string, w common.Hash, what string) common.Address {
	a, err := ci.WordAddress(w)
	if err != nil {
		p.fail(st, what, err)
	}
	return a
}

func (p *planner) deployment(role string) common.Address {
	d, ok := p.f.Manifest.Deployment(p.f.Chain, role)
	if !ok {
		p.fail(StationSettle, "address_not_published", fmt.Errorf("no %s row for chain %d", role, p.f.Chain))
		return common.Address{}
	}
	return common.HexToAddress(d.Address)
}

// groth16Of derives the generated verifier G from the carried code of V: the value at the first reference of the build's groth16Verifier
// immutable (all three references are judged equal by step 12).
func (p *planner) groth16Of(st string, v common.Address, code []byte) common.Address {
	dep, ok := p.f.Manifest.Deployment(p.f.Chain, "blsZkVerifier")
	if !ok {
		p.fail(st, "address_not_published", errors.New("no blsZkVerifier row"))
		return common.Address{}
	}
	b, ok := p.f.Manifest.Build(dep.Build)
	if !ok {
		p.fail(st, "build_unknown", errors.New(dep.Build))
		return common.Address{}
	}
	for _, im := range b.Immutables {
		if im.Name != "groth16Verifier" || len(im.References) == 0 {
			continue
		}
		r := im.References[0]
		if r.Start < 0 || r.Length != 32 || r.Start+r.Length > len(code) {
			p.fail(st, "verifier_code_shorter_than_references", fmt.Errorf("%s: %d bytes, reference %d+%d", v.Hex(), len(code), r.Start, r.Length))
			return common.Address{}
		}
		w := code[r.Start : r.Start+r.Length]
		for _, c := range w[:12] {
			if c != 0 {
				p.fail(st, "verifier_reference_not_an_address", errors.New(v.Hex()))
				return common.Address{}
			}
		}
		return common.BytesToAddress(w[12:])
	}
	p.fail(st, "build_without_groth16_reference", errors.New(dep.Build))
	return common.Address{}
}

// authSet reads the AUTH slot set (the frozen table: rows A01-A21, V01-V03, C01) at one station. flip adds A15 usedCommitments, read at
// the attestation stations only (the flips are not judged at N).
func (p *planner) authSet(st string, flip bool) {
	f := p.f
	lim := ci.DefaultLimits()
	A := p.deployment("anchor")
	p.account(st, A)
	rec := ci.MappingSlotAt(ci.KeyBytes32(f.AnchorID), 1)
	for k := uint64(0); k < 13; k++ { // A02: all 13 words of anchors[anchorId]
		p.slot(st, A, ci.MemberSlot(rec, k))
	}
	for _, s := range []common.Hash{ci.SlotIndex(0), ci.MappingSlotAt(ci.KeyBytes32(f.AnchorID), 2), ci.MappingSlotAt(ci.KeyBytes32(f.AnchorID), 3),
		ci.MappingSlotAt(ci.KeyBytes32(f.PKC), 4), ci.SlotIndex(5), ci.SlotIndex(6)} {
		p.slot(st, A, s)
	}
	lenWord := p.slot(st, A, ci.SlotIndex(13))
	if p.err != nil {
		return
	}
	n, err := ci.WordUint64(lenWord)
	if err != nil || n > uint64(lim.MaxValidators) {
		p.fail(st, "validator_list_too_large", fmt.Errorf("length word %s, limit %d: %v", lenWord.Hex(), lim.MaxValidators, err))
		return
	}
	for i := uint64(0); i < n && p.err == nil; i++ { // A10 elements, A09 per validator: words 0-3 and the bytes key data
		el, _, _ := ci.ArrayElementSlot(13, i, 20)
		w := p.slot(st, A, el)
		if p.err != nil || p.pending {
			continue
		}
		v := p.addrWord(st, w, "validator_list_element_invalid")
		base := ci.MappingSlotAt(ci.KeyAddress(v), 12)
		p.slot(st, A, base)
		p.slot(st, A, ci.MemberSlot(base, 1))
		p.dyn(st, A, ci.MemberSlot(base, 2), uint64(lim.MaxString))
		p.slot(st, A, ci.MemberSlot(base, 3))
	}
	for _, s := range []uint64{14, 15, 16, 17} {
		p.slot(st, A, ci.SlotIndex(s))
	}
	ownerA := p.slot(st, A, ci.SlotIndex(27))
	p.slot(st, A, ci.SlotIndex(29))
	slot30 := p.slot(st, A, ci.SlotIndex(30))
	if flip {
		p.slot(st, A, ci.MappingSlotAt(ci.KeyBytes32(f.OperationID), 18))
	}
	if p.err != nil || p.pending {
		return
	}
	V, err := ci.PackedAddress(slot30, 0) // A18: bytes 0-19
	if err != nil {
		p.fail(st, "verifier_pointer_invalid", err)
		return
	}
	owners := []common.Address{p.addrWord(st, ownerA, "owner_invalid")}
	if V != (common.Address{}) {
		p.account(st, V)
		for _, s := range []uint64{0, 1, 2} { // V01-V03
			p.slot(st, V, ci.SlotIndex(s))
		}
		ownerV := p.slot(st, V, ci.SlotIndex(2))
		if p.err == nil && !p.pending {
			owners = append(owners, p.addrWord(st, ownerV, "owner_invalid"))
		}
		if vc := p.code(st, V); vc != nil {
			if G := p.groth16Of(st, V, vc); G != (common.Address{}) {
				p.account(st, G)
				p.code(st, G)
			}
		}
		p.code(st, V)
	}
	p.code(st, A)
	for i, o := range owners { // C01: the owner accounts of rule IB, once each
		if i == 1 && o == owners[0] {
			break
		}
		p.account(st, o)
	}
}

// abiEncodeStrings is abi.encode(string a, string b).
func abiEncodeStrings(a, b []byte) []byte {
	pad := func(n int) int { return (n + 31) / 32 * 32 }
	word := func(v int) []byte { return common.LeftPadBytes(big.NewInt(int64(v)).Bytes(), 32) }
	out := append(word(64), word(64+32+pad(len(a)))...)
	for _, s := range [][]byte{a, b} {
		out = append(out, word(len(s))...)
		out = append(out, s...)
		out = append(out, make([]byte, pad(len(s))-len(s))...)
	}
	return out
}

// runSettle is steps 5-14 and the last hop read under the settlement root.
func (p *planner) runSettle() {
	f, st := p.f, StationSettle
	lim := ci.DefaultLimits()
	acct := f.Account
	p.account(st, acct)
	adi := p.dyn(st, acct, ci.SlotIndex(0), uint64(lim.MaxString))
	book := p.dyn(st, acct, ci.SlotIndex(11), uint64(lim.MaxString))
	F := p.deployment("accountFactory")
	p.account(st, F)
	p.slot(st, F, ci.MappingSlotAt(ci.KeyAddress(acct), 2))
	if p.err == nil && !p.pending {
		h := common.BytesToHash(crypto.Keccak256(abiEncodeStrings(adi, book)))
		p.slot(st, F, ci.MappingSlotAt(ci.KeyBytes32(h), 3))
	}
	p.slot(st, acct, ci.SlotIndex(2))
	p.authSet(st, false)
	for _, sel := range f.Selectors { // step 14
		p.slot(st, acct, ci.PageSlot(10, f.Book, f.Page))
		p.slot(st, acct, ci.PageSlot(9, f.Book, f.Page))
		p.slot(st, acct, ci.MappingSlotAt(ci.KeyBytes4(sel), 8))
	}
	p.code(st, acct)
	p.code(st, F)
	p.hop(len(f.HopNumbers) - 1)
}

// hop is the EIP-2935 read of hop i (0 <= i <= k): the history account and the slot of H_i under the root of H_{i+1} (the settlement root
// for the last hop).
func (p *planner) hop(i int) {
	f := p.f
	if f.Link != ci.LinkHops || i < 0 || i >= len(f.HopNumbers) {
		return
	}
	e, ok := f.Manifest.EIP2935(f.Chain)
	if !ok || e.Window == 0 {
		p.fail(StationSettle, "eip2935_not_published", fmt.Errorf("chain %d", f.Chain))
		return
	}
	st := StationSettle
	if i < len(f.HopNumbers)-1 {
		st = HopStation(i + 1)
	}
	hist := common.HexToAddress(e.Address)
	p.account(st, hist)
	p.slot(st, hist, common.BigToHash(new(big.Int).SetUint64(f.HopNumbers[i]%e.Window)))
}

// runAttest is the attestation block's reads: both stations, the transaction and the receipt, and every hop below the last.
func (p *planner) runAttest() {
	p.authSet(StationPre, true)
	p.authSet(StationPost, true)
	for _, kind := range []string{"tx", "receipt"} {
		if p.err != nil {
			break
		}
		_, err := p.rd.Indexed(kind, p.f.TxIndex)
		p.take(StationPost, "attestation "+kind, err)
	}
	for i := 0; i < len(p.f.HopNumbers)-1; i++ {
		p.hop(i)
	}
}

// RunSettle executes the settlement station's plan (E2) over rd. It returns the plan error and whether a read was still pending.
func RunSettle(rd Reader, f *Facts) (pending bool, err error) {
	p := &planner{rd: rd, f: f}
	p.runSettle()
	return p.pending, p.err
}

// RunAll executes the whole plan (settlement, attestation and hops) over rd; the assembler runs it over the container's nodes.
func RunAll(rd Reader, f *Facts) (pending bool, err error) {
	p := &planner{rd: rd, f: f}
	p.runSettle()
	p.runAttest()
	return p.pending, p.err
}
