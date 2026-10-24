// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The pure decisions of package 2b-2: the verifier's threshold test (step 19f2), the anchor's floor rule (19f1) with the boundary vectors of
// the specification, the AUTH key order and the frozen allow-list gate.

func TestB2InnerRuleBoundaries(t *testing.T) {
	n, d := big.NewInt(2), big.NewInt(3) // the verifier's stored 2/3
	cases := []struct {
		signed, total int64
		want          bool
	}{
		{6, 10, false}, // 6x3 = 18 < 10x2 = 20
		{7, 10, true},  // 21 >= 20
		{6, 9, true},   // 18 >= 18: the exact-ratio test passes at equality
		{5, 9, false},  // 15 < 18
		{0, 0, true},
	}
	for _, c := range cases {
		if got := b2InnerOK(big.NewInt(c.signed), big.NewInt(c.total), d, n); got != c.want {
			t.Errorf("inner %d of %d at 2/3: %v, want %v", c.signed, c.total, got, c.want)
		}
	}
	// the overflow guard of _checkThresholdOnChain: a product that wraps is false whatever the comparison would say
	huge := new(big.Int).Lsh(big.NewInt(1), 255)
	if b2InnerOK(huge, big.NewInt(1), big.NewInt(4), big.NewInt(1)) {
		t.Error("signed x den wraps modulo 2^256 and the guard must return false")
	}
	if b2InnerOK(big.NewInt(1), huge, big.NewInt(1), big.NewInt(4)) {
		t.Error("total x num wraps modulo 2^256 and the guard must return false")
	}
	if !b2InnerOK(big.NewInt(1), big.NewInt(1), big.NewInt(0), big.NewInt(0)) {
		t.Error("with den = 0 and num = 0 both products are 0 and 0 >= 0 holds")
	}
}

func authStation(total int64, num, den int64, powers ...int64) *AuthStation {
	s := &AuthStation{Words: map[string]common.Hash{"A11": b2Hash(big.NewInt(total)), "A12": b2Hash(big.NewInt(num)), "A13": b2Hash(big.NewInt(den)), "A10": b2Hash(big.NewInt(int64(len(powers))))}}
	for i, p := range powers {
		a := common.BigToAddress(big.NewInt(int64(i + 1)))
		s.Words["A10:"+strconv.Itoa(i)] = a2Word(a)
		s.Words["A09:"+b2Lower(a)+":0"] = SlotIndex(1)
		s.Words["A09:"+b2Lower(a)+":1"] = b2Hash(big.NewInt(p))
	}
	return s
}

func TestB2OuterRuleFloor(t *testing.T) {
	// total 10 at 2/3: required = floor(20/3) = 6, so outer.signed 6 passes and 5 fails (the anchor's rule is a floor, the verifier's is exact)
	s := authStation(10, 2, 3, 3, 3, 4)
	call := func(signed int64, powers ...int64) AttestCall {
		c := AttestCall{OuterSigned: big.NewInt(signed), OuterTotal: big.NewInt(10)}
		for i, p := range powers {
			c.ValidatorAddresses = append(c.ValidatorAddresses, common.BigToAddress(big.NewInt(int64(i+1))))
			c.VotingPowers = append(c.VotingPowers, big.NewInt(p))
		}
		return c
	}
	if st := b2OuterRule(s, call(6, 3, 3), AtAttestPre); st != nil {
		t.Errorf("signed 6 of 10 at 2/3 must pass the floor rule: %v", st)
	}
	if st := b2OuterRule(s, call(5, 3, 2), AtAttestPre); st == nil || st.Fields["field"] != AuthFieldPower {
		t.Errorf("a listed power different from the registry must be refused first: %v", st)
	}
	if st := b2OuterRule(s, call(3, 3), AtAttestPre); st == nil || st.Fields["field"] != AuthFieldThreshold {
		t.Errorf("signed 3 of 10 must fail the threshold: %v", st)
	}
	if st := b2OuterRule(s, call(7, 3, 3), AtAttestPre); st == nil || st.Fields["field"] != AuthFieldPower {
		t.Errorf("outer.signed 7 against listed powers 3+3 must be a power mismatch: %v", st)
	}
	dup := call(6, 3, 3)
	dup.ValidatorAddresses[1] = dup.ValidatorAddresses[0]
	if st := b2OuterRule(s, dup, AtAttestPre); st == nil || st.Fields["field"] != AuthFieldCount {
		t.Errorf("a duplicated validator must be refused: %v", st)
	}
	unknown := call(6, 3, 3)
	unknown.ValidatorAddresses[1] = common.HexToAddress("0x99")
	if st := b2OuterRule(s, unknown, AtAttestPre); st == nil || st.Fields["field"] != AuthFieldKey {
		t.Errorf("an unregistered listed validator must be refused: %v", st)
	}
	c := call(6, 3, 3)
	c.OuterTotal = big.NewInt(11)
	if st := b2OuterRule(s, c, AtAttestPre); st == nil || st.Fields["field"] != AuthFieldTotalPower {
		t.Errorf("outer.total different from totalVotingPower must be refused: %v", st)
	}
	// total 9 at 2/3: required 6 and signed 6 passes
	s9 := authStation(9, 2, 3, 3, 3, 3)
	c9 := AttestCall{OuterSigned: big.NewInt(6), OuterTotal: big.NewInt(9)}
	for i := 0; i < 2; i++ {
		c9.ValidatorAddresses = append(c9.ValidatorAddresses, common.BigToAddress(big.NewInt(int64(i+1))))
		c9.VotingPowers = append(c9.VotingPowers, big.NewInt(3))
	}
	if st := b2OuterRule(s9, c9, AtAttestPre); st != nil {
		t.Errorf("signed 6 of 9 at 2/3 must pass: %v", st)
	}
}

func TestB2KeyOrder(t *testing.T) {
	order := []string{"A01", "A02:2", "A02:10", "A02:11", "A03", "A09:0xaa:0", "A09:0xaa:1", "A09:0xaa:key", "A10", "A10:0", "A10:2", "A10:11", "A19", "C01:A", "V01"}
	for i := 0; i+1 < len(order); i++ {
		if !b2KeyLess(order[i], order[i+1]) || b2KeyLess(order[i+1], order[i]) {
			t.Errorf("%s must sort before %s", order[i], order[i+1])
		}
	}
}

func TestB2GateOnTheEmbeddedManifest(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"CertenAnchorV8_2/r5", "BLSZKVerifierV2_1/r5"} {
		if c := b2GateCondition(m, key); c != "" {
			t.Errorf("%s: the embedded manifest must pass the writer gate, got %q", key, c)
		}
	}
	if c := b2GateCondition(m, "CertenAccountV7_3/r5"); c != BuildCondStatusMissing {
		t.Errorf("a build without authWriters must be status_missing, got %q", c)
	}
}
