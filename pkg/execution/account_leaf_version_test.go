package execution

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// RB5-F57: each settlement chain is on exactly one account leaf version, chosen by configuration.

// Live behaviour is unchanged until the owner switches a chain: all three supported chains are on v3 by default.
func TestAccountLeafVersionDefaultsAreTheLiveGeneration(t *testing.T) {
	for _, id := range []int64{84532, 11155111, 421614} {
		v, err := AccountLeafVersionOf(id)
		if err != nil || v != AccountLeafV3 {
			t.Fatalf("chain %d is on %q (%v); want v3 until its factory V11 is deployed and the owner switches it", id, v, err)
		}
	}
	// A chain with no version is refused by name: there is no version to fall back to.
	if _, err := AccountLeafVersionOf(1); !errors.Is(err, ErrNoAccountLeafVersion) {
		t.Fatalf("chain 1: %v", err)
	}
}

func TestAccountLeafVersionsParse(t *testing.T) {
	v, err := ParseAccountLeafVersions(" 84532=v4 ")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v.For(84532); got != AccountLeafV4 {
		t.Fatalf("84532 on %q", got)
	}
	for _, id := range []int64{11155111, 421614} {
		if got, _ := v.For(id); got != AccountLeafV3 {
			t.Fatalf("%d on %q: switching Base moved another chain", id, got)
		}
	}
	if s := v.String(); s != "84532=v4,421614=v3,11155111=v3" {
		t.Fatalf("String() = %s", s)
	}
	for spec, want := range map[string]error{
		"84532=v5":          ErrUnknownAccountLeafVersion,
		"84532=v2":          ErrUnknownAccountLeafVersion,
		"84532=":            ErrUnknownAccountLeafVersion,
		"84532=v4,84532=v3": nil, // named twice
		"84532":             nil, // not a pair
		"base=v4":           nil, // not a chain id
		"-1=v4":             nil,
	} {
		_, err := ParseAccountLeafVersions(spec)
		if err == nil {
			t.Fatalf("%q was accepted", spec)
		}
		if want != nil && !errors.Is(err, want) {
			t.Fatalf("%q: %v, want %v", spec, err, want)
		}
	}
}

// Startup refuses, by name, a settlement chain on no version.
func TestAccountLeafVersionsFromEnvRefusesAChainOnNone(t *testing.T) {
	t.Setenv(AccountLeafVersionsEnv, "")
	if _, err := AccountLeafVersionsFromEnv([]int64{84532, 11155111, 421614}); err != nil {
		t.Fatalf("the supported chains: %v", err)
	}
	_, err := AccountLeafVersionsFromEnv([]int64{84532, 10})
	if !errors.Is(err, ErrNoAccountLeafVersion) || !strings.Contains(err.Error(), "10") {
		t.Fatalf("chain 10 on no version: %v", err)
	}
	t.Setenv(AccountLeafVersionsEnv, "10=v4")
	if v, err := AccountLeafVersionsFromEnv([]int64{84532, 10}); err != nil {
		t.Fatal(err)
	} else if got, _ := v.For(10); got != AccountLeafV4 {
		t.Fatalf("10 on %q", got)
	}
	t.Setenv(AccountLeafVersionsEnv, "84532=v9")
	if _, err := AccountLeafVersionsFromEnv([]int64{84532}); !errors.Is(err, ErrUnknownAccountLeafVersion) {
		t.Fatalf("an unknown version started: %v", err)
	}
}

// The window a v4 leaf binds is exactly PendingBatchIntent.Deadline (and the commit time): the deadline the chain enforces
// is the number every validator computes, from the signed legs and the commit time - including when the settlement
// horizon, not a signed deadline, is the earlier.
func TestTheLeafWindowIsTheMembersDeadline(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	commit := time.Unix(1_790_000_000, 0).UTC()
	signed := commit.Add(20 * time.Minute).Unix()
	for _, c := range []struct {
		name      string
		deadlines []int64
		position  int
		want      int64
	}{
		{"the earliest signed deadline", []int64{signed + 60, signed}, 0, signed},
		{"no signed deadline: the settlement horizon", []int64{0}, 0, commit.Add(maxGasDeferral).Unix()},
		{"a signed deadline past the horizon", []int64{commit.Add(48 * time.Hour).Unix()}, 0, commit.Add(maxGasDeferral).Unix()},
		{"a later member of a sequence: a longer horizon", []int64{0}, 2, commit.Add(3 * maxGasDeferral).Unix()},
	} {
		var legs []LegExecution
		for _, d := range c.deadlines {
			l := oneLeg(84532, dst, 1)
			l.Deadline = d
			legs = append(legs, l)
		}
		p := pending("w-"+c.name, "acc://window.acme", 84532, acct1, 77, legs...)
		p.CommitTime, p.SequencePosition = commit.Add(400*time.Millisecond), c.position
		deadline, ok := p.Deadline()
		if !ok || deadline.Unix() != c.want {
			t.Fatalf("%s: Deadline() = %v", c.name, deadline)
		}
		in, err := p.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		if in.NotAfter != uint64(deadline.Unix()) || in.NotBefore != uint64(commit.Unix()) {
			t.Fatalf("%s: window [%d, %d], want [%d, %d]", c.name, in.NotBefore, in.NotAfter, commit.Unix(), deadline.Unix())
		}
		leaf, err := p.Leaf()
		if err != nil || leaf != ComputeBatchLeafV4(84532, in) {
			t.Fatalf("%s: leaf %x (%v)", c.name, leaf, err)
		}
		// The deadline enforced off chain when the settlement is sent is the same number.
		if exp, err := settlementExpiry(p, commit.Unix()+60, time.Time{}); err != nil || exp > int64(in.NotAfter) {
			t.Fatalf("%s: expiresAt %d (%v) past the leaf's notAfter %d", c.name, exp, err, in.NotAfter)
		}
	}
}

// A member whose window cannot be stated yet has no v4 leaf, by name - never a leaf without its deadline. On a v3 chain
// the same member's leaf is formed exactly as before.
func TestAMemberWithoutAWindowHasNoV4Leaf(t *testing.T) {
	p := pending("nowin", "acc://nowin.acme", 84532, acct1, 78, oneLeg(84532, dst, 1))
	v3, err := p.Leaf()
	if err != nil {
		t.Fatalf("v3 chain: %v", err)
	}
	withAccountLeafVersions(t, "84532=v4")
	if _, err := p.Leaf(); !errors.Is(err, ErrNoMemberWindow) {
		t.Fatalf("no commit time: %v", err)
	}
	p.CommitTime = time.Unix(1_790_000_000, 0)
	v4, err := p.Leaf()
	if err != nil || v4 == v3 {
		t.Fatalf("v4 leaf %x (%v), v3 %x", v4, err, v3)
	}
	if _, err := ComputeAccountLeaf(84532, BatchLeafInput{ADIURL: "acc://x.acme"}); !errors.Is(err, ErrNoMemberWindow) {
		t.Fatalf("a v4 leaf without notAfter: %v", err)
	}
}

// A chain is on exactly one version: a member of a v4 chain gets the v4 leaf and its peers on v3 chains keep theirs - one
// intent can settle on both.
func TestOneIntentSettlesOnAV4AndAV3Chain(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	commit := time.Unix(1_790_000_000, 0)
	base := pending("mixed", "acc://mixed.acme", 84532, acct1, 79, oneLeg(84532, dst, 1))
	sep := pending("mixed", "acc://mixed.acme", 11155111, acct2, 79, oneLeg(11155111, dst, 1))
	base.CommitTime, sep.CommitTime = commit, commit
	bin, _ := base.LeafInput()
	sin, _ := sep.LeafInput()
	if bin.NotAfter == 0 || sin.NotAfter != 0 || sin.NotBefore != 0 {
		t.Fatalf("windows: base [%d,%d], sepolia [%d,%d]", bin.NotBefore, bin.NotAfter, sin.NotBefore, sin.NotAfter)
	}
	if l, _ := base.Leaf(); l != ComputeBatchLeafV4(84532, bin) {
		t.Fatal("the Base member's leaf is not v4")
	}
	if l, _ := sep.Leaf(); l != ComputeBatchLeafV3(11155111, sin) {
		t.Fatal("the Sepolia member's leaf is not v3")
	}
}

// A successor's predecessor leaf is formed on the PREDECESSOR's chain's version.
func TestAPredecessorLeafIsOfItsOwnChainsVersion(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	commit := time.Unix(1_790_000_000, 0)
	pred := pending("seq", "acc://seq.acme", 84532, acct1, 80, oneLeg(84532, dst, 1))
	pred.CommitTime = commit
	succ := pending("seq", "acc://seq.acme", 11155111, acct2, 80, oneLeg(11155111, dst, 1))
	succ.CommitTime = commit
	pexec, _ := pred.ExecutionCommitment()
	pdl, _ := pred.Deadline()
	succ.After = &MemberPredecessor{ChainID: 84532, OperationID: pred.OperationID, Account: pred.Account, ADIURL: pred.ADIURL,
		ExecutionCommitment: pexec, Deadline: pdl}
	got, err := succ.After.leafFor(succ)
	if err != nil {
		t.Fatal(err)
	}
	want, err := pred.Leaf()
	if err != nil || got != want {
		t.Fatalf("the predecessor's leaf %x, its own %x (%v)", got, want, err)
	}
}

// A kept tree re-derives with the leaves it was formed with, whatever version its chain is on now: a v3 tree kept before
// Base moves to v4 (written exactly as before, with no version) still verifies after - a kept tree that does not verify
// stops the store - and a v4 tree states its version and verifies after a move back.
func TestAKeptTreeVerifiesAsTheVersionItWasFormedWith(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	a := outcomeTestMember(t, 84532, "kv-a", f77NativeLeg(84532, "1000"))
	tree, byOp := outcomeTestTree(t, 84532, a)
	v3, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v3)
	if strings.Contains(string(raw), "leaf_version") || strings.Contains(string(raw), "not_before") {
		t.Fatalf("a v3 kept tree is no longer written as before: %s", raw)
	}

	withAccountLeafVersions(t, "84532=v4")
	if err := v3.Verify(); err != nil {
		t.Fatalf("a v3 tree kept before the switch: %v", err)
	}
	tree4, byOp4 := outcomeTestTree(t, 84532, a)
	v4, err := NewOutcomeTree(tree4, byOp4, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if v4.LeafVersion != AccountLeafV4 || v4.Members[0].NotBefore != outcomeTestCommit.Unix() || v4.Members[0].Leaf == v3.Members[0].Leaf {
		t.Fatalf("v4 kept tree %+v", v4)
	}
	withAccountLeafVersions(t, "84532=v3")
	if err := v4.Verify(); err != nil {
		t.Fatalf("a v4 tree after its chain moved back: %v", err)
	}
	// The version is part of what the tree states: another one does not re-derive it.
	forged := *v4
	forged.LeafVersion = ""
	if err := forged.Verify(); err == nil {
		t.Fatal("a v4 tree verified as v3")
	}
	forged.LeafVersion = "v9"
	if err := forged.Verify(); !errors.Is(err, ErrOutcome) {
		t.Fatalf("an unknown version: %v", err)
	}
}
