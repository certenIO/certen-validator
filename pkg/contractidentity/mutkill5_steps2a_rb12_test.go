// Copyright 2026 Certen Protocol

package contractidentity

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the pure helpers of steps_2a.go.

func TestMutKill5A2BlockedRefusals(t *testing.T) {
	part := JudgedParts[0]
	env := &Env{Facts: &Facts{}}
	if out, blocked, err := a2Blocked(env, part); !blocked || err == nil || len(out.Parts) != 0 {
		t.Errorf("no account and no recorded failure: %v %v %v", out, blocked, err)
	}
	env = &Env{Facts: &Facts{}, Container: &Container{Settle: Part{Tag: TagStated, Stated: &Stated{Reason: "no_such_reason"}}}}
	if out, blocked, err := a2Blocked(env, part); !blocked || err == nil || len(out.Parts) != 0 {
		t.Errorf("a stated settle part with a reason the step cannot carry: %v %v %v", out, blocked, err)
	}
}

func TestMutKill5A2InfrastructureWithoutATarget(t *testing.T) {
	if ok, why := a2Infrastructure(&Env{}, common.Address{1}, false); ok || why != "" {
		t.Errorf("no target: %v %q", ok, why)
	}
}

func TestMutKill5A2IsGoverningBookOf(t *testing.T) {
	for _, c := range []struct {
		adi, book string
		want      bool
	}{
		{"acc://x.acme", "acc://x.acme/book", true},
		{"acc://x.acme", "acc://y.acme/book", false},
		{"acc://x.acme", "acc://x.acmeZ/book", false},
		{"acc://x.acme/", "acc://x.acme//book", false},
		{"", "acc://x.acme/book", false},
		{"acc://x.acme", "acc://x.acme", false},
		{"acc://x.acme", "acc://X.acme/book", false},
	} {
		if got := a2IsGoverningBookOf(c.adi, c.book); got != c.want {
			t.Errorf("a2IsGoverningBookOf(%q,%q) = %v", c.adi, c.book, got)
		}
	}
}
