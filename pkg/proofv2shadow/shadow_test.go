package proofv2shadow

import (
	"context"
	"errors"
	"reflect"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Accumulate's authority resolution (GetAccountAuthoritySet): an account that lists no authorities inherits from its
// parent identity, recursively. The shadow must capture what that resolution reads, not only the account itself. (This is
// the rb7b test, carried over: the inheritance cases are unchanged; the cases it expected to skip a foreign book now capture
// it, a disabled authority is captured as well, and a root identity that lists none is the executor's error.)
func TestGoverningFollowsInheritedAuthority(t *testing.T) {
	disabled := authEntries("acc://sub.alice.acme/book", "acc://alice.acme/old")
	disabled.Authorities[1].Disabled = true
	w := world{}
	w.add(&protocol.ADI{Url: url.MustParse("acc://alice.acme"), AccountAuth: authEntries("acc://alice.acme/book")})
	w.add(&protocol.KeyBook{Url: url.MustParse("acc://alice.acme/book"), PageCount: 2})
	w.add(&protocol.KeyPage{Url: url.MustParse("acc://alice.acme/book/1")})
	w.add(&protocol.KeyPage{Url: url.MustParse("acc://alice.acme/book/2")})
	w.add(data("alice.acme", "data"))
	w.add(&protocol.ADI{Url: url.MustParse("acc://alice.acme/sub")})
	w.add(data("alice.acme", "sub/data"))
	w.add(&protocol.DataAccount{Url: url.MustParse("acc://alice.acme/own"), AccountAuth: disabled})
	w.add(&protocol.KeyBook{Url: url.MustParse("acc://sub.alice.acme/book"), PageCount: 1})
	w.add(&protocol.KeyPage{Url: url.MustParse("acc://sub.alice.acme/book/1")})
	w.add(&protocol.ADI{Url: url.MustParse("acc://bob.acme")})
	w.add(&protocol.KeyBook{Url: url.MustParse("acc://bob.acme/book"), PageCount: 1})
	w.add(&protocol.KeyPage{Url: url.MustParse("acc://bob.acme/book/1")})
	w.add(data("alice.acme", "delegated", "acc://bob.acme/book"))

	cases := []struct {
		account string
		want    []string
	}{
		// A data account with no authorities inherits its identity's book.
		{"acc://alice.acme/data", []string{"acc://alice.acme/data", "acc://alice.acme", "acc://alice.acme/book", "acc://alice.acme/book/1", "acc://alice.acme/book/2"}},
		// Through a sub-identity that lists none either, up to the root.
		{"acc://alice.acme/sub/data", []string{"acc://alice.acme/sub/data", "acc://alice.acme/sub", "acc://alice.acme", "acc://alice.acme/book", "acc://alice.acme/book/1", "acc://alice.acme/book/2"}},
		// An account's own list is used; its enabled authority on another identity is captured, and the disabled one - which
		// does not exist - is named.
		{"acc://alice.acme/own", []string{"acc://alice.acme/own", "acc://sub.alice.acme/book", "acc://sub.alice.acme/book/1"}},
		// Another identity's book is captured, not skipped.
		{"acc://alice.acme/delegated", []string{"acc://alice.acme/delegated", "acc://bob.acme/book", "acc://bob.acme/book/1"}},
	}
	for _, c := range cases {
		got, err := governing(context.Background(), facts(c.account), w.get)
		if err != nil {
			t.Fatalf("%s: %v", c.account, err)
		}
		if !reflect.DeepEqual(got.URLs(), c.want) {
			t.Fatalf("%s:\n got %v\nwant %v", c.account, got.URLs(), c.want)
		}
	}
	own, _ := governing(context.Background(), facts("acc://alice.acme/own"), w.get)
	if !reflect.DeepEqual(noteCodes(own), []string{proofv2.StateAuthorityMissing}) {
		t.Fatalf("the disabled authority that does not exist is not named: %v", noteCodes(own))
	}

	// A root identity that lists no authority is the executor's error under Baikonur and later, not an empty set.
	_, err := governing(context.Background(), facts("acc://bob.acme"), w.get)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateCompletenessUnproven {
		t.Fatalf("a root identity without authorities gave %v", err)
	}
}
