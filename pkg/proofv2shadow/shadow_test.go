package proofv2shadow

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func auth(books ...string) protocol.AccountAuth {
	var a protocol.AccountAuth
	for _, b := range books {
		a.Authorities = append(a.Authorities, protocol.AuthorityEntry{Url: url.MustParse(b)})
	}
	return a
}

// Accumulate's authority resolution (GetAccountAuthoritySet): an account that lists no authorities inherits from its
// parent identity, recursively. The shadow must capture what that resolution reads, not only the account itself.
func TestGoverningFollowsInheritedAuthority(t *testing.T) {
	disabled := auth("acc://sub.alice.acme/book", "acc://alice.acme/old")
	disabled.Authorities[1].Disabled = true
	accounts := map[string]protocol.Account{
		"acc://alice.acme":           &protocol.ADI{Url: url.MustParse("acc://alice.acme"), AccountAuth: auth("acc://alice.acme/book")},
		"acc://alice.acme/book":      &protocol.KeyBook{Url: url.MustParse("acc://alice.acme/book"), PageCount: 2},
		"acc://alice.acme/data":      &protocol.DataAccount{Url: url.MustParse("acc://alice.acme/data")},
		"acc://sub.alice.acme":       &protocol.ADI{Url: url.MustParse("acc://alice.acme/sub")},
		"acc://alice.acme/sub":       &protocol.ADI{Url: url.MustParse("acc://alice.acme/sub")},
		"acc://alice.acme/sub/data":  &protocol.DataAccount{Url: url.MustParse("acc://alice.acme/sub/data")},
		"acc://alice.acme/own":       &protocol.DataAccount{Url: url.MustParse("acc://alice.acme/own"), AccountAuth: disabled},
		"acc://sub.alice.acme/book":  &protocol.KeyBook{Url: url.MustParse("acc://sub.alice.acme/book"), PageCount: 1},
		"acc://bob.acme":             &protocol.ADI{Url: url.MustParse("acc://bob.acme")},
		"acc://alice.acme/delegated": &protocol.DataAccount{Url: url.MustParse("acc://alice.acme/delegated"), AccountAuth: auth("acc://bob.acme/book")},
	}
	get := func(_ context.Context, u *url.URL) (protocol.Account, error) {
		a, ok := accounts[u.String()]
		if !ok {
			return nil, fmt.Errorf("no account %v", u)
		}
		return a, nil
	}
	cases := []struct {
		account       string
		want, skipped []string
	}{
		// A data account with no authorities inherits its identity's book.
		{"acc://alice.acme/data", []string{"acc://alice.acme/data", "acc://alice.acme", "acc://alice.acme/book", "acc://alice.acme/book/1", "acc://alice.acme/book/2"}, nil},
		// Through a sub-identity that lists none either, up to the root.
		{"acc://alice.acme/sub/data", []string{"acc://alice.acme/sub/data", "acc://alice.acme/sub", "acc://alice.acme", "acc://alice.acme/book", "acc://alice.acme/book/1", "acc://alice.acme/book/2"}, nil},
		// An account's own list is used even when an entry is disabled; the disabled one governs nothing.
		{"acc://alice.acme/own", []string{"acc://alice.acme/own"}, []string{"acc://sub.alice.acme/book"}},
		// Another identity's book is named, not captured.
		{"acc://alice.acme/delegated", []string{"acc://alice.acme/delegated"}, []string{"acc://bob.acme/book"}},
		// A root identity with no authorities resolves to its own empty set.
		{"acc://bob.acme", []string{"acc://bob.acme"}, nil},
	}
	for _, c := range cases {
		got, skipped, err := governing(context.Background(), c.account, get)
		if err != nil {
			t.Fatalf("%s: %v", c.account, err)
		}
		if !reflect.DeepEqual(got, c.want) || !reflect.DeepEqual(skipped, c.skipped) {
			t.Fatalf("%s:\n got %v skipped %v\nwant %v skipped %v", c.account, got, skipped, c.want, c.skipped)
		}
	}
}
