// Copyright 2026 Certen Protocol
//
// The one comparison of two key pages in what decides who may sign (RB9 Phase C1b-2, finding RB9-C1b-1-F3). The certified timeline
// (xtimeline.go: the replay of a page's history must end in the page proven at B_Y) and the shadow cross-check (pkg/proofv2shadow
// crosscheck.go: v1's replay must equal the page v2 captured) ask exactly the same question; both call this.

package proofv2

import (
	"bytes"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// AuthorityFieldDiff is one field in which two key pages differ in what decides who may sign. A and B are the two values as text;
// Text is the one-line description of the difference.
type AuthorityFieldDiff struct {
	Field string
	A, B  string
	Text  string
}

// AuthorityFieldDiffs lists every field in which a and b differ in what decides who may sign: the version, the four thresholds, the
// number of entries, the transaction blacklist and each entry's key hash and delegate (LastUsedOn and the credit balance change
// without changing who may sign). The order is fixed; the first element is the first difference.
func AuthorityFieldDiffs(a, b *protocol.KeyPage) []AuthorityFieldDiff {
	var out []AuthorityFieldDiff
	add := func(field, av, bv, text string) {
		if av != bv {
			out = append(out, AuthorityFieldDiff{Field: field, A: av, B: bv, Text: text})
		}
	}
	num := func(field string, av, bv uint64) {
		add(field, fmt.Sprint(av), fmt.Sprint(bv), fmt.Sprintf("%s %d vs %d", field, av, bv))
	}
	num("version", a.Version, b.Version)
	num("acceptThreshold", a.AcceptThreshold, b.AcceptThreshold)
	num("rejectThreshold", a.RejectThreshold, b.RejectThreshold)
	num("responseThreshold", a.ResponseThreshold, b.ResponseThreshold)
	num("blockThreshold", a.BlockThreshold, b.BlockThreshold)
	add("entries", fmt.Sprint(len(a.Keys)), fmt.Sprint(len(b.Keys)), fmt.Sprintf("%d entries vs %d", len(a.Keys), len(b.Keys)))
	var ba, bb protocol.AllowedTransactions
	if a.TransactionBlacklist != nil {
		ba = *a.TransactionBlacklist
	}
	if b.TransactionBlacklist != nil {
		bb = *b.TransactionBlacklist
	}
	add("transactionBlacklist", fmt.Sprint(uint64(ba)), fmt.Sprint(uint64(bb)), "transaction blacklist")
	n := min(len(a.Keys), len(b.Keys))
	for i := 0; i < n; i++ {
		if !bytes.Equal(a.Keys[i].PublicKeyHash, b.Keys[i].PublicKeyHash) {
			f := fmt.Sprintf("keys[%d].publicKeyHash", i)
			add(f, fmt.Sprintf("%x", a.Keys[i].PublicKeyHash), fmt.Sprintf("%x", b.Keys[i].PublicKeyHash), f)
		}
		da, db := delegateKey(a.Keys[i]), delegateKey(b.Keys[i])
		f := fmt.Sprintf("keys[%d].delegate", i)
		add(f, da, db, f)
	}
	return out
}

// AuthorityDiff names the first difference between two key pages in what decides who may sign, or "" when they agree.
func AuthorityDiff(a, b *protocol.KeyPage) string {
	if d := AuthorityFieldDiffs(a, b); len(d) > 0 {
		return d[0].Text
	}
	return ""
}

func delegateKey(k *protocol.KeySpec) string {
	if k.Delegate == nil {
		return ""
	}
	return strings.ToLower(k.Delegate.String())
}
