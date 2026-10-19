package proof

import (
	"encoding/json"
	"strings"
	"testing"
)

// RB8-G (verifier notes 1 and 2 on the RB8-E delegation read).
//
// Note 1: a page that is only NAMED as the delegator of a delegated vote is not thereby the signer. The network records that a
// delegating page counted the vote as an `authority` record in the delegating page's OWN signature set, over this transaction,
// listing the page in its delegator list (testdata/kermit_delegated_ecdsa_signing_sets.json shows it). A page without that
// record is not named; a delegated vote that merely says so is a claim, not evidence.

func withDelegatingSetRecords(t *testing.T, edit func(rec map[string]any) bool) []signingKeyPageSet {
	t.Helper()
	sets := liveDelegatedSets(t)
	for i := range sets {
		if sets[i].Account.URL != delegPage {
			continue
		}
		var kept []json.RawMessage
		for _, r := range sets[i].Signatures.Records {
			blob, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(blob, &m); err != nil {
				t.Fatal(err)
			}
			if edit(m) {
				out, _ := json.Marshal(m)
				kept = append(kept, out)
			}
		}
		raw, _ := json.Marshal(map[string]any{"records": kept})
		sets[i].Signatures.Records = nil // decoding into a reused slice would keep the fields the edit removed
		if err := json.Unmarshal(raw, &sets[i].Signatures); err != nil {
			t.Fatal(err)
		}
	}
	return sets
}

func TestSigningKeyPage_TheLiveDelegatingPageHoldsItsAuthorityRecord(t *testing.T) {
	var set *signingKeyPageSet
	sets := liveDelegatedSets(t)
	for i := range sets {
		if sets[i].Account.URL == delegPage {
			set = &sets[i]
		}
	}
	if set == nil || !set.holdsAuthorityRecord(normalizeAccountURL(delegPage), delegTx) {
		t.Fatal("the recorded live response must show the delegating page's authority record over the transaction")
	}
	if set.holdsAuthorityRecord(normalizeAccountURL("acc://pv2-sig-1.acme/book-other/1"), delegTx) ||
		set.holdsAuthorityRecord(normalizeAccountURL(delegPage), strings.Repeat("22", 32)) {
		t.Fatal("an authority record for another page or another transaction counted")
	}
}

func TestSigningKeyPage_ADelegatedRecordNamingAPageWithNoAuthorityRecordIsRefused(t *testing.T) {
	cases := map[string]func(rec map[string]any) bool{
		"no record at all": func(map[string]any) bool { return false },
		"authority record over another transaction": func(rec map[string]any) bool {
			msg := rec["message"].(map[string]any)
			msg["txID"] = "acc://" + strings.Repeat("22", 32) + "@pv2-sig-1.acme/data-deleg"
			return true
		},
		"authority record whose delegator list does not hold the page": func(rec map[string]any) bool {
			sig := rec["message"].(map[string]any)["signature"].(map[string]any)
			sig["delegator"] = []any{"acc://pv2-sig-1.acme/book-other/1"}
			return true
		},
		"authority record without a delegator list": func(rec map[string]any) bool {
			delete(rec["message"].(map[string]any)["signature"].(map[string]any), "delegator")
			return true
		},
		"a record that is not an authority record": func(rec map[string]any) bool {
			rec["message"].(map[string]any)["signature"].(map[string]any)["type"] = "set"
			return true
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			sets := withDelegatingSetRecords(t, edit)
			page, notes, err := selectSigningKeyPage(delegBook, delegPage, delegTx, sets)
			if err == nil {
				t.Fatalf("%s: named %q for a page the chain created no authority evidence for (notes %v)", name, page, notes)
			}
			if !strings.Contains(strings.Join(notes, "|"), "authority record") {
				t.Fatalf("%s: the refusal does not say why: %v", name, notes)
			}
		})
	}
}

// The evidence is the delegating page's OWN set: the same record under another page's set is not it.
func TestSigningKeyPage_AnAuthorityRecordUnderAnotherPageIsNotTheEvidence(t *testing.T) {
	sets := withDelegatingSetRecords(t, func(map[string]any) bool { return false })
	live := liveDelegatedSets(t)
	var authority signingKeyPageSet
	for _, s := range live {
		if s.Account.URL == delegPage {
			authority = s
		}
	}
	for i := range sets {
		if strings.HasSuffix(sets[i].Account.URL, "book-dinner/1") {
			sets[i].Signatures.Records = append(sets[i].Signatures.Records, authority.Signatures.Records...)
		}
	}
	if page, _, err := selectSigningKeyPage(delegBook, delegPage, delegTx, sets); err == nil {
		t.Fatalf("named %q on an authority record that sits under the delegate's page", page)
	}
}

// Note 2: a delegator shape this layer does not know is no delegator; it must not fail the decode of the whole response.
func TestSigningDelegators_AnUnknownShapeIsNoDelegator(t *testing.T) {
	for _, in := range []string{`{"url":"acc://x.acme/book/1"}`, `5`, `true`, `[{"url":"acc://x.acme/book/1"}]`, `["acc://x.acme/book/1", 7]`, `null`, `""`, `[]`} {
		var d signingDelegators
		if err := json.Unmarshal([]byte(in), &d); err != nil {
			t.Errorf("delegator %s failed the decode: %v", in, err)
		}
		if len(d) != 0 {
			t.Errorf("delegator %s names %v; an unknown shape names nobody", in, []string(d))
		}
	}
	var one, many signingDelegators
	if err := json.Unmarshal([]byte(`"acc://x.acme/book/1"`), &one); err != nil || len(one) != 1 {
		t.Errorf("a URL delegator: %v %v", one, err)
	}
	if err := json.Unmarshal([]byte(`["acc://x.acme/book/1","acc://y.acme/book/2"]`), &many); err != nil || len(many) != 2 {
		t.Errorf("a list delegator: %v %v", many, err)
	}
}

func TestSigningKeyPage_AnUnknownDelegatorShapeDoesNotFailTheWholeQuery(t *testing.T) {
	const directVote = `{"message":{"type":"signature","txID":"acc://` + delegTx + `@pv2-sig-1.acme/data","signature":{"type":"eth","publicKey":"04ab","signer":"acc://pv2-sig-1.acme/book-a/2","signerVersion":1}}}`
	body := func(a2Records string) string {
		return `{"result":{"signatures":{"records":[
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-a/1","version":1,"keys":[]},"signatures":{"records":[]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-a/2","version":1,"keys":[]},"signatures":{"records":[` + a2Records + `]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-c/1","version":1,"keys":[]},"signatures":{"records":[{"message":{"type":"signature",
	    "txID":"acc://` + delegTx + `@pv2-sig-1.acme/data","signature":{"type":"delegated","signature":{"type":"ed25519","publicKey":"00","signature":"00","signer":"acc://pv2-sig-1.acme/book-c/1","signerVersion":1},"delegator":{"url":"acc://pv2-sig-1.acme/book-a/1"}}}}]}}
	]}}}`
	}
	var q signingKeyPageQuery
	if err := json.Unmarshal([]byte(body(directVote)), &q); err != nil {
		t.Fatalf("one delegator of an unknown shape failed the decode of the whole response: %v", err)
	}
	page, _, err := selectSigningKeyPage("acc://pv2-sig-1.acme/book-a", "", delegTx, q.Result.Signatures.Records)
	if err != nil || page != "acc://pv2-sig-1.acme/book-a/2" {
		t.Fatalf("got %q, %v; the page that filed its own vote must still resolve", page, err)
	}
	// The unknown delegator names no page: with no direct vote in book-a, book-a/1 is not guessed from it.
	if err := json.Unmarshal([]byte(body("")), &q); err != nil {
		t.Fatal(err)
	}
	if page, _, err := selectSigningKeyPage("acc://pv2-sig-1.acme/book-a", "", delegTx, q.Result.Signatures.Records); err == nil {
		t.Fatalf("an unknown delegator shape named %q", page)
	}
}
