package proof

import (
	"encoding/json"
	"testing"
)

// A delegation names a page only through its `delegator`: a delegated signature whose delegator is some other page does
// not make the delegating book's page a signer.
func TestSigningKeyPage_OnlyTheNamedDelegatorIsCounted(t *testing.T) {
	sets := liveDelegatedSets(t)
	for i := range sets {
		for j := range sets[i].Signatures.Records {
			sig := &sets[i].Signatures.Records[j].Message.Signature
			if sig.Type == "delegated" {
				sig.Delegator = signingDelegators{"acc://pv2-sig-1.acme/book-elsewhere/1"}
			}
		}
	}
	if _, _, err := selectSigningKeyPage(delegBook, delegPage, delegTx, sets); err == nil {
		t.Fatal("the delegating book was named although the delegation names another page")
	}
	var elsewhere signingKeyPageSet
	if err := json.Unmarshal([]byte(`{"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-elsewhere/1","version":1,"keys":[]},"signatures":{"records":[]}}`), &elsewhere); err != nil {
		t.Fatal(err)
	}
	sets = append(sets, elsewhere)
	if page, _, err := selectSigningKeyPage("acc://pv2-sig-1.acme/book-elsewhere", "", delegTx, sets); err != nil || page != "acc://pv2-sig-1.acme/book-elsewhere/1" {
		t.Fatalf("the page the delegation names is the signer of its book: %q, %v", page, err)
	}
}

// Two hops deep: the outermost delegator sits in the principal's book, the inner one in the first delegate's. Both are
// delegating pages of a vote that was cast, and each names its own book's signer.
func TestSigningKeyPage_ATwoHopDelegationNamesEachDelegatingPage(t *testing.T) {
	const inner = `{"type":"delegated","signature":{"type":"ecdsaSha256","publicKey":"3059","signature":"30","signer":"acc://pv2-sig-1.acme/book-c/1","signerVersion":1},"delegator":"acc://pv2-sig-1.acme/book-b/1"}`
	body := `{"result":{"signatures":{"records":[
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-a/1","version":1,"keys":[]},"signatures":{"records":[]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-b/1","version":1,"keys":[]},"signatures":{"records":[]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-c/1","version":1,"keys":[]},"signatures":{"records":[{"message":{"type":"signature",
	    "txID":"acc://` + delegTx + `@pv2-sig-1.acme/data","signature":{"type":"delegated","signature":` + inner + `,"delegator":"acc://pv2-sig-1.acme/book-a/1"}}}]}}
	]}}}`
	var q signingKeyPageQuery
	if err := json.Unmarshal([]byte(body), &q); err != nil {
		t.Fatal(err)
	}
	for _, book := range []string{"a", "b"} {
		want := "acc://pv2-sig-1.acme/book-" + book + "/1"
		page, _, err := selectSigningKeyPage("acc://pv2-sig-1.acme/book-"+book, "", delegTx, q.Result.Signatures.Records)
		if err != nil || page != want {
			t.Errorf("book-%s: got %q, %v; want %s", book, page, err, want)
		}
	}
}

// A delegating page is a fallback for a book none of whose pages filed a vote of its own: it never displaces a page that
// signed directly, so an intent that resolved before this change resolves to the same page.
func TestSigningKeyPage_ADelegatingPageNeverDisplacesADirectVote(t *testing.T) {
	body := `{"result":{"signatures":{"records":[
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-a/1","version":1,"keys":[]},"signatures":{"records":[]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-a/2","version":1,"keys":[]},"signatures":{"records":[{"message":{"type":"signature",
	    "txID":"acc://` + delegTx + `@pv2-sig-1.acme/data","signature":{"type":"eth","publicKey":"04ab","signer":"acc://pv2-sig-1.acme/book-a/2","signerVersion":1}}}]}},
	  {"account":{"type":"keyPage","url":"acc://pv2-sig-1.acme/book-c/1","version":1,"keys":[]},"signatures":{"records":[{"message":{"type":"signature",
	    "txID":"acc://` + delegTx + `@pv2-sig-1.acme/data","signature":{"type":"delegated","signature":{"type":"ed25519","publicKey":"00","signature":"00","signer":"acc://pv2-sig-1.acme/book-c/1","signerVersion":1},"delegator":"acc://pv2-sig-1.acme/book-a/1"}}}]}}
	]}}}`
	var q signingKeyPageQuery
	if err := json.Unmarshal([]byte(body), &q); err != nil {
		t.Fatal(err)
	}
	page, _, err := selectSigningKeyPage("acc://pv2-sig-1.acme/book-a", "", delegTx, q.Result.Signatures.Records)
	if err != nil || page != "acc://pv2-sig-1.acme/book-a/2" {
		t.Fatalf("got %q, %v; the page that filed its own vote must stay the signing page", page, err)
	}
}
