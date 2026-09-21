package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	skpTx    = "aad58e15bd8395d6f3d7b8d5c17cc69b6a4a6190299afe0f84a5d59a696a0600"
	skpOther = "1111111111111111111111111111111111111111111111111111111111111111"
	skpBook  = "acc://orchid-logistics-tcl1.acme/book"
)

// skpSig describes one signature filed under one page, as the network reports it.
type skpSig struct {
	page          string
	pageVersion   uint64
	pageKeys      []string // public keys whose hashes are on the page NOW
	signerKey     string   // public key that signed
	signerVersion uint64
	sigType       string
	txHash        string
}

func skpKeyHash(pub string) string {
	b, _ := hex.DecodeString(pub)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// skpResponse builds a v3 transaction-query response with one signature set per sig.
func skpResponse(sigs ...skpSig) map[string]any {
	var records []any
	// The principal's key BOOK carries a signature request, never a vote: it must be ignored.
	records = append(records, map[string]any{
		"account": map[string]any{"type": "keyBook", "url": skpBook},
		"signatures": map[string]any{"records": []any{map[string]any{
			"message": map[string]any{"type": "signatureRequest", "txID": "acc://" + skpTx + "@orchid-logistics-tcl1.acme/data"},
		}}},
	})
	for _, s := range sigs {
		var keys []any
		for _, k := range s.pageKeys {
			keys = append(keys, map[string]any{"publicKeyHash": skpKeyHash(k)})
		}
		typ := s.sigType
		if typ == "" {
			typ = "ed25519"
		}
		tx := s.txHash
		if tx == "" {
			tx = skpTx
		}
		records = append(records, map[string]any{
			"account": map[string]any{"type": "keyPage", "url": s.page, "version": s.pageVersion, "keys": keys},
			"signatures": map[string]any{"records": []any{map[string]any{
				"message": map[string]any{
					"type": "signature",
					"txID": "acc://" + tx + "@orchid-logistics-tcl1.acme/data",
					"signature": map[string]any{
						"type": typ, "publicKey": s.signerKey, "signer": s.page, "signerVersion": s.signerVersion,
					},
				},
			}}},
		})
	}
	return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
		"recordType": "message",
		"signatures": map[string]any{"records": records},
	}}
}

func skpSets(t *testing.T, resp map[string]any) []signingKeyPageSet {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var q signingKeyPageQuery
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	return q.Result.Signatures.Records
}

const (
	machineKey = "228ef8919d08e7ee0000000000000000000000000000000000000000000000aa"
	humanKey   = "5a5a5a5a5a5a5a5a0000000000000000000000000000000000000000000000bb"
	seatKey    = "04952a856d2c4a780000000000000000000000000000000000000000000000cc"
)

// The live case: the blob declares the unresolvable template <book>/page, and the
// payment was signed by the machine key on page 2. The old resolver named page 1.
func TestSigningKeyPage_MachineKeyOnPage2WithTemplateDeclared(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
		// Other ADIs' pages signed too (seats); they are not pages of this book.
		skpSig{page: "acc://fdb-compliance-tcl1.acme/book/2", pageVersion: 1, pageKeys: []string{seatKey}, signerKey: seatKey, signerVersion: 1},
		skpSig{page: "acc://orchid-logistics-erp-tcl1.acme/book/1", pageVersion: 2, pageKeys: []string{humanKey}, signerKey: humanKey, signerVersion: 2},
	))
	page, notes, err := selectSigningKeyPage(skpBook, skpBook+"/page", skpTx, sets)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if page != skpBook+"/2" {
		t.Fatalf("resolved %s, want %s/2 - the page holding the key that signed", page, skpBook)
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, "|"), "is not a page of") {
		t.Fatalf("the declared template must be reported, not silently replaced; notes=%v", notes)
	}
}

// A well-formed declared page that did not sign is not trusted over the chain.
func TestSigningKeyPage_DeclaredPageThatDidNotSignIsNotNamed(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
	))
	page, notes, err := selectSigningKeyPage(skpBook, skpBook+"/1", skpTx, sets)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if page != skpBook+"/2" {
		t.Fatalf("resolved %s, want page 2", page)
	}
	if !strings.Contains(strings.Join(notes, "|"), "did not sign") {
		t.Fatalf("a declared page that did not sign must be reported; notes=%v", notes)
	}
}

func TestSigningKeyPage_DeclaredPageThatSignedIsHonoured(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/1", pageVersion: 2, pageKeys: []string{humanKey}, signerKey: humanKey, signerVersion: 2},
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
	))
	page, _, err := selectSigningKeyPage(skpBook, skpBook+"/2", skpTx, sets)
	if err != nil || page != skpBook+"/2" {
		t.Fatalf("got %q, %v; want the declared page 2, which signed", page, err)
	}
	// Undeclared, two pages signed: the priority page, identically on every validator.
	page, notes, err := selectSigningKeyPage(skpBook, "", skpTx, sets)
	if err != nil || page != skpBook+"/1" {
		t.Fatalf("got %q, %v; want the priority page 1", page, err)
	}
	if !strings.Contains(strings.Join(notes, "|"), "2 pages") {
		t.Fatalf("several signing pages must be reported; notes=%v", notes)
	}
}

// The failure must be loud: no page of the book signed, so there is nothing to name.
func TestSigningKeyPage_NoPageOfTheBookSignedFails(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: "acc://fdb-risk-tcl1.acme/book/2", pageVersion: 1, pageKeys: []string{seatKey}, signerKey: seatKey, signerVersion: 1},
	))
	if page, _, err := selectSigningKeyPage(skpBook, skpBook+"/page", skpTx, sets); err == nil {
		t.Fatalf("resolved %q with no signature from the book; must fail", page)
	}
}

// A key that is not on the page at the version it signed with is not a vote.
func TestSigningKeyPage_KeyNotOnPageIsNotCounted(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: humanKey, signerVersion: 4},
	))
	if page, _, err := selectSigningKeyPage(skpBook, skpBook+"/page", skpTx, sets); err == nil {
		t.Fatalf("resolved %q from a key the page does not hold; must fail", page)
	}
}

// A page updated since it signed cannot be confirmed from its current keys; G1's
// replay at the execution block decides membership, and the resolver says so.
func TestSigningKeyPage_PageRotatedSinceSigningDefersToReplay(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/2", pageVersion: 5, pageKeys: []string{humanKey}, signerKey: machineKey, signerVersion: 4},
	))
	page, notes, err := selectSigningKeyPage(skpBook, skpBook+"/page", skpTx, sets)
	if err != nil || page != skpBook+"/2" {
		t.Fatalf("got %q, %v; want page 2", page, err)
	}
	if !strings.Contains(strings.Join(notes, "|"), "replay") {
		t.Fatalf("deferral to replay must be reported; notes=%v", notes)
	}
}

// Signatures over another transaction and non-vote records are not evidence.
func TestSigningKeyPage_IgnoresOtherTransactionsAndNonVoteRecords(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/1", pageVersion: 2, pageKeys: []string{humanKey}, signerKey: humanKey, signerVersion: 2, txHash: skpOther},
		skpSig{page: skpBook + "/1", pageVersion: 2, pageKeys: []string{humanKey}, signerKey: humanKey, signerVersion: 2, sigType: "authority"},
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
	))
	page, _, err := selectSigningKeyPage(skpBook, "", skpTx, sets)
	if err != nil || page != skpBook+"/2" {
		t.Fatalf("got %q, %v; want page 2 - page 1's records are not votes on this transaction", page, err)
	}
}

// A page whose vote is DELEGATED - its key lives in a delegate's book - signed, and G1 accepts
// delegation. Refusing it would fail every delegated intent outright.
func TestSigningKeyPage_DelegatedVoteNamesItsPage(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: "", signerVersion: 4, sigType: "delegated"},
	))
	page, notes, err := selectSigningKeyPage(skpBook, skpBook+"/page", skpTx, sets)
	if err != nil || page != skpBook+"/2" {
		t.Fatalf("got %q, %v; want the delegated page 2", page, err)
	}
	if !strings.Contains(strings.Join(notes, "|"), "delegated") {
		t.Fatalf("notes %v", notes)
	}
	// A non-ED25519 key vote is a vote too.
	sets = skpSets(t, skpResponse(
		skpSig{page: skpBook + "/1", pageVersion: 2, signerKey: "02abcdef", signerVersion: 2, sigType: "eth"},
	))
	if page, _, err := selectSigningKeyPage(skpBook, "", skpTx, sets); err != nil || page != skpBook+"/1" {
		t.Fatalf("got %q, %v; want page 1 from its eth key vote", page, err)
	}
}

// The page is named as the network spells it: the URL is hashed into the govRoot.
func TestSigningKeyPage_NamedAsTheNetworkSpellsIt(t *testing.T) {
	sets := skpSets(t, skpResponse(
		skpSig{page: "acc://Orchid-Logistics-TCL1.acme/book/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
	))
	page, _, err := selectSigningKeyPage(skpBook, "", skpTx, sets)
	if err != nil || page != "acc://Orchid-Logistics-TCL1.acme/book/2" {
		t.Fatalf("got %q, %v", page, err)
	}
}

func TestSigningKeyPage_BookDerivedFromDeclaredPage(t *testing.T) {
	book, err := keyBookFor("", "acc://Orchid-Logistics-TCL1.acme/book/page")
	if err != nil || book != skpBook {
		t.Fatalf("got %q, %v; want %s", book, err, skpBook)
	}
	if _, err := keyBookFor("", ""); err == nil {
		t.Fatal("with neither a book nor a page there is nothing to resolve in; must fail")
	}
}

// End to end against a v3 endpoint: the query is scoped to the transaction on its
// principal, and the result is the page that signed.
func TestChainKeyPageResolver_QueriesTheTransaction(t *testing.T) {
	var gotScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3" {
			http.Error(w, "wrong path "+r.URL.Path, http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Params struct {
				Scope string `json:"scope"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		gotScope = req.Params.Scope
		_ = json.NewEncoder(w).Encode(skpResponse(
			skpSig{page: skpBook + "/2", pageVersion: 4, pageKeys: []string{machineKey}, signerKey: machineKey, signerVersion: 4},
		))
	}))
	defer srv.Close()

	r, err := NewChainKeyPageResolver(srv.URL, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.ResolveSigningKeyPage(context.Background(),
		"acc://orchid-logistics-tcl1.acme/data", skpTx, skpBook, skpBook+"/page")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if page != skpBook+"/2" {
		t.Fatalf("resolved %s, want page 2", page)
	}
	if want := "acc://" + skpTx + "@orchid-logistics-tcl1.acme/data"; gotScope != want {
		t.Fatalf("queried scope %q, want %q", gotScope, want)
	}
}

func TestChainKeyPageResolver_NetworkErrorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-33404,"message":"not found"}}`))
	}))
	defer srv.Close()
	r, _ := NewChainKeyPageResolver(srv.URL+"/v3", nil)
	if page, err := r.ResolveSigningKeyPage(context.Background(),
		"acc://orchid-logistics-tcl1.acme/data", skpTx, skpBook, ""); err == nil {
		t.Fatalf("resolved %q from a failed query; must fail", page)
	}
}
