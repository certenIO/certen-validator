// Copyright 2026 Certen Protocol

// Package difftest checks govproof's key page replay against accumulate-core's
// own executor.
//
// A key page's history is written by real transactions into core's simulator,
// the simulator is served over its real v3 JSON-RPC, and the production
// govproof binary replays the page at every block the history touched. At each
// one, the replayed state must be the page the executor produced. The last
// replay also runs govproof's own check that the page replayed to the head is
// the page the network holds, on every authority field.
//
// It is its own module so that importing core's simulator adds nothing to the
// requirements of the lite client or the validator.
package difftest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	api "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"gitlab.com/accumulatenetwork/accumulate/test/harness"
	"gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
	acctesting "gitlab.com/accumulatenetwork/accumulate/test/testing"
)

type step struct {
	name  string
	url   *url.URL
	index uint64 // the page main chain entry this step produced
	block uint64
	page  *protocol.KeyPage // the executor's page after this step
}

type replayed struct {
	StateExec struct {
		Version   uint64 `json:"version"`
		Threshold uint64 `json:"threshold"`
		Entries   []struct {
			KeyHash  string `json:"keyHash"`
			Delegate string `json:"delegate"`
		} `json:"entries"`
	} `json:"stateExec"`
	Mutations []struct {
		TxType string `json:"txType"`
	} `json:"mutations"`
}

func TestReplayMatchesTheExecutor(t *testing.T) {
	govproof := buildGovproof(t)

	sim := harness.NewSim(t,
		simulator.SimpleNetwork(t.Name(), 1, 1),
		simulator.Genesis(harness.GenesisTime),
	)

	// Funding: a lite token account written directly. It is not under test;
	// everything that touches the pages under test is a real transaction.
	liteKey := acctesting.GenerateKey(t.Name(), "lite")
	lta := helpers.MakeLiteTokenAccount(t, sim.DatabaseFor(protocol.LiteAuthorityForKey(liteKey[32:], protocol.SignatureTypeED25519)), liteKey[32:], protocol.AcmeUrl())
	lid := lta.RootIdentity()
	var ts uint64

	alice := protocol.AccountUrl("alice")
	alicePage := alice.JoinPath("book", "1")
	bob := protocol.AccountUrl("bob")
	bobPage := bob.JoinPath("book", "1")
	k := func(name string) []byte { return acctesting.GenerateKey(t.Name(), name) }
	hashOf := func(key []byte) []byte { h := sha256.Sum256(key[32:]); return h[:] }
	k1, k2, k3, k4, k5, k6, b1 := k("k1"), k("k2"), k("k3"), k("k4"), k("k5"), k("k6"), k("b1")

	var steps []step
	// record captures the page as the executor left it, and the position of
	// the entry the step wrote to the page's main chain. That entry is the
	// transaction itself, or the synthetic message it produced for the page.
	record := func(name string, _ [32]byte, page *url.URL) {
		t.Helper()
		chain, err := sim.Query().QueryChain(context.Background(), page, &api.ChainQuery{Name: "main"})
		if err != nil {
			t.Fatalf("%s: main chain of %v: %v", name, page, err)
		}
		if chain.Count == 0 {
			t.Fatalf("%s: %v has no main chain entries", name, page)
		}
		steps = append(steps, step{name: name, url: page, index: chain.Count - 1,
			page: helpers.GetAccount[*protocol.KeyPage](t, sim.DatabaseFor(page), page)})
	}
	version := func(page *url.URL) uint64 {
		return helpers.GetAccount[*protocol.KeyPage](t, sim.DatabaseFor(page), page).Version
	}

	// sign names one signature: a key on a page.
	type sign struct {
		page *url.URL
		key  []byte
	}
	// submitAs submits the transaction with the first signature and adds the
	// rest, each at its own page's current version.
	submitAs := func(principal *url.URL, body protocol.TransactionBody, sigs ...sign) [32]byte {
		t.Helper()
		st := sim.BuildAndSubmitTxnSuccessfully(
			build.Transaction().For(principal).Body(body).
				SignWith(sigs[0].page).Version(version(sigs[0].page)).Timestamp(&ts).PrivateKey(sigs[0].key))
		for _, sg := range sigs[1:] {
			sim.StepN(2)
			sim.BuildAndSubmitSuccessfully(
				build.SignatureForTxID(st.TxID).Url(sg.page).Version(version(sg.page)).Timestamp(&ts).PrivateKey(sg.key))
		}
		t.Logf("submitted %v (%T) with %d signature(s)", st.TxID, body, len(sigs))
		sim.StepUntil(harness.Txn(st.TxID).Completes())
		sim.StepN(3)
		return st.TxID.Hash()
	}
	// submit signs with keys of one page.
	submit := func(principal *url.URL, body protocol.TransactionBody, signer *url.URL, keys ...[]byte) [32]byte {
		t.Helper()
		sigs := make([]sign, len(keys))
		for i, key := range keys {
			sigs[i] = sign{signer, key}
		}
		return submitAs(principal, body, sigs...)
	}
	createIdentity := func(id *url.URL, key []byte, direct bool) [32]byte {
		t.Helper()
		principal := lid
		if direct {
			principal = id
		}
		st := sim.BuildAndSubmitTxnSuccessfully(
			build.Transaction().For(principal).Body(&protocol.CreateIdentity{
				Url: id, KeyHash: hashOf(key), KeyBookUrl: id.JoinPath("book"),
			}).SignWith(lid).Version(1).Timestamp(&ts).PrivateKey(liteKey))
		sim.StepUntil(harness.Txn(st.TxID).Completes())
		sim.StepN(3)
		return st.TxID.Hash()
	}
	addCredits := func(to *url.URL) [32]byte {
		t.Helper()
		st := sim.BuildAndSubmitTxnSuccessfully(
			build.Transaction().For(lta).Body(&protocol.AddCredits{
				Recipient: to, Amount: *big.NewInt(1e12), Oracle: uint64(protocol.InitialAcmeOracle * protocol.AcmeOraclePrecision),
			}).SignWith(lid).Version(1).Timestamp(&ts).PrivateKey(liteKey))
		sim.StepUntil(harness.Txn(st.TxID).Completes())
		sim.StepN(3)
		return st.TxID.Hash()
	}
	ukp := func(ops ...protocol.KeyPageOperation) protocol.TransactionBody {
		return &protocol.UpdateKeyPage{Operation: ops}
	}
	add := func(key []byte) protocol.KeyPageOperation {
		return &protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: hashOf(key)}}
	}
	remove := func(key []byte) protocol.KeyPageOperation {
		return &protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: hashOf(key)}}
	}

	// alice: born by a synthetic CreateIdentity, then changed only by
	// transactions on her page's main chain.
	record("genesis", createIdentity(alice, k1, false), alicePage)
	record("credits", addCredits(alicePage), alicePage)
	record("add k2 k3", submit(alicePage, ukp(add(k2), add(k3)), alicePage, k1), alicePage)
	record("threshold 2", submit(alicePage, ukp(&protocol.SetThresholdKeyPageOperation{Threshold: 2}), alicePage, k1), alicePage)
	record("add k4, threshold unset", submit(alicePage, ukp(add(k4)), alicePage, k1, k2), alicePage)
	record("updateKey k3 -> k5", submit(alicePage, &protocol.UpdateKey{NewKeyHash: hashOf(k5)}, alicePage, k3), alicePage)

	// bob, whose book becomes a delegate on alice's page.
	createIdentity(bob, b1, false)
	addCredits(bobPage)
	// Every new delegate signs its own addition, so bob's page signs as well.
	record("add delegate bob", submitAs(alicePage, ukp(&protocol.AddKeyOperation{
		Entry: protocol.KeySpecParams{Delegate: bob.JoinPath("book")}}),
		sign{alicePage, k1}, sign{alicePage, k2}, sign{bobPage, b1}), alicePage)
	record("updateKey via delegate", submit(alicePage, &protocol.UpdateKey{NewKeyHash: hashOf(k6)}, bobPage, b1), alicePage)

	record("reject and response 1", submit(alicePage, ukp(
		&protocol.SetRejectThresholdKeyPageOperation{Threshold: 1},
		&protocol.SetResponseThresholdKeyPageOperation{Threshold: 1}), alicePage, k1, k2), alicePage)
	record("threshold 4", submit(alicePage, ukp(&protocol.SetThresholdKeyPageOperation{Threshold: 4}), alicePage, k1, k2), alicePage)
	record("remove k4 k5, clamps", submit(alicePage, ukp(remove(k4), remove(k5)), alicePage, k1, k2, k4, k5), alicePage)

	// A page cannot change its own allowed operations; a higher-priority page
	// of the same book does. Page 2 is born by createKeyPage, and page 1 sets
	// its blacklist.
	alicePage2 := alice.JoinPath("book", "2")
	k7 := k("k7")
	record("page 2 genesis", submit(alice.JoinPath("book"), &protocol.CreateKeyPage{
		Keys: []*protocol.KeySpecParams{{KeyHash: hashOf(k7)}}}, alicePage, k1, k2, k6), alicePage2)
	record("credits page 2", addCredits(alicePage2), alicePage2)
	record("deny updateAccountAuth on page 2", submit(alicePage2, ukp(&protocol.UpdateAllowedKeyPageOperation{
		Deny: []protocol.TransactionType{protocol.TransactionTypeUpdateAccountAuth}}), alicePage, k1, k2, k6), alicePage2)

	// A second book, whose page 1 is born by createKeyBook.
	book2Page := alice.JoinPath("book2", "1")
	k8 := k("k8")
	record("book2 page 1 genesis", submit(alice, &protocol.CreateKeyBook{
		Url: alice.JoinPath("book2"), PublicKeyHash: hashOf(k8)}, alicePage, k1, k2, k6), book2Page)
	record("credits book2", addCredits(book2Page), book2Page)
	record("book2 add a key", submit(book2Page, ukp(add(k("k9"))), book2Page, k8), book2Page)

	// Anchors carry every entry's receipt to a directory root.
	sim.StepN(50)

	srv := serve(t, sim)
	for i := range steps {
		steps[i].block = entryBlock(t, srv.URL, steps[i].url, steps[i].index)
	}

	prev := map[string]*step{}
	for i := range steps {
		s := &steps[i]
		t.Run(fmt.Sprintf("%02d %s", i, s.name), func(t *testing.T) {
			got := runAuthority(t, govproof, srv.URL, s.url, s.block)
			requireSameAuthority(t, s.page, got)
			if p := prev[s.url.String()]; p != nil && p.block < s.block-1 {
				// One block before this step, the page is its previous step's.
				before := runAuthority(t, govproof, srv.URL, s.url, s.block-1)
				requireSameAuthority(t, p.page, before)
			}
		})
		prev[s.url.String()] = s
	}

	final1 := prev[alicePage.String()].page
	if final1.AcceptThreshold != 3 || final1.RejectThreshold != 1 || final1.ResponseThreshold != 1 {
		t.Fatalf("the scripted history did not produce the page 1 it was written to produce: %+v", final1)
	}
	if prev[alicePage2.String()].page.TransactionBlacklist == nil {
		t.Fatal("the scripted history did not blacklist anything on page 2")
	}
}

// A page born by a CreateIdentity sent DIRECTLY - principal the new identity -
// executes on the identity's own partition. Its genesis is whatever that
// leaves on the page's main chain, and the replay must read it.
func TestReplayOfAPageBornByADirectCreateIdentity(t *testing.T) {
	govproof := buildGovproof(t)
	sim := harness.NewSim(t,
		simulator.SimpleNetwork(t.Name(), 1, 1),
		simulator.Genesis(harness.GenesisTime),
	)
	liteKey := acctesting.GenerateKey(t.Name(), "lite")
	lta := helpers.MakeLiteTokenAccount(t, sim.DatabaseFor(protocol.LiteAuthorityForKey(liteKey[32:], protocol.SignatureTypeED25519)), liteKey[32:], protocol.AcmeUrl())
	lid := lta.RootIdentity()
	var ts uint64

	carol := protocol.AccountUrl("carol")
	carolPage := carol.JoinPath("book", "1")
	key := acctesting.GenerateKey(t.Name(), "c1")
	h := sha256.Sum256(key[32:])
	st := sim.BuildAndSubmitTxnSuccessfully(
		build.Transaction().For(carol).Body(&protocol.CreateIdentity{
			Url: carol, KeyHash: h[:], KeyBookUrl: carol.JoinPath("book"),
		}).SignWith(lid).Version(1).Timestamp(&ts).PrivateKey(liteKey))
	sim.StepUntil(harness.Txn(st.TxID).Completes())
	sim.StepN(50)

	srv := serve(t, sim)
	chain, err := sim.Query().QueryChain(context.Background(), carolPage, &api.ChainQuery{Name: "main"})
	if err != nil || chain.Count == 0 {
		t.Fatalf("main chain of %v: %v", carolPage, err)
	}
	block := entryBlock(t, srv.URL, carolPage, chain.Count-1)
	got := runAuthority(t, govproof, srv.URL, carolPage, block)
	requireSameAuthority(t, helpers.GetAccount[*protocol.KeyPage](t, sim.DatabaseFor(carolPage), carolPage), got)
}

func buildGovproof(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src := filepath.Dir(filepath.Dir(file)) // the govproof package
	out := filepath.Join(t.TempDir(), "govproof")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = src
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build govproof: %v\n%s", err, b)
	}
	return out
}

func serve(t *testing.T, sim *harness.Sim) *httptest.Server {
	t.Helper()
	h, err := jsonrpc.NewHandler(
		jsonrpc.Querier{Querier: sim.S.Services()},
		jsonrpc.NetworkService{NetworkService: sim.S.Services()},
	)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// entryBlock is the block the entry at a page main chain index was recorded
// in, read from the entry's own receipt through the API.
func entryBlock(t *testing.T, endpoint string, page *url.URL, index uint64) uint64 {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"query","params":{"scope":%q,"query":{"queryType":"chain","name":"main","index":%d,"includeReceipt":{"forAny":true}}}}`,
		page.String(), index)
	var out struct {
		Result struct {
			Receipt struct {
				LocalBlock uint64 `json:"localBlock"`
			} `json:"receipt"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	postJSON(t, endpoint, body, &out)
	if out.Result.Receipt.LocalBlock == 0 {
		t.Fatalf("no receipt for entry %d of %v: %s", index, page, out.Error)
	}
	return out.Result.Receipt.LocalBlock
}

func runAuthority(t *testing.T, govproof, endpoint string, page *url.URL, block uint64) replayed {
	t.Helper()
	cmd := exec.Command(govproof, "--level", "AUTHORITY", "--keypage", page.String(),
		"--exec-mbi", fmt.Sprint(block), "--endpoint", endpoint, "--http", "--json", "--quiet",
		"--workdir", t.TempDir())
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("govproof AUTHORITY %v @%d: %v\n%s", page, block, err, tail(b))
	}
	var r replayed
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("decode govproof output: %v", err)
			}
			return r
		}
	}
	t.Fatalf("govproof produced no JSON:\n%s", tail(b))
	return r
}

func requireSameAuthority(t *testing.T, want *protocol.KeyPage, got replayed) {
	t.Helper()
	var wantEntries, gotEntries []string
	for _, k := range want.Keys {
		e := hex.EncodeToString(k.PublicKeyHash)
		if k.Delegate != nil {
			e += "->" + strings.ToLower(k.Delegate.String())
		}
		wantEntries = append(wantEntries, e)
	}
	for _, e := range got.StateExec.Entries {
		s := strings.ToLower(e.KeyHash)
		if e.Delegate != "" {
			s += "->" + strings.ToLower(e.Delegate)
		}
		gotEntries = append(gotEntries, s)
	}
	sort.Strings(wantEntries)
	sort.Strings(gotEntries)
	if got.StateExec.Version != want.Version || got.StateExec.Threshold != want.AcceptThreshold ||
		strings.Join(wantEntries, ",") != strings.Join(gotEntries, ",") {
		t.Fatalf("replay disagrees with the executor:\n  executor: v%d threshold %d %v\n  replay:   v%d threshold %d %v",
			want.Version, want.AcceptThreshold, wantEntries,
			got.StateExec.Version, got.StateExec.Threshold, gotEntries)
	}
}

func tail(b []byte) string {
	s := string(b)
	if len(s) > 4000 {
		s = "..." + s[len(s)-4000:]
	}
	return s
}

func postJSON(t *testing.T, endpoint, body string, out interface{}) {
	t.Helper()
	resp, err := http.Post(endpoint, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
