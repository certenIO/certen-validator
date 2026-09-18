package proofrequests

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
)

func openDB(t *testing.T) (*sql.DB, *database.Repositories) {
	t.Helper()
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CERTEN_TEST_DB is required in CI")
		}
		t.Skip("CERTEN_TEST_DB not set — the proof request fulfiller needs PostgreSQL")
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := (schema.Runner{DB: db}).Up(context.Background(), "proofrequests-test"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, database.NewRepositories(database.NewClientFromDB(db))
}

// callbackRecorder is a callback endpoint that remembers what it was sent.
type callbackRecorder struct {
	mu       sync.Mutex
	payloads []CallbackPayload
	server   *httptest.Server
}

func newCallbackRecorder(t *testing.T) *callbackRecorder {
	r := &callbackRecorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var p CallbackPayload
		if err := json.NewDecoder(req.Body).Decode(&p); err == nil {
			r.mu.Lock()
			r.payloads = append(r.payloads, p)
			r.mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *callbackRecorder) forRequest(id uuid.UUID) []CallbackPayload {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []CallbackPayload
	for _, p := range r.payloads {
		if p.RequestID == id {
			out = append(out, p)
		}
	}
	return out
}

func newRequest(t *testing.T, db *sql.DB, repos *database.Repositories, input *database.NewProofRequest) *database.ProofRequest {
	t.Helper()
	request, err := repos.Requests.CreateRequest(context.Background(), input)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_requests WHERE request_id = $1`, request.RequestID)
	})
	return request
}

func newArtifact(t *testing.T, db *sql.DB, repos *database.Repositories, accumTx, account string) *database.ProofArtifact {
	t.Helper()
	artifact, err := repos.ProofArtifacts.CreateProofArtifact(context.Background(), &database.NewProofArtifact{
		ProofType: database.ProofTypeCertenAnchor, AccumTxHash: accumTx, AccountURL: account,
		ProofClass: database.ProofClassOnDemand, ValidatorID: "requests-test", ArtifactJSON: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("create artifact: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM proof_artifacts WHERE proof_id = $1`, artifact.ProofID)
	})
	return artifact
}

func fulfiller(t *testing.T, repos *database.Repositories, now func() time.Time) *Fulfiller {
	t.Helper()
	f, err := New(repos, Config{ValidatorID: "requests-test", Now: now, BatchSize: 10000, MaxRetries: 2, OnDemandDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func getRequest(t *testing.T, repos *database.Repositories, id uuid.UUID) *database.ProofRequest {
	t.Helper()
	request, err := repos.Requests.GetRequest(context.Background(), id)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	return request
}

func TestARequestWhoseProofExistsIsCompletedAndItsCallbackCalled(t *testing.T) {
	db, repos := openDB(t)
	callbacks := newCallbackRecorder(t)
	accumTx := "requests-tx-" + uuid.NewString()
	artifact := newArtifact(t, db, repos, accumTx, "acc://requests.acme/tokens")
	request := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand, CallbackURL: callbacks.server.URL + "/done",
	})

	fulfiller(t, repos, time.Now).RunOnce(context.Background())

	got := getRequest(t, repos, request.RequestID)
	if got.Status != database.RequestStatusCompleted || !got.ProofID.Valid || got.ProofID.UUID != artifact.ProofID {
		t.Fatalf("request after one pass: %+v", got)
	}
	sent := callbacks.forRequest(request.RequestID)
	if len(sent) != 1 || sent[0].Status != "completed" || sent[0].ProofID != artifact.ProofID.String() {
		t.Fatalf("callbacks = %+v", sent)
	}
}

// Clients send the Accumulate transaction ID (acc://<hash>@<principal>); artifacts and batch members are
// keyed by the bare hash. This is the form every production request has.
func TestARequestNamingTheAccumulateTransactionIDIsCompleted(t *testing.T) {
	db, repos := openDB(t)
	hash := strings.Repeat("ab", 16) + strings.ReplaceAll(uuid.NewString(), "-", "")
	artifact := newArtifact(t, db, repos, hash, "acc://txid.acme/data")
	request := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: "acc://" + strings.ToUpper(hash) + "@txid.acme/data", RequestType: database.RequestTypeOnDemand,
	})
	fulfiller(t, repos, time.Now).RunOnce(context.Background())
	if got := getRequest(t, repos, request.RequestID); got.Status != database.RequestStatusCompleted || got.ProofID.UUID != artifact.ProofID {
		t.Fatalf("a request naming the transaction ID was not answered by its artifact: %+v", got)
	}
}

func TestARequestWhoseTransactionIsBatchedIsMarkedBatched(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	accumTx := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	batchID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO anchor_batches (id) VALUES ($1)`, batchID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM anchor_batches WHERE id = $1`, batchID)
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index) VALUES ($1, $2, 'acc://b.acme', 0)`, batchID, accumTx); err != nil {
		t.Fatal(err)
	}
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: "acc://" + accumTx + "@b.acme/data", RequestType: database.RequestTypeOnDemand})

	fulfiller(t, repos, time.Now).RunOnce(ctx)

	got := getRequest(t, repos, request.RequestID)
	if got.Status != database.RequestStatusBatched || !got.BatchID.Valid || got.BatchID.UUID != batchID {
		t.Fatalf("request after one pass: %+v", got)
	}
}

func TestARequestWithoutAProofFailsAtItsDeadlineAndIsRetriedUntilItsAttemptsRunOut(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	callbacks := newCallbackRecorder(t)
	request := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: "requests-never-" + uuid.NewString(), RequestType: database.RequestTypeOnDemand, CallbackURL: callbacks.server.URL,
	})
	clock := time.Now()
	now := func() time.Time { return clock }
	f := fulfiller(t, repos, now)

	f.RunOnce(ctx) // claimed, inside its window
	if got := getRequest(t, repos, request.RequestID); got.Status != database.RequestStatusProcessing {
		t.Fatalf("a fresh request is %s, want processing", got.Status)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		clock = clock.Add(2 * time.Minute)
		f.RunOnce(ctx) // the window has passed: failed
		got := getRequest(t, repos, request.RequestID)
		if got.Status != database.RequestStatusFailed || got.RetryCount != attempt {
			t.Fatalf("attempt %d: request is %s with %d retries", attempt, got.Status, got.RetryCount)
		}
		f.RunOnce(ctx) // retried: back to pending, and claimed again with a fresh window
		got = getRequest(t, repos, request.RequestID)
		if attempt < 2 && got.Status != database.RequestStatusProcessing {
			t.Fatalf("attempt %d: a retried request is %s, want processing", attempt, got.Status)
		}
		if attempt == 2 && got.Status != database.RequestStatusFailed {
			t.Fatalf("a request out of attempts was retried: %s", got.Status)
		}
	}
	sent := callbacks.forRequest(request.RequestID)
	if len(sent) != 2 || sent[0].Status != "failed" || sent[0].Error == "" {
		t.Fatalf("failure callbacks = %+v", sent)
	}
}

func TestAnAccountRequestIsAnsweredByAProofMadeAfterIt(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	account := "acc://requests-" + uuid.NewString() + ".acme/tokens"
	newArtifact(t, db, repos, "old-"+uuid.NewString(), account)
	request := newRequest(t, db, repos, &database.NewProofRequest{AccountURL: account, RequestType: database.RequestTypeOnDemand})
	f := fulfiller(t, repos, time.Now)

	f.RunOnce(ctx)
	if got := getRequest(t, repos, request.RequestID); got.Status == database.RequestStatusCompleted {
		t.Fatal("an account request was answered by a proof made before it")
	}
	time.Sleep(10 * time.Millisecond)
	fresh := newArtifact(t, db, repos, "new-"+uuid.NewString(), account)
	f.RunOnce(ctx)
	if got := getRequest(t, repos, request.RequestID); got.Status != database.RequestStatusCompleted || got.ProofID.UUID != fresh.ProofID {
		t.Fatalf("account request after a new proof: %+v", got)
	}
}

func TestTwoValidatorsSettleARequestOnce(t *testing.T) {
	db, repos := openDB(t)
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	accumTx := "requests-race-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://race.acme")
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand, CallbackURL: server.URL})

	a, b := fulfiller(t, repos, time.Now), fulfiller(t, repos, time.Now)
	var wg sync.WaitGroup
	for _, f := range []*Fulfiller{a, b} {
		wg.Add(1)
		go func(f *Fulfiller) { defer wg.Done(); f.RunOnce(context.Background()) }(f)
	}
	wg.Wait()
	if got := getRequest(t, repos, request.RequestID); got.Status != database.RequestStatusCompleted {
		t.Fatalf("request is %s", got.Status)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("callback called %d times, want once", n)
	}
}

// A validator acting on a stale view of a request (another validator settled it after this one listed
// it) must not call the callback: only the validator whose terminal update took effect does.
func TestAValidatorThatLosesTheSettlementDoesNotCallTheCallback(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	accumTx := "requests-stale-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://stale.acme")
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand, CallbackURL: server.URL})
	if err := repos.Requests.MarkProcessing(ctx, request.RequestID); err != nil {
		t.Fatal(err)
	}
	stale := getRequest(t, repos, request.RequestID)

	a, b := fulfiller(t, repos, time.Now), fulfiller(t, repos, time.Now)
	if got := a.settle(ctx, stale); got != outcomeCompleted {
		t.Fatalf("first settlement = %v", got)
	}
	if got := b.settle(ctx, stale); got != outcomeWaiting {
		t.Fatalf("second settlement of a settled request = %v", got)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("callback called %d times, want once", n)
	}
}

func TestACallbackThatIsNotHTTPIsNotCalled(t *testing.T) {
	db, repos := openDB(t)
	accumTx := "requests-file-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://file.acme")
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand, CallbackURL: "ftp://example.com/proofs"})
	var called int32
	f := fulfiller(t, repos, time.Now)
	f.cfg.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&called, 1)
		return nil, http.ErrUseLastResponse
	})}
	f.RunOnce(context.Background())
	if got := getRequest(t, repos, request.RequestID); got.Status != database.RequestStatusCompleted {
		t.Fatalf("request is %s", got.Status)
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("a non-http callback URL was called")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
