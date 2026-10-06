package proofrequests

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/database"
)

func openDB(t *testing.T) (*sql.DB, *database.Repositories) {
	t.Helper()
	// Its own database (RB3-F150): the fulfiller claims every pending request, and took other packages' rows.
	conn, err := testdb.PackageURL("proofrequests")
	if err != nil {
		t.Fatalf("the proof request fulfiller needs PostgreSQL: %v", err)
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

func TestARequestWhoseProofExistsIsCompleted(t *testing.T) {
	db, repos := openDB(t)
	accumTx := "requests-tx-" + uuid.NewString()
	artifact := newArtifact(t, db, repos, accumTx, "acc://requests.acme/tokens")
	request := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand,
	})

	fulfiller(t, repos, time.Now).RunOnce(context.Background())

	got := getRequest(t, repos, request.RequestID)
	if got.Status != database.RequestStatusCompleted || !got.ProofID.Valid || got.ProofID.UUID != artifact.ProofID {
		t.Fatalf("request after one pass: %+v", got)
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

// Production had more requests in flight than one page, the first page all still waiting, and the
// requests behind them already proven: a pass that read only the first page never settled them.
func TestAPassSettlesRequestsBeyondTheFirstPage(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 5; i++ {
		waiting := newRequest(t, db, repos, &database.NewProofRequest{
			AccumTxHash: strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", ""), RequestType: database.RequestTypeOnDemand,
		})
		if err := repos.Requests.MarkProcessingAt(ctx, waiting.RequestID, now); err != nil {
			t.Fatal(err)
		}
	}
	hash := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	proven := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: "acc://" + hash + "@pages.acme/data", RequestType: database.RequestTypeOnDemand,
	})
	if err := repos.Requests.MarkProcessingAt(ctx, proven.RequestID, now); err != nil {
		t.Fatal(err)
	}
	artifact := newArtifact(t, db, repos, hash, "acc://pages.acme/data")

	f, err := New(repos, Config{ValidatorID: "requests-test", Now: func() time.Time { return now }, BatchSize: 2, OnDemandDeadline: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.RunOnce(ctx)
	if got := getRequest(t, repos, proven.RequestID); got.Status != database.RequestStatusCompleted || got.ProofID.UUID != artifact.ProofID {
		t.Fatalf("a proven request behind a full page of waiting ones was not settled: %+v", got)
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
	request := newRequest(t, db, repos, &database.NewProofRequest{
		AccumTxHash: "requests-never-" + uuid.NewString(), RequestType: database.RequestTypeOnDemand,
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
	accumTx := "requests-race-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://race.acme")
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand})

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
}

// A validator acting on a stale view of a request (another validator settled it after this one listed it) does not
// settle it again: only the validator whose terminal update took effect does.
func TestAValidatorThatLosesTheSettlementDoesNotSettleAgain(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	accumTx := "requests-stale-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://stale.acme")
	request := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand})
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
}

// RB7 Task 5 (T5-4): the fulfiller used to POST each outcome, unsigned, to a caller-chosen URL from every validator. It makes
// no outbound request at all now, whatever happens to a request.
type countingTransport struct{ n int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.n, 1)
	return nil, http.ErrUseLastResponse
}

func TestTheFulfillerMakesNoOutboundRequest(t *testing.T) {
	db, repos := openDB(t)
	ctx := context.Background()
	counter := &countingTransport{}
	previous := http.DefaultTransport
	http.DefaultTransport = counter
	t.Cleanup(func() { http.DefaultTransport = previous })

	accumTx := "requests-quiet-" + uuid.NewString()
	newArtifact(t, db, repos, accumTx, "acc://quiet.acme")
	completed := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: accumTx, RequestType: database.RequestTypeOnDemand})
	failing := newRequest(t, db, repos, &database.NewProofRequest{AccumTxHash: "requests-never-" + uuid.NewString(), RequestType: database.RequestTypeOnDemand})

	clock := time.Now()
	f := fulfiller(t, repos, func() time.Time { return clock })
	f.RunOnce(ctx)
	clock = clock.Add(2 * time.Minute)
	f.RunOnce(ctx)

	if got := getRequest(t, repos, completed.RequestID); got.Status != database.RequestStatusCompleted {
		t.Fatalf("request is %s, want completed", got.Status)
	}
	if got := getRequest(t, repos, failing.RequestID); got.Status != database.RequestStatusFailed {
		t.Fatalf("request is %s, want failed", got.Status)
	}
	if n := atomic.LoadInt32(&counter.n); n != 0 {
		t.Fatalf("the fulfiller made %d outbound requests", n)
	}
}

// The tripwire against the callback returning: the worker's source does not even import net/http.
func TestTheFulfillerSourceHasNoHTTPClient(t *testing.T) {
	src, err := os.ReadFile("fulfiller.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{`"net/http"`, "HTTPClient", "CallbackPayload"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("fulfiller.go mentions %s: proof request callbacks were removed", banned)
		}
	}
}
