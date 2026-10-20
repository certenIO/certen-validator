package ethrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// RB10-B14a (V-R10B5 D3): every provider-error sink in ethrpc is clean at its origin, and what classifies an error still does.

// leaky is an error shaped the way Go's HTTP stack and go-ethereum shape a provider failure, carrying the key in a URL.
func leaky(key string) error {
	return &url.Error{Op: "Post", URL: "https://eth-sepolia.g.alchemy.com/v2/" + key, Err: syscall.ECONNREFUSED}
}

func noKey(t *testing.T, what, key, got string) {
	t.Helper()
	if strings.Contains(got, key) {
		t.Fatalf("%s holds the key %q:\n%s", what, key, got)
	}
}

func TestB14a_TransientErrorTextIsRedactedAndStillUnwraps(t *testing.T) {
	const key = "SECRETKEY-transient-0001"
	te := &TransientError{Host: "eth-sepolia.g.alchemy.com", Attempts: 3, Elapsed: 1500 * time.Millisecond, Err: leaky(key)}
	noKey(t, "TransientError.Error", key, te.Error())
	if !strings.Contains(te.Error(), "eth-sepolia.g.alchemy.com") || !strings.Contains(te.Error(), "refused") {
		t.Fatalf("the host or the cause was lost: %s", te.Error())
	}
	if !errors.Is(te, syscall.ECONNREFUSED) || !IsTransient(te) {
		t.Fatal("the TransientError no longer unwraps to its cause")
	}
	var ue *url.Error
	if !errors.As(te, &ue) || !strings.Contains(ue.URL, key) {
		t.Fatal("errors.As no longer reaches the original url.Error")
	}
	// a body echo, and a stop by the caller's context
	he := &TransientError{Host: "h", Attempts: 1, Err: rpc.HTTPError{StatusCode: 429, Status: "429 Too Many Requests", Body: []byte(`denied for https://eth-sepolia.g.alchemy.com/v2/` + key)},
		Stopped: context.DeadlineExceeded}
	noKey(t, "TransientError.Error (body echo)", key, he.Error())
	var hc rpc.HTTPError
	if !errors.Is(he, context.DeadlineExceeded) || !errors.As(he, &hc) || hc.StatusCode != 429 || IsTransient(he) {
		t.Fatal("the stop, or the 429 under it, is no longer seen (a caller's deadline is never transient)")
	}
}

func TestB14a_UnansweredTextIsRedacted(t *testing.T) {
	const key = "SECRETKEY-unanswered-0002"
	as := []answer[int]{{host: "a.example", err: leaky(key)}, {host: "b.example", err: fmt.Errorf("read: %w", leaky(key))},
		{host: "c.example", err: rpc.HTTPError{StatusCode: 400, Status: "400 Bad Request", Body: []byte(`bad URL /v2/` + key)}}}
	RegisterProviderURL("https://c.example/v2/" + key)
	got := unanswered(as)
	noKey(t, "unanswered", key, got)
	for _, h := range []string{"a.example", "b.example", "c.example", "400 Bad Request"} {
		if !strings.Contains(got, h) {
			t.Fatalf("%q was lost: %s", h, got)
		}
	}
}

// echoProvider is a provider that serves its chain id and answers everything else with a 400 that echoes the request URL.
func echoProvider(t *testing.T, addr string, chainID int64) string {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("cannot listen on %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "eth_chainId") {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%x"}`, chainID)
			return
		}
		http.Error(w, "The requested URL "+r.URL.RequestURI()+" was not found; POST "+r.URL.RequestURI()+" HTTP/1.1 from http://"+r.Host+r.URL.RequestURI(), http.StatusBadRequest)
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestB14a_AnAgreedReadThatCannotBeEstablishedNamesNoKey(t *testing.T) {
	const key = "SECRETKEY-agreed-0003abc"
	final := header(testHeight, "final")
	good := provider(11155111, final)
	goodURL := good.serveOn(t, "127.0.0.1:0")
	echoURL := echoProvider(t, "127.0.0.2:0", 11155111) + "/v2/" + key
	r, err := NewAgreeingReader(context.Background(), 11155111, []string{goodURL, echoURL}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.HeaderByNumber(context.Background(), big.NewInt(testHeight))
	if !errors.Is(err, ErrTooFewProviders) {
		t.Fatalf("one provider answering is too few: %v", err)
	}
	noKey(t, "the agreed read's error", key, err.Error())
	if !strings.Contains(err.Error(), "400 Bad Request") || !strings.Contains(err.Error(), "127.0.0.2") {
		t.Fatalf("the provider and its answer must still be named: %v", err)
	}
	// the construction error names no key either: a chain-id read that fails with the key in its URL
	_, cerr := NewAgreeingReader(context.Background(), 1, []string{goodURL + "/v2/" + key, echoURL}, time.Second)
	if cerr == nil {
		t.Fatal("a wrong chain id was accepted")
	}
	noKey(t, "the construction error", key, cerr.Error())
}

func TestB14a_AProviderRestingForAFailureNamesNoKey(t *testing.T) {
	const key = "SECRETKEY-health-0004abc"
	h := &providerHealth{}
	ctx := context.Background()
	h.record(ctx, ctx, &TransientError{Host: "h", Attempts: 2, Err: leaky(key)})
	noKey(t, "the health reason", key, h.reason)
	_, _, resting := h.admit(time.Now())
	if !errors.Is(resting, ErrProviderResting) {
		t.Fatalf("the provider should rest: %v", resting)
	}
	noKey(t, "ErrProviderResting", key, resting.Error())
	// a long error is redacted before it is cut, never cut inside the key
	long := &TransientError{Host: "h", Attempts: 2, Err: fmt.Errorf("%s%w", strings.Repeat("x", 150), leaky(key))}
	h2 := &providerHealth{}
	h2.record(ctx, ctx, long)
	noKey(t, "the cut health reason", key[:12], h2.reason)
}

type leakyFinality struct {
	fakeFinality
	err error
}

func (f *leakyFinality) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return nil, f.err
}

type leakyHeader struct {
	fakeFinality
	err error
}

func (f *leakyHeader) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return nil, f.err
}

func TestB14a_FinalityLogLinesAndErrorsNameNoKey(t *testing.T) {
	const key = "SECRETKEY-finality-0005a"
	tx := common.HexToHash("0x01")
	var mu sync.Mutex
	var logged bytes.Buffer
	logf := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&logged, format+"\n", args...)
	}
	_, err := SettledInFinalizedChain(context.Background(), &leakyFinality{err: leaky(key)}, tx, time.Now().Add(30*time.Millisecond), time.Millisecond, logf)
	if err == nil {
		t.Fatal("an unreadable receipt settled")
	}
	if logged.Len() == 0 {
		t.Fatal("nothing was logged")
	}
	noKey(t, "the finality log (receipt)", key, logged.String())
	noKey(t, "the finality error (receipt)", key, err.Error())
	logged.Reset()
	canon := &types.Header{Number: big.NewInt(5), Difficulty: big.NewInt(0)}
	rc := &types.Receipt{TxHash: tx, BlockNumber: big.NewInt(5), BlockHash: canon.Hash(), Status: 1}
	f := &leakyHeader{fakeFinality: fakeFinality{canonical: canon, indexed: rc}, err: leaky(key)}
	_, err = SettledInFinalizedChain(context.Background(), f, tx, time.Now().Add(30*time.Millisecond), time.Millisecond, logf)
	if !errors.Is(err, ErrNotYetFinalized) {
		t.Fatalf("an unreadable finalized block: %v", err)
	}
	if logged.Len() == 0 {
		t.Fatal("nothing was logged for the finalized block")
	}
	noKey(t, "the finality log (finalized block)", key, logged.String())
	noKey(t, "the finality error (finalized block)", key, err.Error())
}

func TestB14a_APoolLogAndItsFinalErrorNameNoKey(t *testing.T) {
	const key = "SECRETKEY-pool-0006abcde"
	p := poolOf(2, time.Minute)
	var buf bytes.Buffer
	p.logger = log.New(&buf, "", 0)
	for _, e := range p.endpoints {
		e.url += "/v2/" + key
	}
	err := p.Do(context.Background(), func(*ethclient.Client) error {
		return &url.Error{Op: "Post", URL: p.endpoints[0].url, Err: errors.New("429 Too Many Requests")}
	})
	if err == nil {
		t.Fatal("every endpoint failed")
	}
	noKey(t, "the pool's final error", key, err.Error())
	noKey(t, "the pool's log", key, buf.String())
	if buf.Len() == 0 || !strings.Contains(err.Error(), "429") {
		t.Fatalf("the failure must still be told: log %q, error %v", buf.String(), err)
	}
	// a non-failover error is returned with its type and no key
	werr := &url.Error{Op: "Post", URL: "https://e0.example/v2/" + key, Err: errors.New("execution reverted")}
	got := p.Do(context.Background(), func(*ethclient.Client) error { return werr })
	noKey(t, "the pool's returned error", key, got.Error())
	var ue *url.Error
	if !errors.As(got, &ue) || ue != werr {
		t.Fatal("the returned error no longer unwraps to the original")
	}
}

// The classification of an error by type and by text is the same before and after redaction.
func TestB14a_ClassificationIsUnchangedByRedaction(t *testing.T) {
	const key = "SECRETKEY-class-0007abcd"
	u := "https://eth-sepolia.g.alchemy.com/v2/" + key
	post := func(err error) error { return &url.Error{Op: "Post", URL: u, Err: err} }
	cases := []struct {
		name         string
		err          error
		failover     bool
		transient    bool
		wantIs       error
		wantHTTPCode int
	}{
		{"url.Error connection refused", post(syscall.ECONNREFUSED), true, true, syscall.ECONNREFUSED, 0},
		{"url.Error connection reset", post(syscall.ECONNRESET), true, true, syscall.ECONNRESET, 0},
		{"url.Error EOF", post(io.EOF), true, true, io.EOF, 0},
		{"url.Error timeout", post(timeoutErr{}), true, true, nil, 0},
		{"429 with a body echo", rpc.HTTPError{StatusCode: 429, Status: "429 Too Many Requests", Body: []byte("limit " + u)}, true, true, nil, 429},
		{"503 with a body echo", rpc.HTTPError{StatusCode: 503, Status: "503 Service Unavailable", Body: []byte("busy " + u)}, true, true, nil, 503},
		{"403 archive", rpc.HTTPError{StatusCode: 403, Status: "403 Forbidden", Body: []byte("Archive requests require a personal token " + u)}, true, false, nil, 403},
		{"400 body echo", rpc.HTTPError{StatusCode: 400, Status: "400 Bad Request", Body: []byte("bad " + u)}, false, false, nil, 400},
		{"json-rpc -32005", jsonRPCError{-32005, "limit exceeded for " + u}, false, true, nil, 0},
		{"json-rpc execution reverted", jsonRPCError{3, "execution reverted at " + u}, false, false, nil, 0},
		{"text 429", errors.New(`Post "` + u + `": 429 Too Many Requests`), true, true, nil, 0},
		{"text client timeout", errors.New(`Post "` + u + `": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`), true, false, nil, 0},
		{"text history unavailable", errors.New(`Post "` + u + `": pruned history unavailable: requested 5, earliest available 9`), true, false, nil, 0},
		{"text rate limit exceeded", errors.New(`Get "` + u + `": rate limit exceeded`), true, true, nil, 0},
		{"wrapped 429", fmt.Errorf("chain 84532: %w", rpc.HTTPError{StatusCode: 429, Body: []byte(u)}), false, true, nil, 429},
		{"TransientError of a 429", &TransientError{Host: "h", Attempts: 2, Err: rpc.HTTPError{StatusCode: 429, Status: "429 Too Many Requests", Body: []byte(u)}}, true, true, nil, 429},
		{"a plain error", errors.New("insufficient funds for gas"), false, false, nil, 0},
		{"cancelled", context.Canceled, false, false, context.Canceled, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			red := RedactError(tc.err)
			if got := ShouldFailover(tc.err); got != tc.failover {
				t.Fatalf("ShouldFailover(original) = %v, want %v", got, tc.failover)
			}
			if got := IsTransient(tc.err); got != tc.transient {
				t.Fatalf("IsTransient(original) = %v, want %v", got, tc.transient)
			}
			if got := ShouldFailover(red); got != tc.failover {
				t.Fatalf("ShouldFailover(redacted) = %v, want %v (%s)", got, tc.failover, red)
			}
			if got := IsTransient(red); got != tc.transient {
				t.Fatalf("IsTransient(redacted) = %v, want %v (%s)", got, tc.transient, red)
			}
			if tc.wantIs != nil && !errors.Is(red, tc.wantIs) {
				t.Fatalf("errors.Is(redacted, %v) is false", tc.wantIs)
			}
			if tc.wantHTTPCode != 0 {
				var he rpc.HTTPError
				if !errors.As(red, &he) || he.StatusCode != tc.wantHTTPCode {
					t.Fatalf("errors.As(rpc.HTTPError) lost: %v", red)
				}
			}
			if strings.Contains(tc.err.Error(), key) {
				noKey(t, "the redacted error", key, red.Error())
			}
		})
	}
	// An error with nothing to redact is returned itself: a sentinel is still the sentinel.
	if RedactError(context.Canceled) != context.Canceled || RedactError(nil) != nil {
		t.Fatal("an error with nothing to redact must be returned as it is")
	}
}

// The constructors register the secrets of the URLs they are given.
func TestB14a_D2_TheConstructorsRegisterTheirURLsSecrets(t *testing.T) {
	echo := func(key string) string { return "The requested URL /v2/" + key + " was not found; user:" + key + "@h" }
	t.Run("RegisterProviderURL derives userinfo, long segments, query values and the fragment", func(t *testing.T) {
		undo := RegisterProviderURL("https://opuser-ab12:pw-SECRET-9f@rpc.example.org/v2/SECRETSEGMENT-12345/ws?apikey=QUERYVALUE-7&n=ab#FRAGMENT-3")
		for _, lit := range []string{"opuser-ab12", "pw-SECRET-9f", "SECRETSEGMENT-12345", "QUERYVALUE-7", "FRAGMENT-3"} {
			if got := RedactText("x " + lit + " y"); got != "x "+RedactedMarker+" y" {
				t.Errorf("%q: %q", lit, got)
			}
		}
		for _, public := range []string{"v2", "ws", "rpc.example.org", "n", "ab", "apikey", "rpc ethereum v3 sepolia"} {
			if got := RedactText("x " + public + " y"); got != "x "+public+" y" {
				t.Errorf("a public part was redacted: %q -> %q", public, got)
			}
		}
		undo()
		if got := RedactText("x SECRETSEGMENT-12345 y"); strings.Contains(got, RedactedMarker) {
			t.Errorf("undone registration still applies: %q", got)
		}
	})
	t.Run("encoded spellings", func(t *testing.T) {
		undo := RegisterProviderURL("https://rpc.example.org/p?apikey=a%2Fb%26c%20dd-ee-ff")
		defer undo()
		decoded := "a/b&c dd-ee-ff"
		bsch := string(rune(bs))
		for _, in := range []string{"a%2Fb%26c%20dd-ee-ff", "a%2fb%26c%20dd-ee-ff", decoded, "a" + bsch + "/b" + bsch + "u0026c dd-ee-ff", "a%2Fb%26c+dd-ee-ff"} {
			if got := RedactText("saw " + in + " here"); strings.Contains(got, "dd-ee-ff") {
				t.Errorf("spelling %q left: %q", in, got)
			}
		}
	})
	t.Run("a literal that is part of a host or of the marker is not applied", func(t *testing.T) {
		undo := RegisterProviderURL("https://sepolia-rollup.example.org/p?network=sepolia&mode=redact")
		defer undo()
		for _, in := range []string{"sepolia-rollup.example.org is up", "<redacted> stays", "https://sepolia-rollup.example.org/<redacted>"} {
			if got := RedactText(in); got != in {
				t.Errorf("%q changed to %q", in, got)
			}
		}
	})
	t.Run("a literal shorter than the floor is not registered", func(t *testing.T) {
		undo := RegisterProviderURL("https://ab:xyz@rpc.example.org/")
		defer undo()
		if got := RedactText("ab xyz"); got != "ab xyz" {
			t.Errorf("a short word was redacted: %q", got)
		}
	})
	t.Run("NewPool", func(t *testing.T) {
		key := "POOLKEY-b14a-0008abcdef"
		p, err := NewPool([]string{"http://127.0.0.1:1/v2/" + key}, time.Minute, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		noKey(t, "a path-only echo after NewPool", key, RedactText(echo(key)))
	})
	t.Run("NewAgreeingReader", func(t *testing.T) {
		key := "READERKEY-b14a-0009abcd"
		saved := constructionRetryBudget
		constructionRetryBudget = 100 * time.Millisecond
		defer func() { constructionRetryBudget = saved }()
		_, _ = NewAgreeingReader(context.Background(), 1, []string{"http://127.0.0.1:1/v2/" + key, "http://127.0.0.2:1/v2/" + key}, 50*time.Millisecond)
		noKey(t, "a path-only echo after NewAgreeingReader", key, RedactText(echo(key)))
	})
	t.Run("DialRetrying and dialProvider", func(t *testing.T) {
		k1, k2 := "RETRYKEY-b14a-0010abcde", "DIALKEY-b14a-0011abcdef"
		c, err := DialRetrying(context.Background(), "http://127.0.0.1:1/v2/"+k1)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if cl, _, derr := dialProvider(context.Background(), "127.0.0.1", "http://127.0.0.1:1/v2/"+k2, time.Second, 0); derr == nil {
			cl.Close()
		}
		noKey(t, "a path-only echo after DialRetrying", k1, RedactText(echo(k1)))
		noKey(t, "a path-only echo after dialProvider", k2, RedactText(echo(k2)))
	})
	t.Run("the redaction is idempotent", func(t *testing.T) {
		key := "IDEMKEY-b14a-0012abcdef"
		undo := RegisterProviderURL("https://h.example.org/v2/" + key)
		defer undo()
		once := RedactText(echo(key) + ` Post "https://h.example.org/v2/` + key + `": EOF`)
		if twice := RedactText(once); twice != once {
			t.Fatalf("%q then %q", once, twice)
		}
	})
}
