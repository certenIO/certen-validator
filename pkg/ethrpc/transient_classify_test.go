package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/rpc"
)

type jsonRPCError struct {
	code int
	msg  string
}

func (e jsonRPCError) Error() string  { return e.msg }
func (e jsonRPCError) ErrorCode() int { return e.code }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsTransientClassifiesNotNowApartFromAnswers(t *testing.T) {
	post := func(err error) error { return &url.Error{Op: "Post", URL: "https://example.invalid", Err: err} }
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"429", rpc.HTTPError{StatusCode: 429, Status: "429 Too Many Requests"}, true},
		{"502", rpc.HTTPError{StatusCode: 502, Status: "502 Bad Gateway"}, true},
		{"503", rpc.HTTPError{StatusCode: 503, Status: "503 Service Unavailable"}, true},
		{"504", rpc.HTTPError{StatusCode: 504, Status: "504 Gateway Timeout"}, true},
		{"-32005 limit exceeded", jsonRPCError{-32005, "limit exceeded"}, true},
		{"connection refused", post(syscall.ECONNREFUSED), true},
		{"connection reset", post(syscall.ECONNRESET), true},
		{"EOF", post(io.EOF), true},
		{"unexpected EOF", post(io.ErrUnexpectedEOF), true},
		{"DNS temporary", post(&net.DNSError{Err: "server misbehaving", IsTemporary: true}), true},
		{"network timeout", post(timeoutErr{}), true},
		{"wrapped 429", fmt.Errorf("chain 84532: %w", rpc.HTTPError{StatusCode: 429}), true},

		{"nil", nil, false},
		{"400", rpc.HTTPError{StatusCode: 400, Status: "400 Bad Request"}, false},
		{"403 archive", rpc.HTTPError{StatusCode: 403, Status: "403 Forbidden"}, false},
		{"execution reverted", jsonRPCError{3, "execution reverted"}, false},
		{"-32000 header not found", jsonRPCError{-32000, "header not found"}, false},
		{"not found", ethereum.NotFound, false},
		{"DNS no such host", post(&net.DNSError{Err: "no such host", IsNotFound: true}), false},
		{"cancelled", context.Canceled, false},
		{"caller deadline", context.DeadlineExceeded, false},
		{"anything else", errors.New("chain 11155111 provider x serves chain 84532"), false},
	}
	for _, c := range cases {
		if got := IsTransient(c.err); got != c.want {
			t.Errorf("%s: IsTransient(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("3", now); !ok || d != 3*time.Second {
		t.Fatalf("seconds: %v %v", d, ok)
	}
	if d, ok := parseRetryAfter(now.Add(5*time.Second).Format(httpTimeFormat), now); !ok || d != 5*time.Second {
		t.Fatalf("date: %v %v", d, ok)
	}
	if _, ok := parseRetryAfter("", now); ok {
		t.Fatal("empty accepted")
	}
	if _, ok := parseRetryAfter("soon", now); ok {
		t.Fatal("garbage accepted")
	}
}

const httpTimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// A per-attempt timeout while the caller's context is live is transient; the caller's own deadline is not retried past.
func TestAnAttemptThatTimesOutIsAskedAgain(t *testing.T) {
	saved := backoffBase
	backoffBase = 10 * time.Millisecond
	t.Cleanup(func() { backoffBase = saved })
	n := 0
	v, err := retryTransient(context.Background(), "p", nil, 5*time.Second, 50*time.Millisecond, func(c context.Context) (int, error) {
		n++
		if n < 3 {
			<-c.Done()
			return 0, c.Err()
		}
		return 7, nil
	})
	if err != nil || v != 7 || n != 3 {
		t.Fatalf("(%d, %v) after %d attempts", v, err, n)
	}
}
