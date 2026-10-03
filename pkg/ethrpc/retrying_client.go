package ethrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// =============================================================================
// One provider's client whose every read is asked again while the provider answers transiently
// =============================================================================
//
// The AgreeingReader retries per query (askAll, LocatorClient). Everything else on the settlement chains reads ONE
// provider through a plain client: the observer's transaction, block, receipts and eth_getProof reads, the strategy's
// pinned client, the anchor event monitor, the read-only anchor resolver, the layer-5 online check, the contract
// manager. DialRetrying gives those a client whose HTTP transport applies the same policy - IsTransient, retryTransient,
// the provider's Retry-After - to every JSON-RPC request: the SAME request to the SAME provider, within QueryRetryBudget
// or the request's own context, whichever ends first. It never moves a request to another provider.
//
// Sends are never retried: a dropped connection after eth_sendRawTransaction does not say whether the provider took the
// transaction, and a resend can come back "already known" or "nonce too low" for a transaction that was in fact sent.

// QueryRetryBudget caps how long one JSON-RPC request is asked again through a retrying client: the same bound as an
// agreed read's own deadline (DefaultReadTimeout), so a single-provider read gives a throttled provider the time an
// agreed read does.
const QueryRetryBudget = DefaultReadTimeout

// queryRetryBudget is the budget in force; tests shorten it.
var queryRetryBudget = QueryRetryBudget

// neverRetried are the methods a retrying client sends exactly once.
var neverRetried = map[string]bool{
	"eth_sendRawTransaction":            true,
	"eth_sendTransaction":               true,
	"eth_sendRawTransactionConditional": true,
	"eth_sendRawTransactionSync":        true,
	"eth_sendBundle":                    true,
	"eth_sendPrivateTransaction":        true,
}

// DialRetrying dials rawurl as one provider whose reads are asked again while it answers transiently (see above).
func DialRetrying(ctx context.Context, rawurl string) (*ethclient.Client, error) {
	c, err := DialRPCRetrying(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return ethclient.NewClient(c), nil
}

// DialRPCRetrying is DialRetrying for callers that also make raw calls (eth_getProof).
func DialRPCRetrying(ctx context.Context, rawurl string) (*rpc.Client, error) {
	host := providerHost(rawurl)
	hint := &retryAfterHint{}
	httpClient := &http.Client{Transport: &retryingTransport{base: http.DefaultTransport, host: host, hint: hint}}
	// Dialling HTTP makes no request; a websocket endpoint connects here, and a transient failure to connect is retried.
	return retryTransient(ctx, host, hint, queryRetryBudget, 0, func(c context.Context) (*rpc.Client, error) {
		return rpc.DialOptions(c, rawurl, rpc.WithHTTPClient(httpClient))
	})
}

type retryingTransport struct {
	base http.RoundTripper
	host string
	hint *retryAfterHint
}

// limitAnswer is a JSON-RPC rate-limit error a provider returned inside an HTTP 200; it satisfies rpc.Error, so
// IsTransient classifies it by its code like any other.
type limitAnswer struct {
	code int
	msg  string
	resp *http.Response
	body []byte
}

func (e *limitAnswer) Error() string  { return e.msg }
func (e *limitAnswer) ErrorCode() int { return e.code }

func (t *retryingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil {
		return t.base.RoundTrip(req)
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	send := func(ctx context.Context) (*http.Response, error) {
		r := req.Clone(ctx)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		r.ContentLength = int64(len(body))
		return t.base.RoundTrip(r)
	}
	if !retryableRequest(body) {
		return send(req.Context())
	}
	resp, err := retryTransient(req.Context(), t.host, t.hint, queryRetryBudget, 0, func(ctx context.Context) (*http.Response, error) {
		resp, err := send(ctx)
		if err != nil {
			return nil, err
		}
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok &&
			(resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
			t.hint.set(d)
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			return nil, rpc.HTTPError{StatusCode: resp.StatusCode, Status: resp.Status, Body: b}
		case http.StatusOK:
			b, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewReader(b))
			if code, msg := rateLimitAnswer(b); code != 0 {
				return nil, &limitAnswer{code: code, msg: msg, resp: resp, body: b}
			}
			return resp, nil
		default:
			// Any other status is the provider's answer; go-ethereum reports it.
			return resp, nil
		}
	})
	if err == nil {
		return resp, nil
	}
	te, ok := err.(*TransientError)
	if !ok {
		return nil, err
	}
	// Retries ran out. The provider's own last answer is handed back, so the caller sees the provider's error -
	// annotated with the provider and the attempts - exactly as it would have without the retries.
	note := fmt.Sprintf(" (provider %s, %d attempts over %s", te.Host, te.Attempts, te.Elapsed.Round(time.Millisecond))
	if te.Stopped != nil {
		note += fmt.Sprintf("; stopped by %v", te.Stopped)
	}
	note += ")"
	switch last := te.Err.(type) {
	case rpc.HTTPError:
		return &http.Response{StatusCode: last.StatusCode, Status: last.Status + note, Header: http.Header{},
			Body: io.NopCloser(bytes.NewReader(last.Body)), ContentLength: int64(len(last.Body)), Request: req,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}, nil
	case *limitAnswer:
		last.resp.Body = io.NopCloser(bytes.NewReader(annotateRPCError(last.body, note)))
		last.resp.ContentLength = -1
		return last.resp, nil
	}
	return nil, err
}

// retryableRequest: a JSON-RPC request, or batch, none of whose methods is a send. A body that does not parse is sent
// once.
func retryableRequest(body []byte) bool {
	type call struct {
		Method string `json:"method"`
	}
	var calls []call
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if json.Unmarshal(trimmed, &calls) != nil {
			return false
		}
	} else {
		var one call
		if json.Unmarshal(trimmed, &one) != nil {
			return false
		}
		calls = []call{one}
	}
	for _, c := range calls {
		if c.Method == "" || neverRetried[c.Method] {
			return false
		}
	}
	return len(calls) > 0
}

// rateLimitAnswer returns the code and message of a JSON-RPC rate-limit error (-32005, -32029) in a 200 response - a
// single response, or any element of a batch - or 0.
func rateLimitAnswer(b []byte) (int, string) {
	type rpcErr struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var rs []rpcErr
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if json.Unmarshal(trimmed, &rs) != nil {
			return 0, ""
		}
	} else {
		var one rpcErr
		if json.Unmarshal(trimmed, &one) != nil {
			return 0, ""
		}
		rs = []rpcErr{one}
	}
	for _, r := range rs {
		if r.Error != nil && (r.Error.Code == -32005 || r.Error.Code == -32029) {
			return r.Error.Code, r.Error.Message
		}
	}
	return 0, ""
}

// annotateRPCError appends note to the message of a single JSON-RPC error response; anything else is returned as is.
func annotateRPCError(b []byte, note string) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || m["error"] == nil {
		return b
	}
	var e map[string]interface{}
	if json.Unmarshal(m["error"], &e) != nil {
		return b
	}
	if msg, ok := e["message"].(string); ok {
		e["message"] = strings.TrimSpace(msg) + note
	}
	enc, err := json.Marshal(e)
	if err != nil {
		return b
	}
	m["error"] = enc
	out, err := json.Marshal(m)
	if err != nil {
		return b
	}
	return out
}
