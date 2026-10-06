package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// RB7 Task 5 (T5-4): a proof request carrying a callback_url is refused by name. The validators used to POST the
// outcome to it, unsigned, from inside the validator network.
func TestARequestWithACallbackURLIsRefusedByName(t *testing.T) {
	h := NewBundleHandlers(nil, nil, nil, nil, nil)
	h.apiKeyValidator.cache["k"] = &database.APIKey{KeyID: uuid.New(), ClientName: "t", CanRequestProofs: true}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/proofs/request", strings.NewReader(body))
		req.Header.Set("X-API-Key", "k")
		rr := httptest.NewRecorder()
		h.HandleRequestProof(rr, req)
		return rr
	}
	rr := post(`{"proof_class":"on_demand","accum_tx_hash":"ab","callback_url":"http://169.254.169.254/x"}`)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "CALLBACK_NOT_SUPPORTED") ||
		!strings.Contains(rr.Body.String(), "/api/v1/proofs/requests/completed") {
		t.Fatalf("callback_url must be refused by name with a pointer to the feed: %d %s", rr.Code, rr.Body.String())
	}
	// An absent or empty field is not a callback.
	for _, body := range []string{`{"proof_class":"bogus","accum_tx_hash":"ab"}`, `{"proof_class":"bogus","accum_tx_hash":"ab","callback_url":""}`} {
		rr = post(body)
		if strings.Contains(rr.Body.String(), "CALLBACK_NOT_SUPPORTED") {
			t.Fatalf("%s was refused as a callback: %s", body, rr.Body.String())
		}
	}
}
