// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB11-DBFIX D5: the status document is read by the gateway and must never carry a credential, whatever shape a state's field has
// and whichever branch built it. The sink redacts recursively (string, error, []string, map, fmt.Stringer, nested structs) on
// the pending branch as well as the error branch, and Document() is itself the last gate.

const (
	fakeKey   = "FAKEKEY0123456789ABCDEF"
	fakeURL   = "https://rpc-provider.example/v2/" + fakeKey
	fakeUser  = "https://alice:s3cr3tPassw0rd99@rpc-other.example/path"
	fakeQuery = "https://rpc-q.example/jsonrpc?apikey=" + fakeKey
)

type stringerWithKey struct{ n int }

func (s stringerWithKey) String() string { return fmt.Sprintf("endpoint %s #%d", fakeURL, s.n) }

type nestedWithKey struct {
	Endpoint string
	Inner    struct{ Cause error }
	Many     []string
	hidden   string
}

func registerFake(t *testing.T) {
	t.Helper()
	un := ethrpc.RegisterProviderURL(fakeURL)
	un2 := ethrpc.RegisterProviderURL(fakeQuery)
	t.Cleanup(func() { un(); un2() })
}

// hostile is a field of every shape that can carry the registered key.
func hostile() map[string]any {
	n := nestedWithKey{Endpoint: fakeURL, Many: []string{"ok", fakeQuery}, hidden: fakeKey}
	n.Inner.Cause = errors.New("dial " + fakeURL + ": refused")
	return map[string]any{
		"str":        "contacting " + fakeURL + " failed",
		"err":        errors.New("get " + fakeQuery + ": 401"),
		"strings":    []string{"a", "b " + fakeURL},
		"map":        map[string]any{"deep": "x " + fakeURL, "deeper": map[string]any{"e": errors.New(fakeURL)}},
		"strmap":     map[string]string{"k": fakeURL},
		"stringer":   stringerWithKey{7},
		"struct":     n,
		"structptr":  &n,
		"any":        []any{1, "n", fakeURL, errors.New(fakeQuery)},
		"userinfo":   "proxy " + fakeUser,
		"wrappedErr": fmt.Errorf("outer: %w", errors.New("inner "+fakeURL)),
		"number":     uint64(84532),
		"level":      LevelL1Posted,
		"bytes":      []byte{1, 2, 3},
		"time":       time.Unix(1_800_000_000, 0).UTC(),
	}
}

func noCredential(t *testing.T, where string, b []byte) {
	t.Helper()
	for _, s := range []string{fakeKey, "s3cr3tPassw0rd99", "alice:"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("%s carries the credential %q:\n%s", where, s, b)
		}
	}
}

func TestStatusSinkRedactsEveryShapeOfFieldOnBothBranches(t *testing.T) {
	registerFake(t)
	at := time.Unix(1_800_000_000, 0)

	t.Run("the error branch", func(t *testing.T) {
		st := NewState(CodeVerifierFailed, "chain", uint64(84532), "kind", "x", "cause", "c")
		for k, v := range hostile() {
			st.Fields[k] = v
		}
		s := BuilderStatusOf("00000000-0000-4000-8000-000000000001", 84532, LevelFinalized, LevelIncluded, nil, st, false, at)
		doc, err := s.Document()
		if err != nil {
			t.Fatal(err)
		}
		noCredential(t, "the document of the error branch", doc)
		noCredential(t, "the in-memory state of the error branch", s.State.Canonical())
		// the facts that are not credentials are still there
		for _, want := range []string{`"number":"84532"`, `"level":"l1_posted"`, `"bytes":"0x010203"`, `"time":"2027-01-15T08:00:00Z"`, `"chain":"84532"`} {
			if !strings.Contains(string(doc), want) {
				t.Fatalf("the redaction dropped %s:\n%s", want, doc)
			}
		}
	})

	t.Run("the pending branch (the reviewer's probe: stored verbatim before)", func(t *testing.T) {
		pd := &PendingState{Chain: 84532, LevelReached: LevelIncluded, NextLevel: LevelL1Posted, Reason: "awaiting " + fakeURL, Judged: hostile()}
		s := BuilderStatusOf("00000000-0000-4000-8000-000000000001", 84532, LevelL1Posted, LevelIncluded, pd, nil, false, at)
		doc, err := s.Document()
		if err != nil {
			t.Fatal(err)
		}
		noCredential(t, "the document of the pending branch", doc)
		noCredential(t, "the in-memory state of the pending branch", s.State.Canonical())
		if _, err := ParseBuilderStatusDocument(doc); err != nil {
			t.Fatalf("the redacted document does not read back: %v", err)
		}
	})

	t.Run("Document is the last gate for a status built without the sink", func(t *testing.T) {
		raw := BuilderStatus{ProofID: "00000000-0000-4000-8000-000000000001", Chain: 84532, TargetLevel: LevelFinalized, Class: BuilderUnavailable,
			LevelReached: LevelIncluded, NextLevel: LevelFinalized, JudgedAt: at, State: NewState(CodeVerifierFailed, "chain", uint64(84532), "kind", "x", "cause", fakeURL)}
		for k, v := range hostile() {
			raw.State.Fields[k] = v
		}
		doc, err := raw.Document()
		if err != nil {
			t.Fatal(err)
		}
		noCredential(t, "a hand-built status document", doc)
		rawPending := BuilderStatus{ProofID: "00000000-0000-4000-8000-000000000001", Chain: 84532, TargetLevel: LevelFinalized, Class: BuilderPending,
			LevelReached: LevelIncluded, NextLevel: LevelFinalized, JudgedAt: at, State: (&PendingState{Chain: 84532, LevelReached: LevelIncluded, NextLevel: LevelFinalized, Reason: fakeURL, Judged: hostile()}).State()}
		doc, err = rawPending.Document()
		if err != nil {
			t.Fatal(err)
		}
		noCredential(t, "a hand-built pending document", doc)
	})
}
