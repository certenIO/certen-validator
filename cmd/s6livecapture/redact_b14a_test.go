// Copyright 2026 Certen Protocol

package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// RB10-B14a (V-R10B5 D1, D2): the world the capture stores holds no key in a body that echoes a URL JSON-escaped, nor in a path-only
// echo, and the recorder's lock is not held while a large body is scrubbed.

const b14aKey = "SECRETKEY123abc"

func b14aBsl(s string) string { return strings.ReplaceAll(s, "~", "\x5c") }

func readWorldFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestB14a_AWorldHoldsNoKeyInABodyOrATransportThatEchoesAURLEscaped(t *testing.T) {
	provs := []Provider{{Host: "eth.g.alchemy.com", URL: "https://eth.g.alchemy.com/v2/" + b14aKey}}
	rec := NewRecorder(1, "test", provs)
	for _, x := range []Exchange{
		{Host: "eth.g.alchemy.com", Method: "eth_a", HTTPStatus: 404, Body: b14aBsl(`{"error":"not found https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + `"}`)},
		{Host: "eth.g.alchemy.com", Method: "eth_b", Transport: b14aBsl(`Post "https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + `": EOF`)},
		{Host: "eth.g.alchemy.com", Method: "eth_c", HTTPStatus: 404, Body: `The requested URL /v2/` + b14aKey + ` was not found on this server.`},
		{Host: "eth.g.alchemy.com", Method: "eth_d", HTTPStatus: 400, Body: b14aBsl(`{"detail":"Post ~"https://eth.g.alchemy.com/v2/~n` + b14aKey + `~": bad","path":"/v2/` + b14aKey + `"}`)},
		{Host: "eth.g.alchemy.com", Method: "eth_e", HTTPStatus: 502, Body: `<html>502 Bad Gateway request: "POST /v2/` + b14aKey + ` HTTP/1.1", host: "eth.g.alchemy.com"</html>`},
	} {
		rec.add(x)
	}
	w := rec.World()
	for _, x := range w.Exchanges {
		if strings.Contains(x.Body+x.Transport, b14aKey) {
			t.Fatalf("an exchange holds the key:\n%+v", x)
		}
	}
	path := filepath.Join(t.TempDir(), "w.world.json.gz")
	if err := WriteWorldGz(path, w); err != nil {
		t.Fatal(err)
	}
	if text := readWorldFile(t, path); strings.Contains(text, b14aKey) {
		t.Fatalf("the written world holds the key")
	}
	// and a world that was never scrubbed at record time is scrubbed as it is written
	raw := &World{Format: WorldFormat, Providers: provs, Exchanges: []Exchange{
		{Host: "eth.g.alchemy.com", Method: "eth_a", HTTPStatus: 404, Body: b14aBsl(`{"error":"not found https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + `"}`)}}}
	if err := WriteWorldGz(path, raw); err != nil {
		t.Fatal(err)
	}
	if text := readWorldFile(t, path); strings.Contains(text, b14aKey) {
		t.Fatalf("a world written unscrubbed holds the key")
	}
}

// A body that is JSON is scrubbed string by string: a URL inside it is read as the URL it is, and the rest of the document is
// kept as it was.
func TestB14a_AJSONBodyIsScrubbedStructurally(t *testing.T) {
	in := b14aBsl(`{"error":{"code":-32000,"message":"see https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + `","data":["ok",7]},"id":1}`)
	got := scrubBody(in)
	if strings.Contains(got, b14aKey) {
		t.Fatalf("the key is left: %s", got)
	}
	for _, keep := range []string{`"code":-32000`, `"data":["ok",7]`, `"id":1`, `https://eth.g.alchemy.com/<redacted>`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("%q was lost from %s", keep, got)
		}
	}
	if again := scrubBody(got); again != got {
		t.Fatalf("not idempotent: %q then %q", got, again)
	}
	// text that is no JSON, a JSON document with nothing to scrub, and the empty body
	if got := scrubBody("plain text, no url"); got != "plain text, no url" {
		t.Fatalf("plain text changed: %q", got)
	}
	clean := `{"a": [1,  2],"b":"c"}`
	if got := scrubBody(clean); got != clean {
		t.Fatalf("a clean JSON body must be returned as it is: %q", got)
	}
	if scrubBody("") != "" {
		t.Fatal("the empty body changed")
	}
}

// The recorder's lock is not held while a large body is scrubbed: another exchange or a read of the world is not made to wait for it.
func TestB14a_TheRecorderLockIsNotHeldWhileABodyIsScrubbed(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("[")
	for sb.Len() < 1<<20-200 {
		sb.WriteString(`"see https://h.example.org/v2/` + b14aKey + ` for more",`)
	}
	sb.WriteString(`"end"]`)
	big := Exchange{Host: "h.example.org", Method: "eth_big", HTTPStatus: 500, Body: sb.String()}

	start := time.Now()
	_ = scrubExchange(big)
	scrub := time.Since(start)
	if scrub < 10*time.Millisecond {
		t.Fatalf("the calibration body scrubs in %s, too fast to show anything", scrub)
	}

	rec := NewRecorder(1, "test", []Provider{{Host: "h.example.org", URL: "https://h.example.org/rpc"}})
	var wg sync.WaitGroup
	started := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		rec.add(big)
	}()
	<-started
	time.Sleep(scrub / 10)
	t0 := time.Now()
	_ = rec.World()
	waited := time.Since(t0)
	wg.Wait()
	if waited > scrub/2 {
		t.Fatalf("World() waited %s while a body that takes %s to scrub was recorded", waited, scrub)
	}
	if got := rec.World(); len(got.Exchanges) != 1 || strings.Contains(got.Exchanges[0].Body, b14aKey) {
		t.Fatalf("the large body was not recorded scrubbed: %d exchanges", len(got.Exchanges))
	}
}
