// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/config"
)

// lockedBuffer is a log sink the client's health monitor can write to while a test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// poolLines are the lines a client wrote about its pool budget.
func poolLines(out string) (all, warnings []string) {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "[DB-POOL]") {
			all = append(all, l)
			if strings.Contains(l, "🚨") {
				warnings = append(warnings, l)
			}
		}
	}
	return
}

// A real PostgreSQL, started through the production client: the budget is judged against the max_connections the SERVER
// reports (SHOW max_connections), not against a number the test makes up.
func TestStartupWarnsOnceWhenTheFleetOutgrowsTheServersMaxConnections(t *testing.T) {
	var raw string
	if err := testDB.QueryRow(`SHOW max_connections`).Scan(&raw); err != nil {
		t.Fatalf("read the test server's max_connections: %v", err)
	}
	serverMax, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("max_connections %q: %v", raw, err)
	}
	url, err := testdb.PackageURL("database")
	if err != nil {
		t.Fatal(err)
	}
	const pool = 4
	open := func(peers int) (*lockedBuffer, func()) {
		t.Helper()
		out := &lockedBuffer{}
		client, err := NewClient(&config.Config{
			DatabaseURL: url, DatabaseMaxConns: pool, DatabaseMinConns: 1, DatabaseMaxIdleTime: 60, DatabaseMaxLifetime: 300,
			AttestationPeers: make([]string, peers),
		}, WithLogger(log.New(out, "", 0)))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		return out, func() { client.Close() }
	}

	// A fleet that fits: said plainly, with no warning.
	out, closeFits := open(0)
	all, warnings := poolLines(out.String())
	closeFits()
	if len(all) != 1 || len(warnings) != 0 || !strings.Contains(all[0], fmt.Sprintf("max_connections of %d", serverMax)) {
		t.Fatalf("a fleet of one with a pool of %d on a server of %d: want one plain budget line, got %q", pool, serverMax, all)
	}

	// A fleet whose pools together exceed the server's limit: exactly one loud warning, naming both numbers.
	validators := serverMax/pool + 1
	out, closeOver := open(validators - 1)
	all, warnings = poolLines(out.String())
	closeOver()
	if len(all) != 1 || len(warnings) != 1 {
		t.Fatalf("an over-subscribed fleet: want exactly one pool line and it a warning, got all=%q warnings=%q", all, warnings)
	}
	w := warnings[0]
	demand := pool * validators
	for _, want := range []string{strconv.Itoa(demand), strconv.Itoa(serverMax), "DATABASE_MAX_CONNS", "max_connections"} {
		if !strings.Contains(w, want) {
			t.Fatalf("the warning does not name %q (demand %d, server %d): %s", want, demand, serverMax, w)
		}
	}
}
