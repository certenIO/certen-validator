// Copyright 2026 Certen Protocol

// Package testdb gives each test package its own PostgreSQL database (RB3-F150).
//
// `go test ./...` runs packages concurrently, each in its own process. They used to share the one database
// CERTEN_TEST_DB names, and some of them drive process-wide queues: the proof request fulfiller claims
// every pending request and re-queues every retryable failure, so it took rows another package's test had
// just written, and that test read back a state it never set - a gate that failed now and then for reasons
// no test was about. Each package now works in a database of its own on the same server, created on first
// use; tests within a package still share it, as they did.
//
// Imported only by tests; nothing here is in a shipped binary.
package testdb

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/lib/pq"
)

// Env is the variable naming the test server (and the base database the per-package names derive from).
const Env = "CERTEN_TEST_DB"

var validName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// PackageURL returns the connection string of the database the test package `pkg` uses alone, creating the
// database if it does not exist. It fails when CERTEN_TEST_DB is not set: a skipped gate is not a green one.
func PackageURL(pkg string) (string, error) {
	base := strings.TrimSpace(os.Getenv(Env))
	if base == "" {
		return "", fmt.Errorf("%s is required: this test runs against PostgreSQL (a skipped gate is not a green gate)", Env)
	}
	if !validName.MatchString(pkg) {
		return "", fmt.Errorf("test database name %q must be lower-case letters, digits and underscores", pkg)
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", Env, err)
	}
	baseName := strings.TrimPrefix(u.Path, "/")
	if baseName == "" {
		return "", fmt.Errorf("%s names no database", Env)
	}
	name := baseName + "_" + pkg

	admin, err := sql.Open("postgres", base)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", Env, err)
	}
	defer admin.Close()
	var exists bool
	if err := admin.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		return "", fmt.Errorf("look for test database %s: %w", name, err)
	}
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE ` + pq.QuoteIdentifier(name)); err != nil {
			// Another process of the same package may have created it first.
			var pe *pq.Error
			if !errors.As(err, &pe) || pe.Code != "42P04" {
				return "", fmt.Errorf("create test database %s: %w", name, err)
			}
		}
	}
	u.Path = "/" + name
	return u.String(), nil
}
