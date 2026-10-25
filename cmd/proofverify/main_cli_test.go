// Copyright 2026 Certen Protocol
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// EPS-MUTKILL-6: the test binary is re-executed as the CLI (TestMain), so main()'s flag dispatch and exit-code mapping are asserted
// against a real process: stdout, stderr and the exit status. PV2MUT_ID and PV2MUT_TRACE are inherited, so a mutant is active in the child.

const cliEnv = "PV2_PROOFVERIFY_AS_CLI"

func TestMain(m *testing.M) {
	if os.Getenv(cliEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runCLI runs the CLI with args and returns stdout, stderr and the exit status.
func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), cliEnv+"=1", "CERTEN_DB=")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running the CLI: %v", err)
	}
	return out.String(), errb.String(), code
}

const (
	deadDSN = "postgres://127.0.0.1:1/none?sslmode=disable&connect_timeout=2"
	uuidA   = "0b0f0f5a-1c2d-4e3f-8a4b-5c6d7e8f9a0b"
)

func TestCLIDispatchRefusesEachFlagCombinationAndMapsEachOutcomeToItsExitCode(t *testing.T) {
	dir := t.TempDir()
	f, o := filepath.Join(dir, "f.json"), filepath.Join(dir, "missing-outcome.json")
	usageCI := "--contract-identity judges the contractIdentity member of a --finality-file document against the leg of an --outcome-file evidence: " +
		"name both, and no --proof-id (a stored bundle carries no batch facts)"
	usagePins := "--pins-selfcheck checks the embedded pins on their own: no --proof-id, --finality, --finality-file, --outcome, --outcome-file, --l5 or --governance"
	usageFF := "--finality-file verifies a file against ONE Settlement source: --outcome-file <evidence.json> or --proof-id with --db; not --finality, --outcome, --l5 or --governance"
	usageOF := "--outcome-file verifies a file on its own: no --proof-id, --outcome, --l5 or --governance"
	usageMain := "usage: proofverify --proof-id <uuid> --db <dsn> [--offline] [--governance] [--l5] [--outcome] [--finality] [--online-rpc <url> --offline=false] [-v]"
	usageOn := "--online-rpc checks the anchor or the outcome on its chain: it needs --l5 or --outcome, and --offline=false"
	notUUID := `proof-id "not-a-uuid" is not a UUID`
	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string // prefix
		stderr string // substring
	}{
		{"contract-identity alone", []string{"--contract-identity"}, 2, "", usageCI},
		{"contract-identity with a proof id", []string{"--contract-identity", "--finality-file", f, "--outcome-file", o, "--proof-id", uuidA}, 2, "", usageCI},
		{"contract-identity without an outcome file", []string{"--contract-identity", "--finality-file", f}, 2, "", usageCI},
		{"contract-identity without a finality file", []string{"--contract-identity", "--outcome-file", o}, 2, "", usageCI},
		{"contract-identity with an outcome file that is not there", []string{"--contract-identity", "--finality-file", f, "--outcome-file", o}, 1,
			"FAILED (finality)  " + f + "\n  the Settlement source " + o + " does not decode: ", ""},

		{"pins-selfcheck with a proof id", []string{"--pins-selfcheck", "--proof-id", uuidA}, 2, "", usagePins},
		{"pins-selfcheck with --outcome", []string{"--pins-selfcheck", "--outcome"}, 2, "", usagePins},
		{"pins-selfcheck with an outcome file", []string{"--pins-selfcheck", "--outcome-file", o}, 2, "", usagePins},
		{"pins-selfcheck with --l5", []string{"--pins-selfcheck", "--l5"}, 2, "", usagePins},
		{"pins-selfcheck with --governance", []string{"--pins-selfcheck", "--governance"}, 2, "", usagePins},
		{"pins-selfcheck with --finality", []string{"--pins-selfcheck", "--finality"}, 2, "", usagePins},
		{"pins-selfcheck with a finality file", []string{"--pins-selfcheck", "--finality-file", f}, 2, "", usagePins},
		{"pins-selfcheck alone", []string{"--pins-selfcheck"}, 0, "PINS SELFCHECK ok  ", ""},

		{"finality-file with --outcome", []string{"--finality-file", f, "--outcome"}, 2, "", usageFF},
		{"finality-file with --l5", []string{"--finality-file", f, "--l5"}, 2, "", usageFF},
		{"finality-file with --governance", []string{"--finality-file", f, "--governance"}, 2, "", usageFF},
		{"finality-file with --finality", []string{"--finality-file", f, "--finality"}, 2, "", usageFF},
		{"finality-file with two Settlement sources", []string{"--finality-file", f, "--outcome-file", o, "--proof-id", uuidA}, 2, "", usageFF},
		{"finality-file with a proof id and no database", []string{"--finality-file", f, "--proof-id", uuidA}, 2, "",
			"--finality-file with --proof-id needs --db (the stored bundle is the Settlement source)"},
		{"finality-file with a proof id and a database that is not there", []string{"--finality-file", f, "--proof-id", uuidA, "--db", deadDSN}, 1,
			"FAILED (finality)  " + f + "\n  the Settlement source (proof " + uuidA + ") cannot be read: ", ""},
		{"finality-file with an outcome file that is not there", []string{"--finality-file", f, "--outcome-file", o}, 1,
			"FAILED (finality)  " + f + "\n  the Settlement source " + o + " does not decode: ", ""},
		{"finality-file alone", []string{"--finality-file", f}, 1, "FAILED (finality)", ""},

		{"outcome-file with a proof id", []string{"--outcome-file", o, "--proof-id", uuidA}, 2, "", usageOF},
		{"outcome-file with --outcome", []string{"--outcome-file", o, "--outcome"}, 2, "", usageOF},
		{"outcome-file with --l5", []string{"--outcome-file", o, "--l5"}, 2, "", usageOF},
		{"outcome-file with --governance", []string{"--outcome-file", o, "--governance"}, 2, "", usageOF},
		{"outcome-file online while offline", []string{"--outcome-file", o, "--online-rpc", "http://127.0.0.1:1"}, 2, "",
			"--online-rpc checks the outcome on its chain: it needs --offline=false"},
		{"outcome-file that is not there", []string{"--outcome-file", o}, 1, "FAILED (outcome)  " + o + "\n", ""},
		{"outcome-file that is not there, online allowed", []string{"--outcome-file", o, "--online-rpc", "http://127.0.0.1:1", "--offline=false"}, 1,
			"FAILED (outcome)  " + o + "\n", ""},
		{"outcome-file that is not there, offline=false alone", []string{"--outcome-file", o, "--offline=false"}, 1, "FAILED (outcome)  " + o + "\n", ""},

		{"no arguments", nil, 2, "", usageMain},
		{"a proof id without a database", []string{"--proof-id", uuidA}, 2, "", usageMain},
		{"a database without a proof id", []string{"--db", deadDSN}, 2, "", usageMain},
		{"an unknown flag", []string{"--no-such-flag"}, 2, "", "flag provided but not defined: -no-such-flag"},
		{"online while offline", []string{"--proof-id", "not-a-uuid", "--db", deadDSN, "--online-rpc", "http://x", "--l5"}, 2, "", usageOn},
		{"online without l5 or outcome", []string{"--proof-id", "not-a-uuid", "--db", deadDSN, "--online-rpc", "http://x", "--offline=false"}, 2, "", usageOn},
		{"online with l5", []string{"--proof-id", "not-a-uuid", "--db", deadDSN, "--online-rpc", "http://x", "--offline=false", "--l5"}, 2, "", notUUID},
		{"online with outcome", []string{"--proof-id", "not-a-uuid", "--db", deadDSN, "--online-rpc", "http://x", "--offline=false", "--outcome"}, 2, "", notUUID},
		{"a proof id that is not a uuid", []string{"--proof-id", "not-a-uuid", "--db", deadDSN}, 2, "", notUUID},
		{"an incarnation that is not hex", []string{"--proof-id", uuidA, "--db", deadDSN, "--incarnation", "zz"}, 2, "", `--incarnation "zz" is not 32 bytes of hex`},
		{"an incarnation of 31 bytes", []string{"--proof-id", uuidA, "--db", deadDSN, "--incarnation", strings.Repeat("ab", 31)}, 2, "",
			`is not 32 bytes of hex`},
		{"an incarnation of 33 bytes", []string{"--proof-id", uuidA, "--db", deadDSN, "--incarnation", "0x" + strings.Repeat("AB", 33)}, 2, "",
			`is not 32 bytes of hex`},
		{"a database that is not there, offline", []string{"--proof-id", uuidA, "--db", deadDSN, "--incarnation", "0x" + strings.Repeat("AB", 32)}, 1, "", "connect to database: "},
		{"a database that is not there, online allowed", []string{"--proof-id", uuidA, "--db", deadDSN, "--offline=false"}, 1, "", "connect to database: "},
	}
	for _, c := range cases {
		stdout, stderr, code := runCLI(t, c.args...)
		if code != c.code || !strings.HasPrefix(stdout, c.stdout) || !strings.Contains(stderr, c.stderr) {
			t.Errorf("%s: exit %d (want %d)\n  stdout %.300q (want prefix %.120q)\n  stderr %.300q (want to contain %.120q)", c.name, code, c.code, stdout, c.stdout, stderr, c.stderr)
		}
		// a usage error prints on stderr and nothing on stdout
		if c.code == 2 && stdout != "" {
			t.Errorf("%s: a usage error wrote to stdout: %.200q", c.name, stdout)
		}
	}
}
