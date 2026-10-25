// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// RB12-OPS-A1 item 3 (ledger F9): pr/rb11-deploy-check.sh printed the builder status as two columns (code, class) and its EXPECTED block
// read the code finality_verifier_failed as if it were a class. Every sentence of the block that makes a claim about a class or a code is
// backed here by the code that decides it (BuilderStatusOf), and the script stays read-only (its offline selftest, with both directions).

func deployCheckScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pr", "rb11-deploy-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func gitBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\usr\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		t.Fatal("Git for Windows' bash is required (the bash on PATH is the WSL launcher)")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runSelftest(t *testing.T, script string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rb11-deploy-check.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gitBash(t), filepath.ToSlash(path), "--selftest")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		t.Fatal("the selftest hung")
	}
	return "", nil
}

func TestDeployCheckIsReadOnlyAndItsSelftestSaysSoBothWays(t *testing.T) {
	script := deployCheckScript(t)
	out, err := runSelftest(t, script)
	if err != nil || !strings.Contains(out, "selftest ok: ") {
		t.Fatalf("the shipped script: %v\n%s", err, out)
	}
	// the grep the brief names: no write or DDL statement exists in the file's SQL
	_, sqlBody, _ := strings.Cut(script, "sql <<'SQL'")
	for _, kw := range []string{"INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE ", "TRUNCATE "} {
		if strings.Contains(strings.ToUpper(sqlBody), kw) && strings.Contains(sqlBody, kw) {
			t.Errorf("the SQL of the script contains %q", kw)
		}
	}
	// and each way of making it write is caught by the selftest
	for name, mutate := range map[string]func(string) string{
		"an INSERT statement": func(s string) string {
			return strings.Replace(s, "sql <<'SQL'\n-- the LIVE capture loops' rows", "sql <<'SQL'\nINSERT INTO proof_finality_capture(chain) VALUES (1);\n-- the LIVE capture loops' rows", 1)
		},
		"a DELETE in a statement that starts with SELECT": func(s string) string {
			return strings.Replace(s, "GROUP BY 1 ORDER BY 1;\nSELECT chain, max(l1_block) AS cursor_block", "GROUP BY 1 ORDER BY 1;\nSELECT 1; DELETE FROM proof_finality_capture;\nSELECT chain, max(l1_block) AS cursor_block", 1)
		},
		"an UPDATE after the first statement": func(s string) string {
			return strings.Replace(s, "SELECT version, name, applied_at", "SELECT 1; UPDATE public.certen_schema_history SET applied_by = 'x';\nSELECT version, name, applied_at", 1)
		},
		"a session SET": func(s string) string {
			return strings.Replace(s, "SELECT version, name, applied_at", "SET statement_timeout = 0;\nSELECT version, name, applied_at", 1)
		},
		"the read-only transaction removed": func(s string) string {
			return strings.Replace(s, "{ echo 'BEGIN TRANSACTION READ ONLY;'; cat; echo 'ROLLBACK;'; }", "{ echo 'BEGIN;'; cat; echo 'ROLLBACK;'; }", 1)
		},
		"the read-only session removed": func(s string) string {
			return strings.Replace(s, "docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on'", "docker exec -i -e PGOPTIONS='-c application_name=x'", 1)
		},
	} {
		mutated := mutate(script)
		if mutated == script {
			t.Errorf("%s: the mutation did not apply", name)
			continue
		}
		if out, err := runSelftest(t, mutated); err == nil {
			t.Errorf("%s: the selftest accepted it:\n%s", name, out)
		}
	}
}

func expectedBlock(t *testing.T) string {
	t.Helper()
	_, block, ok := strings.Cut(deployCheckScript(t), "# EXPECTED (healthy deploy of this branch")
	if !ok {
		t.Fatal("no EXPECTED block")
	}
	return strings.Join(strings.Fields(strings.ReplaceAll(block, "\n#", " ")), " ")
}

// The class of a row is decided by BuilderStatusOf alone; the block's statements about which code lands in which class are those answers.
func TestDeployCheckExpectedBlockSeparatesTheCodeFromTheClass(t *testing.T) {
	block := expectedBlock(t)
	at := time.Unix(1_700_000_000, 0)
	row := func(err error, refused bool) BuilderStatus {
		return BuilderStatusOf("p", ChainSepolia, LevelFinalized, LevelIncluded, nil, err, refused, at)
	}
	// the facts of the code
	verifier := NewState(CodeVerifierFailed, "chain", ChainSepolia, "kind", "k", "cause", "x")
	if s := row(verifier, true); s.Class != BuilderRefused || s.State.Code != CodeVerifierFailed {
		t.Fatalf("a verifier failure of an append: %s %s", s.Class, s.State.Code)
	}
	if s := row(verifier, false); s.Class != BuilderUnavailable || s.State.Code != CodeVerifierFailed {
		t.Fatalf("a verifier code raised by a prover: %s %s", s.Class, s.State.Code)
	}
	for _, code := range []string{CodeChainBroken, CodeBlockMismatch, CodeGuardRefused} {
		if s := row(NewState(code), true); s.Class != BuilderRefused || s.State.Code != code {
			t.Fatalf("%s as a refusal of an append: %s %s", code, s.Class, s.State.Code)
		}
	}
	if s := row(os.ErrNotExist, false); s.Class != BuilderUnavailable || s.State.Code != CodeBuilderError {
		t.Fatalf("an error with no name: %s %s", s.Class, s.State.Code)
	}
	if s := row(AtStage(StageAppend, os.ErrNotExist), false); s.Class != BuilderUnavailable || s.State.Code != CodeBuilderError || s.State.Fields["stage"] != StageAppend {
		t.Fatalf("an append error with no name: %s %v", s.Class, s.State.Fields)
	}
	// the sentences that state them
	for _, want := range []string{
		"class 'refused' = evidence was BUILT and its APPEND was refused; nothing stored",
		"The class names the event, never the reason: the CODE says who refused",
		"finality_chain_broken, finality_block_mismatch{leg}",
		"finality_guard_refused",
		"finality_verifier_failed is a CODE, not a class.",
		"(refused, finality_verifier_failed) = a verifier rejected built evidence",
		"(unavailable, finality_verifier_failed) = a prover raised that code for a failure that built no evidence",
		"is class 'unavailable' with the code finality_builder_error{stage=build|append}",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the EXPECTED block does not say %q", want)
		}
	}
	// the sentence this item removed: it named the code as the Kind's own refusal under the class
	for _, gone := range []string{"the code is that Kind's own named refusal", "whatever its class, means evidence was built and failed verification"} {
		if strings.Contains(block, gone) {
			t.Errorf("the EXPECTED block still says %q", gone)
		}
	}
	// every class the block names is a class of the code
	classes := map[string]bool{string(BuilderPending): true, string(BuilderUnavailable): true, string(BuilderRefused): true, string(BuilderNotApplicable): true, string(BuilderVerified): true}
	for _, field := range strings.Split(block, "class '")[1:] {
		name, _, _ := strings.Cut(field, "'")
		if !classes[name] {
			t.Errorf("the EXPECTED block names the class %q, which is no BuilderClass", name)
		}
	}
	// every code the block names exists in the registry
	reg, err := os.ReadFile(filepath.Join("testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{CodeVerifierFailed, CodeChainBroken, CodeBlockMismatch, CodeGuardRefused, CodeBuilderError} {
		if !bytes.Contains(reg, []byte("\""+code+"\"")) {
			t.Errorf("%s is not in the states registry", code)
		}
	}
}
