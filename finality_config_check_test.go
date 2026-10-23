package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
)

// RB12-DBFIX-FIX (verifier V4): the read-only deploy check of the provider variables judges them with the validator's own code (url.Parse
// through the runtime's startup rule), names every variable the runtime parses as a provider list, accepts what url.Parse accepts
// (a scheme in any case) and prints only positions and classes.

func envJSON(t *testing.T, kv ...string) string {
	t.Helper()
	b, err := json.Marshal(kv)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runCheck(t *testing.T, input string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := runFinalityConfigCheck(strings.NewReader(input), &out, &errw)
	return code, out.String(), errw.String()
}

func TestFinalityConfigCheckJudgesTheVerifiersInputsByWhatUrlParseRejects(t *testing.T) {
	const secret = "hunter2-fake-credential"
	// the verifier's three inputs, each in the variable that used to be missing from the script or classified by prefix only
	code, out, errw := runCheck(t, envJSON(t,
		"PATH=/usr/bin", "HOME=/root",
		"CERTEN_FINALITY_LC_URLS=https://u:p%ss"+secret+"@h/",                            // url.Parse: invalid URL escape
		"BASE_SEPOLIA_RPC_URL=https://h:abc"+secret+"/",                                  // url.Parse: invalid port
		"ETHEREUM_SEPOLIA_URL_FALLBACKS=HTTPS://h.example/k,wss://k"+secret+"@x.example", // scheme in any case is accepted; wss is not
		"FOO_URL=not a url "+secret,                                                      // not a provider variable: never read
	))
	if code != 1 || errw != "" {
		t.Fatalf("exit %d, stderr %q\n%s", code, errw, out)
	}
	for _, want := range []string{
		"REFUSED CERTEN_FINALITY_LC_URLS entry 0 bad_escape",
		"REFUSED BASE_SEPOLIA_RPC_URL entry 0 bad_port",
		"REFUSED ETHEREUM_SEPOLIA_URL_FALLBACKS entry 1 other_scheme",
		"RESULT refused=3",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{secret, "h.example", "x.example", "u:p", "FOO_URL"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the output echoes %q:\n%s", leak, out)
		}
	}
	// every provider variable is accounted for: ok, unset or refused
	for _, v := range finruntime.ProviderVariables() {
		if !strings.Contains(out, " "+v.Name) {
			t.Fatalf("%s is not mentioned:\n%s", v.Name, out)
		}
	}
}

func TestFinalityConfigCheckAcceptsASchemeInAnyCaseAndEveryGoodList(t *testing.T) {
	code, out, errw := runCheck(t, envJSON(t,
		"ETHEREUM_SEPOLIA_URL_FALLBACKS=HTTPS://h.example/",
		"BASE_SEPOLIA_RPC_URL=Http://h.example:8545/k, https://u:p%40w@h2.example/p%20q?x=1",
		"CERTEN_FINALITY_BEACON_URLS=https://[::1]:8545/",
	))
	if code != 0 || errw != "" || !strings.Contains(out, "RESULT refused=0\n") {
		t.Fatalf("exit %d, stderr %q\n%s", code, errw, out)
	}
	for _, want := range []string{"ok      ETHEREUM_SEPOLIA_URL_FALLBACKS 1 entries", "ok      BASE_SEPOLIA_RPC_URL 2 entries", "ok      CERTEN_FINALITY_BEACON_URLS 1 entries", "unset   TELCOIN_ADIRI_RPC_URL"} {
		if !strings.Contains(out, want+"\n") {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "h.example") {
		t.Fatalf("the output echoes a host:\n%s", out)
	}
}

func TestFinalityConfigCheckJudgesOnlyItsInputAndAVariableThatHoldsNoEntryIsNamed(t *testing.T) {
	t.Setenv("BASE_SEPOLIA_RPC_URL", "wss://in-the-process-environment.example")
	code, out, _ := runCheck(t, envJSON(t, "CERTEN_FINALITY_LC_URLS= , ;"))
	if code != 1 || !strings.Contains(out, "REFUSED CERTEN_FINALITY_LC_URLS holds no entry\n") || strings.Contains(out, "BASE_SEPOLIA_RPC_URL entry") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestFinalityConfigCheckRefusesAnInputThatIsNotAnEnvironmentWithoutEchoingIt(t *testing.T) {
	for _, in := range []string{"", "not json hunter2", `{"a":"b"}`, `[1,2]`, `["A=b"`} {
		code, out, errw := runCheck(t, in)
		if code != 2 || out != "" || strings.Contains(errw, "hunter2") || strings.Contains(errw, "A=b") {
			t.Fatalf("input %q: exit %d out %q err %q", in, code, out, errw)
		}
	}
}

// The script's header names exactly the variables the runtime parses as provider lists (the table ConfigFromEnv and the check share).
func TestProviderURLCheckScriptHeaderNamesEveryProviderVariable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("pr", "rb12-dbfix-provider-url-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	start := strings.Index(text, "# THE VARIABLES")
	end := strings.Index(text, "# Exit status")
	if start < 0 || end < start {
		t.Fatal("the header lacks its THE VARIABLES section")
	}
	word := regexp.MustCompile(`[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+`)
	got := map[string]bool{}
	for _, line := range strings.Split(text[start:end], "\n")[1:] {
		line = strings.TrimPrefix(line, "#")
		if i := strings.Index(line, ":"); i >= 0 && !strings.HasPrefix(strings.TrimSpace(line), "CERTEN_FINALITY_ADIRI") {
			line = line[i+1:]
		}
		for _, w := range word.FindAllString(line, -1) {
			got[w] = true
		}
	}
	var want []string
	for _, v := range finruntime.ProviderVariables() {
		want = append(want, v.Name)
	}
	sort.Strings(want)
	var have []string
	for w := range got {
		have = append(have, w)
	}
	sort.Strings(have)
	if strings.Join(have, " ") != strings.Join(want, " ") {
		t.Fatalf("the script header names\n %v\nthe runtime parses\n %v", have, want)
	}
}

func bashForScripts(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\usr\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		t.Fatal("Git for Windows' bash is required to run the deploy-check script (the bash on PATH is the WSL launcher)")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to run the deploy-check script: %v", err)
	}
	return p
}

// The script end to end with a fake docker: `docker inspect` answers a container's configured environment, `docker run` executes this
// test binary as `validator finality-config-check`. Only positions and classes reach the output.
func TestProviderURLCheckScriptPrintsOnlyPositionsAndClassesAndFailsWhatTheRuntimeWouldRefuse(t *testing.T) {
	const secret = "hunter2-fake-credential"
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  inspect)\n" +
		"    if [ \"$2\" = \"-f\" ]; then f=\"$FIXTURES/$4.json\"; else f=\"$FIXTURES/$2.json\"; fi\n" +
		"    [ -f \"$f\" ] || exit 1\n" +
		"    if [ \"$2\" = \"-f\" ]; then cat \"$f\"; fi ;;\n" +
		"  run)\n" +
		"    case \"$*\" in *\"--network none\"*\"./validator finality-config-check\") ;; *) echo \"unexpected docker run: $*\" >&2; exit 9;; esac\n" +
		"    CERTEN_TEST_RUN_FINALITY_CONFIG_CHECK=1 exec \"$TESTBIN\" ;;\n" +
		"  *) echo \"unexpected docker $1\" >&2; exit 9 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	put := func(name string, kv ...string) {
		if err := os.WriteFile(filepath.Join(fixtures, name+".json"), []byte(envJSON(t, kv...)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("certen-validator-1", "BASE_SEPOLIA_RPC_URL=HTTPS://h.example/"+secret, "ETHEREUM_SEPOLIA_URL_FALLBACKS=https://f.example/"+secret)
	put("certen-validator-2", "CERTEN_FINALITY_LC_URLS=https://u:p%ss"+secret+"@h/", "BASE_SEPOLIA_RPC_URL=https://h:abc"+secret+"/", "ETHEREUM_SEPOLIA_URL_FALLBACKS=wss://k"+secret+"@s.example")

	script, err := filepath.Abs(filepath.Join("pr", "rb12-dbfix-provider-url-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) (int, string) {
		cmd := exec.Command(bashForScripts(t), filepath.ToSlash(script))
		cmd.Env = append(os.Environ(), append([]string{
			"PATH=" + filepath.ToSlash(dir) + string(os.PathListSeparator) + os.Getenv("PATH"),
			"FIXTURES=" + filepath.ToSlash(fixtures), "TESTBIN=" + filepath.ToSlash(self),
		}, env...)...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running the script: %v", err)
		}
		return code, out.String()
	}
	noLeak := func(out string) {
		t.Helper()
		for _, leak := range []string{secret, "h.example", "f.example", "s.example", "u:p"} {
			if strings.Contains(out, leak) {
				t.Fatalf("the script printed %q:\n%s", leak, out)
			}
		}
	}

	code, out := run("VALIDATORS=1", "CHECK_IMAGE=certen/validator:test")
	noLeak(out)
	if code != 0 || !strings.Contains(out, "PASS  certen-validator-1: 2 http(s) provider entries, none that would be refused") {
		t.Fatalf("a good container (scheme HTTPS) must pass: exit %d\n%s", code, out)
	}
	code, out = run("VALIDATORS=1 2", "CHECK_IMAGE=certen/validator:test")
	noLeak(out)
	for _, want := range []string{
		"PASS  certen-validator-1",
		"FAIL  certen-validator-2: finality would be switched off as finality_upgrader_disabled{reason=config_invalid}:",
		"CERTEN_FINALITY_LC_URLS[entry 0]=bad_escape", "BASE_SEPOLIA_RPC_URL[entry 0]=bad_port", "ETHEREUM_SEPOLIA_URL_FALLBACKS[entry 0]=other_scheme",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if code, out = run("VALIDATORS=1"); code != 2 || !strings.Contains(out, "NOT-CHECKED CHECK_IMAGE is not set") {
		t.Fatalf("without CHECK_IMAGE: exit %d\n%s", code, out)
	}
	if code, out = run("VALIDATORS=5", "CHECK_IMAGE=certen/validator:test"); code != 2 || !strings.Contains(out, "FAIL  certen-validator-5: container not found") {
		t.Fatalf("a missing container: exit %d\n%s", code, out)
	}
}

// The bound of what the check reads: exactly the bound is accepted, one byte more is refused, and a read error after valid bytes is
// not judged as an environment.
func TestFinalityConfigCheckBoundsItsInputExactly(t *testing.T) {
	pad := func(n int) string { // a JSON array of one string, n bytes in all
		overhead := len(`["X="]`)
		return `["X=` + strings.Repeat("a", n-overhead) + `"]`
	}
	if code, _, errw := runCheck(t, pad(maxFinalityConfigInput)); code != 0 || errw != "" {
		t.Fatalf("an input of exactly the bound: exit %d %q", code, errw)
	}
	if code, out, _ := runCheck(t, pad(maxFinalityConfigInput+1)); code != 2 || out != "" {
		t.Fatalf("an input one byte over the bound: exit %d %q", code, out)
	}
	if code, out, _ := runFinalityConfigCheckWith(errReader{data: `["BASE_SEPOLIA_RPC_URL=https://h.example/"]`}); code != 2 || out != "" {
		t.Fatalf("a read error after valid bytes: exit %d %q", code, out)
	}
}

type errReader struct{ data string }

func (e errReader) Read(p []byte) (int, error) {
	n := copy(p, e.data)
	return n, errors.New("connection reset")
}

func runFinalityConfigCheckWith(r io.Reader) (int, string, string) {
	var out, errw bytes.Buffer
	code := runFinalityConfigCheck(r, &out, &errw)
	return code, out.String(), errw.String()
}

// Only provider variables are ever set in the process, and a refused variable is not also reported ok.
func TestFinalityConfigCheckSetsNothingButProviderVariablesAndNeverCallsARefusedOneOk(t *testing.T) {
	t.Setenv("FOO_VARIABLE_OF_THE_TEST", "")
	code, out, _ := runCheck(t, envJSON(t, "FOO_VARIABLE_OF_THE_TEST=set-by-the-input", "BASE_SEPOLIA_RPC_URL=https://h:abc/", "BARE_ENTRY_WITHOUT_EQUALS"))
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := os.Getenv("FOO_VARIABLE_OF_THE_TEST"); got != "" {
		t.Fatalf("the check set a variable that is not a provider variable: %q", got)
	}
	if strings.Contains(out, "ok      BASE_SEPOLIA_RPC_URL") || !strings.Contains(out, "REFUSED BASE_SEPOLIA_RPC_URL entry 0 bad_port\n") {
		t.Fatalf("%s", out)
	}
}
