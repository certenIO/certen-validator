// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
)

// maxFinalityConfigInput bounds what the check reads: a container's whole environment is a few KiB.
const maxFinalityConfigInput = 1 << 20

// runFinalityConfigCheck is `validator finality-config-check`: the read-only deploy check of the provider variables. It reads from in
// a JSON array of "NAME=VALUE" strings - exactly what `docker inspect -f '{{json .Config.Env}}' <container>` prints - judges the
// provider variables in it by the rule the finality runtime applies at startup (finruntime.CheckProviderEnvironment, which is
// url.Parse's: the same code, not a copy of its rules) and prints one line per provider variable, never a value:
//
//	unset  <NAME>                            the variable is not in the environment (or is blank)
//	ok     <NAME> <n> entries                every entry is accepted
//	REFUSED <NAME> entry <i> <class>         entry i (counted among the non-blank entries) would be refused, and why
//	REFUSED <NAME> holds no entry            the variable is set but holds no entry at all
//
// and a last line RESULT refused=<k>. Names outside finruntime.ProviderVariables() are ignored and never read. The process
// environment of the check itself is cleared of the provider variables first, so only the input is judged. Exit status: 0 nothing
// would be refused, 1 at least one entry would be refused, 2 the input is not a JSON array of strings.
func runFinalityConfigCheck(in io.Reader, out, errw io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(in, maxFinalityConfigInput+1))
	if err != nil || len(raw) > maxFinalityConfigInput {
		fmt.Fprintln(errw, "finality-config-check: the input could not be read within its bound")
		return 2
	}
	var env []string
	if err := json.Unmarshal(raw, &env); err != nil {
		// a JSON error message may quote input bytes: say only that the shape is wrong
		fmt.Fprintln(errw, "finality-config-check: the input is not a JSON array of NAME=VALUE strings (docker inspect -f '{{json .Config.Env}}')")
		return 2
	}
	vars := finruntime.ProviderVariables()
	for _, v := range vars {
		os.Unsetenv(v.Name)
	}
	allowed := map[string]bool{}
	for _, v := range vars {
		allowed[v.Name] = true
	}
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !allowed[name] {
			continue
		}
		os.Setenv(name, value)
	}
	refused := finruntime.CheckProviderEnvironment()
	bad := map[string]bool{}
	for _, r := range refused {
		bad[r.Variable] = true
	}
	for _, v := range vars {
		value := os.Getenv(v.Name)
		switch {
		case strings.TrimSpace(value) == "":
			fmt.Fprintf(out, "unset   %s\n", v.Name)
		case !bad[v.Name]:
			fmt.Fprintf(out, "ok      %s %d entries\n", v.Name, finruntime.ProviderEntryCount(value))
		}
	}
	for _, r := range refused {
		if r.Class == finruntime.ClassNoEntry {
			fmt.Fprintf(out, "REFUSED %s holds no entry\n", r.Variable)
			continue
		}
		fmt.Fprintf(out, "REFUSED %s entry %d %s\n", r.Variable, r.Entry, r.Class)
	}
	fmt.Fprintf(out, "RESULT refused=%d\n", len(refused))
	if len(refused) > 0 {
		return 1
	}
	return 0
}
