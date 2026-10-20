package main

import (
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// RB10-B15 (V-R10B7 D3): the command's fatal exit and its error report print no provider key.

const b15Key = "ZkQ9xPLm2Tn7VbR4sWcY8dHgJf1A5eUo"

func b15Leaky() error {
	return &url.Error{Op: "Post", URL: "https://eth-sepolia.g.alchemy.com/v2/" + b15Key, Err: syscall.ECONNREFUSED}
}

func TestB15_D3_FatalAndReportPrintNoKey(t *testing.T) {
	switch os.Getenv("B15_CHILD") {
	case "fatal":
		fatal("%v", b15Leaky())
	case "report":
		report(nil, b15Leaky())
		return
	}
	for _, mode := range []string{"fatal", "report"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestB15_D3_FatalAndReportPrintNoKey$")
		cmd.Env = append(os.Environ(), "B15_CHILD="+mode)
		out, _ := cmd.CombinedOutput()
		text := string(out)
		if !strings.Contains(text, "s6livecapture:") || !strings.Contains(text, "eth-sepolia.g.alchemy.com") {
			t.Fatalf("%s: the child printed no error naming the provider:\n%s", mode, text)
		}
		if strings.Contains(text, b15Key) {
			t.Fatalf("%s: the output holds the key:\n%s", mode, text)
		}
	}
}
