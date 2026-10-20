package execution

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// RB10-B15 (V-R10B7 D2 D3): the dial callers and the online verifiers name no provider key.

const b15Key = "ZkQ9xPLm2Tn7VbR4sWcY8dHgJf1A5eUo"

type b15Logger struct {
	mu    sync.Mutex
	lines []string
}

func (l *b15Logger) Printf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, v...))
}

func (l *b15Logger) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var b15Malformed = []string{
	"https://eth-sepolia.g.alchemy.com/v2/" + b15Key + "\r",
	"https://eth-sepolia.g.alchemy.com/v2/" + b15Key + "\n",
	"https://eth-sepolia.g.alchemy.com/v2/" + b15Key + "%zz",
	"https://eth-sepolia.g.alchemy.com:99999x/v2/" + b15Key,
	"https://eth-sepolia.g.alchemy.com\x7f/v2/" + b15Key,
}

func TestB15_D3_TheG2BindingLogsNoKeyOnConnectOrFailure(t *testing.T) {
	// a good URL is logged on every connect: it names the host and not the key
	l := &b15Logger{}
	NewG2OutcomeBindingService(&G2Config{EthereumRPCURL: "https://eth-sepolia.g.alchemy.com/v2/" + b15Key}, l)
	if !strings.Contains(l.text(), "eth-sepolia.g.alchemy.com") {
		t.Fatalf("the connect is not logged by host:\n%s", l.text())
	}
	if strings.Contains(l.text(), b15Key) {
		t.Fatalf("the connect line holds the key:\n%s", l.text())
	}
	for _, raw := range b15Malformed {
		l := &b15Logger{}
		NewG2OutcomeBindingService(&G2Config{EthereumRPCURL: raw}, l)
		if l.text() == "" || strings.Contains(l.text(), b15Key) {
			t.Fatalf("%q: the failure line is empty or holds the key:\n%s", raw, l.text())
		}
	}
}

func TestB15_D3_TheOnlineVerifiersNameNoKeyInTheirConnectError(t *testing.T) {
	l5 := &Layer5{AnchorTx: "0x" + strings.Repeat("ab", 32)}
	for _, raw := range b15Malformed {
		_, err := VerifyLayer5Online(context.Background(), raw, l5)
		if err == nil || strings.Contains(err.Error(), b15Key) || strings.Contains(fmt.Sprintf("%+v", err), b15Key) {
			t.Fatalf("VerifyLayer5Online(%q): %v", raw, err)
		}
		_, err = VerifyOutcomeEvidenceOnline(context.Background(), raw, &OutcomeEvidence{})
		if err == nil || strings.Contains(err.Error(), b15Key) || strings.Contains(fmt.Sprintf("%+v", err), b15Key) {
			t.Fatalf("VerifyOutcomeEvidenceOnline(%q): %v", raw, err)
		}
	}
}
