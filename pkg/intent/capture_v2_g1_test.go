// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F6, B1: discovery starts an intent's capture with the activation signal proveV2 builds the certificate with, when the shadow can take one
// (ProofV2G1Capturer) and the gate knows the activation (ProofV2G1Gate). The shadow reads the signal once, when its capture is complete, and
// judges the capture's closure budget for the document form the build will produce. Anything less is Capture, exactly as before.

type g1Capturer struct {
	captures, g1Captures int
	signal               func() (bool, error)
}

func (c *g1Capturer) Capture(intentID, account, tx, keyBook, keyPage string) { c.captures++ }
func (c *g1Capturer) CaptureG1(intentID, account, tx, keyBook, keyPage string, g1 func() (bool, error)) {
	c.g1Captures++
	c.signal = g1
}
func (c *g1Capturer) Build(intentID, account, tx, bvn string) {}
func (c *g1Capturer) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	return &proofv2.Evidence{Version: proofv2.Version}, nil
}

func TestCaptureV2IsGivenTheGatesActivationSignal(t *testing.T) {
	// A capturer and a gate that knows the activation: CaptureG1, with the gate's own signal (read later, by the shadow).
	c := &g1Capturer{}
	g := &movingGate{}
	id := discoveryWith(g, c)
	id.captureV2("i1", "acc://a.acme/x", "tx", "book", "page")
	if c.g1Captures != 1 || c.captures != 0 || c.signal == nil {
		t.Fatalf("CaptureG1 calls %d, Capture calls %d, signal set %v", c.g1Captures, c.captures, c.signal != nil)
	}
	if in, err := c.signal(); err != nil || in {
		t.Fatalf("before the activation the signal says %v (%v)", in, err)
	}
	g.g1 = true // the activation comes into force while the capture is running: the shadow reads it when it judges the budget
	if in, err := c.signal(); err != nil || !in {
		t.Fatalf("after the activation the signal says %v (%v)", in, err)
	}
	g.g1Err = errors.New("the committed state is unreadable")
	if _, err := c.signal(); err == nil {
		t.Fatal("an unreadable activation was answered")
	}

	// A gate that knows nothing of the activation (rules before v15), or a shadow that cannot take it: Capture, as before.
	c = &g1Capturer{}
	discoveryWith(legacyGate{}, c).captureV2("i1", "acc://a.acme/x", "tx", "book", "page")
	if c.captures != 1 || c.g1Captures != 0 {
		t.Fatalf("legacy gate: Capture %d, CaptureG1 %d", c.captures, c.g1Captures)
	}
	p := &plainProver{}
	discoveryWith(&movingGate{g1: true}, p).captureV2("i1", "acc://a.acme/x", "tx", "book", "page")
	discoveryWith(nil, c).captureV2("i1", "acc://a.acme/x", "tx", "book", "page")
	if c.captures != 2 || c.g1Captures != 0 {
		t.Fatalf("no gate: Capture %d, CaptureG1 %d", c.captures, c.g1Captures)
	}
}

// movingGate is a gate whose activation can change after the capture started.
type movingGate struct {
	g1    bool
	g1Err error
}

func (g *movingGate) ProofV2Bound() (bool, uint64, error)     { return true, 7, nil }
func (g *movingGate) G1CrossPartitionRequired() (bool, error) { return g.g1, g.g1Err }
