// Copyright 2026 Certen Protocol

package ethproof

import (
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// SetSettlementVerifierForTest replaces the function a capturer verifies a proven settlement with, so a test can make that
// verification panic (RB10-B8: a panic in it is a named state, built without calling it again).
func (c *ReplayGuardCapturer) SetSettlementVerifierForTest(f func(*Settlement) (*types.Header, *ReceiptLeaf, error)) {
	c.verifySettlement = f
}

// SetBindWaitForTest replaces how long Bind waits for a capture that has not finished (RB10-B10: the branch that names the
// wait is otherwise reachable only after the capture's budget plus two minutes).
func (c *ReplayGuardCapturer) SetBindWaitForTest(d time.Duration) { c.bindWait = d }
