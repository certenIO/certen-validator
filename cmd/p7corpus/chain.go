package main

// Talking to Kermit: the few operations the corpus needs, and nothing else.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		fatal("parse url %q: %v", s, err)
	}
	return u
}

// account returns an account record, or nil if it does not exist. A query error
// that is not "not found" is returned as an error: treating an outage as
// absence is how a script creates a second copy of something that already
// exists.
func account(ctx context.Context, c *client, u *url.URL) (protocol.Account, error) {
	rec, err := c.Query(ctx, u, &api.DefaultQuery{})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query %s: %w", u, err)
	}
	ar, ok := rec.(*api.AccountRecord)
	if !ok {
		return nil, fmt.Errorf("query %s: not an account record (%T)", u, rec)
	}
	return ar.Account, nil
}

func isNotFound(err error) bool {
	s := err.Error()
	return strings.Contains(s, "not found") || strings.Contains(s, "does not exist")
}

// pageVersion returns a key page's current version. A signature carries the
// version it was made against and Accumulate refuses one made against an older
// page (KPSW-EXEC), so this is read fresh every time rather than cached.
func pageVersion(ctx context.Context, c *client, page string) (uint64, error) {
	acct, err := account(ctx, c, mustURL(page))
	if err != nil {
		return 0, err
	}
	if acct == nil {
		return 0, fmt.Errorf("key page %s does not exist", page)
	}
	kp, ok := acct.(*protocol.KeyPage)
	if !ok {
		return 0, fmt.Errorf("%s is a %v, not a key page", page, acct.Type())
	}
	return kp.Version, nil
}

// submit sends an envelope and reports what the network said about it.
//
// The status code of the SUBMISSION is not the status of the TRANSACTION -
// PHASE7_CORPUS_MANIFEST.md section 6 records a whole class of failures that
// read as success because "code: ok" from the envelope layer was taken as
// evidence about execution. So this returns the submission outcome and the
// caller confirms the effect separately.
func submit(ctx context.Context, c *client, env *messaging.Envelope) (string, error) {
	subs, err := c.Submit(ctx, env, api.SubmitOptions{})
	if err != nil {
		return "", err
	}
	var msg string
	for _, s := range subs {
		if s.Status == nil {
			continue
		}
		if s.Status.Error != nil {
			return "", fmt.Errorf("%s", s.Status.Error.Message)
		}
		if s.Message != "" {
			msg = s.Message
		}
	}
	if !allSubmissionsAccepted(subs) {
		return msg, fmt.Errorf("submission not accepted: %s", msg)
	}
	return msg, nil
}

func allSubmissionsAccepted(subs []*api.Submission) bool {
	if len(subs) == 0 {
		return false
	}
	for _, s := range subs {
		if !s.Success {
			return false
		}
	}
	return true
}

// awaitDelivered polls a transaction until it is delivered or the deadline
// passes, and reports the code the executor gave it.
func awaitDelivered(ctx context.Context, c *client, txid *url.TxID, within time.Duration) (string, string) {
	deadline := time.Now().Add(within)
	var lastCode, lastErr string
	for time.Now().Before(deadline) {
		rec, err := c.Query(ctx, txid.AsUrl(), &api.DefaultQuery{})
		if err == nil {
			if mr, ok := rec.(*api.MessageRecord[messaging.Message]); ok && mr.Status != 0 {
				lastCode = mr.Status.String()
				if mr.Error != nil {
					lastErr = mr.Error.Message
				}
				if mr.Status.Delivered() {
					return lastCode, lastErr
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if lastCode == "" {
		lastCode = "unresolved"
	}
	return lastCode, lastErr
}
