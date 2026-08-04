package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// On-demand attestation — the proposer side
// =============================================================================
//
// Same wire discipline as the period client: the request carries NO member data, only the key
// to look one up. Peers rebuild from their own copy, which is the only thing standing between a
// malicious proposer and a genuine quorum signing a root that drains an ADI's account.
//
// # WHAT IS NEW HERE: REFUSALS ARE CLASSIFIED
//
// On the period path every refusal is equivalent — the batch simply fails and falls back. That
// is affordable when the batch waits four minutes anyway. Here the whole point is to stop
// waiting, so the proposer needs to know WHY a peer said no:
//
//	member_not_held  -> the peer has not finished processing the round. Retry; it will.
//	bundle_mismatch  -> the peer holds the member and disagrees about it. Retrying cannot help.
//
// Measured live on 2026-08-04: all seven validators enqueued the same intent within a 5-second
// window and answered a quorum request in 0.53s. So "not held" resolves in seconds, and a fixed
// grace sized for the worst case spends a minute waiting for something that already happened.
//
// Classification reads the Code field, never the prose in Error — a proposer matching on
// substrings would silently reclassify every refusal the moment a message was reworded.

// OnDemandCollectResult is what one round of fan-out produced.
type OnDemandCollectResult struct {
	// Responses are the peers that agreed and returned a usable partial.
	Responses []*BatchAttestationResponse
	// NotHeld counts peers that do not yet hold the member. These are the retryable ones.
	NotHeld int
	// Mismatch counts peers that hold it and derived a different bundleId. For a one-member
	// batch this is a real disagreement about the intent itself, not a membership race.
	Mismatch int
	// Unreachable counts peers that errored, timed out, or returned a non-200.
	Unreachable int
	// Other counts refusals that are neither retryable nor a mismatch (config, not-ready).
	Other int
}

// Agreed reports how many peers contributed a partial.
func (r OnDemandCollectResult) Agreed() int { return len(r.Responses) }

// CouldStillConverge reports whether waiting is worth it: at least one peer is merely behind or
// briefly unreachable, as opposed to actively disagreeing.
func (r OnDemandCollectResult) CouldStillConverge() bool {
	return r.NotHeld > 0 || r.Unreachable > 0
}

// CollectOnDemandAttestations asks every peer to co-sign a one-member batch.
//
// The proposer's OWN partial is not gathered here — the caller adds it, because it needs no
// round trip and the proposer reproduced the batch by constructing it.
func CollectOnDemandAttestations(
	ctx context.Context,
	logger *log.Logger,
	peers []string,
	req *OnDemandAttestationRequest,
	timeout time.Duration,
) OnDemandCollectResult {
	var result OnDemandCollectResult
	if req == nil || len(peers) == 0 {
		return result
	}
	if timeout <= 0 {
		timeout = DefaultBatchAttestationTimeout
	}
	logf := func(format string, a ...interface{}) {
		if logger != nil {
			logger.Printf(format, a...)
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		logf("⚠️ [OD-ATTEST] encoding request: %v", err)
		return result
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	client := &http.Client{Timeout: timeout}

	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()

			reqCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			httpReq, err := http.NewRequestWithContext(
				reqCtx, http.MethodPost, peer+OnDemandAttestationEndpoint, bytes.NewReader(body))
			if err != nil {
				logf("⚠️ [OD-ATTEST] %s: building request: %v", peer, err)
				mu.Lock()
				result.Unreachable++
				mu.Unlock()
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(httpReq)
			if err != nil {
				logf("⚠️ [OD-ATTEST] %s: unreachable: %v", peer, err)
				mu.Lock()
				result.Unreachable++
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				// A peer that has not been upgraded answers 404 here. That is "unreachable" for
				// this path — retryable in principle, but it will never start working, which is
				// why the deadline in the submitter bounds the wait.
				logf("⚠️ [OD-ATTEST] %s: HTTP %d (a peer without the on-demand route answers 404)",
					peer, resp.StatusCode)
				mu.Lock()
				result.Unreachable++
				mu.Unlock()
				return
			}

			var out BatchAttestationResponse
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				logf("⚠️ [OD-ATTEST] %s: decoding response: %v", peer, err)
				mu.Lock()
				result.Unreachable++
				mu.Unlock()
				return
			}

			if out.Error != "" {
				mu.Lock()
				switch out.Code {
				case CodeMemberNotHeld:
					result.NotHeld++
				case CodeBundleMismatch:
					result.Mismatch++
				default:
					result.Other++
				}
				mu.Unlock()
				switch out.Code {
				case CodeMemberNotHeld:
					// The expected answer for the first seconds. Not a warning.
					logf("⏳ [OD-ATTEST] %s does not hold it yet", peer)
				case CodeBundleMismatch:
					logf("❌ [OD-ATTEST] %s DISAGREES on a one-member batch: %s", peer, out.Error)
				default:
					logf("↩️  [OD-ATTEST] %s declined (%s): %s", peer, out.Code, out.Error)
				}
				return
			}
			if out.SignatureHex == "" || out.EVMAddress == "" {
				logf("⚠️ [OD-ATTEST] %s: agreed but returned no usable signature", peer)
				mu.Lock()
				result.Other++
				mu.Unlock()
				return
			}
			// Belt and braces: the peer must have derived the same bundleId it was asked about.
			// A peer returning a signature over a different batch is malfunctioning or hostile;
			// either way its partial must not be folded in.
			if !strings.EqualFold(strings.TrimSpace(out.BundleID), strings.TrimSpace(req.BundleID)) {
				logf("⚠️ [OD-ATTEST] %s signed a DIFFERENT bundleId (%s) — discarding",
					peer, shortHex(out.BundleID))
				mu.Lock()
				result.Mismatch++
				mu.Unlock()
				return
			}

			mu.Lock()
			result.Responses = append(result.Responses, &out)
			mu.Unlock()
			logf("✅ [OD-ATTEST] %s attested", peer)
		}(peer)
	}
	wg.Wait()

	return result
}

// NewOnDemandAttestationRequest builds the request for a formed one-member batch.
//
// Takes the tree AND the member so the operationID on the wire is the one actually in the leaf,
// rather than a value typed in alongside it that could drift.
func NewOnDemandAttestationRequest(
	tree *BatchTree,
	member *PendingBatchIntent,
	proposerID string,
) (*OnDemandAttestationRequest, error) {
	if tree == nil {
		return nil, fmt.Errorf("nil tree")
	}
	if member == nil {
		return nil, fmt.Errorf("nil member")
	}
	if len(tree.Inputs) != 1 {
		return nil, fmt.Errorf("on-demand batch must have exactly 1 member, got %d", len(tree.Inputs))
	}
	if tree.Inputs[0].OperationID != member.OperationID {
		return nil, fmt.Errorf("tree leaf operationID does not match the member's; the request "+
			"would name a member the leaf does not commit to (intent %s)", member.IntentID)
	}
	if member.OperationID == ([32]byte{}) {
		return nil, fmt.Errorf("intent %s has a zero operationID", member.IntentID)
	}
	return &OnDemandAttestationRequest{
		ChainID:     tree.ChainID,
		OperationID: "0x" + hex.EncodeToString(member.OperationID[:]),
		BundleID:    "0x" + hex.EncodeToString(tree.BundleID[:]),
		ProposerID:  proposerID,
	}, nil
}
