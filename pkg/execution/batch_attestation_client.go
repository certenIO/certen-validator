package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Batch attestation — the proposer side
// =============================================================================
//
// Fans a batch out to peer validators and collects their partial signatures.
//
// # THE WIRE FORMAT CARRIES NO MEMBER DATA, ON PURPOSE
//
// BatchAttestationRequest is (chainID, cutoffHeight, bundleId, proposerID) and nothing more.
// Peers rebuild membership themselves from their own mempools; that independent reconstruction
// is the ONLY thing standing between a malicious proposer and a genuine quorum signing a root
// that drains an ADI's account.
//
// If a future change adds members to this request "so the peer doesn't have to look them up",
// the attester would be checking the proposer's data against itself, the security boundary
// would be gone, and every existing test would still pass. TestWireFormat_CarriesNoMemberData
// exists to make that change fail loudly.
//
// Refusals are normal and expected: a peer that has not yet seen an intent derives a different
// bundleId and declines. That costs liveness, never safety — the batch simply falls back.

// BatchAttestationEndpoint is the peer path this client posts to.
const BatchAttestationEndpoint = "/api/batch/attestation/request"

// DefaultBatchAttestationTimeout bounds one peer round trip.
const DefaultBatchAttestationTimeout = 20 * time.Second

// BatchAttestationPeersFromEnv reads ATTESTATION_PEERS (comma-separated base URLs).
//
// Already populated in production, e.g.
//
//	ATTESTATION_PEERS=http://validator-2:8080,http://validator-3:8080,...
func BatchAttestationPeersFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("ATTESTATION_PEERS"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, strings.TrimRight(p, "/"))
		}
	}
	return out
}

// CollectBatchAttestations asks every peer to attest the batch and returns those that agreed.
//
// The proposer's OWN partial is not gathered here — the caller adds it, because it needs no
// round trip and the proposer has already reproduced the batch by construction.
//
// Peers that error, time out, or disagree are skipped with a log line rather than failing the
// collection: reaching threshold with 5 of 7 is the normal case, not a degraded one.
func CollectBatchAttestations(
	ctx context.Context,
	logger *log.Logger,
	peers []string,
	req *BatchAttestationRequest,
	timeout time.Duration,
) []*BatchAttestationResponse {
	if req == nil || len(peers) == 0 {
		return nil
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
		logf("⚠️ [BATCH-ATTEST] encoding request: %v", err)
		return nil
	}

	var (
		mu        sync.Mutex
		collected []*BatchAttestationResponse
		wg        sync.WaitGroup
	)
	client := &http.Client{Timeout: timeout}

	for _, peer := range peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()

			reqCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			httpReq, err := http.NewRequestWithContext(
				reqCtx, http.MethodPost, peer+BatchAttestationEndpoint, bytes.NewReader(body))
			if err != nil {
				logf("⚠️ [BATCH-ATTEST] %s: building request: %v", peer, err)
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(httpReq)
			if err != nil {
				logf("⚠️ [BATCH-ATTEST] %s: unreachable: %v", peer, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logf("⚠️ [BATCH-ATTEST] %s: HTTP %d", peer, resp.StatusCode)
				return
			}

			var out BatchAttestationResponse
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				logf("⚠️ [BATCH-ATTEST] %s: decoding response: %v", peer, err)
				return
			}
			if out.Error != "" {
				// A disagreement is the system working. Log it plainly — a burst of these
				// means peers are seeing a different mempool, which is worth noticing.
				logf("↩️  [BATCH-ATTEST] %s declined: %s", peer, out.Error)
				return
			}
			if out.SignatureHex == "" || out.EVMAddress == "" {
				logf("⚠️ [BATCH-ATTEST] %s: agreed but returned no usable signature", peer)
				return
			}
			// Belt and braces: the peer must have derived the same bundleId it was asked
			// about. A peer returning a signature over a different batch is malfunctioning
			// or hostile; either way its partial must not be folded in.
			if !strings.EqualFold(strings.TrimSpace(out.BundleID), strings.TrimSpace(req.BundleID)) {
				logf("⚠️ [BATCH-ATTEST] %s signed a DIFFERENT bundleId (%s) — discarding",
					peer, shortHex(out.BundleID))
				return
			}

			mu.Lock()
			collected = append(collected, &out)
			mu.Unlock()
			logf("✅ [BATCH-ATTEST] %s attested", peer)
		}(peer)
	}
	wg.Wait()

	return collected
}

// NewBatchAttestationRequest builds the request for a formed batch.
//
// Takes the tree rather than loose fields so the bundleId can never be typed in by hand and
// drift from the root it belongs to.
func NewBatchAttestationRequest(tree *BatchTree, cutoffHeight uint64, proposerID string) (*BatchAttestationRequest, error) {
	if tree == nil {
		return nil, fmt.Errorf("nil tree")
	}
	if cutoffHeight == 0 {
		return nil, fmt.Errorf("cutoff height 0 is not a valid period")
	}
	return &BatchAttestationRequest{
		ChainID:      tree.ChainID,
		CutoffHeight: cutoffHeight,
		BundleID:     "0x" + hex.EncodeToString(tree.BundleID[:]),
		ProposerID:   proposerID,
	}, nil
}
