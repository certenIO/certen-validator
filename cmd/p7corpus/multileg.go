package main

// Build a real multi-partition proof for corpus case F.
//
// Everything else in Phase 4 and 5 is checked offline against captured
// evidence. This is the step that asks whether the thing actually happens: case
// F's principal is on BVN1 and its delegated signer on BVN2, so a proof of that
// transaction needs a leg for each, and either the network yields both or it
// does not.
//
// It reports what it got. A refusal here is a finding, not a failure to hide:
// the verifier states precisely what a cross-partition proof still needs, and
// an honest "refused, because X" is worth more than a proof that passes because
// nobody looked.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// signatureMessageOn finds the signature message a given key page contributed to
// a transaction, and returns its message hash.
//
// The hash is read off the message's own id rather than recomputed: the id is
// what the signature chain is keyed by, and recomputing it would be a second
// implementation of something the network already states.
func signatureMessageOn(ctx context.Context, endpoint, txID, page string) (string, error) {
	var resp struct {
		Result struct {
			Signatures struct {
				Records []struct {
					Account struct {
						URL string `json:"url"`
					} `json:"account"`
					Signatures struct {
						Records []struct {
							ID      string `json:"id"`
							Message struct {
								Type      string          `json:"type"`
								Signature json.RawMessage `json:"signature"`
							} `json:"message"`
						} `json:"records"`
					} `json:"signatures"`
				} `json:"records"`
			} `json:"signatures"`
		} `json:"result"`
	}
	if err := rawRPC(ctx, endpoint, "query", map[string]any{"scope": txID}, &resp); err != nil {
		return "", err
	}

	want := strings.ToLower(strings.TrimSuffix(page, "/"))
	for _, set := range resp.Result.Signatures.Records {
		if strings.ToLower(set.Account.URL) != want {
			continue
		}
		for _, rec := range set.Signatures.Records {
			// The signature message, not a signatureRequest or a credit
			// payment: only a signature is a vote, and only a vote is what this
			// leg is meant to prove.
			var probe struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(rec.Message.Signature, &probe); err != nil {
				continue
			}
			if probe.Type != "delegated" && probe.Type != "ed25519" {
				continue
			}
			h, err := hashOfAccURL(rec.ID)
			if err != nil {
				return "", err
			}
			return h, nil
		}
	}
	return "", fmt.Errorf("no user signature message from %s on %s", page, txID)
}

// hashOfAccURL pulls the hash out of acc://<hash>@<scope>.
func hashOfAccURL(id string) (string, error) {
	s := strings.TrimPrefix(id, "acc://")
	at := strings.Index(s, "@")
	if at <= 0 {
		return "", fmt.Errorf("message id %q is not acc://<hash>@<scope>", id)
	}
	h := strings.ToLower(s[:at])
	if len(h) != 64 {
		return "", fmt.Errorf("message id %q does not carry a 32-byte hash", id)
	}
	return h, nil
}

// buildMultiLeg builds and verifies a multi-partition proof for case F.
func buildMultiLeg(ctx context.Context, endpoint string, raw map[string]json.RawMessage) error {
	cases, err := parseCases(raw)
	if err != nil {
		return err
	}
	f, ok := cases["F"]
	if !ok {
		return fmt.Errorf("case F is not in the manifest")
	}

	traces, err := readJSON[captureResult](traceFile)
	if err != nil {
		return fmt.Errorf("read traces (run -stage capture first): %w", err)
	}

	var fTrace *trace
	for i := range traces.Traces {
		if traces.Traces[i].Case == "F" {
			fTrace = &traces.Traces[i]
			break
		}
	}
	if fTrace == nil {
		return fmt.Errorf("case F has no captured trace")
	}
	if fTrace.TxID == "" || fTrace.ExecStatus != "delivered" {
		return fmt.Errorf("case F's transaction is %q, not delivered; there is nothing to prove",
			fTrace.ExecStatus)
	}

	r, err := newRouter(ctx, endpoint)
	if err != nil {
		return err
	}
	principalPart, err := r.route(f.Principal)
	if err != nil {
		return err
	}
	signerPart, err := r.route(fTrace.Signer)
	if err != nil {
		return err
	}
	fmt.Printf("case F: principal %s on %s, delegated signer %s on %s\n",
		f.Principal, principalPart, fTrace.Signer, signerPart)
	if strings.EqualFold(principalPart, signerPart) {
		return fmt.Errorf("both accounts route to %s; this is not the cross-partition case",
			principalPart)
	}

	msgHash, err := signatureMessageOn(ctx, endpoint, fTrace.TxID, fTrace.Signer)
	if err != nil {
		return fmt.Errorf("locate the signer's signature message: %w", err)
	}
	fmt.Printf("signature message on %s: %s\n", shortURL(fTrace.Signer), msgHash[:16])

	pb := chained_proof.NewProofBuilder(jsonrpc.NewClient(endpoint), false)
	in := chained_proof.ProofInput{
		Account: f.Principal + "/data",
		TxHash:  fTrace.TransactionHash,
		BVN:     strings.ToLower(principalPart),
	}
	signers := []chained_proof.SignerLeg{{
		Account: fTrace.Signer, Partition: strings.ToLower(signerPart), MessageHash: msgHash,
	}}

	proof, err := pb.BuildMultiPartitionProof(ctx, in, signers)
	if err != nil {
		return fmt.Errorf("build multi-partition proof: %w", err)
	}

	fmt.Printf("built a proof with %d partition leg(s): %v\n",
		len(proof.Legs()), proof.SignerPartitions())
	if len(proof.Legs()) < 2 {
		return fmt.Errorf("only %d leg was built; case F needs one per partition", len(proof.Legs()))
	}

	// Offline, with no client at all - the whole point of L4 carrying its own
	// evidence.
	if err := chained_proof.NewProofVerifier(false).Verify(ctx, proof); err != nil {
		return fmt.Errorf("the built proof does not verify offline: %w", err)
	}
	fmt.Println("the multi-partition proof VERIFIES OFFLINE")
	return nil
}
