// Copyright 2026 Certen Protocol
//
// proofverify — read a governance proof out of PostgreSQL and verify it
// offline, L1 through L4.
//
// This is the operator-facing form of the claim Phase 6 exists to make good
// on. Governance spec §4 requires a governance proof to be verifiable offline;
// until the L4 quorum evidence was persisted, nothing could make that check,
// because the signatures, validator set and signed bytes a verifier needs were
// stored nowhere.
//
// It answers three DIFFERENT questions with three different exit codes,
// because collapsing them is how a weaker claim ends up wearing a stronger
// one's name:
//
//	0  verified      — reassembled from storage and checked by the real
//	                   verifier, with no network access.
//	3  summary-only  — the record carries the CONCLUSIONS of the quorum check
//	                   and not the evidence. Nothing is known to be wrong; it
//	                   simply cannot be re-checked. Every proof written before
//	                   Phase 6 is in this state and cannot be repaired:
//	                   re-querying Accumulate returns today's validator set,
//	                   not the one that signed.
//	1  FAILED        — the evidence is present and does not check out. This is
//	                   the only one of the three that means something is wrong.
//
// Verification performs no network access. The --offline flag does not enable
// that — it installs a dialer that makes any outbound connection a hard error,
// so "offline" is enforced rather than asserted.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

const (
	exitVerified    = 0
	exitFailed      = 1
	exitUsage       = 2
	exitSummaryOnly = 3
)

type refusingDialer struct{}

func (refusingDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("BLOCKED: verification attempted to reach %s/%s; "+
		"an offline proof must not need the network", network, addr)
}

func main() {
	var (
		proofID = flag.String("proof-id", "", "proof_artifacts.proof_id to verify (UUID)")
		dsn     = flag.String("db", os.Getenv("CERTEN_DB"), "PostgreSQL DSN (default $CERTEN_DB)")
		offline = flag.Bool("offline", true, "refuse all outbound network access during verification")
		verbose = flag.Bool("v", false, "print the reassembled proof's layer summary")
		govern  = flag.Bool("governance", false, "also recompute the stored G0/G1/G2 receipts from level_json")
		l5      = flag.Bool("l5", false, "also recompute the stored external-anchor binding (leaf -> batch root)")
		online  = flag.String("online-rpc", "", "with --l5 and --offline=false: also check, at this JSON-RPC endpoint of "+
			"the anchor's chain, that the anchor-create transaction published the batch root and batch operation id")
		incarnation = flag.String("incarnation", "", "with --l5: the Accumulate incarnation you trust (hex32, docs/l4/"+
			"INCARNATION_ANCHOR.md; derive it with cmd/incarnation). Without it, which Accumulate chain a V8.2 anchor's "+
			"committed validator set belongs to rests on the anchor alone")
	)
	flag.Parse()

	if *proofID == "" || *dsn == "" {
		fmt.Fprintln(os.Stderr, "usage: proofverify --proof-id <uuid> --db <dsn> [--offline] [--governance] [--l5] "+
			"[--online-rpc <url> --offline=false] [-v]")
		os.Exit(exitUsage)
	}
	if *online != "" && (*offline || !*l5) {
		fmt.Fprintln(os.Stderr, "--online-rpc checks the anchor on its chain: it needs --l5 and --offline=false")
		os.Exit(exitUsage)
	}
	id, err := uuid.Parse(*proofID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proof-id %q is not a UUID: %v\n", *proofID, err)
		os.Exit(exitUsage)
	}
	var pinned *[32]byte
	if *incarnation != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(*incarnation), "0x"))
		if err != nil || len(raw) != 32 {
			fmt.Fprintf(os.Stderr, "--incarnation %q is not 32 bytes of hex\n", *incarnation)
			os.Exit(exitUsage)
		}
		pinned = new([32]byte)
		copy(pinned[:], raw)
	}

	// Cut the network BEFORE opening the database, so the block cannot be
	// mistaken for "we happened not to call out this time". The database
	// connection is made through lib/pq's own dialer, not http.
	if *offline {
		dead := &http.Transport{DialContext: refusingDialer{}.DialContext, ResponseHeaderTimeout: time.Millisecond}
		http.DefaultTransport = dead
		http.DefaultClient = &http.Client{Transport: dead}
	}

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(exitFailed)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(exitFailed)
	}

	store := certenproof.NewPostgresProofStorage(db)
	cp, err := certenproof.VerifyStoredProof(ctx, store, id)

	switch {
	case err == nil:
		fmt.Printf("VERIFIED  %s\n", id)
		fmt.Printf("  network:  disabled (offline=%v)\n", *offline)
		fmt.Printf("  L1  leaf %s… in BVN block %d\n", short(cp.Layer1.Leaf), cp.Layer1.BVNMinorBlockIndex)
		fmt.Printf("  L2  BVN stateTreeAnchor %s… at DN block %d\n", short(cp.Layer2.BVNStateTreeAnchor), cp.Layer2.DNMinorBlockIndex)
		fmt.Printf("  L3  DN stateTreeAnchor  %s… at consensus height %d\n", short(cp.Layer3.DNStateTreeAnchor), cp.Layer3.DNConsensusHeight)
		fmt.Printf("  L4  %s quorum: %d/%d distinct signers over %d validators\n",
			cp.Layer4BVN.Partition, len(cp.Layer4BVN.Signatures), cp.Layer4BVN.Threshold, len(cp.Layer4BVN.ValidatorSet))
		fmt.Printf("  L4  %s quorum: %d/%d distinct signers over %d validators\n",
			cp.Layer4DN.Partition, len(cp.Layer4DN.Signatures), cp.Layer4DN.Threshold, len(cp.Layer4DN.ValidatorSet))

		// PHASE 8 ITEM 1 — say how many SIGNER PARTITIONS this proof carries,
		// and whether the govRoot preimage committed to the extra ones.
		//
		// A one-leg proof and a two-leg proof both verify; the difference is
		// which quorums the root attests to, and that difference is invisible
		// unless it is printed. ConsensusProof.BVNs is omitempty, so an absent
		// slot and a deliberately-empty one look identical in the JSON, and
		// reporting the count is what separates "this authority lives on one
		// partition" from "we only proved one of the two it lives on".
		legs := cp.Legs()
		fmt.Printf("  L4  signer partitions: %d leg(s) %v\n", len(legs), cp.SignerPartitions())
		consensus := certenproof.BuildL4ConsensusProofFromProof(cp)
		if consensus == nil {
			// Not a verification failure: L1-L4 checked out. It means a leg the
			// proof NAMES carries no quorum evidence, so no summary can be
			// rebuilt from storage — which is summary-only, by the same rule
			// the governance levels follow.
			fmt.Printf("  L4  govRoot preimage: NOT RECONSTRUCTABLE from storage — a named leg " +
				"carries no quorum evidence\n")
		} else {
			fmt.Printf("  L4  govRoot preimage: version %q, principal %s, bvns = %d additional partition(s)\n",
				consensus.Version, consensus.BVN.Partition, len(consensus.BVNs))
			for _, b := range consensus.BVNs {
				fmt.Printf("        bvns[] %s: %d distinct signer(s), threshold %d\n",
					b.Partition, len(b.Signers), b.Threshold)
			}
			// FAIL CLOSED. A root that commits to one leg of a multi-leg proof
			// is perfectly well-formed and attests to less than the proof
			// carries — the silent under-proving this whole path exists to
			// prevent, arrived at from the other end.
			if len(legs) > 1 && len(consensus.BVNs) == 0 {
				fmt.Printf("FAILED  the proof carries %d legs and the govRoot preimage commits to ONE\n",
					len(legs))
				os.Exit(exitFailed)
			}
		}

		if *verbose {
			fmt.Printf("  L4  %s signedHash %s…\n", cp.Layer4BVN.Partition, short(cp.Layer4BVN.SignedHash))
			fmt.Printf("  L4  %s signedHash %s…\n", cp.Layer4DN.Partition, short(cp.Layer4DN.SignedHash))
		}
		// Each extra check can only WEAKEN the verdict, never strengthen it, and
		// the weakest of the three is what gets reported. L1-L4 verifying says
		// nothing about whether the governance receipts or the anchor binding
		// were stored, and reporting the strongest result would put a weaker
		// claim under a stronger one's name — the failure mode this tool exists
		// to prevent.
		code := exitVerified
		if *govern {
			code = worseExit(code, reportGovernance(ctx, store, id, *verbose))
			code = worseExit(code, reportG0Binding(ctx, store, id, cp))
		}
		if *l5 {
			code = worseExit(code, reportLayer5(ctx, store, id, cp, pinned))
		}
		if *govern && *l5 {
			code = worseExit(code, reportGovernanceDecision(ctx, store, id))
			code = worseExit(code, reportIntentCertificate(ctx, db, store, id, cp, pinned))
		}
		if *online != "" {
			code = worseExit(code, reportLayer5Online(ctx, store, id, *online))
		}
		os.Exit(code)

	case errors.Is(err, certenproof.ErrSummaryOnly), errors.Is(err, certenproof.ErrNoStoredProof):
		// Not a failure. The distinction is the whole point of this tool.
		fmt.Printf("SUMMARY-ONLY  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  Nothing about this proof is known to be wrong — its quorum was checked in\n")
		fmt.Printf("  flight. What is missing is the evidence needed to check it again, and it cannot\n")
		fmt.Printf("  be recovered. (The governance root is not anchored anywhere: it was used only in\n")
		fmt.Printf("  each validator's own pre-execution signature - RB4-F66.)\n")
		os.Exit(exitSummaryOnly)

	default:
		fmt.Printf("FAILED  %s\n", id)
		fmt.Printf("  %v\n", err)
		os.Exit(exitFailed)
	}
}

func short(hexStr string) string {
	if len(hexStr) <= 16 {
		return hexStr
	}
	return hexStr[:16]
}

// reportGovernance recomputes every stored governance receipt FROM level_json
// ALONE and returns the exit code for the combined result.
//
// Kept separate from the L1-L4 verdict on purpose. They are different claims
// about different evidence, and a proof can perfectly well have a checkable
// quorum and an uncheckable governance level: the L4 legs were persisted in
// Phase 6 and the receipt paths only from Stage 2, so every proof written
// between those two is exactly that shape. Collapsing them would report the
// weaker of the two under the stronger one's name, which is the failure mode
// this tool exists to prevent.
//
// The same three-way discipline applies: 0 verified, 3 summary-only, 1 failed.
// L1-L4 has already verified by the time this runs, so a governance level with
// no evidence downgrades the RESULT to summary-only rather than failing it —
// nothing is known to be wrong.
func reportGovernance(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID, verbose bool) int {
	levels, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, id)

	for _, l := range levels {
		switch {
		case l.HasEvidence():
			fmt.Printf("  %-3s RECOMPUTED from level_json: %d merkle step(s), leaf %s… under anchor %s…\n",
				l.Level, len(l.Receipt.Entries), short(l.Receipt.Start), short(l.Receipt.Anchor))
			if verbose && l.HasResult() {
				fmt.Printf("      result stored (%d bytes of canonical G-result)\n", len(l.Result))
			}
		case l.HasResult():
			fmt.Printf("  %-3s result stored but NO receipt path — the conclusion is recorded and cannot be checked\n", l.Level)
		default:
			fmt.Printf("  %-3s verdict flags only — this row does not contain the governance proof\n", l.Level)
		}
	}

	switch {
	case err == nil:
		fmt.Printf("  governance: every stored level recomputes from level_json alone, network disabled\n")
		return exitVerified

	case errors.Is(err, certenproof.ErrGovernanceSummaryOnly),
		errors.Is(err, certenproof.ErrNoStoredGovernanceLevels):
		fmt.Printf("SUMMARY-ONLY (governance)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  L1-L4 verified. Nothing about the governance levels is known to be wrong — the\n")
		fmt.Printf("  proof was generated and checked in flight. What is missing is the receipt\n")
		fmt.Printf("  merkle path needed to check it\n")
		fmt.Printf("  again, and it cannot be recovered: a receipt fetched today is not necessarily\n")
		fmt.Printf("  the one this proof was built on.\n")
		return exitSummaryOnly

	default:
		fmt.Printf("FAILED (governance)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  The receipt evidence IS present and does not recompute to its own anchor.\n")
		fmt.Printf("  This is the one outcome that means something is wrong.\n")
		return exitFailed
	}
}

// reportG0Binding checks, from storage, that the governance levels describe
// the same execution the chained proof proves: G0's receipt is L1's receipt,
// ending at the root and block the BVN quorum signed. It is what makes G0's
// finality checkable offline rather than a label.
func reportG0Binding(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID,
	cp *chained_proof.ChainedProof) int {

	// The levels' own receipts were judged by reportGovernance; this reads them
	// again only to compare them with the chained proof.
	levels, _ := certenproof.VerifyStoredGovernanceLevels(ctx, store, id)
	err := certenproof.VerifyStoredG0Binding(levels, cp)
	switch {
	case err == nil:
		fmt.Printf("  G0 binding: the governance levels' execution receipt IS the chained proof's L1 receipt, " +
			"ending at the root and block the BVN quorum signed\n")
		return exitVerified
	case errors.Is(err, certenproof.ErrG0BindingUncheckable):
		fmt.Printf("SUMMARY-ONLY (G0 binding)  %s\n", id)
		fmt.Printf("  %v\n", err)
		return exitSummaryOnly
	default:
		fmt.Printf("FAILED (G0 binding)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  The governance levels and the chained proof describe different executions.\n")
		return exitFailed
	}
}

// worseExit returns the weaker of two verdicts: failed beats summary-only beats
// verified. A tool that reported the best of several checks would let one green
// answer hide two absent ones.
func worseExit(a, b int) int {
	rank := map[int]int{exitVerified: 0, exitSummaryOnly: 1, exitFailed: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// reportLayer5 recomputes the stored external-anchor binding and returns the
// exit code for it.
//
// The two halves are reported SEPARATELY and deliberately:
//
//	leaf -> batchRoot   recomputed here, offline, network disabled.
//	batchRoot -> chain  printed as COORDINATES. Not checked, and not claimed.
//
// "L1-L4 verified, L5 absent" is summary-only, not a failure — every proof
// written before Stage 3 is in that state, and so is every proof that settled
// with no observable external transaction. Nothing about them is known to be
// wrong.
func reportLayer5(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID,
	cp *chained_proof.ChainedProof, pinned *[32]byte) int {
	l5, err := execution.VerifyStoredLayer5(ctx, store, id)

	switch {
	case err == nil:
		if len(l5.Path) == 0 {
			fmt.Printf("  L5  leaf IS the batch root (one-member batch) — accepted only because " +
				"leafHash == batchRoot\n")
		} else {
			fmt.Printf("  L5  leaf %s… recomputed to batch root %s… over %d step(s), OFFLINE\n",
				short(l5.LeafHash), short(l5.BatchRoot), len(l5.Path))
		}
		fmt.Printf("  L5  external coordinates: tx %s at block %d on %s (chainId %d)\n",
			l5.AnchorTx, l5.BlockNumber, l5.Network, l5.ChainID)
		fmt.Printf("  L5  NOT verified offline: that the transaction above exists and contains this\n")
		fmt.Printf("      batch root. That is an ONLINE check (--online-rpc); proving it offline needs a light\n")
		fmt.Printf("      client, which is deliberately out of scope.\n")
		return reportAccumulateCommitment(id, l5, cp, pinned)

	case errors.Is(err, execution.ErrNoLayer5):
		// A DISTINCT message, not the L1-L4 one: "L1-L4 verified, L5 absent" is
		// its own state and an operator has to be able to tell it from a proof
		// whose quorum evidence is missing.
		fmt.Printf("SUMMARY-ONLY (L5)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  L1-L4 verified. This proof is not bound to a publication — either it predates\n")
		fmt.Printf("  the external anchor binding, or it settled with no observable external\n")
		fmt.Printf("  transaction. Nothing about it is known to be wrong.\n")
		return exitSummaryOnly

	default:
		fmt.Printf("FAILED (L5)  %s\n", id)
		fmt.Printf("  %v\n", err)
		if l5 != nil {
			fmt.Printf("  claimed: %s\n", l5.ExternalClaim())
		}
		fmt.Printf("  The binding IS present and the leaf does not recompute to the batch root it\n")
		fmt.Printf("  names. This proof is not in the batch it claims to be in.\n")
		return exitFailed
	}
}

// reportAccumulateCommitment says what the anchor establishes about the Accumulate validator set the proof's L4 was
// verified against (RB5 Phase G), never more.
func reportAccumulateCommitment(id uuid.UUID, l5 *execution.Layer5, cp *chained_proof.ChainedProof, pinned *[32]byte) int {
	if l5.Commitment != nil {
		fmt.Printf("  L5  anchor (%s): bundle id %s… and the quorum's message recompute from what it committed, OFFLINE\n",
			l5.Commitment.Version, short(strings.TrimPrefix(l5.Commitment.BundleID, "0x")))
	}
	state, err := execution.CheckAccumulateCommitment(l5, cp.Layer4DN, pinned)
	switch {
	case err != nil:
		fmt.Printf("FAILED (Accumulate validator set)  %s\n  %v\n", id, err)
		return exitFailed
	case state == execution.AccumulateSetCommittedVerified:
		fmt.Printf("  L4↔L5 the Accumulate validator set this proof's L4 was verified against IS the one CERTEN's quorum\n")
		fmt.Printf("      committed on-chain (root %s…), under the incarnation you pinned (%s…). It cannot be\n",
			short(strings.TrimPrefix(l5.Commitment.AccumulateSetRoot, "0x")), short(strings.TrimPrefix(l5.Commitment.Incarnation, "0x")))
		fmt.Printf("      substituted. Whether it descends from that incarnation's genesis set is not checked here.\n")
		return reportValidatorSetEvidence(id, l5, cp, pinned, exitVerified)
	case state == execution.AccumulateSetCommittedUnpinned:
		fmt.Printf("SUMMARY-ONLY (Accumulate incarnation)  %s\n", id)
		fmt.Printf("  the validator set this proof's L4 used IS the one its anchor committed (root %s…), under\n",
			short(strings.TrimPrefix(l5.Commitment.AccumulateSetRoot, "0x")))
		fmt.Printf("  incarnation %s…; no --incarnation was pinned, so which Accumulate chain that is rests on the\n",
			short(strings.TrimPrefix(l5.Commitment.Incarnation, "0x")))
		fmt.Printf("  anchor alone. Pin one (cmd/incarnation) to check it.\n")
		return reportValidatorSetEvidence(id, l5, cp, pinned, exitSummaryOnly)
	case state == execution.AccumulateSetNotCommittedV8_1:
		fmt.Printf("SUMMARY-ONLY (Accumulate validator set)  %s\n", id)
		fmt.Printf("  this proof settled under a V8.1 anchor, which committed no Accumulate validator set: the set\n")
		fmt.Printf("  L4 was verified against is carried by the proof and bound to nothing on-chain.\n")
		return exitSummaryOnly
	default:
		fmt.Printf("SUMMARY-ONLY (Accumulate validator set)  %s\n", id)
		fmt.Printf("  this proof's layer 5 records no anchor commitment (written before it was recorded): the set L4\n")
		fmt.Printf("  was verified against is carried by the proof and not checked against its anchor.\n")
		return exitSummaryOnly
	}
}

// reportValidatorSetEvidence checks the Accumulate validator-set evidence layer 5 carries (RB5-F4) and says what it
// establishes, never more: the set DERIVED from account bytes, and whether it is bound to the anchor the L4 leg signed
// (today it is not: binding needs historical state, AIP-058). Evidence that is present and proven wrong fails the proof.
func reportValidatorSetEvidence(id uuid.UUID, l5 *execution.Layer5, cp *chained_proof.ChainedProof, pinned *[32]byte, code int) int {
	if l5.Accumulate == nil {
		fmt.Printf("  L5  carries no Accumulate validator-set evidence: the set L4 was verified against is the proof's own\n")
		fmt.Printf("      statement, committed on-chain but not derived from chain state here.\n")
		return code
	}
	if cp.Layer4DN == nil {
		fmt.Printf("FAILED (Accumulate validator set)  %s\n", id)
		fmt.Printf("  layer 5 carries validator-set evidence but the proof has no Directory leg to check it against\n")
		return exitFailed
	}
	var pin *string
	if pinned != nil {
		h := hex.EncodeToString(pinned[:])
		pin = &h
	}
	res := l5.Accumulate.VerifyAgainstDirectoryLeg(cp.Layer4DN, pin)
	if res.Err != nil {
		fmt.Printf("FAILED (Accumulate validator set)  %s\n  %s\n", id, res.Claim())
		return exitFailed
	}
	fmt.Printf("  L5  validator-set evidence (verdict %s): %s\n", res.Verdict, res.Claim())
	return code
}

// reportGovernanceDecision re-derives who decided the proof's transaction from the stored vote record and checks
// that the batch the proof settled in commits to it (RB4-F66). Offline.
func reportGovernanceDecision(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID) int {
	levels, err := certenproof.GovernanceLevelsFromStorage(ctx, store, id)
	if err != nil {
		fmt.Printf("FAILED (governance decision)  %s\n  %v\n", id, err)
		return exitFailed
	}
	l5, l5err := execution.VerifyStoredLayer5(ctx, store, id)
	if l5err != nil {
		l5 = nil // reportLayer5 has already reported it; the decision is checked against no batch
	}
	got, err := execution.CheckGovernanceDecision(levels, l5)
	switch {
	case err == nil:
		fmt.Printf("  GOV vote: evaluated again from %d chain-bound message(s) and %d page history/ies replayed\n",
			got.EvidenceMessages, got.EvidencePages)
		fmt.Printf("      from genesis; it reaches the stored vote record exactly\n")
		reportAuthoritySetBasis(got)
		fmt.Printf("  GOV decision: %d authority/ies, commitment %s… re-derived from that vote record\n",
			got.Authorities, short(strings.TrimPrefix(got.Commitment, "0x")))
		fmt.Printf("  GOV anchored: the batch operation id %s… (%s) recomputes from its members, this one\n",
			short(strings.TrimPrefix(got.BatchOperationID, "0x")), got.BatchVersion)
		fmt.Printf("      committing to that decision - the quorum signed, and the anchor stores, who decided\n")
		return exitVerified
	case errors.Is(err, execution.ErrNoGovernanceDecision):
		fmt.Printf("SUMMARY-ONLY (governance decision)  %s\n  %v\n", id, err)
		fmt.Printf("  Who decided the transaction is not recorded for this proof. Nothing about it is known\n")
		fmt.Printf("  to be wrong.\n")
		return exitSummaryOnly
	case errors.Is(err, execution.ErrGovernanceNotAnchored):
		fmt.Printf("SUMMARY-ONLY (governance decision)  %s\n  %v\n", id, err)
		fmt.Printf("  GOV vote: evaluated again from %d chain-bound message(s) and %d page history/ies\n",
			got.EvidenceMessages, got.EvidencePages)
		fmt.Printf("  GOV decision: %d authority/ies, commitment %s… re-derived from the stored vote record,\n",
			got.Authorities, short(strings.TrimPrefix(got.Commitment, "0x")))
		fmt.Printf("  and NOT anchored: no quorum signature or anchor commits to it.\n")
		return exitSummaryOnly
	default:
		fmt.Printf("FAILED (governance decision)  %s\n  %v\n", id, err)
		fmt.Printf("  The stored decision does not agree with its own evidence or with its anchored batch.\n")
		return exitFailed
	}
}

// reportAuthoritySetBasis says what the authority set at execution was replayed from, and names each account whose
// part of it rests on the network's present set rather than on the chain alone.
func reportAuthoritySetBasis(got *execution.GovernanceDecisionCheck) {
	fmt.Printf("  GOV authorities: the set at execution replayed from %d account history/ies\n", got.EvidenceAccounts)
	if got.Declared == nil {
		fmt.Printf("  GOV declared: the intent declares no authority set; nothing it claims is checked beyond the chain\n")
	} else {
		fmt.Printf("  GOV declared: %s - the governance that executed the intent\n",
			certenproof.DescribeDeclaredGovernance(got.Declared))
	}
	for _, a := range got.DecidedByLiveState {
		fmt.Printf("      %s: which creation rule applied was chosen by the set the network held when read,\n", a)
		fmt.Printf("      not by the chain alone\n")
	}
}

// reportLayer5Online checks the stored layer 5 against the anchor's chain.
func reportLayer5Online(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID, rpc string) int {
	l5, err := execution.VerifyStoredLayer5(ctx, store, id)
	if err != nil {
		fmt.Printf("FAILED (L5 online)  %s\n  no layer 5 to check online: %v\n", id, err)
		return exitFailed
	}
	got, err := execution.VerifyLayer5Online(ctx, rpc, l5)
	if err != nil {
		fmt.Printf("FAILED (L5 online)  %s\n  %v\n", id, err)
		return exitFailed
	}
	fmt.Printf("  L5  ONLINE: anchor tx %s (to %s) published root %s… and batch operation id %s…\n",
		l5.AnchorTx, got.AnchorContract, short(strings.TrimPrefix(got.BatchRoot, "0x")),
		short(strings.TrimPrefix(got.BatchOperationID, "0x")))
	if got.AnchorVersion == "v8_2" {
		fmt.Printf("      as a V8.2 anchor committing Accumulate set %s… under incarnation %s…\n",
			short(strings.TrimPrefix(got.AccumulateSetRoot, "0x")), short(strings.TrimPrefix(got.Incarnation, "0x")))
	}
	if got.AnchorRecordChecked {
		fmt.Printf("      and the anchor's own record (anchors(bundleId)) holds exactly that, valid\n")
	}
	fmt.Printf("      compare the contract with the chain's published CERTEN anchor\n")
	return exitVerified
}

// reportIntentCertificate checks, offline, CERTEN's quorum certificate over the proof's intent (RB5 D3): it verifies
// against its registry, the registry is the quorum the anchor committed, and the certified message is the one the
// stored proof computes.
func reportIntentCertificate(ctx context.Context, db *sql.DB, store *certenproof.PostgresProofStorage, id uuid.UUID,
	cp *chained_proof.ChainedProof, pinned *[32]byte) int {
	l5, err := execution.VerifyStoredLayer5(ctx, store, id)
	if err != nil || l5 == nil || l5.Governance == nil {
		fmt.Printf("SUMMARY-ONLY (intent certificate)  %s\n", id)
		fmt.Printf("  the proof's layer 5 names no operation, so no certificate can be looked up (%v)\n", err)
		return exitSummaryOnly
	}
	row, err := database.NewConsensusRepository(database.NewClientFromDB(db)).IntentQuorumCertificate(ctx, l5.Governance.OperationID)
	if errors.Is(err, database.ErrIntentCertificatesNotInSchema) {
		fmt.Printf("SUMMARY-ONLY (intent certificate)  %s\n  %v\n", id, err)
		fmt.Printf("  This database records no per-intent certificates at all. Nothing about the proof is known to be wrong.\n")
		return exitSummaryOnly
	}
	if err != nil {
		fmt.Printf("FAILED (intent certificate)  %s\n  %v\n", id, err)
		return exitFailed
	}
	levels, err := certenproof.GovernanceLevelsFromStorage(ctx, store, id)
	if err != nil {
		fmt.Printf("FAILED (intent certificate)  %s\n  %v\n", id, err)
		return exitFailed
	}
	got, err := execution.CheckIntentCertificate(row, cp, levels, l5, pinned)
	switch {
	case err == nil:
		fmt.Printf("  QC  CERTEN's quorum certified this intent: %d signers, %s of %s power (registry v%d, %s), at CERTEN\n",
			got.Signers, got.SignedPower, got.TotalPower, got.RegistryVersion, got.CertenChainID)
		fmt.Printf("      height %d, over message %s… - the message this stored proof computes: its operation,\n",
			got.CertifiedHeight, short(strings.TrimPrefix(got.Message, "0x")))
		fmt.Printf("      govRoot v2 over its L1-L4 and G0-G2, its Directory leg's validator set, its governance\n")
		fmt.Printf("      decision; the registry is the CERTEN quorum the anchor committed")
		if got.IncarnationPinned {
			fmt.Printf(", under the incarnation you pinned")
		}
		if got.AnchoredInBatch {
			fmt.Printf("; and the anchored v3 batch operation id commits exactly this certified message")
		} else {
			fmt.Printf("; the batch it settled in (pre-v3) does not commit it on-chain")
		}
		fmt.Printf("\n")
		return exitVerified
	case errors.Is(err, execution.ErrNoIntentCertificate):
		fmt.Printf("SUMMARY-ONLY (intent certificate)  %s\n  %v\n", id, err)
		fmt.Printf("  This intent settled before CERTEN's BLS registry was in force: its quorum signed the batch, not the\n")
		fmt.Printf("  intent's own message. Nothing about it is known to be wrong.\n")
		return exitSummaryOnly
	default:
		fmt.Printf("FAILED (intent certificate)  %s\n  %v\n", id, err)
		return exitFailed
	}
}
