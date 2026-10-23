// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// S7: staged finality (PROOF_V2 section 7, pkg/finality, domain tag certen:finality:v1).
//
// A proof's finality addenda are append-only evidence beside the proof. The database path (--finality) verifies them offline
// against the leg's own Settlement: D0 (the leg binding, V2_SPEC_S7 2.6) is recomputed from the verified Settlement's block
// and never read from the file; then the chain of addenda (sequence, previous-hash links, own hashes under that D0, each
// level at most once and in any order, every (chain, level, kind) a row of the table) and the carried leg member are checked,
// then each addendum's evidence by its registered verifier. The report names every level - verified, pending or not
// applicable - and the level reached. The file path (--finality-file) reads and strictly parses the carried leg and addenda;
// the portable document carries no Settlement, so a Settlement SOURCE is named beside it: --outcome-file (an exported outcome
// evidence file: the block that holds the recorded outcome, proven offline into its header) or --proof-id with --db (the
// stored bundle's L6 execution proof). With a Settlement the leg is judged exactly as on the database path; without one the
// file judges nothing and says so by name (finality_included_unavailable, summary-only).
// Exit codes are the tool's own:
//
//	0  verified     the chain verifies and every addendum verifies to exactly its level (a level not yet reached is
//	                reported as finality_pending with the level reached, never as a failure)
//	3  summary-only an addendum's kind or pins are not known to this verifier (nothing is known to be wrong), or the
//	                proof carries no settlement evidence to attach finality to
//	1  FAILED       the chain or some evidence is present and does not check out

// reportFinality verifies a stored proof's finality (S7): its bundle's L6 settlement (level 1, derived, never stored), the
// addenda stored for the leg, and each stored level's evidence, judged by the registered Kinds against the pins. D0 is
// recomputed from the verified Settlement's block; the stored addenda never supply it.
func reportFinality(ctx context.Context, w io.Writer, db *sql.DB, id uuid.UUID, reg *finality.Registry, pins *finality.Pins) int {
	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	ref, err := repo.LegRef(ctx, id.String())
	if err != nil {
		if n, ok := finality.AsNamed(err); ok {
			fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n  The proof carries no settlement evidence, so there is nothing for finality to attach to.\n", id, n)
			return exitSummaryOnly
		}
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", id, err)
		return exitFailed
	}
	settlement, err := repo.LegSettlement(ctx, ref)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the bundle's L6 settlement evidence does not verify: %v\n", id, err)
		return exitFailed
	}
	if settlement.Unrecorded {
		fmt.Fprint(w, unrecordedNote)
	}
	chain, err := repo.Chain(ctx, id.String())
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  reading the stored addenda: %v\n", id, err)
		return exitFailed
	}
	// The stored chain belongs to the leg this proof's bundle proves: its carried block is that block.
	rep := reg.Verify(ref.Chain, settlement.Included, settlement.Block(), chain, pins)
	return printReport(w, rep, id.String())
}

// reportFinalityFile reads the `finality` member (certen-finality-addenda/1) of a portable proof v2 document file. With a
// Settlement (leg != nil) the leg is judged against it exactly as the database path judges a stored leg: the Settlement is
// verified (level 1, derived), D0 is the LegBinding of its block and never read from the file, the carried `leg` member must
// equal that block (finality_chain_broken{leg_binding}), the chain of addenda is recomputed under D0 and each addendum is
// judged by its registered Kind; the report names every level and the headline. Without a Settlement the portable document
// holds nothing to recompute D0 from: no level is judged and none is claimed, and the report says so by name
// (finality_included_unavailable, summary-only).
func reportFinalityFile(w io.Writer, path string, reg *finality.Registry, pins *finality.Pins, leg *legSettlement) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	var doc struct {
		Finality json.RawMessage `json:"finality"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  not a portable document: %v\n", path, err)
		return exitFailed
	}
	if len(doc.Finality) == 0 || string(doc.Finality) == "null" {
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  the document carries no finality section: no level beyond the proof itself is evidenced.\n", path)
		return exitSummaryOnly
	}
	section, err := finality.ParseSection(doc.Finality)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	if leg == nil {
		st := finality.IncludedUnavailable(finality.IncludedSettlementNotJudged, "chain", section.Leg.Chain)
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n  S7  carried leg: chain %d block %d %s; %d addenda are not judged "+
			"(name the Settlement: --outcome-file, or --proof-id with --db)\n", path, st, section.Leg.Chain,
			section.Leg.BlockNumber, section.Leg.BlockHash, len(section.Addenda))
		return exitSummaryOnly
	}
	carried, err := section.Leg.Ref()
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	fmt.Fprintf(w, "  S7  Settlement source: %s\n", leg.source)
	rep := reg.Verify(leg.chain, leg.s, carried, section.Addenda, pins)
	return printReport(w, rep, path)
}

// legSettlement is the Settlement a file path is judged against, with the chain it settled on and where it came from.
type legSettlement struct {
	chain  uint64
	s      *ethproof.Settlement
	source string
	// unrecorded: the stored proof row does not record its settlement (settlement_tx_hash / settlement_block_number NULL), so the
	// bundle's evidence is bound to the proof by its custody hash only and its tx and block were not cross-checked.
	unrecorded bool
}

// settlementFromOutcomeFile reads an exported outcome evidence file (execution.OutcomeEvidence) and returns the Settlement of the
// block that holds the recorded outcome: its header, the recording transaction and its receipt, each proven into that header by
// ethproof (the same checks finality level 1 runs). Nothing in the file is trusted: DeriveIncluded verifies the Settlement.
func settlementFromOutcomeFile(path string) (*legSettlement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ev := new(execution.OutcomeEvidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		return nil, fmt.Errorf("the outcome evidence does not decode: %w", err)
	}
	if ev.ChainID <= 0 {
		return nil, fmt.Errorf("the outcome evidence names chain %d", ev.ChainID)
	}
	inc := ev.Record.Inclusion
	var hdr types.Header
	if err := rlp.DecodeBytes(inc.Header, &hdr); err != nil {
		return nil, fmt.Errorf("the outcome evidence header does not decode: %w", err)
	}
	proof := func(value []byte, nodes []hexutil.Bytes, root common.Hash) *ethproof.InclusionProof {
		p := &ethproof.InclusionProof{LeafHash: [32]byte(crypto.Keccak256Hash(value)), LeafIndex: inc.Index, ExpectedRoot: [32]byte(root), LeafValue: value}
		for _, n := range nodes {
			p.ProofNodes = append(p.ProofNodes, []byte(n))
			p.ProofHashes = append(p.ProofHashes, [32]byte(crypto.Keccak256Hash(n)))
		}
		return p
	}
	// the file STATES which block and transaction hold the recorded outcome: the header and the transaction bytes must be those,
	// or the Settlement would be the proof of some other block that merely verifies by itself
	if got, want := crypto.Keccak256Hash(inc.Header), common.HexToHash(ev.Record.BlockHash); got != want {
		return nil, fmt.Errorf("the outcome evidence header hashes to %s, the record names block %s", got.Hex(), want.Hex())
	}
	if hdr.Number == nil || hdr.Number.Uint64() != ev.Record.BlockNumber {
		return nil, fmt.Errorf("the outcome evidence header is not block %d", ev.Record.BlockNumber)
	}
	if got, want := crypto.Keccak256Hash(inc.Transaction), common.HexToHash(ev.Record.Tx); got != want {
		return nil, fmt.Errorf("the outcome evidence transaction hashes to %s, the record names %s", got.Hex(), want.Hex())
	}
	s := &ethproof.Settlement{
		BlockHash: crypto.Keccak256Hash(inc.Header), Header: inc.Header, TxHash: crypto.Keccak256Hash(inc.Transaction),
		Tx:      proof(inc.Transaction, inc.TransactionProof, hdr.TxHash),
		Receipt: proof(inc.Receipt, inc.ReceiptProof, hdr.ReceiptHash),
	}
	return &legSettlement{chain: uint64(ev.ChainID), s: s, source: "outcome evidence " + path}, nil
}

// settlementFromDB loads the stored bundle's L6 execution proof of a proof id (the same leg the database path judges).
func settlementFromDB(ctx context.Context, dsn, proofID string) (*legSettlement, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	ref, err := repo.LegRef(ctx, proofID)
	if err != nil {
		return nil, err
	}
	st, err := repo.LegSettlement(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &legSettlement{chain: ref.Chain, s: st.Included, source: "the bundle of proof " + proofID, unrecorded: st.Unrecorded}, nil
}

// printReport writes one leg's per-statement S7 verdicts and returns the leg's exit code.
func printReport(w io.Writer, rep finality.Report, subject string) int {
	if rep.Unsupported != nil {
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n", subject, rep.Unsupported)
		return exitSummaryOnly
	}
	if st := rep.Levels[finality.LevelIncluded]; st.Status == finality.StatusRefused {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the leg's Settlement does not verify as the included level: %v\n", subject, st.State)
		return exitFailed
	}
	fmt.Fprintf(w, "  S7  chain %d  block %d  %x…  pins %s (%s)\n", rep.Block.Chain, rep.Block.Number, rep.Block.Hash[:6], rep.PinsSHA256, rep.PinsSource)
	for _, l := range finality.Levels {
		st := rep.Levels[l]
		line := fmt.Sprintf("  S7    %-9s  %s", l, st.Status)
		if st.State != nil {
			line += "  " + st.State.Error()
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "  S7  level reached: %s\n", rep.Headline)
	if rep.FinalizedBlock != nil {
		fmt.Fprintf(w, "  S7  finalized_block: number %d hash %x stateRoot %x\n", rep.FinalizedBlock.Number, rep.FinalizedBlock.Hash, rep.FinalizedBlock.StateRoot)
	}
	if rep.FinalizedBlockState != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the finalized level is verified but the leg block cannot be exposed for S8: %v\n", subject, rep.FinalizedBlockState)
		return exitFailed
	}
	if rep.Broken != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the addendum chain does not verify: %v\n", subject, rep.Broken)
		return exitFailed
	}
	code := exitVerified
	for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
		switch st := rep.Levels[l]; st.Status {
		case finality.StatusRefused:
			if notCoveredByThePins(st.State) {
				code = worseExit(code, exitSummaryOnly)
			} else {
				code = exitFailed
			}
		}
	}
	switch code {
	case exitFailed:
		fmt.Fprintf(w, "FAILED (finality)  %s\n  an addendum's evidence is present and does not check out\n", subject)
	case exitSummaryOnly:
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  an addendum's kind or pins are not known to this verifier; nothing is known to be wrong, and the levels above\n  %s are not judged here.\n", subject, rep.Headline)
	default:
		fmt.Fprintf(w, "VERIFIED (finality)  %s  level %s\n", subject, rep.Headline)
	}
	return code
}

// notCoveredByThePins is true for a refusal that does not say the evidence is wrong, only that this verifier cannot judge it: its kind is
// unknown (finality_evidence_unrecognised), the pins hold no entry for the period it names (finality_pin_unknown), or the pins' ledger ends
// before the period it is anchored at (finality_ledger_behind, also when a rollup kind carries it as the inner code of
// l1_finality_unproven). Those are the summary-only class, exit 3; every other refusal means evidence that does not check out, exit 1.
// A wrapped finality_pin_unknown is deliberately NOT in the class: it was FAILED before and this change does not move it (recorded as
// a finding).
func notCoveredByThePins(st *finality.StateError) bool {
	if st == nil {
		return false
	}
	switch st.Code {
	case finality.CodeEvidenceUnrecognised, finality.CodePinUnknown, ethl1.CodeLedgerBehind:
		return true
	case ethl1.CodeL1FinalityUnproven:
		inner, _ := st.Fields["inner"].(string)
		return inner == ethl1.CodeLedgerBehind
	}
	return false
}

// reportPinsSelfcheck re-derives the whole Sepolia ledger of the pins from its root pin through the link files embedded beside
// them (V2_SPEC_S7 4.3, SO3). It uses no network and no database: the links are configuration, re-verified here exactly as a
// proof's links are. Exit codes follow the verifier's: 0 re-derived, 1 a step was refused (the state is printed).
func reportPinsSelfcheck(out, errw io.Writer, pins *finality.Pins) int {
	links, err := finality.EmbeddedLedgerLinks()
	if err != nil {
		fmt.Fprintln(errw, err)
		return exitFailed
	}
	if err := pins.VerifyLedger(links); err != nil {
		fmt.Fprintf(errw, "PINS SELFCHECK FAILED  %v\n", err)
		return exitFailed
	}
	e, _ := pins.Sepolia()
	hash, src := pins.Identity()
	last := e.Anchors[len(e.Anchors)-1]
	fmt.Fprintf(out, "PINS SELFCHECK ok  %d Sepolia ledger anchors re-derived from the root pin (period %d .. %d)  pins %s (%s)\n",
		len(e.Anchors), e.Anchors[0].Period, last.Period, hash, src)
	return exitVerified
}

// unrecordedNote is printed when the stored proof row does not record its settlement yet (settlement_tx_hash or
// settlement_block_number is NULL): the bundle was bound to the proof by its custody hash, and the settlement was not
// cross-checked against the row. It is a statement about the stored row and does not change the verdict or the portable section.
const unrecordedNote = "  S7  settlement columns not recorded: the bundle is bound to the proof by its custody hash, tx/block not cross-checked\n"
