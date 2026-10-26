// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/finality"
)

// S8: contract identity (V2_SPEC_S8 Freeze item 6, pkg/contractidentity, domain tag certen:contract-identity:v1).
//
// `--contract-identity` with `--finality-file <portable document> --outcome-file <evidence>` judges the document's `contractIdentity`
// member (certen-contract-identity/1) against the leg the outcome evidence settles: the LegContext is built from the outcome evidence
// (Settlement, transaction, receipt, ADI, the batch facts of its anchor, the S9 registry of its quorum), from the S6 replay-guard evidence
// of the member (deriveS6) and from the S7 report of the same run. The headline is one of six rows with its own exit code, in a space
// that does not meet the S7 codes except 2 (usage or internal error) and 0:
//
//	0   VERIFIED         contract identity: VERIFIED at <level> (registry <via>)
//	5   not applicable   contract identity: not applicable (<reason>)
//	10  verified core    contract identity: verified core, <N> open: <part>:<reason>, ...   (NEVER printed, counted or exit-coded as verified)
//	20  PENDING          contract identity: PENDING (state root not authenticated; <N> findings)
//	30  UNPROVEN         contract identity: UNPROVEN: <parts>
//	40  REFUSED          contract identity: REFUSED: <first refusal state>
//	2   usage / internal proofverify: <error>  (an input that cannot form a container, a verifier error or panic: a Go error, never a Report)
//
// The two phases run in order, S7 then S8, and the exit code is combineExit: an S7 FAILED (1) wins, then a non-zero S8 code, then S7's.
// Without the flag the member is not read and every output and exit code is what it was before this file existed.

// ciMemberFormat is the format string of the portable member.
const ciMemberFormat = "certen-contract-identity/1"

// The exit codes of the headline rows (Freeze item 6).
const (
	exitCIVerified      = 0
	exitCINotApplicable = 5
	exitCIVerifiedCore  = 10
	exitCIPending       = 20
	exitCIUnproven      = 30
	exitCIRefused       = 40
)

// ciRequest is what the flag asks of reportFinalityFileCI.
type ciRequest struct {
	verifier ci.Verifier
	manifest *ci.Manifest
}

// combineExit joins the exit codes of the two phases: S7 FAILED wins (the leg's own evidence is wrong), then any non-zero S8 code, then S7's.
func combineExit(s7, s8 int) int {
	switch {
	case s7 == exitFailed:
		return exitFailed
	case s8 != exitCIVerified:
		return s8
	}
	return s7
}

// renderContractIdentity maps a headline to its CLI line and exit code. A headline that does not carry what its row prints is an error:
// nothing is printed in its place.
func renderContractIdentity(h ci.Headline) (string, int, error) {
	const p = "contract identity: "
	switch h.Kind {
	case ci.HeadlineVerified:
		if h.JudgedAtLevel == "" || h.RegistryLink == "" {
			return "", 0, fmt.Errorf("a verified headline names no judged level or registry link (level %q, registry %q)", h.JudgedAtLevel, h.RegistryLink)
		}
		return fmt.Sprintf("%sVERIFIED at %s (registry %s)", p, h.JudgedAtLevel, h.RegistryLink), exitCIVerified, nil
	case ci.HeadlineNotApplicable:
		if h.NotApplicable == nil {
			return "", 0, fmt.Errorf("a not_applicable headline carries no state")
		}
		reason := h.NotApplicable.Reason
		if reason == "" {
			reason = h.NotApplicable.Code
		}
		return fmt.Sprintf("%snot applicable (%s)", p, reason), exitCINotApplicable, nil
	case ci.HeadlineVerifiedCore:
		if len(h.Open) == 0 {
			return "", 0, fmt.Errorf("a verified_core headline carries no open entry")
		}
		open := make([]string, 0, len(h.Open))
		for _, o := range h.Open {
			if o.State == nil {
				return "", 0, fmt.Errorf("an open entry of part %s carries no state", o.Part)
			}
			open = append(open, openEntryText(o))
		}
		return fmt.Sprintf("%sverified core, %d open: %s", p, len(h.Open), strings.Join(open, ", ")), exitCIVerifiedCore, nil
	case ci.HeadlinePending:
		return fmt.Sprintf("%sPENDING (state root not authenticated; %d findings)", p, len(h.Findings)), exitCIPending, nil
	case ci.HeadlineUnproven:
		if len(h.Parts) == 0 {
			return "", 0, fmt.Errorf("an unproven headline names no part")
		}
		return fmt.Sprintf("%sUNPROVEN: %s", p, strings.Join(h.Parts, ", ")), exitCIUnproven, nil
	case ci.HeadlineRefused:
		if h.First == nil {
			return "", 0, fmt.Errorf("a refused headline names no first refusal")
		}
		return fmt.Sprintf("%sREFUSED: %s", p, h.First.Error()), exitCIRefused, nil
	}
	return "", 0, fmt.Errorf("unknown headline kind %q", h.Kind)
}

// openEntryText is `<part>:<reason>`; an S6 non-proof state is `s6_link:s6_not_proven(<state>)`.
func openEntryText(o ci.OpenEntry) string {
	reason := o.State.Reason
	if o.Part == ci.JudgedS6Link && o.State.Code == ci.CodeNotChecked {
		if s, ok := o.State.Fields["state"].(string); ok {
			reason = "s6_not_proven(" + s + ")"
		}
	}
	if reason == "" {
		reason = o.State.Code
	}
	return o.Part + ":" + reason
}

// ciMember is the decoded portable member.
type ciMember struct {
	chain, number uint64
	hash          [32]byte
	container     []byte
	digest        [32]byte
}

// strictObject decodes one JSON object into its members, refusing a duplicate key and a value that is not a single object.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := kt.(string)
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the object")
	}
	return out, nil
}

// onlyKeys refuses a member the format does not define.
func onlyKeys(m map[string]json.RawMessage, allowed ...string) error {
	for k := range m {
		known := false
		for _, a := range allowed {
			known = known || a == k
		}
		if !known {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}

func hexField(s string, name string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%s is not 0x-prefixed hex", name)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %v", name, err)
	}
	if n > 0 && len(b) != n {
		return nil, fmt.Errorf("%s is %d bytes, want %d", name, len(b), n)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	return b, nil
}

// parseCIMember reads the member strictly and checks it against the leg being judged. It returns exactly one of: the member; a refusal state
// (a version this verifier does not know, a container above the bound, a leg that is not the Settlement's); an error (a member that cannot
// form a container). The container itself is judged by the verifier, never here. The digest is a storage-consistency check under D0,
// recomputed from the leg and never read as authority.
func parseCIMember(raw []byte, ctx ci.LegContext) (*ciMember, *ci.StateError, error) {
	top, err := strictObject(raw)
	if err != nil {
		return nil, nil, err
	}
	var format string
	if err := json.Unmarshal(top["format"], &format); err != nil {
		return nil, nil, fmt.Errorf("format is not a string")
	}
	if format != ciMemberFormat {
		if len(format) == 0 || len(format) > ci.DefaultLimits().MaxKindBytes || strings.TrimFunc(format, func(r rune) bool { return r >= 0x20 && r < 0x7f }) != "" {
			return nil, nil, fmt.Errorf("format is not a printable ASCII string of 1 to %d bytes", ci.DefaultLimits().MaxKindBytes)
		}
		return nil, ci.Unrecognised(format), nil
	}
	if err := onlyKeys(top, "format", "leg", "evidence", "digest"); err != nil {
		return nil, nil, err
	}
	for _, k := range []string{"leg", "evidence", "digest"} {
		if len(top[k]) == 0 {
			return nil, nil, fmt.Errorf("missing %s", k)
		}
	}
	legObj, err := strictObject(top["leg"])
	if err == nil {
		err = onlyKeys(legObj, "chain", "blockNumber", "blockHash")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("leg: %w", err)
	}
	m := &ciMember{}
	var hash, evidence, digest string
	for _, f := range []struct {
		name string
		dst  any
	}{{"chain", &m.chain}, {"blockNumber", &m.number}, {"blockHash", &hash}} {
		if len(legObj[f.name]) == 0 {
			return nil, nil, fmt.Errorf("leg: missing %s", f.name)
		}
		if err := json.Unmarshal(legObj[f.name], f.dst); err != nil {
			return nil, nil, fmt.Errorf("leg.%s: %v", f.name, err)
		}
	}
	if err := json.Unmarshal(top["evidence"], &evidence); err != nil {
		return nil, nil, fmt.Errorf("evidence is not a string")
	}
	if err := json.Unmarshal(top["digest"], &digest); err != nil {
		return nil, nil, fmt.Errorf("digest is not a string")
	}
	hb, err := hexField(hash, "leg.blockHash", 32)
	if err != nil {
		return nil, nil, err
	}
	copy(m.hash[:], hb)
	// the bound is read from the text, before any byte is decoded or allocated
	lim := ci.DefaultLimits().MaxContainerBytes
	if hexPart := strings.TrimPrefix(evidence, "0x"); strings.HasPrefix(evidence, "0x") && (len(hexPart)+1)/2 > lim {
		return nil, ci.TooLarge("container", uint64((len(hexPart)+1)/2), uint64(lim)), nil
	}
	if m.container, err = hexField(evidence, "evidence", 0); err != nil {
		return nil, nil, err
	}
	db, err := hexField(digest, "digest", 32)
	if err != nil {
		return nil, nil, err
	}
	copy(m.digest[:], db)
	// the leg the member names is the leg the Settlement proves
	if ctx.Settlement != nil && len(ctx.Settlement.Header) > 0 {
		var hdr types.Header
		if derr := rlp.DecodeBytes(ctx.Settlement.Header, &hdr); derr == nil && hdr.Number != nil {
			switch {
			case m.chain != ctx.Chain:
				return nil, ci.BlockMismatch("chain", ctx.Chain, m.chain), nil
			case m.number != hdr.Number.Uint64():
				return nil, ci.BlockMismatch("number", hdr.Number.Uint64(), m.number), nil
			case m.hash != ctx.Settlement.BlockHash:
				return nil, ci.BlockMismatch("hash", fmt.Sprintf("0x%x", ctx.Settlement.BlockHash), fmt.Sprintf("0x%x", m.hash)), nil
			}
		}
	}
	if want := ci.DigestOf(m.chain, m.number, m.hash, m.container); want != m.digest {
		return nil, nil, fmt.Errorf("digest 0x%x is not the container's digest under the leg (0x%x)", m.digest, want)
	}
	return m, nil, nil
}

// judgeContractIdentity judges a leg's contract identity and prints the one line of its row. member is the raw `contractIdentity` member of
// the portable document; nil or JSON null is an absent member, which the verifier judges as unproven{all} (no_evidence_in_file). A verifier
// error, a recovered panic and a member that cannot form a container are exit 2 with `proofverify: <error>`: never a Report.
func judgeContractIdentity(w io.Writer, member json.RawMessage, ctx ci.LegContext, m *ci.Manifest, v ci.Verifier) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(w, "proofverify: contract identity verifier panicked: %v\n", r)
			code = exitUsage
		}
	}()
	var container []byte
	if t := bytes.TrimSpace(member); len(t) > 0 && string(t) != "null" {
		mem, st, err := parseCIMember(t, ctx)
		switch {
		case err != nil:
			fmt.Fprintf(w, "proofverify: contractIdentity member: %v\n", err)
			return exitUsage
		case st != nil:
			line, c, rerr := renderContractIdentity(ci.Headline{Kind: ci.HeadlineRefused, First: st})
			if rerr != nil {
				fmt.Fprintf(w, "proofverify: %v\n", rerr)
				return exitUsage
			}
			fmt.Fprintln(w, line)
			return c
		}
		container = mem.container
	}
	rep, err := v.Verify(ctx, container, m)
	if err != nil {
		fmt.Fprintf(w, "proofverify: contract identity verifier: %v\n", err)
		return exitUsage
	}
	h := rep.Headline
	if h.Kind == ci.HeadlineUnproven && noEvidenceOnly(rep) {
		h.Parts = []string{ci.UnprovenPartAll}
	}
	line, c, err := renderContractIdentity(h)
	if err != nil {
		fmt.Fprintf(w, "proofverify: contract identity report: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(w, line)
	return c
}

// ---- the LegContext of an outcome evidence file ----

// s6Result is what S6 established about the leg, as the LegContext states it (V2_SPEC_S8 step 3).
type s6Result struct {
	Status ci.S6Status
	Reason string // s6_silent: unsupported_generation | absent
	State  string // s6_not_proven: the S6 named state, state{reason=reason}
	Link   *ci.S6Link
}

// deriveS6 states what S6 (the replay-slot proof) established about a settlement that is already proven in its block: s6_proven iff the call is
// a settlement of a pinned account generation and the evidence proves the slot consumed; s6_silent iff S6 made no claim (the call is of no
// pinned generation, or no evidence is carried); s6_not_proven, with the named state, iff the evidence judged the leg and did not prove it.
func deriveS6(h *types.Header, tx *types.Transaction, success bool, logs []*types.Log, rg *ethproof.ReplayGuardEvidence) s6Result {
	if tx == nil || h == nil {
		return s6Result{Status: ci.S6Silent, Reason: "absent"}
	}
	if _, pinned := ethproof.SettlementCallGeneration(tx.Data()); !pinned {
		return s6Result{Status: ci.S6Silent, Reason: "unsupported_generation"}
	}
	if rg == nil {
		return s6Result{Status: ci.S6Silent, Reason: "absent"}
	}
	chk, err := rg.VerifyAgainst(h, tx, success, logs)
	if err != nil {
		var re *ethproof.ReplayError
		if errors.As(err, &re) {
			return s6Result{Status: ci.S6NotProven, State: fmt.Sprintf("%s{reason=%s}", re.State, re.Reason)}
		}
		return s6Result{Status: ci.S6NotProven, State: fmt.Sprintf("%s{reason=%s}", ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)}
	}
	if chk.State != ethproof.ReplayProven {
		return s6Result{Status: ci.S6NotProven, State: fmt.Sprintf("%s{reason=%s}", chk.State, chk.Reason)}
	}
	return s6Result{Status: ci.S6Proven, Link: &ci.S6Link{
		Contract: chk.Contract, LeafKey: [32]byte(chk.Slot.Key),
		SettlementBlock: ci.BlockRef{Number: chk.SettlementBlock.Number, Hash: [32]byte(chk.SettlementBlock.Hash)},
		ProvenAt:        ci.BlockRef{Number: chk.ProvenAt.Number, Hash: [32]byte(chk.ProvenAt.Hash)},
		CodeHash:        [32]byte(chk.CodeHash),
	}}
}

func hash32(s, name string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%s is not 32 bytes of hex", name)
	}
	copy(out[:], b)
	return out, nil
}

// registry9FromOutcome is the S9 registry the batch-outcome quorum states (V2_SPEC_S8, "S9 keys proven by S8"): the validators with their
// powers and BLS keys, the threshold and the anchor's CERTEN set root. It has no signer commitment (the Open entry pkc_signer_check). A quorum
// that names no validator supplies none. The keys are re-spelled as the registry form (lowercase hex, no 0x); whether they are the keys of
// the contract is what the verifier judges.
func registry9FromOutcome(ev *execution.OutcomeEvidence) (*ci.Registry9, error) {
	if len(ev.Quorum.Validators) == 0 {
		return nil, nil
	}
	root, err := hash32(ev.Anchor.CertenSetRoot, "anchor.certenSetRoot")
	if err != nil {
		return nil, err
	}
	r := &ci.Registry9{Num: ev.Quorum.ThresholdNumerator, Den: ev.Quorum.ThresholdDenominator, CertenSetRoot: root}
	for i, v := range ev.Quorum.Validators {
		power, err := strconv.ParseUint(v.VotingPower, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("quorum validator %d: voting power %q is not a uint64", i, v.VotingPower)
		}
		r.Members = append(r.Members, ci.RegistryMember{Address: common.HexToAddress(v.Address), Power: power, BLSKey: strings.TrimPrefix(strings.ToLower(v.BLSPublicKey), "0x")})
	}
	return r, nil
}

// legContextFromOutcome builds the LegContext of the leg an outcome evidence file settles, judged against the S7 report of the same run.
func legContextFromOutcome(leg *legSettlement, s7 *finality.Report) (ci.LegContext, error) {
	if leg == nil || leg.ev == nil || leg.s == nil {
		return ci.LegContext{}, fmt.Errorf("--contract-identity needs the outcome evidence (--outcome-file) as the Settlement source")
	}
	ev := leg.ev
	hdr, rcpt, err := leg.s.Verify()
	if err != nil {
		return ci.LegContext{}, fmt.Errorf("the outcome evidence settlement does not verify: %w", err)
	}
	ctx := ci.LegContext{Chain: leg.chain, Settlement: leg.s, Receipt: rcpt, ADIURL: ev.Member.ADIURL, S7: s7}
	if leg.s.Tx == nil {
		return ctx, nil
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(leg.s.Tx.LeafValue); err != nil {
		return ci.LegContext{}, fmt.Errorf("the outcome evidence settlement transaction does not decode: %w", err)
	}
	ctx.Tx = &tx
	s6 := deriveS6(hdr, &tx, rcpt.Succeeded(), rcpt.Logs, ev.Member.ReplayGuard)
	ctx.S6Status, ctx.S6Reason, ctx.S6State, ctx.S6 = s6.Status, s6.Reason, s6.State, s6.Link
	for name, dst := range map[string]struct {
		src string
		to  *[32]byte
	}{"anchor.batchRoot": {ev.Anchor.BatchRoot, &ctx.Batch.BatchRoot}, "anchor.batchOperationId": {ev.Anchor.BatchOperationID, &ctx.Batch.OperationID},
		"anchor.accumulateSetRoot": {ev.Anchor.AccumulateSetRoot, &ctx.Batch.AccSetRoot}, "anchor.incarnation": {ev.Anchor.Incarnation, &ctx.Batch.Incarnation}} {
		if *dst.to, err = hash32(dst.src, name); err != nil {
			return ci.LegContext{}, err
		}
	}
	if ctx.Registry9, err = registry9FromOutcome(ev); err != nil {
		return ci.LegContext{}, err
	}
	return ctx, nil
}

// reportContractIdentityFile is the S8 phase of reportFinalityFileCI: the document's member is judged against the leg of the outcome evidence
// and the S7 report of the run that has just printed. s7Code is that run's exit code.
func reportContractIdentityFile(w io.Writer, path string, leg *legSettlement, s7 *finality.Report, s7Code int, req *ciRequest) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(w, "proofverify: "+format+"\n", a...)
		return combineExit(s7Code, exitUsage)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s7Code
	}
	var doc struct {
		ContractIdentity json.RawMessage `json:"contractIdentity"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return s7Code
	}
	ctx, err := legContextFromOutcome(leg, s7)
	if err != nil {
		return fail("%v", err)
	}
	return combineExit(s7Code, judgeContractIdentity(w, doc.ContractIdentity, ctx, req.manifest, req.verifier))
}

// noEvidenceOnly is true when the report judged no part at all because the file carried no container: every part is unproven{part:all,
// reason:no_evidence_in_file} (step 1c(a)). The row then names the one part the states name, `all`, instead of listing every part.
func noEvidenceOnly(rep ci.Report) bool {
	if len(rep.Parts) == 0 {
		return false
	}
	for _, p := range rep.Parts {
		if p.Status != ci.StatusUnproven || p.State == nil || p.State.Reason != ci.UnprovenNoEvidence || p.State.Fields["part"] != ci.UnprovenPartAll {
			return false
		}
	}
	return true
}
