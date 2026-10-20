// Copyright 2026 Certen Protocol

package ethl1

// rules is the seam through which the mutation tests turn ONE check of the verifier off (or move the signing-domain epoch)
// and require the vector that exists for that check to change verdict. The only implementation in this package is specRules,
// which skips nothing and implements the specification; the wrong variants live in the test files and nowhere else.
type rules interface {
	skip(check string) bool
	// domainEpoch is the epoch whose fork version signs an update: epoch(saturating_sub(signature_slot, 1)).
	domainEpoch(attestedSlot, signatureSlot uint64) uint64
}

// Names of the checks a mutation test may switch off.
const (
	chkFloor                 = "participation_floor"
	chkFinalityBranch        = "finality_branch"
	chkNextBranch            = "next_committee_branch"
	chkNextMismatch          = "next_committee_mismatch"
	chkPeriodRuleNextKnown   = "period_rule_next_known"
	chkPeriodRuleNextUnknown = "period_rule_next_unknown"
	chkLedgerFirstLearn      = "ledger_first_learn"
	chkLedgerRotation        = "ledger_rotation"
	chkLedgerFinalSigner     = "ledger_final_signer"
	chkWindow                = "window"
	chkFinalNotFinality      = "final_not_finality"
	chkExecBranch            = "exec_branch"
)

type specRules struct{}

func (specRules) skip(string) bool { return false }
func (specRules) domainEpoch(_, signatureSlot uint64) uint64 {
	if signatureSlot == 0 {
		return 0
	}
	return epochOf(signatureSlot - 1)
}

// VerifyFinalizedHead is spec section 5.2 steps 1-4: it establishes, from the pins and the LC part alone, a finalized
// beacon head and its finalized execution block hash. It returns a *Fault for every other outcome and never a weaker
// answer. current_slot is each update's own signature_slot; process_light_client_store_force_update is never called.
func VerifyFinalizedHead(p Pins, lc LC) (FinalizedHead, error) {
	h, f := verifyFinalizedHead(p, lc, specRules{})
	if f != nil {
		return FinalizedHead{}, f
	}
	return h, nil
}

// CheckNetwork reports finality_network_mismatch unless the pins describe the chain the caller is judging.
func CheckNetwork(p Pins, chainID uint64) error {
	if p.Network.ChainID != chainID {
		return NetworkMismatch(chainID, p.Network.ChainID)
	}
	return nil
}

type walkStore struct {
	finSlot   uint64
	cur       *committee
	next      *committee // nil while unknown
	curPeriod uint64     // label of cur, for reports
}

type walker struct {
	p Pins
	r rules
	s walkStore

	anchor Anchor
	gvr    [32]byte
}

func verifyFinalizedHead(p Pins, lc LC, r rules) (FinalizedHead, *Fault) {
	if err := CheckNetwork(p, SepoliaChainID); err != nil {
		return FinalizedHead{}, err.(*Fault)
	}
	// Step 1: profile, bounds, shapes, forks.
	if lc.Profile != ProfileLC {
		return FinalizedHead{}, EvidenceMalformed("profile", 0, "unsupported_profile", len(lc.Profile), len(ProfileLC))
	}
	if len(lc.Links) > p.MaxLinks {
		return FinalizedHead{}, EvidenceTooLarge("links", len(lc.Links), p.MaxLinks)
	}
	if lc.AnchorKind != 1 && lc.AnchorKind != 2 {
		return FinalizedHead{}, EvidenceMalformed("anchor_kind", 0, "unknown_kind", int(lc.AnchorKind), 2)
	}
	w := &walker{p: p, r: r, gvr: p.Network.GenesisValidatorsRoot}

	var boot *bootstrapObj
	var committeeRaw []byte
	if lc.AnchorKind == 1 {
		if lc.AnchorBody.Layout != LayoutNone {
			return FinalizedHead{}, EvidenceMalformed("anchor_body", 0, "layout_byte_not_zero", int(lc.AnchorBody.Layout), 0)
		}
		if len(lc.AnchorBody.SSZ) != SyncCommitteeBytes {
			return FinalizedHead{}, EvidenceMalformed("anchor_body", 0, "length", len(lc.AnchorBody.SSZ), SyncCommitteeBytes)
		}
		committeeRaw = lc.AnchorBody.SSZ
	} else {
		bo, f := w.parseBootstrap(lc.AnchorBody)
		if f != nil {
			return FinalizedHead{}, f
		}
		if f := w.checkForkOfSlot(bo.Header.Beacon.Slot, bo.Shape); f != nil {
			return FinalizedHead{}, f
		}
		boot = &bo
	}
	links := make([]updateObj, len(lc.Links))
	for i, lb := range lc.Links {
		u, f := w.parseUpdate(i, lb)
		if f != nil {
			return FinalizedHead{}, f
		}
		if f := w.checkForkOfSlot(u.Attested.Beacon.Slot, u.Shape); f != nil {
			return FinalizedHead{}, f
		}
		links[i] = u
	}
	final, f := w.parseFinalityUpdate(lc.FinalUpdate)
	if f != nil {
		return FinalizedHead{}, f
	}
	if f := w.checkForkOfSlot(final.Attested.Beacon.Slot, final.Shape); f != nil {
		return FinalizedHead{}, f
	}

	// Step 2: the anchor.
	a, ok := p.anchorFor(lc.AnchorPeriod)
	if !ok {
		if head, any := p.ledgerHead(); any && lc.AnchorPeriod > head {
			return FinalizedHead{}, LedgerBehind(lc.AnchorPeriod, head)
		}
		return FinalizedHead{}, PinUnknown(lc.AnchorKind, lc.AnchorPeriod, lc.AnchorRoot)
	}
	w.anchor = a
	if lc.AnchorKind == 1 {
		c := newCommittee(committeeRaw)
		if c.root != a.CommitteeRoot {
			return FinalizedHead{}, PinMismatch(lc.AnchorPeriod, a.CommitteeRoot, c.root)
		}
		if lc.AnchorRoot != a.CommitteeRoot {
			return FinalizedHead{}, PinMismatch(lc.AnchorPeriod, a.CommitteeRoot, lc.AnchorRoot)
		}
		w.s = walkStore{finSlot: lc.AnchorPeriod * EpochsPerPeriod * SlotsPerEpoch, cur: c, curPeriod: lc.AnchorPeriod}
	} else {
		if a.BlockRoot == nil {
			return FinalizedHead{}, PinUnknown(lc.AnchorKind, lc.AnchorPeriod, lc.AnchorRoot)
		}
		if lc.AnchorRoot != *a.BlockRoot {
			return FinalizedHead{}, PinMismatch(lc.AnchorPeriod, *a.BlockRoot, lc.AnchorRoot)
		}
		slot := boot.Header.Beacon.Slot
		if periodOf(slot) != lc.AnchorPeriod {
			return FinalizedHead{}, BootstrapInvalid("anchor_period", slot)
		}
		if ok, f := w.headerValid(boot.Header); f != nil {
			return FinalizedHead{}, f
		} else if !ok {
			return FinalizedHead{}, BootstrapInvalid("header_exec_branch", slot)
		}
		if root := hashTreeRootBeaconHeader(boot.Header.Beacon); root != *a.BlockRoot {
			return FinalizedHead{}, PinMismatch(lc.AnchorPeriod, *a.BlockRoot, root)
		}
		c := newCommittee(boot.Committee)
		if !IsValidNormalizedMerkleBranch(c.root, boot.CommitteeBranch, gindicesOf(boot.Shape).current, boot.Header.Beacon.StateRoot) {
			return FinalizedHead{}, BootstrapInvalid("committee_branch", slot)
		}
		if c.root != a.CommitteeRoot {
			return FinalizedHead{}, PinMismatch(lc.AnchorPeriod, a.CommitteeRoot, c.root)
		}
		w.s = walkStore{finSlot: slot, cur: c, curPeriod: lc.AnchorPeriod}
	}

	// Step 3: every link, then the final update.
	for i := range links {
		if f := w.update(i, &links[i], false); f != nil {
			return FinalizedHead{}, f
		}
	}
	idx := len(links)
	if f := w.update(idx, &final, true); f != nil {
		return FinalizedHead{}, f
	}

	// Step 4: the result.
	return FinalizedHead{
		Slot:           final.Finalized.Beacon.Slot,
		Epoch:          epochOf(final.Finalized.Beacon.Slot),
		BeaconRoot:     hashTreeRootBeaconHeader(final.Finalized.Beacon),
		ExecHash:       final.Finalized.ExecHash,
		Participants:   final.Aggregate.count(),
		PeriodsCrossed: periodOf(final.SignatureSlot) - lc.AnchorPeriod,
	}, nil
}

// layoutLength validates the layout byte of a carried object and, for the fixed-size Gloas layout, its exact length; the
// electra layout is variable-size and is checked by its decoder (minimum size, offsets). A wrong layout byte cannot select a
// different parse that succeeds: every electra blob is longer than its Gloas twin (spec 3.2 e).
func layoutByte(part string, index int, lb LB) *Fault {
	switch lb.Layout {
	case LayoutGloas, LayoutElectra:
		return nil
	case LayoutNone:
		return EvidenceMalformed(part, index, "layout_byte_zero", 0, 1)
	}
	return EvidenceMalformed(part, index, "layout_byte_unknown", int(lb.Layout), 2)
}

func (w *walker) parseBootstrap(lb LB) (bootstrapObj, *Fault) {
	if f := layoutByte("anchor_body", 0, lb); f != nil {
		return bootstrapObj{}, f
	}
	if lb.Layout == LayoutElectra {
		return decodeElectraBootstrap(lb.SSZ)
	}
	if len(lb.SSZ) != LightClientBootstrapSize {
		return bootstrapObj{}, EvidenceMalformed("anchor_body", 0, "length", len(lb.SSZ), LightClientBootstrapSize)
	}
	return decodeBootstrap(lb.SSZ), nil
}

func (w *walker) parseUpdate(index int, lb LB) (updateObj, *Fault) {
	if f := layoutByte("link", index, lb); f != nil {
		return updateObj{}, f
	}
	if lb.Layout == LayoutElectra {
		return decodeElectraUpdate(lb.SSZ, index)
	}
	if len(lb.SSZ) != LightClientUpdateSize {
		return updateObj{}, EvidenceMalformed("link", index, "length", len(lb.SSZ), LightClientUpdateSize)
	}
	return decodeUpdate(lb.SSZ), nil
}

func (w *walker) parseFinalityUpdate(lb LB) (updateObj, *Fault) {
	if f := layoutByte("final_update", 0, lb); f != nil {
		return updateObj{}, f
	}
	if lb.Layout == LayoutElectra {
		return decodeElectraFinalityUpdate(lb.SSZ)
	}
	if len(lb.SSZ) != LightClientFinalityUpdateSize {
		return updateObj{}, EvidenceMalformed("final_update", 0, "length", len(lb.SSZ), LightClientFinalityUpdateSize)
	}
	return decodeFinalityUpdate(lb.SSZ), nil
}

// checkForkOfSlot requires the fork at the slot's epoch to carry the layout the object was parsed by (spec 3.2 b).
func (w *walker) checkForkOfSlot(slot uint64, layout Layout) *Fault {
	f, ok := w.p.Network.forkAt(epochOf(slot))
	if !ok || f.Layout != layout {
		return ForkUnsupported(slot, epochOf(slot), layout.String())
	}
	return nil
}

// headerValid is is_valid_light_client_header keyed on the fork of the header's OWN slot (spec 3.2 c). An electra-shaped
// header is hashed as ExecutionPayloadHeader and its 4-node branch is checked at gindex 25 of the body, valid only in a fork of
// the electra layout. A Gloas-shaped header is checked at gindex 2856 from the Gloas fork on, and at the Deneb gindex 812 over a
// zero-extended branch (as upgrade_lc_header_to_gloas builds it) for an Electra or Fulu header carried forward. A fork with no
// layout, and any shape/fork combination the specification has no rule for, is finality_fork_unsupported.
func (w *walker) headerValid(h lcHeader) (bool, *Fault) {
	slot := h.Beacon.Slot
	f, ok := w.p.Network.forkAt(epochOf(slot))
	if !ok {
		return false, ForkUnsupported(slot, epochOf(slot), h.Shape.String())
	}
	if h.Shape == LayoutElectra {
		if f.Layout != LayoutElectra {
			return false, ForkUnsupported(slot, epochOf(slot), h.Shape.String())
		}
		depth := floorLog2(gindexExecPayloadInBody)
		return isValidMerkleBranch(executionHeaderRoot(h.Exec), h.Branch, depth, gindexExecPayloadInBody%(uint64(1)<<uint(depth)), h.Beacon.BodyRoot), nil
	}
	var g uint64
	switch f.Layout {
	case LayoutGloas:
		g = gindexExecHashGloas
	case LayoutElectra:
		g = gindexExecHashDeneb
	default:
		return false, ForkUnsupported(slot, epochOf(slot), h.Shape.String())
	}
	return IsValidNormalizedMerkleBranch(h.ExecHash, h.Branch, g, h.Beacon.BodyRoot), nil
}

func (w *walker) enforce(label uint64, root [32]byte) *Fault {
	a, ok := w.p.anchorFor(label)
	if ok && a.CommitteeRoot != root {
		return PinMismatch(label, a.CommitteeRoot, root)
	}
	return nil
}

// update is validate_light_client_update followed by the window rule and, for a link, apply_light_client_update, with
// current_slot := the update's own signature_slot. idx is the link's index; the final update has idx == len(links).
func (w *walker) update(idx int, u *updateObj, isFinal bool) *Fault {
	as, fs, ss := u.Attested.Beacon.Slot, u.Finalized.Beacon.Slot, u.SignatureSlot
	sigPeriod := periodOf(ss)
	li := func(check string) *Fault { return LinkInvalid(idx, check, as, ss, sigPeriod) }
	gi := gindicesOf(u.Shape)

	// participation: 3n >= 2*512 (342) on every update, the final one included.
	n := u.Aggregate.count()
	if !w.r.skip(chkFloor) && (n*3 < SyncCommitteeSize*2 || n < w.p.MinParticipants) {
		return ParticipationInsufficient(idx, n, MinParticipantsFloor, SyncCommitteeSize)
	}

	if !w.r.skip(chkExecBranch) {
		if ok, f := w.headerValid(u.Attested); f != nil {
			return f
		} else if !ok {
			return li("attested_header_exec_branch")
		}
	}
	if !(ss > as && as >= fs) { // current_slot >= signature_slot holds by construction (current_slot := signature_slot)
		return li("slot_order")
	}
	storePeriod := periodOf(w.s.finSlot)
	if w.s.next != nil {
		if !w.r.skip(chkPeriodRuleNextKnown) && sigPeriod != storePeriod && sigPeriod != storePeriod+1 {
			if isFinal {
				return PeriodGap(sigPeriod, storePeriod)
			}
			return li("period_skip")
		}
	} else if !w.r.skip(chkPeriodRuleNextUnknown) && sigPeriod != storePeriod {
		if isFinal {
			return PeriodGap(sigPeriod, storePeriod)
		}
		return li("period_skip")
	}
	attestedPeriod := periodOf(as)
	isSyncUpdate := !isFinal && !branchAllZero(u.NextBranch)
	hasNextCommittee := w.s.next == nil && isSyncUpdate && attestedPeriod == storePeriod
	if !(as > w.s.finSlot || hasNextCommittee) {
		return li("not_relevant")
	}

	// finality
	if branchAllZero(u.FinalityBranch) {
		return li("not_finality")
	}
	// A final update must establish a finalized execution head: a finalized slot of 0 (the empty finalized header, whose zero
	// root a zero branch of the right shape can prove) establishes none, and is refused explicitly.
	if isFinal && fs == 0 && !w.r.skip(chkFinalNotFinality) {
		return li("not_finality")
	}
	var finalizedRoot [32]byte
	if fs == 0 {
		if !u.Finalized.isEmpty() {
			return li("finality_branch")
		}
	} else {
		if !w.r.skip(chkExecBranch) {
			if ok, f := w.headerValid(u.Finalized); f != nil {
				return f
			} else if !ok {
				return li("finalized_header_exec_branch")
			}
		}
		finalizedRoot = hashTreeRootBeaconHeader(u.Finalized.Beacon)
	}
	if !w.r.skip(chkFinalityBranch) && !IsValidNormalizedMerkleBranch(finalizedRoot, u.FinalityBranch, gi.finalized, u.Attested.Beacon.StateRoot) {
		return li("finality_branch")
	}

	// next sync committee (links only; a finality update has none)
	var learned *committee
	if !isFinal {
		if !isSyncUpdate {
			return li("not_sync_committee_update")
		}
		learned = newCommittee(u.NextCommittee)
		if !w.r.skip(chkNextMismatch) && attestedPeriod == storePeriod && w.s.next != nil && w.s.next.root != learned.root {
			return li("next_committee_mismatch")
		}
		if !w.r.skip(chkNextBranch) && !IsValidNormalizedMerkleBranch(learned.root, u.NextBranch, gi.next, u.Attested.Beacon.StateRoot) {
			return li("next_committee_branch")
		}
	}

	// signature
	signing := w.s.cur
	if sigPeriod != storePeriod {
		signing = w.s.next
	}
	if signing == nil { // the period rules above make this unreachable; a named state, never a nil committee
		if isFinal {
			return PeriodGap(sigPeriod, storePeriod)
		}
		return li("period_skip")
	}
	if isFinal && !w.r.skip(chkLedgerFinalSigner) {
		if f := w.enforce(sigPeriod, signing.root); f != nil {
			return f
		}
	}
	fk, ok := w.p.Network.forkAt(w.r.domainEpoch(as, ss))
	if !ok {
		return ForkUnsupported(ss, epochOf(ss), u.Shape.String())
	}
	version := fk.Version
	domain := computeDomain(version, w.gvr)
	msg := signingRoot(hashTreeRootBeaconHeader(u.Attested.Beacon), domain)
	if err := fastAggregateVerify(signing, u.Aggregate, msg); err != nil {
		return SignatureInvalid(idx, ss, version, n)
	}

	// weak-subjectivity window (spec 5.2 step 3, r2 F10): the finalized epoch of this update may lie at most wsp_epochs past
	// the epoch 256*period at which the signing committee's period (its ledger label) begins; for the anchor that is the
	// "previous epoch = 256*period" of step 2. Measured on the live chain: the finalized epochs of consecutive best updates
	// are up to 338 and 402 epochs apart, so a step-to-step reading refuses genuine chains (RB11-C1A finding F1).
	prevEpoch := EpochsPerPeriod * sigPeriod
	newEpoch := epochOf(fs)
	if !w.r.skip(chkWindow) && newEpoch > prevEpoch && newEpoch-prevEpoch > w.anchor.WSPEpochs {
		return PinWindow(prevEpoch, newEpoch, w.anchor.WSPEpochs)
	}
	if isFinal {
		return nil
	}

	// process_light_client_update's apply condition, then apply_light_client_update.
	updateHasFinalizedNext := w.s.next == nil && periodOf(fs) == attestedPeriod
	if !(fs > w.s.finSlot || updateHasFinalizedNext) {
		return li("not_applied")
	}
	finalizedPeriod := periodOf(fs)
	if w.s.next == nil {
		if finalizedPeriod != storePeriod {
			return li("finalized_period")
		}
		if !w.r.skip(chkLedgerFirstLearn) {
			if f := w.enforce(attestedPeriod+1, learned.root); f != nil {
				return f
			}
		}
		w.s.next = learned
	} else if finalizedPeriod == storePeriod+1 {
		if !w.r.skip(chkLedgerRotation) {
			if f := w.enforce(attestedPeriod+1, learned.root); f != nil {
				return f
			}
		}
		w.s.cur = w.s.next
		w.s.curPeriod++
		w.s.next = learned
	}
	if fs > w.s.finSlot {
		w.s.finSlot = fs
	}
	return nil
}
