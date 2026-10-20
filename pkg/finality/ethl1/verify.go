// Copyright 2026 Certen Protocol

package ethl1

import (
	"encoding/binary"
)

// quirks are deliberately wrong variants of the verifier. The exported API never sets them; the mutation tests set one
// at a time and require the matching adversarial vector to change verdict, which proves the vector exercises the rule.
type quirks struct {
	dropFloor           bool // accept any update with at least one participant (the Altair validate-only rule)
	attestedEpochDomain bool // take the signing-domain fork version from the attested header's epoch (go-ethereum beacon/light)
	skipLedgerLearned   bool // do not hold learned and final-signing committees to their ledger entries
	skipWindow          bool // do not apply the weak-subjectivity window rule
	skipFinalityBranch  bool
	skipNextBranch      bool
}

// VerifyFinalizedHead is spec section 5.2 steps 1-4: it establishes, from the pins and the LC part alone, a finalized
// beacon head and its finalized execution block hash. It returns a *Fault for every other outcome and never a weaker
// answer. current_slot is each update's own signature_slot; process_light_client_store_force_update is never called.
func VerifyFinalizedHead(p Pins, lc LC) (FinalizedHead, error) {
	h, f := verifyFinalizedHead(p, lc, quirks{})
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

// Electra-layout minimum sizes by SSZ arithmetic (spec section 3.2 e): every Electra blob is longer than its Gloas twin.
const (
	electraMinUpdate          = 26872
	electraMinBootstrap       = 25648
	electraMinFinalityUpdate  = 2056
	electraFirstOffsetMinimum = 4
)

type walkStore struct {
	finSlot   uint64
	cur       *committee
	next      *committee // nil while unknown
	curPeriod uint64     // label of cur, for reports
}

type walker struct {
	p Pins
	q quirks
	s walkStore

	anchor Anchor
	gvr    [32]byte
}

func verifyFinalizedHead(p Pins, lc LC, q quirks) (FinalizedHead, *Fault) {
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
	w := &walker{p: p, q: q, gvr: p.Network.GenesisValidatorsRoot}

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
		if f := w.checkLayout("anchor_body", 0, lc.AnchorBody, LightClientBootstrapSize, electraMinBootstrap); f != nil {
			return FinalizedHead{}, f
		}
		b := decodeBootstrap(lc.AnchorBody.SSZ)
		if f := w.checkForkOfSlot(b.Header.Beacon.Slot, LayoutGloas); f != nil {
			return FinalizedHead{}, f
		}
		boot = &b
	}
	links := make([]updateObj, len(lc.Links))
	for i, lb := range lc.Links {
		if f := w.checkLayout("link", i, lb, LightClientUpdateSize, electraMinUpdate); f != nil {
			return FinalizedHead{}, f
		}
		links[i] = decodeUpdate(lb.SSZ)
		if f := w.checkForkOfSlot(links[i].Attested.Beacon.Slot, LayoutGloas); f != nil {
			return FinalizedHead{}, f
		}
	}
	if f := w.checkLayout("final_update", 0, lc.FinalUpdate, LightClientFinalityUpdateSize, electraMinFinalityUpdate); f != nil {
		return FinalizedHead{}, f
	}
	final := decodeFinalityUpdate(lc.FinalUpdate.SSZ)
	if f := w.checkForkOfSlot(final.Attested.Beacon.Slot, LayoutGloas); f != nil {
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
		if !IsValidNormalizedMerkleBranch(c.root, boot.CommitteeBranch, gindexCurrentCommitteeGlo, boot.Header.Beacon.StateRoot) {
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

// checkLayout validates the layout byte and the blob length. A Gloas blob must have exactly want bytes. An Electra blob is
// recognised (its minimum size and first offset are checked, its attested slot read) and refused as finality_fork_unsupported
// until the electra layout is implemented; that is a named state with the spec's field list, not a skipped check.
func (w *walker) checkLayout(part string, index int, lb LB, want, electraMin int) *Fault {
	switch lb.Layout {
	case LayoutGloas:
		if len(lb.SSZ) != want {
			return EvidenceMalformed(part, index, "length", len(lb.SSZ), want)
		}
		return nil
	case LayoutElectra:
		if len(lb.SSZ) < electraMin {
			return EvidenceMalformed(part, index, "length", len(lb.SSZ), electraMin)
		}
		off := int(binary.LittleEndian.Uint32(lb.SSZ[0:4]))
		if off < electraFirstOffsetMinimum || off+8 > len(lb.SSZ) {
			return EvidenceMalformed(part, index, "offset", off, len(lb.SSZ))
		}
		slot := binary.LittleEndian.Uint64(lb.SSZ[off : off+8])
		return ForkUnsupported(slot, epochOf(slot), LayoutElectra.String())
	case LayoutNone:
		return EvidenceMalformed(part, index, "layout_byte_zero", 0, 1)
	}
	return EvidenceMalformed(part, index, "layout_byte_unknown", int(lb.Layout), 2)
}

// checkForkOfSlot requires the fork at the slot's epoch to carry the layout the object was parsed by (spec 3.2 b).
func (w *walker) checkForkOfSlot(slot uint64, layout Layout) *Fault {
	f, ok := w.p.Network.forkAt(epochOf(slot))
	if !ok || f.Layout != layout {
		return ForkUnsupported(slot, epochOf(slot), layout.String())
	}
	return nil
}

// headerValid is is_valid_light_client_header for a Gloas-shaped header, keyed on the fork of the header's own slot: the
// Gloas gindex 2856 from the Gloas fork, and the Deneb gindex 812 (over a zero-extended branch, as upgrade_lc_header_to_gloas
// builds it) for an Electra or Fulu header. A fork with no layout has no rule here and is finality_fork_unsupported.
func (w *walker) headerValid(h lcHeader) (bool, *Fault) {
	slot := h.Beacon.Slot
	f, ok := w.p.Network.forkAt(epochOf(slot))
	if !ok {
		return false, ForkUnsupported(slot, epochOf(slot), LayoutGloas.String())
	}
	var g uint64
	switch f.Layout {
	case LayoutGloas:
		g = gindexExecHashGloas
	case LayoutElectra:
		g = gindexExecHashDeneb
	default:
		return false, ForkUnsupported(slot, epochOf(slot), LayoutGloas.String())
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

	// participation: 3n >= 2*512 (342) on every update, the final one included.
	n := u.Aggregate.count()
	if w.q.dropFloor {
		if n < 1 {
			return ParticipationInsufficient(idx, n, 1, SyncCommitteeSize)
		}
	} else if n*3 < SyncCommitteeSize*2 || n < w.p.MinParticipants {
		return ParticipationInsufficient(idx, n, MinParticipantsFloor, SyncCommitteeSize)
	}

	if ok, f := w.headerValid(u.Attested); f != nil {
		return f
	} else if !ok {
		return li("attested_header_exec_branch")
	}
	if !(ss > as && as >= fs) { // current_slot >= signature_slot holds by construction (current_slot := signature_slot)
		return li("slot_order")
	}
	storePeriod := periodOf(w.s.finSlot)
	if w.s.next != nil {
		if sigPeriod != storePeriod && sigPeriod != storePeriod+1 {
			if isFinal {
				return PeriodGap(sigPeriod, storePeriod)
			}
			return li("period_skip")
		}
	} else if sigPeriod != storePeriod {
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
	var finalizedRoot [32]byte
	if fs == 0 {
		if !u.Finalized.isEmpty() {
			return li("finality_branch")
		}
	} else {
		if ok, f := w.headerValid(u.Finalized); f != nil {
			return f
		} else if !ok {
			return li("finalized_header_exec_branch")
		}
		finalizedRoot = hashTreeRootBeaconHeader(u.Finalized.Beacon)
	}
	if !w.q.skipFinalityBranch && !IsValidNormalizedMerkleBranch(finalizedRoot, u.FinalityBranch, gindexFinalizedRootGloas, u.Attested.Beacon.StateRoot) {
		return li("finality_branch")
	}

	// next sync committee (links only; a finality update has none)
	var learned *committee
	if !isFinal {
		if !isSyncUpdate {
			return li("not_sync_committee_update")
		}
		learned = newCommittee(u.NextCommittee)
		if attestedPeriod == storePeriod && w.s.next != nil && w.s.next.root != learned.root {
			return li("next_committee_mismatch")
		}
		if !w.q.skipNextBranch && !IsValidNormalizedMerkleBranch(learned.root, u.NextBranch, gindexNextCommitteeGloas, u.Attested.Beacon.StateRoot) {
			return li("next_committee_branch")
		}
	}

	// signature
	signing := w.s.cur
	if sigPeriod != storePeriod {
		signing = w.s.next
	}
	if isFinal && !w.q.skipLedgerLearned {
		if f := w.enforce(sigPeriod, signing.root); f != nil {
			return f
		}
	}
	var version [4]byte
	var versionEpoch uint64
	if w.q.attestedEpochDomain {
		versionEpoch = epochOf(as)
	} else {
		var base uint64
		if ss > 0 {
			base = ss - 1
		}
		versionEpoch = epochOf(base)
	}
	fk, ok := w.p.Network.forkAt(versionEpoch)
	if !ok {
		return ForkUnsupported(ss, epochOf(ss), LayoutGloas.String())
	}
	version = fk.Version
	domain := computeDomain(version, w.gvr)
	msg := signingRoot(hashTreeRootBeaconHeader(u.Attested.Beacon), domain)
	if err := fastAggregateVerify(signing, u.Aggregate, msg); err != nil {
		return SignatureInvalid(idx, ss, version, n)
	}

	// weak-subjectivity window (spec 5.2 step 3): the finalized epoch of this update may lie at most wsp_epochs past the epoch
	// 256*period at which the signing committee's period (its ledger label, "period labels") begins; for the anchor that is the
	// "previous epoch = 256*period" of step 2. Measured on the live chain: the finalized epochs of consecutive best updates
	// are up to 338 and 402 epochs apart (periods 1388-1389 and 1389-final), so a step-to-step reading of the rule refuses
	// genuine chains; see the RB11-C1A check-in (FINDING: window rule reading).
	prevEpoch := EpochsPerPeriod * sigPeriod
	newEpoch := epochOf(fs)
	if !w.q.skipWindow && newEpoch > prevEpoch && newEpoch-prevEpoch > w.anchor.WSPEpochs {
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
		if !w.q.skipLedgerLearned {
			if f := w.enforce(attestedPeriod+1, learned.root); f != nil {
				return f
			}
		}
		w.s.next = learned
	} else if finalizedPeriod == storePeriod+1 {
		if !w.q.skipLedgerLearned {
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
