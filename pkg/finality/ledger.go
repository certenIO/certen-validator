// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

// This file is the rolling Sepolia ledger of V2_SPEC_S7 4.3: one anchor per sync-committee period, each derived from its
// predecessor by a verified light-client link. The single primitive is ledgerStep (a step of the walk, judged by
// ethl1.VerifyFinalizedHead); Extend applies it to the entries an extension file appends, and VerifyLedger re-derives the
// whole ledger from its root pin (cmd/proofverify --pins-selfcheck, tools/finalitypins derive-sepolia).

// LedgerReason is the reason of finality_ledger_extension_invalid: a CLOSED set (testdata/finality/states.json).
type LedgerReason string

const (
	// LedgerNonLedgerContentDiffers: the extension changes something other than eth_sepolia.anchors.
	LedgerNonLedgerContentDiffers LedgerReason = "non_ledger_content_differs"
	// LedgerBaseNotPrefix: the base file's anchors are not a prefix of the extension's.
	LedgerBaseNotPrefix LedgerReason = "base_not_prefix"
	// LedgerPeriodNotNext: an appended entry's period is not its predecessor's plus one.
	LedgerPeriodNotNext LedgerReason = "period_not_next"
	// LedgerWspWidened: an appended entry's wsp_epochs exceeds the largest wsp_epochs of the base file.
	LedgerWspWidened LedgerReason = "wsp_widened"
	// LedgerLinkMissing: no link bytes were supplied for the appended entry's period.
	LedgerLinkMissing LedgerReason = "link_missing"
	// LedgerLinkSHA256Mismatch: the supplied link bytes do not hash to the entry's link_sha256.
	LedgerLinkSHA256Mismatch LedgerReason = "link_sha256_mismatch"
	// LedgerPredecessorUnavailable: the predecessor's committee cannot be re-established from its own link bytes.
	LedgerPredecessorUnavailable LedgerReason = "predecessor_committee_unavailable"
	// LedgerCommitteeRootMismatch: the committee the link carries does not hash to the entry's committee_root.
	LedgerCommitteeRootMismatch LedgerReason = "committee_root_mismatch"
	// LedgerLinkRefused: the light-client verifier refused the link; the inner code is in the state's `inner` field.
	LedgerLinkRefused LedgerReason = "link_refused"
	// LedgerRootPinUnverifiable: the first entry of a re-derived ledger is not a block_root pin with its bootstrap.
	LedgerRootPinUnverifiable LedgerReason = "root_pin_unverifiable"
)

// LedgerExtensionInvalid is finality_ledger_extension_invalid{period, reason[, inner]}.
func LedgerExtensionInvalid(period uint64, reason LedgerReason, kv ...any) *StateError {
	return NewState(CodeLedgerExtensionBad, append([]any{"period", period, "reason", string(reason)}, kv...)...)
}

// L1Pins converts the Sepolia section to the L1 head verifier's pins, with the given ledger entries instead of e.Anchors.
func (e *EthSepoliaPins) L1Pins(anchors []AnchorPin) ethl1.Pins {
	var out ethl1.Pins
	out.Network.ChainID = e.ChainID
	gvr, _ := hex.DecodeString(strings.TrimPrefix(e.GenesisValidatorsRoot, "0x"))
	copy(out.Network.GenesisValidatorsRoot[:], gvr)
	for _, f := range e.Forks {
		fk := ethl1.Fork{Name: f.Name, Epoch: f.Epoch}
		v, _ := hex.DecodeString(strings.TrimPrefix(f.Version, "0x"))
		copy(fk.Version[:], v)
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				fk.Layout = ethl1.LayoutElectra
			case "gloas":
				fk.Layout = ethl1.LayoutGloas
			}
		}
		out.Network.Forks = append(out.Network.Forks, fk)
	}
	for _, a := range anchors {
		an := ethl1.Anchor{Period: a.Period, WSPEpochs: a.WspEpochs}
		r, _ := hex.DecodeString(strings.TrimPrefix(a.CommitteeRoot, "0x"))
		copy(an.CommitteeRoot[:], r)
		if a.BlockRoot != "" {
			var br [32]byte
			b, _ := hex.DecodeString(strings.TrimPrefix(a.BlockRoot, "0x"))
			copy(br[:], b)
			an.BlockRoot = &br
		}
		out.Anchors = append(out.Anchors, an)
	}
	out.MinParticipants, out.MaxLinks, out.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return out
}

func rootOf(h string) [32]byte {
	var r [32]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	copy(r[:], b)
	return r
}

// L1Layout is the L1 head verifier's layout of a light-client object layout (the one conversion, shared by the Sepolia kind, the
// ledger and cmd/finalitypins).
func L1Layout(l lcssz.Layout) ethl1.Layout {
	if l == lcssz.Gloas {
		return ethl1.LayoutGloas
	}
	return ethl1.LayoutElectra
}

// LedgerStepLC builds the light-client part that judges one ledger step: the walk starts at pred (a committee_root anchor with
// the committee body predBody, or, when pred is a block_root pin, with the bootstrap in predBootstrap), applies `link` (the
// LightClientUpdate attested in pred's period that carries the next sync committee) and ends with that same update's finality
// projection, signed by the same committee. Walking the link is what makes ethl1 enforce the candidate's committee_root:
// "a committee learned from a link is labelled attested_period + 1" (5.2 step 3).
func LedgerStepLC(pred AnchorPin, predBody, predBootstrap, link []byte) (ethl1.LC, error) {
	ll := lcssz.LayoutOfUpdate(link)
	final, err := lcssz.UpdateToFinalityUpdate(ll, link)
	if err != nil {
		return ethl1.LC{}, err
	}
	lc := ethl1.LC{
		Profile: ethl1.ProfileLC, AnchorPeriod: pred.Period,
		Links:       []ethl1.LB{{Layout: L1Layout(ll), SSZ: link}},
		FinalUpdate: ethl1.LB{Layout: L1Layout(lcssz.LayoutOfFinalityUpdate(final)), SSZ: final},
	}
	if pred.BlockRoot != "" {
		lc.AnchorKind, lc.AnchorRoot = 2, rootOf(pred.BlockRoot)
		lc.AnchorBody = ethl1.LB{Layout: L1Layout(lcssz.LayoutOfBootstrap(predBootstrap)), SSZ: predBootstrap}
	} else {
		lc.AnchorKind, lc.AnchorRoot = 1, rootOf(pred.CommitteeRoot)
		lc.AnchorBody = ethl1.LB{Layout: ethl1.LayoutNone, SSZ: predBody}
	}
	return lc, nil
}

// LedgerStep verifies that `cand` is derived from `pred` by `link`: the sha256 of the link bytes is cand.link_sha256, the
// committee the link carries hashes to cand.committee_root, and ethl1 accepts the walk (signatures of the predecessor's
// committee, ≥ 342 participants, the next-committee branch, the period rules, the ledger label of the learned committee). It
// returns the learned committee's 24,624 bytes (the body the next step starts from).
func (e *EthSepoliaPins) LedgerStep(pred, cand AnchorPin, predBody, predBootstrap, link []byte) ([]byte, error) {
	if cand.Period != pred.Period+1 {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerPeriodNotNext, "predecessor_period", pred.Period)
	}
	if len(link) == 0 {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerLinkMissing)
	}
	if sum := sha256.Sum256(link); hex.EncodeToString(sum[:]) != cand.LinkSHA256 {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerLinkSHA256Mismatch, "want_sha256", rootOf("0x"+cand.LinkSHA256), "got_sha256", sum)
	}
	body, err := lcssz.NextCommittee(lcssz.LayoutOfUpdate(link), link)
	if err != nil {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerLinkRefused, "inner", CodeEvidenceMalformed)
	}
	if root, err := ethl1.HashTreeRootSyncCommittee(body); err != nil || root != rootOf(cand.CommitteeRoot) {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerCommitteeRootMismatch)
	}
	lc, err := LedgerStepLC(pred, predBody, predBootstrap, link)
	if err != nil {
		return nil, LedgerExtensionInvalid(cand.Period, LedgerLinkRefused, "inner", CodeEvidenceMalformed)
	}
	if _, err := ethl1.VerifyFinalizedHead(e.L1Pins([]AnchorPin{pred, cand}), lc); err != nil {
		inner := "unknown"
		if f, ok := err.(*ethl1.Fault); ok {
			inner = f.Code
		}
		return nil, LedgerExtensionInvalid(cand.Period, LedgerLinkRefused, "inner", inner)
	}
	return append([]byte(nil), body...), nil
}

// committeeOf re-establishes the committee body of an anchor from the bytes beside the file: the bootstrap for a block_root pin,
// the link that derived the entry otherwise. The bytes must hash to the entry's link_sha256 and the committee to its root.
func committeeOf(a AnchorPin, links map[uint64][]byte) ([]byte, error) {
	raw, ok := links[a.Period]
	if !ok {
		return nil, LedgerExtensionInvalid(a.Period, LedgerPredecessorUnavailable)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != a.LinkSHA256 {
		return nil, LedgerExtensionInvalid(a.Period, LedgerPredecessorUnavailable)
	}
	var body []byte
	var err error
	if a.BlockRoot != "" {
		body, err = lcssz.BootstrapCommittee(lcssz.LayoutOfBootstrap(raw), raw)
	} else {
		body, err = lcssz.NextCommittee(lcssz.LayoutOfUpdate(raw), raw)
	}
	if err != nil {
		return nil, LedgerExtensionInvalid(a.Period, LedgerPredecessorUnavailable)
	}
	if root, err := ethl1.HashTreeRootSyncCommittee(body); err != nil || root != rootOf(a.CommitteeRoot) {
		return nil, LedgerExtensionInvalid(a.Period, LedgerPredecessorUnavailable)
	}
	return body, nil
}

// nonLedgerEqual reports whether two pins files are identical outside eth_sepolia.anchors.
func nonLedgerEqual(a, b []byte) bool {
	strip := func(raw []byte) (map[string]any, bool) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, false
		}
		if es, ok := m["eth_sepolia"].(map[string]any); ok {
			delete(es, "anchors")
		}
		return m, true
	}
	ma, ok1 := strip(a)
	mb, ok2 := strip(b)
	return ok1 && ok2 && reflect.DeepEqual(ma, mb)
}

// Extend is V2_SPEC_S7 4.3 "Extension without a verifier release": raw is a candidate file F' and p the base F. F' extends F iff
// all non-ledger content is identical, F's anchors are a prefix of F”s, and every appended anchor is derived from its
// predecessor by the link named by its link_sha256 (links maps a period to the bytes of finality-pins-links/<period>.ssz, and
// must also hold the bytes of the predecessor of the first appended entry) and accepted by ethl1; an appended wsp_epochs may not
// exceed the largest wsp_epochs of F. The result carries pins_source "extension:<sha256 of raw>". Nothing is returned for a
// file that fails: finality_ledger_extension_invalid{period, reason} (or finality_pins_corrupt for a file that does not parse).
func (p *Pins) Extend(raw []byte, links map[uint64][]byte) (*Pins, error) {
	if p == nil || p.EthSepolia == nil {
		return nil, NewState(CodePinUnknown, "chain", ChainSepolia, "kind", "eth_sepolia")
	}
	sum := sha256.Sum256(raw)
	ext, err := parsePins(raw, sum, "extension:"+hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	if ext.EthSepolia == nil {
		return nil, LedgerExtensionInvalid(0, LedgerNonLedgerContentDiffers)
	}
	baseRaw, err := p.canonicalBytes()
	if err != nil {
		return nil, err
	}
	if !nonLedgerEqual(baseRaw, raw) {
		return nil, LedgerExtensionInvalid(0, LedgerNonLedgerContentDiffers)
	}
	base, more := p.EthSepolia.Anchors, ext.EthSepolia.Anchors
	if len(more) < len(base) {
		return nil, LedgerExtensionInvalid(0, LedgerBaseNotPrefix)
	}
	for i := range base {
		if !reflect.DeepEqual(base[i], more[i]) {
			return nil, LedgerExtensionInvalid(base[i].Period, LedgerBaseNotPrefix, "index", uint64(i))
		}
	}
	if len(more) == len(base) {
		return ext, nil
	}
	if len(base) == 0 {
		return nil, LedgerExtensionInvalid(more[0].Period, LedgerPredecessorUnavailable)
	}
	var maxWsp uint64
	for _, a := range base {
		if a.WspEpochs > maxWsp {
			maxWsp = a.WspEpochs
		}
	}
	predBody, err := committeeOf(base[len(base)-1], links)
	if err != nil {
		return nil, err
	}
	var predBootstrap []byte
	if base[len(base)-1].BlockRoot != "" {
		predBootstrap = links[base[len(base)-1].Period]
	}
	for i := len(base); i < len(more); i++ {
		cand := more[i]
		if cand.WspEpochs > maxWsp {
			return nil, LedgerExtensionInvalid(cand.Period, LedgerWspWidened, "wsp_epochs", cand.WspEpochs, "limit", maxWsp)
		}
		body, err := ext.EthSepolia.LedgerStep(more[i-1], cand, predBody, predBootstrap, links[cand.Period])
		if err != nil {
			return nil, err
		}
		predBody, predBootstrap = body, nil
	}
	return ext, nil
}

// VerifyLedger re-derives the whole ledger from its first entry, which must be a block_root pin whose bootstrap is
// links[anchors[0].Period] (the root pin of the annex), through every appended link: the offline form of
// `proofverify --pins-selfcheck`. It does I/O nowhere; the caller supplies the link bytes.
func (p *Pins) VerifyLedger(links map[uint64][]byte) error {
	if p == nil || p.EthSepolia == nil || len(p.EthSepolia.Anchors) == 0 {
		return NewState(CodePinUnknown, "chain", ChainSepolia, "kind", "eth_sepolia_ledger")
	}
	a := p.EthSepolia.Anchors
	if a[0].BlockRoot == "" {
		return LedgerExtensionInvalid(a[0].Period, LedgerRootPinUnverifiable)
	}
	body, err := committeeOf(a[0], links)
	if err != nil {
		return LedgerExtensionInvalid(a[0].Period, LedgerRootPinUnverifiable)
	}
	boot := links[a[0].Period]
	for i := 1; i < len(a); i++ {
		next, err := p.EthSepolia.LedgerStep(a[i-1], a[i], body, boot, links[a[i].Period])
		if err != nil {
			return err
		}
		body, boot = next, nil
	}
	return nil
}

// canonicalBytes returns the raw bytes this Pins was loaded from, which Extend compares non-ledger content against.
func (p *Pins) canonicalBytes() ([]byte, error) {
	if p.raw == nil {
		return nil, PinsCorrupt(PinsBadValue, "key", "raw")
	}
	return p.raw, nil
}
