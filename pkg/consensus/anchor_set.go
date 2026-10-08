package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// CERTEN's anchor set as consensus state (rules v14, RB4-F35).
//
// # WHY A TRANSACTION
//
// A ValidatorBlock's chain targets name the anchor contract each leg settles on. Admission (declared_anchor.go,
// RB4-F9) refuses a leg that declares any anchor but its chain's live one - but admission runs on the proposer, before
// signing, against the node's own environment (CERTEN_ANCHOR_V8_<chainId>). Nothing in consensus checked it: a
// proposer that skipped admission, or one misconfigured node, could commit a block naming any address. A consensus rule
// cannot read per-node environment without forking on one misconfigured node, so the anchors become chain state, like
// the BLS registry: authorised by the admin quorum in force, recorded at a height, and judged against in FinalizeBlock
// from the next height on every node identically.
//
// # WHAT MAKES IT SAFE
//
//   - The admin quorum in force for the block (AdminSetAt) authorises it, by distinct keys, over the chain id, the
//     version and every anchor, under a length-prefixed encoding nothing else shares.
//   - It names at least one settlement chain of the catalogue (pkg/supportedchains), each at most once, each with a
//     non-zero address. It does NOT have to name every catalogued chain: a chain with no committed anchor is refused by
//     name when a ValidatorBlock targets it (ANCHOR_NOT_COMMITTED), so adding a chain to the catalogue never invalidates
//     a committed set or the rule of an older binary - a chain joins through a later anchor-set version, not a new rules
//     version.
//   - Versions are strictly sequential, so a set cannot be replayed, skipped or reordered.
//
// # THE V14 ACTIVATION
//
// The first anchor set the chain accepts is the v14 activation: from the next height every ValidatorBlock is judged by
// v14's two rules - each chain target names its chain's committed anchor (judgeAnchors), and a cost ceiling that touches
// a chain the epoch does not price is refused (ENTITLEMENT_UNPRICED). Before it, the chain's committed state holds no
// anchor set, every block is decided exactly as v13 decided it, and that is what lets v14 continue v13 history without
// a reset. The window is not silent: until the set is committed, no v14 proposer admits any intent at all
// (CheckAnchorSetAdmission refuses it by name, ErrAnchorSetNotCommitted, and the intent is retried), and the deploy
// commits the set right after the fleet runs v14 (docs/runbooks/rules-v14-ceiling-anchor-set.md).

// AnchorSetKind identifies an anchor-set transaction on the wire.
const AnchorSetKind = "certen.anchorset.set/v1"

// codeAnchorSetRefused is the result code of a refused anchor-set transaction.
const codeAnchorSetRefused uint32 = 16

// codeAnchorNotCommitted is the result code of a ValidatorBlock refused because a chain target names an anchor other
// than its chain's committed one (rules v14).
const codeAnchorNotCommitted uint32 = 17

// ReasonAnchorNotCommitted names that refusal in logs and tools.
const ReasonAnchorNotCommitted = "ANCHOR_NOT_COMMITTED"

// ErrAnchorSetNotCommitted is an intent a v14 proposer will not admit because the chain has no anchor set in force: the
// v14 activation has not happened. Retried, never held against the intent.
var ErrAnchorSetNotCommitted = errors.New("ANCHOR_SET_NOT_COMMITTED: the chain has no anchor set in force")

// ErrAnchorNotCommitted is a chain target, or a configured anchor, that is not its chain's committed anchor.
var ErrAnchorNotCommitted = errors.New(ReasonAnchorNotCommitted)

// AnchorSetTx sets CERTEN's anchor set.
type AnchorSetTx struct {
	Kind    string                  `json:"kind"`
	ChainID string                  `json:"chain_id"`
	Version uint64                  `json:"version"`
	Anchors []ledger.AnchorSetEntry `json:"anchors"`
	// Signatures are the admin signatures over SigningBytes.
	Signatures []PolicySignature `json:"signatures,omitempty"`
}

// canonicalAnchors is the anchors in chain-id order, each address EIP-55 checksummed. Only for a set that passed
// CheckShape.
func (t *AnchorSetTx) canonicalAnchors() []ledger.AnchorSetEntry {
	out := make([]ledger.AnchorSetEntry, len(t.Anchors))
	for i, a := range t.Anchors {
		out[i] = ledger.AnchorSetEntry{ChainID: a.ChainID, Anchor: common.HexToAddress(a.Anchor).Hex()}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChainID < out[j].ChainID })
	return out
}

// SigningBytes is what the admins sign: sha256 over the kind, the chain, the version, the number of anchors and, in
// chain-id order, each chain id with its anchor in lowercase hex - every field length-prefixed.
func (t *AnchorSetTx) SigningBytes() []byte {
	fields := []string{AnchorSetKind, t.ChainID, strconv.FormatUint(t.Version, 10), strconv.Itoa(len(t.Anchors))}
	anchors := append([]ledger.AnchorSetEntry(nil), t.Anchors...)
	sort.SliceStable(anchors, func(i, j int) bool { return anchors[i].ChainID < anchors[j].ChainID })
	for _, a := range anchors {
		fields = append(fields, strconv.FormatInt(a.ChainID, 10), strings.ToLower(strings.TrimSpace(a.Anchor)))
	}
	sum := sha256.Sum256(lengthPrefixed(fields...))
	return sum[:]
}

// AnchorSetID is what an accepted anchor set contributes to the app hash and records.
func (t *AnchorSetTx) AnchorSetID() string {
	return "anchor-set:" + hex.EncodeToString(t.SigningBytes())
}

// DecodeAnchorSet returns the transaction if these bytes are one. The discriminator is the explicit kind; bytes of the
// kind that do not decode are still the kind, refused by CheckShape, never judged as a ValidatorBlock.
func DecodeAnchorSet(tx []byte) (*AnchorSetTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != AnchorSetKind {
		return nil, false
	}
	var t AnchorSetTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &AnchorSetTx{Kind: AnchorSetKind}, true
	}
	return &t, true
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except the chain,
// the version and the admin quorum.
func (t *AnchorSetTx) CheckShape() error {
	if t.Kind != AnchorSetKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, AnchorSetKind)
	}
	if strings.TrimSpace(t.ChainID) == "" || t.Version == 0 {
		return fmt.Errorf("an anchor set names its chain and a version above zero")
	}
	if len(t.Anchors) == 0 {
		return fmt.Errorf("an anchor set names at least one settlement chain (%s)", supportedchains.Describe())
	}
	seen := map[int64]bool{}
	for _, a := range t.Anchors {
		c, ok := supportedchains.Lookup(a.ChainID)
		if !ok {
			return fmt.Errorf("chain %d is not a settlement chain of the catalogue (%s)", a.ChainID, supportedchains.Describe())
		}
		if seen[a.ChainID] {
			return fmt.Errorf("%s (%d) is named twice", c.Name, a.ChainID)
		}
		seen[a.ChainID] = true
		addr := strings.TrimSpace(a.Anchor)
		if addr != a.Anchor || !strings.HasPrefix(addr, "0x") || !common.IsHexAddress(addr) || common.HexToAddress(addr) == (common.Address{}) {
			return fmt.Errorf("%s (%d): %q is not a non-zero 0x EVM address", c.Name, a.ChainID, a.Anchor)
		}
	}
	return nil
}

// highestAnchorSetVersion is the newest accepted version (zero before any).
func highestAnchorSetVersion(log *ledger.AnchorSetLog) uint64 {
	if log == nil || len(log.Versions) == 0 {
		return 0
	}
	return log.Versions[len(log.Versions)-1].Version
}

// AnchorSetAt is the anchor set in force for a block at height h: the newest version accepted below h. Nil when none was
// - the chain has not reached the v14 activation.
func AnchorSetAt(log *ledger.AnchorSetLog, h int64) *ledger.AnchorSetRecord {
	if log == nil {
		return nil
	}
	for i := len(log.Versions) - 1; i >= 0; i-- {
		if log.Versions[i].Height < h {
			return &log.Versions[i]
		}
	}
	return nil
}

// VerifyAnchorSet judges an anchor-set transaction for a block at height h against committed state - the policy, whose
// admin set in force at h (AdminSetAt) must authorise it, and the anchor sets accepted before it - and returns the
// record it sets.
func VerifyAnchorSet(t *AnchorSetTx, chainID string, policy *ledger.EntitlementPolicyState, log *ledger.AnchorSetLog,
	h int64) (*ledger.AnchorSetRecord, error) {
	policy = withAdminSetAt(policy, h)
	if err := t.CheckShape(); err != nil {
		return nil, err
	}
	if t.ChainID != chainID {
		return nil, fmt.Errorf("the anchor set is for chain %q, this is %q", t.ChainID, chainID)
	}
	if want := highestAnchorSetVersion(log) + 1; t.Version != want {
		return nil, fmt.Errorf("version %d is not the next anchor-set version %d (an anchor set cannot be replayed, "+
			"skipped or reordered)", t.Version, want)
	}
	if err := verifyAdminQuorum(t.SigningBytes(), t.Signatures, policy, "anchor set", "no anchor set can be set"); err != nil {
		return nil, err
	}
	return &ledger.AnchorSetRecord{Version: t.Version, Height: h, Anchors: t.canonicalAnchors(), ID: t.AnchorSetID()}, nil
}

// CommittedAnchorOf is a chain's anchor in an anchor set, or false when the set names none for it.
func CommittedAnchorOf(set *ledger.AnchorSetRecord, chainID int64) (common.Address, bool) {
	if set == nil {
		return common.Address{}, false
	}
	for _, a := range set.Anchors {
		if a.ChainID == chainID {
			return common.HexToAddress(a.Anchor), true
		}
	}
	return common.Address{}, false
}

// CheckChainTargetAnchors is the v14 rule for a ValidatorBlock under the anchor set in force: every chain target names
// a chain the set covers, and that chain's committed anchor - as a 0x EVM address, compared as an address, never as
// text. A block with no chain targets settles nothing and has no anchor to check.
func CheckChainTargetAnchors(vb *ValidatorBlock, set *ledger.AnchorSetRecord) error {
	if set == nil {
		return fmt.Errorf("%w: no anchor set is in force", ErrAnchorNotCommitted)
	}
	for i, ct := range vb.CrossChainProof.ChainTargets {
		want, ok := CommittedAnchorOf(set, ct.ChainID)
		if !ok {
			return fmt.Errorf("%w: chain target %d names chain %d, for which anchor set v%d commits no anchor",
				ErrAnchorNotCommitted, i, ct.ChainID, set.Version)
		}
		addr := strings.TrimSpace(ct.ContractAddress)
		if !strings.HasPrefix(addr, "0x") || !common.IsHexAddress(addr) {
			return fmt.Errorf("%w: chain target %d (chain %d) names %q, which is not an anchor address; anchor set v%d "+
				"commits %s", ErrAnchorNotCommitted, i, ct.ChainID, ct.ContractAddress, set.Version, want.Hex())
		}
		if got := common.HexToAddress(addr); got != want {
			return fmt.Errorf("%w: chain target %d (chain %d) names anchor %s; anchor set v%d commits %s",
				ErrAnchorNotCommitted, i, ct.ChainID, got.Hex(), set.Version, want.Hex())
		}
	}
	return nil
}

// AnchorSetSource is the committed anchor set a proposer admits intents against: the set in force for the next block,
// nil when none is recorded.
type AnchorSetSource interface {
	AnchorSetContext() (*ledger.AnchorSetRecord, error)
}

// CheckAnchorSetAdmission is the proposer's half of the v14 anchor rule, run before anything is signed: the chain must
// have an anchor set in force, and every chain the intent settles on must settle on its committed anchor - the anchor
// this node's batch path will call (anchorOf, CERTEN_ANCHOR_V8_<chainId>). Either failing is CERTEN's state, not the
// intent's: the error wraps ErrBatchUnavailable, so the intent is retried and never held against it. A node whose
// configured anchor is not the committed one says so by name instead of building a block every peer refuses.
func CheckAnchorSetAdmission(chains []int64, src AnchorSetSource, anchorOf func(chainID int64) (common.Address, error)) error {
	if src == nil {
		return fmt.Errorf("%w: %w: no anchor-set source is wired, so whether one is in force is not known", ErrBatchUnavailable,
			ErrAnchorSetNotCommitted)
	}
	set, err := src.AnchorSetContext()
	if err != nil {
		return fmt.Errorf("%w: the committed anchor set could not be read: %v", ErrBatchUnavailable, err)
	}
	if set == nil {
		return fmt.Errorf("%w: %w (the v14 activation): no intent is admitted until the admin quorum commits one "+
			"(validator-rotate anchor-set)", ErrBatchUnavailable, ErrAnchorSetNotCommitted)
	}
	for _, ch := range chains {
		want, ok := CommittedAnchorOf(set, ch)
		if !ok {
			return fmt.Errorf("%w: %w: anchor set v%d commits no anchor for chain %d", ErrBatchUnavailable, ErrAnchorNotCommitted,
				set.Version, ch)
		}
		have, err := anchorOf(ch)
		if err != nil {
			return fmt.Errorf("%w: chain %d's configured anchor cannot be named: %v", ErrBatchUnavailable, ch, err)
		}
		if have != want {
			return fmt.Errorf("%w: %w: this node settles chain %d on %s (CERTEN_ANCHOR_V8_%d), but anchor set v%d commits %s",
				ErrBatchUnavailable, ErrAnchorNotCommitted, ch, have.Hex(), ch, set.Version, want.Hex())
		}
	}
	return nil
}
