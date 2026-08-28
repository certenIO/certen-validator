// Copyright 2026 Certen Protocol
//
// The Accumulate validator set, DERIVED rather than ASSERTED.
//
// # THE DEFECT
//
// L4 verifies quorum signatures for real — ed25519 over the derived digest, the
// signer must be in the validator set and active on the signing partition, the
// threshold is recomputed from the network's own AcceptThreshold, and the quorum
// is counted over distinct signers. None of that is a stub.
//
// And then layer4.go:255 sets `ValidatorSet: ni.Validators`, where `ni` came
// from a JSON-RPC "network-status" call at BUILD TIME (layer4.go:421). So
// offline verification proves the signatures are consistent with THE SET THE
// PROOF CARRIES. A forged proof carrying a fabricated set, signed by that set's
// own keys, passes every check.
//
// This type closes that by carrying the evidence to DERIVE the set from chain
// state: the account bytes of acc://dn.acme/network, the BPT membership path
// proving them into a root, and the chain roots proving the account's own
// history length at that root. A verifier recomputes the set and refuses the leg
// if the asserted set differs.
//
// # WHAT IT DOES NOT DO — READ THIS BEFORE TRUSTING IT
//
// Deriving the set is NOT sufficient on its own, and an implementation that
// treats it as sufficient has reintroduced the original defect one level up.
//
// The set authenticates the anchor (L4's signature checks) and the anchor
// authenticates the set (Verify's step 15). That is a CLOSED LOOP. An adversary
// who fabricates an entire consistent chain — account state, BPT root, anchor,
// signatures under their own keys — satisfies every check in this file, because
// verification is offline by design and there is nothing to contradict them.
//
// What this buys is that the loop can be BROKEN at a point the verifier pinned
// OUT OF BAND: the incarnation identity. Verify therefore takes a pinned
// incarnation and returns a strictly WEAKER verdict when it does not have one.
// Never collapse VerdictIncarnationUnverified into VerdictVerified.
//
// # WHERE THIS LIVES, AND WHY
//
// BESIDE the hashed summary, never inside it. L4LegSummary is hashed into
// govRoot (healing_proof.go:160), so widening it would move every govRoot ever
// signed — the trap timing_evidence.go documents and TestP6_CanonicalShapesUnchanged
// blocks. This type is not reachable from any canonical hash; the govRoot
// preimage is byte-identical with or without it.
//
// The on-chain counterpart is CertenAnchorV8_2's pre-exec message, which commits
// AccumulateValidatorSetRoot and Incarnation. This type is the EXPANSION of that
// commitment: a committed root nobody can expand is decoration that looks like
// coverage.
package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// Verdict is the outcome of verifying a ValidatorSetProof. The weaker states are
// modelled on summary_only: a claim that could not be checked must never wear
// the name of one that was.
type Verdict string

const (
	// VerdictVerified — the set was derived from chain state, bound to a
	// quorum-signed anchor, and the incarnation matched a pinned value.
	VerdictVerified Verdict = "verified"

	// VerdictValidatorSetAsserted — no ValidatorSetProof was carried. The quorum
	// was checked; the SET it was checked against is asserted. Every proof
	// issued before this type existed is in this state. NOT an error.
	VerdictValidatorSetAsserted Verdict = "validator_set_asserted"

	// VerdictValidatorSetUnbound — the set was DERIVED from chain bytes, but the
	// BPT root it was proven into could not be tied to a quorum-signed anchor.
	//
	// This is the normal state today, not an anomaly, and it is a CAPABILITY
	// LIMIT rather than a fault in the proof. Measured 2026-08-28: an account
	// query returns a receipt against the node's CURRENT BPT root, and those
	// roots are recorded on anchor(<partition>)-bpt only at anchor-emission
	// points — one per ~46 blocks on Kermit and one per ~2,524 on MainNet. A
	// freshly fetched root is therefore almost never one of the anchored ones
	// (checked against the 300 most recent: no match), and obtaining the state
	// at a root that IS anchored requires the historical membership proof
	// AIP-058 asks for and Accumulate does not serve.
	//
	// So this verdict says exactly what is true: the set is no longer asserted,
	// and it is not yet bound. Reporting it as a failure would be the
	// capability-limit-as-governance-rejection defect this codebase has removed
	// twice.
	VerdictValidatorSetUnbound Verdict = "validator_set_unbound"

	// VerdictIncarnationUnknown — the artifact carries no incarnation, so it
	// cannot say which chain it is about. A could-not-read, not a refusal.
	VerdictIncarnationUnknown Verdict = "incarnation_unknown"

	// VerdictIncarnationUnverified — the artifact names an incarnation but the
	// verifier holds no pinned value to check it against. The derivation is
	// internally consistent and circular; see the package comment. STRICTLY
	// WEAKER than verified.
	VerdictIncarnationUnverified Verdict = "incarnation_unverified"

	// VerdictForeignIncarnation — the artifact belongs to a different
	// incarnation than the verifier pinned. Proven different, not unreadable.
	VerdictForeignIncarnation Verdict = "foreign_incarnation"
)

// Weaker reports whether the verdict is something less than a full verification.
// Callers must not print these as "verified".
func (v Verdict) Weaker() bool { return v != VerdictVerified }

// ChainRoot is one of an account's chains, as the state hasher sees it.
//
// Count and Anchor are RESTATED FOR READABILITY and are not trusted: both are
// recomputed from Pending, and Verify refuses on any disagreement. This is the
// same discipline layer4_types.go applies to its restated anchor fields, and it
// exists here because of a defect a tampering test caught: with Count carried as
// a free field, inflating or — far worse — DEFLATING it went undetected, since
// the chains component is built from the anchor alone. A deflated Count would
// make an account whose validator set had changed several times look like it
// still held its genesis set.
type ChainRoot struct {
	Name string `json:"name"`

	// Pending is the chain's merkle State.Pending list, exactly as the v3 chain
	// query returns it: a sparse list whose non-nil entries are the binary
	// representation of the chain height, and whose fold is the chain's DAG root.
	// Both facts below are derived from it, so lying about either requires a
	// hash collision rather than an edited field.
	Pending []*string `json:"pending"`

	// Count is the chain height. RECOMPUTED from Pending. For
	// acc://dn.acme/network's main chain, 1 means only the genesis entry exists,
	// so the validator set has NEVER changed.
	Count uint64 `json:"count"`

	// Anchor is the chain's merkle DAG root, or 32 zero bytes when Count is 0.
	// RECOMPUTED from Pending.
	Anchor string `json:"anchor"` // hex32
}

// derive recomputes (count, anchor) from Pending and rejects any disagreement
// with the restated values.
func (c *ChainRoot) derive() (uint64, []byte, error) {
	var count uint64
	var anchor []byte
	for i, v := range c.Pending {
		if v == nil {
			continue
		}
		count |= 1 << uint(i)
		h, err := hexBytes(*v, "chain pending entry")
		if err != nil || len(h) != 32 {
			return 0, nil, fmt.Errorf("chain %q: pending[%d] must be 32 bytes of hex", c.Name, i)
		}
		if anchor == nil {
			anchor = h
			continue
		}
		d := sha256.Sum256(append(append([]byte{}, h...), anchor...))
		anchor = d[:]
	}
	if anchor == nil {
		anchor = make([]byte, 32)
	}
	if count != c.Count {
		return 0, nil, fmt.Errorf("chain %q: restated count %d but its merkle state says %d "+
			"— the height is not what the proof claims", c.Name, c.Count, count)
	}
	if got := hex.EncodeToString(anchor); count > 0 && got != strings.ToLower(strings.TrimPrefix(c.Anchor, "0x")) {
		return 0, nil, fmt.Errorf("chain %q: restated anchor does not match its merkle state: "+
			"computed=%s restated=%s", c.Name, got[:16], c.Anchor[:16])
	}
	return count, anchor, nil
}

// AccountStateProof proves one account's bytes into a BPT root, with enough of
// the state hasher's components that the account's own chain history is bound
// rather than asserted.
type AccountStateProof struct {
	AccountURL string `json:"accountUrl"`

	// AccountState is the canonical binary encoding of the account, hex.
	// sha256(AccountState) IS the BPT leaf preimage — "a simple hash of the main
	// state", observer_prod.go:31.
	AccountState string `json:"accountState"`

	// StateReceipt proves that leaf into a BPT root.
	StateReceipt chained_proof.Receipt `json:"stateReceipt"`

	// Chains are the account's chains in the order the state hasher walks them.
	Chains []ChainRoot `json:"chains"`

	// SecondaryHash and PendingHash are the state hasher's second and fourth
	// elements.
	//
	// They are here because of a defect found in adversarial review. The state
	// hasher is [main, secondaryState, chains, pending] (observer_prod.go:28-35),
	// so a receipt from element 0 to the root of that four-leaf tree has TWO
	// steps: the sibling secondaryState, then the sibling H(chains || pending).
	// The chains component is NEVER a sibling on its own. Without both of these
	// the chain-height binding cannot be recomputed and MainChainHeight would be
	// an unverifiable number in a struct. An earlier draft omitted them and
	// would have compiled, passed tests, and silently proved nothing.
	SecondaryHash string `json:"secondaryHash"` // hex32
	PendingHash   string `json:"pendingHash"`   // hex32
}

// ValidatorSetProof derives Layer4.ValidatorSet from chain state.
//
// It proves TWO accounts, because the set and the threshold live in different
// ones. Carrying the threshold as an assertion beside a derived membership would
// leave exactly the defect this exists to remove: a commitment to who signed
// without a commitment to how many were required cannot tell a real quorum from
// three arbitrary keys.
type ValidatorSetProof struct {
	// Incarnation is the genesis root anchor of the Accumulate chain this proof
	// is about — anchor(directory)-root[0]. Nothing in an L4 leg identifies its
	// chain: the signed preimage is a SequencedMessage over a PartitionAnchor,
	// and every URL in it is a protocol constant identical across MainNet,
	// Kermit, and every incarnation of both.
	Incarnation string `json:"incarnation"` // hex32

	// Network is acc://dn.acme/network — the validator set.
	Network AccountStateProof `json:"network"`

	// Globals is acc://dn.acme/globals — validatorAcceptThreshold, the
	// denominator.
	Globals AccountStateProof `json:"globals"`
}

// MainChainHeight returns the height of the network account's main chain at the
// proven root, and whether a main chain was present at all.
func (p *ValidatorSetProof) MainChainHeight() (uint64, bool) {
	for _, c := range p.Network.Chains {
		if c.Name == "main" {
			return c.Count, true
		}
	}
	return 0, false
}

// DerivedSet reconstructs the validator set from the network account and the
// threshold from the globals account. Both are DERIVED; neither is asserted.
func (p *ValidatorSetProof) DerivedSet() ([]chained_proof.ValidatorKey, chained_proof.Rational, error) {
	var thr chained_proof.Rational

	netRaw, err := hexBytes(p.Network.AccountState, "network.accountState")
	if err != nil {
		return nil, thr, err
	}
	set, err := decodeValidators(netRaw)
	if err != nil {
		return nil, thr, err
	}

	globRaw, err := hexBytes(p.Globals.AccountState, "globals.accountState")
	if err != nil {
		return nil, thr, err
	}
	num, den, err := decodeAcceptThreshold(globRaw)
	if err != nil {
		return nil, thr, err
	}
	thr = chained_proof.Rational{Numerator: num, Denominator: den}
	return set, thr, nil
}

// VerifyInput is what Verify needs beyond the proof itself.
type VerifyInput struct {
	// AssertedSet is Layer4.ValidatorSet — what the proof claims. Verify refuses
	// unless the derived set equals it.
	AssertedSet []chained_proof.ValidatorKey

	// AssertedThreshold is Layer4.AcceptThreshold. Verify refuses unless the
	// threshold derived from the globals account equals it.
	AssertedThreshold chained_proof.Rational

	// BoundStateTreeAnchor is the StateTreeAnchor of a quorum-signed anchor in
	// the same proof — the Directory leg's, since both accounts live on the DN.
	// The BPT root they were proven into must equal it, or the root is unbound
	// and proves nothing about who signed.
	BoundStateTreeAnchor string // hex32

	// PinnedIncarnation is the verifier's OUT-OF-BAND value. Nil means the
	// verifier holds no pin, which yields VerdictIncarnationUnverified — never
	// VerdictVerified. See the package comment: without a pin the derivation is
	// circular.
	PinnedIncarnation *string // hex32
}

// Verify runs steps 10-17 of the L4 contract. It performs NO network access.
//
// A non-nil error means the proof is PROVEN WRONG — tampering or corruption. A
// weaker verdict with a nil error means something COULD NOT BE READ, which is
// not the same thing and must never be reported as a failure. An evidence gap is
// a capability limit, not a governance rejection.
func (p *ValidatorSetProof) Verify(in VerifyInput) (Verdict, error) {
	// --- 10. an absent proof is a named state, NOT an error -----------------
	if p == nil || p.Network.AccountState == "" || len(p.Network.StateReceipt.Entries) == 0 {
		return VerdictValidatorSetAsserted, nil
	}
	if p.Globals.AccountState == "" || len(p.Globals.StateReceipt.Entries) == 0 {
		// Membership without the denominator is the defect, not a partial win.
		return VerdictValidatorSetAsserted, nil
	}

	// --- 11-13. both accounts: leaf, path, and chain binding ----------------
	netAnchor, err := p.Network.verify()
	if err != nil {
		return "", fmt.Errorf("validatorSetProof.network: %w", err)
	}
	globAnchor, err := p.Globals.verify()
	if err != nil {
		return "", fmt.Errorf("validatorSetProof.globals: %w", err)
	}
	if netAnchor != globAnchor {
		return "", fmt.Errorf("validatorSetProof: the two accounts are proven into different BPT "+
			"roots (network=%s globals=%s); they must be read at the same block, or the set and "+
			"the threshold need never have coexisted", netAnchor[:16], globAnchor[:16])
	}

	// --- 14. THE STEP THAT CLOSES THE GAP -----------------------------------
	derived, thr, err := p.DerivedSet()
	if err != nil {
		return "", fmt.Errorf("validatorSetProof: %w", err)
	}
	if err := sameValidatorSet(derived, in.AssertedSet); err != nil {
		return "", fmt.Errorf("validatorSetProof: the asserted validator set is not the one on "+
			"chain: %w", err)
	}
	if thr != in.AssertedThreshold {
		return "", fmt.Errorf("validatorSetProof: the asserted accept threshold is not the one on "+
			"chain: chain=%d/%d proof=%d/%d",
			thr.Numerator, thr.Denominator,
			in.AssertedThreshold.Numerator, in.AssertedThreshold.Denominator)
	}

	// --- 15. the root is bound to a quorum-signed anchor ---------------------
	//
	// No binding supplied is a NAMED STATE, not an error. See
	// VerdictValidatorSetUnbound: today it is unachievable, because it needs a
	// membership proof against a historical BPT root. A binding that IS supplied
	// and does NOT hold remains an error — that is tampering, and the two must
	// not be confused.
	if in.BoundStateTreeAnchor == "" {
		return VerdictValidatorSetUnbound, nil
	}
	bound, err := chained_proof.MustHex32Lower(in.BoundStateTreeAnchor, "boundStateTreeAnchor")
	if err != nil {
		return "", fmt.Errorf("validatorSetProof: %w", err)
	}
	if netAnchor != bound {
		return "", fmt.Errorf("validatorSetProof: the BPT root the set was proven into is not the "+
			"one the quorum signed: proven=%s signed=%s", netAnchor[:16], bound[:16])
	}

	// --- 16. base case / induction ------------------------------------------
	height, ok := p.MainChainHeight()
	if !ok {
		return "", fmt.Errorf("validatorSetProof: no main chain in the network account's chain set")
	}
	if height != 1 {
		// Height > 1 means the set has changed at least once. Proving what it WAS
		// needs the historical membership path AIP-058 asks for, plus one update
		// record per change. Neither is carried yet, so this is a could-not-read
		// rather than a refusal.
		return VerdictValidatorSetAsserted, nil
	}

	// --- 17. break the circle, or say plainly that you did not --------------
	if p.Incarnation == "" {
		return VerdictIncarnationUnknown, nil
	}
	inc, err := chained_proof.MustHex32Lower(p.Incarnation, "incarnation")
	if err != nil {
		return "", fmt.Errorf("validatorSetProof: %w", err)
	}
	if in.PinnedIncarnation == nil {
		return VerdictIncarnationUnverified, nil
	}
	pinned, err := chained_proof.MustHex32Lower(*in.PinnedIncarnation, "pinnedIncarnation")
	if err != nil {
		return "", fmt.Errorf("validatorSetProof: %w", err)
	}
	if inc != pinned {
		return VerdictForeignIncarnation, nil
	}
	return VerdictVerified, nil
}

// verify runs steps 11-13 for one account and returns the proven BPT root.
func (a *AccountStateProof) verify() (string, error) {
	// 11. the state hashes to the leaf being proven.
	raw, err := hexBytes(a.AccountState, "accountState")
	if err != nil {
		return "", err
	}
	leaf := sha256.Sum256(raw)
	start, err := chained_proof.MustHex32Lower(a.StateReceipt.Start, "stateReceipt.start")
	if err != nil {
		return "", err
	}
	if hex.EncodeToString(leaf[:]) != start {
		return "", fmt.Errorf("accountState does not hash to the proven leaf: sha256(state)=%x start=%s",
			leaf[:8], start[:16])
	}

	// 12. the merkle path validates.
	got, err := recomputeReceipt(a.StateReceipt)
	if err != nil {
		return "", err
	}
	claimed, err := chained_proof.MustHex32Lower(a.StateReceipt.Anchor, "stateReceipt.anchor")
	if err != nil {
		return "", err
	}
	if got != claimed {
		return "", fmt.Errorf("state receipt does not recompute: got=%s want=%s", got[:16], claimed[:16])
	}

	// 13. the account's own chain history is BOUND, not asserted.
	if err := a.verifyChainBinding(); err != nil {
		return "", err
	}
	return claimed, nil
}

// verifyChainBinding recomputes the state hasher's siblings and checks them
// against the receipt, so Chains is proven rather than claimed.
//
// The state hasher is [main, secondaryState, chains, pending], so a receipt from
// element 0 has two steps: the sibling secondaryState, then the sibling
// H(chains || pending). The chains component is never a sibling on its own,
// which is why PendingHash has to be carried.
func (a *AccountStateProof) verifyChainBinding() error {
	if len(a.StateReceipt.Entries) < 2 {
		return fmt.Errorf("state receipt has %d steps; the four-element state hasher needs at "+
			"least 2 before the BPT path", len(a.StateReceipt.Entries))
	}
	if a.SecondaryHash == "" || a.PendingHash == "" {
		return fmt.Errorf("secondaryHash and pendingHash are required: the receipt's second step " +
			"is H(chains || pending), so the chain roots alone cannot be checked")
	}
	sec, err := chained_proof.MustHex32Lower(a.SecondaryHash, "secondaryHash")
	if err != nil {
		return err
	}
	if got := strings.ToLower(a.StateReceipt.Entries[0].Hash); got != sec {
		return fmt.Errorf("secondaryHash is not the receipt's first sibling: got=%s want=%s",
			sec[:16], got[:16])
	}
	chainsHash, err := a.computeChainsComponent()
	if err != nil {
		return err
	}
	pend, err := hexBytes(a.PendingHash, "pendingHash")
	if err != nil {
		return err
	}
	if len(pend) != 32 {
		return fmt.Errorf("pendingHash must be 32 bytes")
	}
	combined := sha256.Sum256(append(append([]byte{}, chainsHash...), pend...))
	if got := strings.ToLower(a.StateReceipt.Entries[1].Hash); hex.EncodeToString(combined[:]) != got {
		return fmt.Errorf("H(chains||pending) is not the receipt's second sibling: computed=%x "+
			"receipt=%s — the chain heights are NOT bound", combined[:8], got[:16])
	}
	return nil
}

// computeChainsComponent mirrors observer_prod.go's hashChains: a merkle hash
// over each chain's DAG root, in the order the chains are listed.
func (a *AccountStateProof) computeChainsComponent() ([]byte, error) {
	var leaves [][]byte
	for i, c := range a.Chains {
		count, anchor, err := c.derive()
		if err != nil {
			return nil, fmt.Errorf("chains[%d]: %w", i, err)
		}
		if count == 0 {
			leaves = append(leaves, make([]byte, 32))
			continue
		}
		leaves = append(leaves, anchor)
	}
	return merkleHashList(leaves), nil
}

func hexBytes(s, label string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex: %w", label, err)
	}
	return b, nil
}

// merkleHashList mirrors merkle.Hasher.MerkleHash: an empty list hashes to 32
// zero bytes; otherwise entries are folded pairwise as they are added.
func merkleHashList(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, 32)
	}
	var pending [][]byte
	add := func(h []byte) {
		cur := h
		for i := 0; ; i++ {
			if i == len(pending) {
				pending = append(pending, cur)
				return
			}
			if pending[i] == nil {
				pending[i] = cur
				return
			}
			d := sha256.Sum256(append(append([]byte{}, pending[i]...), cur...))
			pending[i] = nil
			cur = d[:]
		}
	}
	for _, l := range leaves {
		add(l)
	}
	var out []byte
	for _, h := range pending {
		if h == nil {
			continue
		}
		if out == nil {
			out = h
			continue
		}
		d := sha256.Sum256(append(append([]byte{}, h...), out...))
		out = d[:]
	}
	if out == nil {
		return make([]byte, 32)
	}
	return out
}

func recomputeReceipt(r chained_proof.Receipt) (string, error) {
	cur, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(r.Start), "0x"))
	if err != nil || len(cur) != 32 {
		return "", fmt.Errorf("receipt.start must be 32 bytes of hex")
	}
	for i, e := range r.Entries {
		h, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(e.Hash), "0x"))
		if err != nil || len(h) != 32 {
			return "", fmt.Errorf("receipt.entries[%d].hash must be 32 bytes of hex", i)
		}
		var d [32]byte
		if e.Right {
			d = sha256.Sum256(append(append([]byte{}, cur...), h...))
		} else {
			d = sha256.Sum256(append(append([]byte{}, h...), cur...))
		}
		cur = d[:]
	}
	return hex.EncodeToString(cur), nil
}

// sameValidatorSet compares canonically: sorted by public key, with ActiveOn
// sorted. Order from the API is not stable, so an order-sensitive comparison
// would reject valid proofs intermittently.
func sameValidatorSet(derived, asserted []chained_proof.ValidatorKey) error {
	if len(derived) != len(asserted) {
		return fmt.Errorf("derived %d validators, proof asserts %d", len(derived), len(asserted))
	}
	norm := func(in []chained_proof.ValidatorKey) []chained_proof.ValidatorKey {
		out := make([]chained_proof.ValidatorKey, len(in))
		for i, v := range in {
			a := make([]string, len(v.ActiveOn))
			copy(a, v.ActiveOn)
			sort.Strings(a)
			out[i] = chained_proof.ValidatorKey{
				PublicKey: strings.ToLower(strings.TrimPrefix(v.PublicKey, "0x")),
				ActiveOn:  a,
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
		return out
	}
	d, a := norm(derived), norm(asserted)
	for i := range d {
		if d[i].PublicKey != a[i].PublicKey {
			return fmt.Errorf("validator %d: chain says %s, proof says %s",
				i, short(d[i].PublicKey), short(a[i].PublicKey))
		}
		if !equalStrings(d[i].ActiveOn, a[i].ActiveOn) {
			return fmt.Errorf("validator %s: chain says active on %v, proof says %v",
				short(d[i].PublicKey), d[i].ActiveOn, a[i].ActiveOn)
		}
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}

var _ = bytes.Equal
