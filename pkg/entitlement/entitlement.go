// Package entitlement decides whether CERTEN will spend its own money on an
// intent.
//
// # WHY THIS EXISTS
//
// Intent discovery is permissionless by construction: any writeData landing on
// Accumulate with the CERTEN_INTENT memo is picked up and executed. That is
// correct — CERTEN does not and must not gate Accumulate. But it means the
// api-gateway's paywall governs only intents that happen to arrive through the
// API, and anyone submitting straight to Accumulate receives the full 9-phase
// cycle for free: CERTEN pays gas on the anchor, the BLS-ZK verify, and the
// execution, and charges nothing.
//
// This package supplies the missing decision. It answers exactly one question:
//
//	"Is the ADI that submitted this intent entitled to have CERTEN spend on it?"
//
// DESIGN CONSTRAINTS, and why the shape is what it is
//
//  1. The answer must be DETERMINISTIC across validators. The authoritative
//     check runs inside VerifyValidatorBlockInvariants, which is reached from
//     both CheckTx and FinalizeBlock — a consensus rule. Two validators
//     disagreeing halts the chain. So the decision may never depend on wall
//     time, on a live query, or on per-node state.
//
//  2. The verifier may not perform I/O. validator_block_invariants.go states
//     this about itself: "It does NOT talk to Accumulate, Ethereum, or any
//     external chain." Therefore the EVIDENCE travels inside the ValidatorBlock
//     and the verifier only does arithmetic.
//
//  3. Exactly one field is unforgeable: the Accumulate header.principal, i.e.
//     the account URL the transaction was actually written under. Accumulate
//     consensus already proved the submitter can sign for it. Every other field
//     in an intent — created_by, intent_id, organizationAdi — is attacker
//     controlled and must never be used for authorization.
//
//  4. Fail closed, including on CERTEN's own infrastructure. If the entitlement
//     feed is stale or absent, refuse. A design where killing the publisher
//     yields free service is not a fee layer.
//
// # WHAT IS NOT HERE
//
// No allowlist. Membership is derived from a funded account, not from an
// operator's approval, so anyone may join by signing up and paying. The gate is
// economic, never identity.
package entitlement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Status is an account's standing. Mirrors billing_accounts.status in the
// gateway, which is the source of truth.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusClosed    Status = "closed"
)

// Leaf is one account's entitlement. Kept small: it is carried inside every
// ValidatorBlock for the intent it authorizes.
type Leaf struct {
	// ADIURL is the Accumulate account URL this entitlement is for. It is
	// compared against the intent's discovered principal, which is the only
	// field a submitter cannot forge.
	ADIURL string `json:"adi_url"`

	Status Status `json:"status"`
	Tier   string `json:"tier,omitempty"`

	// IntentCeilingMicroUSD bounds the worst-case cost of any single intent for
	// this account. Micro-USD so it composes directly with the cost ceiling in
	// pkg/execution and with billing_accounts, which is also micro-USD.
	IntentCeilingMicroUSD int64 `json:"intent_ceiling_microusd"`

	// EpochCeilingMicroUSD bounds cumulative spend within one epoch.
	EpochCeilingMicroUSD int64 `json:"epoch_ceiling_microusd"`
}

// Canonical returns the byte encoding hashed into the tree.
//
// Hand-rolled rather than json.Marshal: Go's map ordering and future struct
// field additions would silently change the hash, and every validator must
// compute an identical leaf hash forever. An explicit, ordered, length-free
// encoding with a field separator that cannot appear in the values keeps this
// stable and unambiguous.
func (l Leaf) Canonical() []byte {
	return []byte(fmt.Sprintf(
		"v1\x1f%s\x1f%s\x1f%s\x1f%d\x1f%d",
		strings.ToLower(strings.TrimSpace(l.ADIURL)),
		l.Status, l.Tier,
		l.IntentCeilingMicroUSD, l.EpochCeilingMicroUSD,
	))
}

// Hash is the leaf hash. Domain-separated with 0x00 per RFC 6962 so a leaf can
// never be reinterpreted as an interior node.
func (l Leaf) Hash() [32]byte {
	return sha256.Sum256(append([]byte{0x00}, l.Canonical()...))
}

// Entitled reports whether this leaf permits CERTEN to spend at all.
func (l Leaf) Entitled() bool {
	return l.Status == StatusActive && l.IntentCeilingMicroUSD > 0
}

// Header is the signed, publishable statement of an epoch. Tiny by design: only
// this goes on Accumulate. The full set is served over untrusted transport and
// verified against SetHash.
type Header struct {
	Epoch uint64 `json:"epoch"`

	// Root is the Merkle root over the sorted leaves.
	Root string `json:"root"`

	// SetHash lets a consumer verify a fetched set blob without trusting where
	// it came from.
	SetHash string `json:"set_hash"`

	// PrevRoot chains epochs so a consumer can detect a forked or rewritten
	// history.
	PrevRoot string `json:"prev_root,omitempty"`

	// NativeUSDMicro is the price of the native token, in micro-USD, that
	// ceilings in this epoch are denominated against.
	//
	// Carried here on purpose. The validator needs a USD rate to enforce a cost
	// ceiling, and the alternatives are worse: querying the gateway per intent
	// makes it a fleet-wide liveness dependency, and a local feed is
	// non-deterministic across validators. Riding on an artifact that is already
	// signed, already fetched and already consensus-safe costs nothing extra.
	NativeUSDMicro int64 `json:"native_usd_micro"`

	// IssuedAtUnix / NotAfterUnix bound freshness. Compared against the ABCI
	// block time, never time.Now() — block time is identical on every validator,
	// wall time is not.
	IssuedAtUnix int64 `json:"issued_at_unix"`
	NotAfterUnix int64 `json:"not_after_unix"`

	// KeyID identifies the signing key so it can be rotated without a fleet
	// redeploy, and revoked without ambiguity.
	KeyID string `json:"key_id"`

	// Signature is ed25519 over SigningBytes().
	Signature string `json:"signature"`
}

// SigningBytes is the exact preimage signed and verified. Excludes Signature.
func (h Header) SigningBytes() []byte {
	return []byte(fmt.Sprintf(
		"certen:entitlement:v1\x1f%d\x1f%s\x1f%s\x1f%s\x1f%d\x1f%d\x1f%d\x1f%s",
		h.Epoch, h.Root, h.SetHash, h.PrevRoot,
		h.NativeUSDMicro, h.IssuedAtUnix, h.NotAfterUnix, h.KeyID,
	))
}

// Evidence is what a proposer puts INSIDE a ValidatorBlock to justify having
// done work for an account. Self-contained: a verifier needs nothing else.
type Evidence struct {
	Header Header `json:"header"`
	Leaf   Leaf   `json:"leaf"`

	// Proof is the inclusion path from Leaf to Header.Root, bottom-up.
	//
	// Note there is no NON-inclusion proof and none is needed: the burden is on
	// the proposer to demonstrate entitlement. An account that is absent from the
	// set simply has no Evidence to attach, the field is nil, and verification
	// fails closed. That is what lets this use an ordinary RFC 6962 tree instead
	// of a sparse Merkle tree.
	Proof []ProofStep `json:"proof"`
}

// ProofStep is one sibling on the inclusion path.
type ProofStep struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right"` // true if the sibling is the RIGHT child
}

// VerifyError distinguishes why entitlement verification failed, so a refusal
// can be reported honestly instead of collapsing to "not entitled".
type VerifyError struct {
	Reason string
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

// Reason codes. Stable strings — they end up in RefusalRecords on chain.
const (
	ReasonNoEvidence     = "NO_ENTITLEMENT_EVIDENCE"
	ReasonBadSignature   = "ENTITLEMENT_SIGNATURE_INVALID"
	ReasonUnknownKey     = "ENTITLEMENT_KEY_UNKNOWN"
	ReasonStale          = "ENTITLEMENT_STALE"
	ReasonBadProof       = "ENTITLEMENT_PROOF_INVALID"
	ReasonPrincipalMatch = "ENTITLEMENT_PRINCIPAL_MISMATCH"
	ReasonNotEntitled    = "NOT_ENTITLED"
	ReasonCeiling        = "INTENT_CEILING_EXCEEDED"
)

// KeySet is the pinned set of keys permitted to sign entitlement headers,
// keyed by KeyID.
//
// Pinned in configuration/genesis rather than fetched. A key set that could be
// fetched would be a key set an attacker could substitute, and it would also be
// per-node mutable state inside a consensus rule.
type KeySet map[string]ed25519.PublicKey

// Verify checks Evidence against a principal and a block time, and reports
// whether CERTEN may spend.
//
// PURE. No I/O, no clocks, no globals. Everything it needs is an argument, which
// is what makes it safe to call from inside a consensus invariant and easy to
// test exhaustively.
//
// nowUnix MUST be the ABCI block time. Passing time.Now() here would make the
// result differ between validators and halt the chain.
func Verify(ev *Evidence, principal string, nowUnix int64, keys KeySet) error {
	if ev == nil {
		return &VerifyError{Reason: ReasonNoEvidence,
			Detail: "no entitlement evidence attached; refusing rather than assuming entitlement"}
	}

	// 1. The header must be signed by a key we already trust.
	pub, ok := keys[ev.Header.KeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return &VerifyError{Reason: ReasonUnknownKey, Detail: ev.Header.KeyID}
	}
	sig, err := hex.DecodeString(ev.Header.Signature)
	if err != nil || !ed25519.Verify(pub, ev.Header.SigningBytes(), sig) {
		return &VerifyError{Reason: ReasonBadSignature, Detail: ev.Header.KeyID}
	}

	// 2. Freshness, against BLOCK time.
	//
	// Fail closed on staleness: if the publisher dies, everything refuses. The
	// alternative — serving on a stale head — makes killing the publisher the
	// cheapest possible bypass.
	if ev.Header.NotAfterUnix <= 0 || nowUnix > ev.Header.NotAfterUnix {
		return &VerifyError{Reason: ReasonStale, Detail: fmt.Sprintf(
			"epoch %d expired at %d, block time %d", ev.Header.Epoch, ev.Header.NotAfterUnix, nowUnix)}
	}
	// An epoch from the future indicates a clock or publishing fault. Refuse
	// rather than honour it, with a small tolerance for ordinary skew.
	if ev.Header.IssuedAtUnix > nowUnix+300 {
		return &VerifyError{Reason: ReasonStale, Detail: fmt.Sprintf(
			"epoch %d issued at %d, ahead of block time %d", ev.Header.Epoch, ev.Header.IssuedAtUnix, nowUnix)}
	}

	// 3. The leaf must be the principal's. Compared case-insensitively on the
	// normalized URL because Accumulate URLs are case-insensitive, and a
	// case-only mismatch must not be exploitable in either direction.
	if !SameADI(ev.Leaf.ADIURL, principal) {
		return &VerifyError{Reason: ReasonPrincipalMatch, Detail: fmt.Sprintf(
			"evidence is for %q but the intent principal is %q", ev.Leaf.ADIURL, principal)}
	}

	// 4. The leaf must actually be in the signed set.
	if err := verifyInclusion(ev.Leaf, ev.Proof, ev.Header.Root); err != nil {
		return &VerifyError{Reason: ReasonBadProof, Detail: err.Error()}
	}

	// 5. Finally, does the entitlement permit spending?
	if !ev.Leaf.Entitled() {
		return &VerifyError{Reason: ReasonNotEntitled, Detail: fmt.Sprintf(
			"account %s is %s with an intent ceiling of %d", ev.Leaf.ADIURL, ev.Leaf.Status, ev.Leaf.IntentCeilingMicroUSD)}
	}

	return nil
}

// SameADI compares two Accumulate account URLs for identity.
//
// Exported because the consensus layer must apply the IDENTICAL rule when it
// checks that a block's declared principal agrees with its governance proof. Two
// normalizations that disagreed would be a bypass in their own right: a block
// the invariant considers consistent but the gate considers a different account,
// or the reverse.
//
// Normalizes case, surrounding whitespace and a trailing slash. Does NOT strip
// path components: acc://foo.acme/data and acc://foo.acme are different
// accounts, and treating them as one would let an entitlement for a data
// account authorize spending for the identity, or vice versa.
func SameADI(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.TrimSuffix(s, "/")
	}
	na, nb := norm(a), norm(b)
	return na != "" && na == nb
}

// verifyInclusion walks the proof from leaf to root.
func verifyInclusion(leaf Leaf, proof []ProofStep, wantRoot string) error {
	h := leaf.Hash()
	cur := h[:]
	for i, step := range proof {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil || len(sib) != 32 {
			return fmt.Errorf("proof step %d is not a 32-byte hash", i)
		}
		if step.Right {
			cur = interiorHash(cur, sib)
		} else {
			cur = interiorHash(sib, cur)
		}
	}
	if !strings.EqualFold(hex.EncodeToString(cur), wantRoot) {
		return fmt.Errorf("computed root %s does not match signed root %s",
			hex.EncodeToString(cur), wantRoot)
	}
	return nil
}

// interiorHash is the RFC 6962 interior node hash, domain-separated with 0x01.
func interiorHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// ── Set construction (used by the publisher and by proposers) ───────────────

// Set is a full entitlement set. Small enough to hold in memory: thousands of
// accounts at a couple of hundred bytes each.
type Set struct {
	Leaves []Leaf `json:"leaves"`
}

// Normalize sorts leaves by ADI and removes duplicates, keeping the LAST
// occurrence. Deterministic ordering is required or two publishers would
// compute different roots for the same data.
func (s *Set) Normalize() {
	byADI := make(map[string]Leaf, len(s.Leaves))
	for _, l := range s.Leaves {
		byADI[strings.ToLower(strings.TrimSpace(l.ADIURL))] = l
	}
	out := make([]Leaf, 0, len(byADI))
	for _, l := range byADI {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].ADIURL) < strings.ToLower(out[j].ADIURL)
	})
	s.Leaves = out
}

// SetHash is the hash of the canonical JSON encoding, used to verify a blob
// fetched over untrusted transport.
func (s *Set) SetHash() (string, error) {
	s.Normalize()
	b, err := json.Marshal(s.Leaves)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Root computes the Merkle root over the normalized leaves.
//
// An EMPTY set hashes to the empty string rather than to sha256("") on purpose:
// an empty root must never be a value a proof can be constructed against, or a
// publisher bug that emits zero accounts would produce a root that some crafted
// proof might satisfy. Empty means "no entitlements", which fails closed
// everywhere because no Evidence can be built.
func (s *Set) Root() string {
	s.Normalize()
	if len(s.Leaves) == 0 {
		return ""
	}
	level := make([][]byte, 0, len(s.Leaves))
	for _, l := range s.Leaves {
		h := l.Hash()
		level = append(level, h[:])
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd node promotes unchanged, per RFC 6962.
				next = append(next, level[i])
				continue
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

// BuildProof returns the inclusion path for an ADI, or false if absent.
func (s *Set) BuildProof(adiURL string) ([]ProofStep, Leaf, bool) {
	s.Normalize()
	idx := -1
	for i, l := range s.Leaves {
		if SameADI(l.ADIURL, adiURL) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, Leaf{}, false
	}
	leaf := s.Leaves[idx]

	level := make([][]byte, 0, len(s.Leaves))
	for _, l := range s.Leaves {
		h := l.Hash()
		level = append(level, h[:])
	}

	var steps []ProofStep
	pos := idx
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				if i == pos {
					pos = len(next) - 1 // promoted; no sibling to record
				}
				continue
			}
			if i == pos {
				steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[i+1]), Right: true})
				pos = len(next)
			} else if i+1 == pos {
				steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[i]), Right: false})
				pos = len(next)
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		level = next
	}
	return steps, leaf, true
}

// Lookup returns an account's leaf.
func (s *Set) Lookup(adiURL string) (Leaf, bool) {
	for _, l := range s.Leaves {
		if SameADI(l.ADIURL, adiURL) {
			return l, true
		}
	}
	return Leaf{}, false
}

// SameIdentity reports whether two Accumulate URLs belong to the same ADI,
// ignoring any sub-account path.
//
// acc://acme.acme and acc://acme.acme/data are the same IDENTITY but different
// ACCOUNTS. Both distinctions matter, in different places:
//
//   - Entitlement is per ACCOUNT: the epoch publishes data-account URLs, and
//     SameADI is used there, because an entitlement for one account must not
//     authorize another.
//   - Principal binding is per IDENTITY: a ValidatorBlock legitimately carries
//     the bare ADI in its governance proof and the data account in its anchor
//     reference. Requiring those to be string-equal would reject every honest
//     block, while requiring nothing would let a proposer name an entitled
//     stranger.
//
// Verified against production: governance_proof.organization_adi is
// `acc://carp-seller-91503.acme` while accumulate_anchor_reference.account_url
// is `acc://carp-seller-91503.acme/data`.
func SameIdentity(a, b string) bool {
	ia, ib := identityOf(a), identityOf(b)
	return ia != "" && ia == ib
}

// identityOf strips any sub-account path, leaving the bare ADI.
func identityOf(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	const scheme = "acc://"
	rest := strings.TrimPrefix(s, scheme)
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return ""
	}
	return scheme + rest
}
