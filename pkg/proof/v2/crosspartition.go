// Copyright 2026 Certen Protocol
//
// Evidence 2.1 (docs/proof/G1_CROSS_PARTITION.md, RB9): the types and canonical encoding of governing pages that live on
// more than one partition. A key book on another identity can sit on another partition, whose block numbering and state
// root differ from the transaction's; each such page is proven at its own partition's block B_Y, through that partition's
// own BlockValidatorAnchor, into the same certified Directory root as the transaction (D2, D4).
//
// This file holds only what the document carries and how it is named. Capturing it is pkg/proofv2shadow (RB9 Phase B);
// verifying it is RB9 Phase C. Until Phase C lands, Verify refuses version 2.1 by name, and a 2.0 document verifies exactly
// as before: every field added here is omitted when empty, so a 2.0 document decodes into these types and re-encodes to the
// same bytes.

package proofv2

import (
	"fmt"
	"sort"
)

// Version21 is the proof_version of evidence that proves pages on more than one partition, and carries the proven vote
// records, the per-partition anchors and the routing proof. Version ("2.0") documents stay valid forever.
const Version21 = "2.1"

// Domain tags of the 2.1 report's commitments. They are new tags and never reuse a v3 tag (docs/proof/GOVROOT_V3.md,
// "Goldens are specification"): govRoot v4 commits the 2.1 report under G1's tag below.
const (
	DomainG1V4      = "certen:g1:v4"
	DomainGovRootV4 = "certen:govroot:v4"
)

// PageRole says why a page is among the proven pages (design D1, D4). A page may carry several roles. The roles are
// recorded by the capture and re-derived by the verifier from the proven states: a recorded role the proven state does not
// justify, or a justified role the evidence omits, is a named refusal, never a claim the verifier trusts.
type PageRole string

const (
	// RolePrincipalChain: the principal account or an account its authority set is inherited through (D1(a)).
	RolePrincipalChain PageRole = "principal-chain"
	// RoleAuthorityBook: the key book of an authority in the resolved set, enabled or disabled (D1(b)); RoleAuthorityPage
	// is each of its pages 1..PageCount.
	RoleAuthorityBook PageRole = "authority-book"
	RoleAuthorityPage PageRole = "authority-page"
	// RoleHeaderAuthority: a book or page of an authority the transaction header (or its body) names (D1(c)).
	RoleHeaderAuthority PageRole = "header-authority"
	// RoleDelegateBook / RoleDelegatePage: the book a page entry delegates to, and its pages, recursively (D1(e)).
	RoleDelegateBook PageRole = "delegate-book"
	RoleDelegatePage PageRole = "delegate-page"
	// RoleVoter: the authority that actually voted when every list authority is disabled, and any page named by a
	// counted vote's origin or delegator path (D1(d), (f)).
	RoleVoter PageRole = "voter"
	// RoleInitiatorSigner: the page of the signature whose initiator hash is the transaction's, and the credit payer's page
	// (D1(f)); it need not be an authority, but the certified key page is one of these.
	RoleInitiatorSigner PageRole = "initiator-signer"
)

// KnownRoles are the roles evidence 2.1 may carry, in canonical order.
var KnownRoles = []PageRole{RolePrincipalChain, RoleAuthorityBook, RoleAuthorityPage, RoleHeaderAuthority,
	RoleDelegateBook, RoleDelegatePage, RoleVoter, RoleInitiatorSigner}

// CanonicalRoles returns roles sorted by KnownRoles' order with duplicates removed, and an error naming an unknown
// role. A page's roles are encoded in this order so two producers write one document for one set of facts.
func CanonicalRoles(roles []PageRole) ([]PageRole, error) {
	rank := map[PageRole]int{}
	for i, r := range KnownRoles {
		rank[r] = i
	}
	seen := map[PageRole]bool{}
	var out []PageRole
	for _, r := range roles {
		if _, ok := rank[r]; !ok {
			return nil, fmt.Errorf("unknown page role %q", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return rank[out[i]] < rank[out[j]] })
	return out, nil
}

// VoteTransport says how a counted authority vote reached the principal's partition (R9 §1a): inline when the voting
// page and the principal share a root identity (counted in the producing block), or as a sequenced synthetic message
// anchored through the Directory (always, for a different root identity, even on the same partition).
type VoteTransport struct {
	Kind        string `json:"kind"` // "inline" or "sequenced"
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Number      uint64 `json:"number,omitempty"`
}

const (
	TransportInline    = "inline"
	TransportSequenced = "sequenced"
)

// Vote is one authority vote copied from the principal's PROVEN signature chain as of the anchor block (design D3). The
// verifier re-evaluates every book's vote on the certified timeline with the executor's rule and requires Origin and Vote to
// equal these, then requires readiness; it never trusts a vote it did not recompute.
type Vote struct {
	Authority  string        `json:"authority"`            // the key book the vote is for
	Origin     string        `json:"origin"`               // the page that decided it (a page URL; the authority itself for an abstain of a missing authority)
	Vote       string        `json:"vote"`                 // accept, reject, abstain or suggest
	Delegators []string      `json:"delegators,omitempty"` // the delegation path, nearest the signer first
	Cause      string        `json:"cause,omitempty"`      // the transaction id of the signature that caused it (AuthoritySignature.Cause)
	Transport  VoteTransport `json:"transport"`
	Message    string        `json:"message"` // the vote's entry hash in the principal's signature chain, hex32
	Receipt    string        `json:"receipt"` // from Message to the anchor of the principal's signature chain as bound at the anchor block (binary merkle.Receipt, hex)
}

// ProvenPage is one proven page in the report: where it was proven and why it is there.
type ProvenPage struct {
	URL       string
	Partition string // the partition whose anchor the page is proven through, as that anchor's Source names it
	Block     uint64 // that partition's block B_Y
	Roles     []PageRole
}

// NamedState is a state the capture or verifier could not establish, with where it was judged. It is the only answer
// there is for anything not established: never a weaker answer shaped like the strong one (standard §3, "No fallback").
type NamedState struct {
	Code      string
	Partition string
	Block     uint64
	Detail    string
}

func (s *NamedState) Error() string {
	where := ""
	switch {
	case s.Partition != "" && s.Block != 0:
		where = fmt.Sprintf("{%s,%d}", s.Partition, s.Block)
	case s.Partition != "":
		where = fmt.Sprintf("{%s}", s.Partition)
	case s.Block != 0:
		where = fmt.Sprintf("{%d}", s.Block)
	}
	if s.Detail == "" {
		return s.Code + where
	}
	return s.Code + where + ": " + s.Detail
}

// The named states of design D6 (and R9 "Named states"). A capture or verification that cannot establish a fact returns a
// *NamedState carrying one of these codes.
const (
	// StateHistoricalUnavailable: the partition no longer serves the block (below its retained range).
	StateHistoricalUnavailable = "g1_historical_unavailable"
	// StateNotReady: the partition has not yet committed the later block that makes the block servable (retrying).
	StateNotReady = "g1_state_not_ready"
	// StatePartitionAnchorUnavailable: the Directory has not executed (or certified) the partition's anchor for the block.
	StatePartitionAnchorUnavailable = "g1_partition_anchor_unavailable"
	// StateForeignPartitionMismatch: a page's claimed partition is not the source of the anchor it is proven through.
	StateForeignPartitionMismatch = "g1_foreign_partition_mismatch"
	// StateRoutingUnproven: the routing table is not proven, so Partition == route(URL) is unchecked.
	StateRoutingUnproven = "g1_routing_unproven"
	// StateAuthorityVoterOutsideList: every list authority is disabled and the voter is not in the list.
	StateAuthorityVoterOutsideList = "g1_authority_voter_outside_list"
	// StateHeaderAuthorityMissing: a Header.Authorities entry has no proven pages.
	StateHeaderAuthorityMissing = "g1_header_authority_missing"
	// StateAuthorityMissing: a vote whose origin is the authority itself (an abstain for a missing authority).
	StateAuthorityMissing = "g1_authority_missing"
	// StateDelegationDepthExceeded: a recorded delegation path longer than protocol.DelegationDepthLimit (20).
	StateDelegationDepthExceeded = "g1_delegation_depth_exceeded"
	// StateDelegateEntryAbsent: the delegating page had no entry for the delegate at the hop's arrival block.
	StateDelegateEntryAbsent = "g1_delegate_entry_absent"
	// StateInitiatorPageUnproven: the initiator's (or payer's) page is not among the proven pages.
	StateInitiatorPageUnproven = "g1_initiator_page_unproven"
	// StateVoteHeld: the vote was produced by a HoldUntil release.
	StateVoteHeld = "g1_vote_held"
	// StateExecutorVersionUnsupported: the transaction executed under a version whose path or inheritance semantics differ.
	StateExecutorVersionUnsupported = "g1_executor_version_unsupported"
	// StateCompletenessUnproven: the closure could not be derived from proven state.
	StateCompletenessUnproven = "g1_completeness_unproven"
	// StateBlockBeforeArrival: B_Y precedes the arrival block of a counted signature on the partition.
	StateBlockBeforeArrival = "g1_block_before_signature"
	// StatePageBlockMismatch: a page was served for a block other than the partition's B_Y.
	StatePageBlockMismatch = "g1_page_block_mismatch"
	// StateBookPageCountUnproven: a book's pages beyond what was captured, or fewer than its proven PageCount.
	StateBookPageCountUnproven = "g1_book_pagecount_unproven"
	// StateChainUnboundPending / StateChainMoved: the page's chains could not be bound at its block (existing capture
	// strings, now with a partition).
	StateChainUnboundPending = "g1_chain_unbound_pending"
	StateChainMoved          = "g1_chain_moved"
	// StateCrossIdentityPending is the state the shadow recorded before RB9 captured foreign books ("authorities on other
	// identities are not captured yet"). SUPERSEDED 2026-10-17 by real capture (docs/proof/G1_CROSS_PARTITION.md D1/D2):
	// nothing emits it any more; the constant stays so a stored shadow row that carries it still decodes and is read as the
	// state it was.
	StateCrossIdentityPending = "g1_cross_identity_pending"
)
