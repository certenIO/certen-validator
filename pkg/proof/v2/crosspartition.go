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
	// (D1(f)); it need not be an authority.
	RoleInitiatorSigner PageRole = "initiator-signer"
	// RoleCertifiedKeyPage: the page the intent certificate names as its key page, exactly as ResolveSigningKeyPage resolves it
	// (D1(f)), whatever other role it has. BindProofV2 requires it among the proven pages.
	RoleCertifiedKeyPage PageRole = "certified-key-page"
	// RoleSyntheticChain: the source partition's synthetic ledger, whose main chain records the SequencedMessage that carried a counted vote
	// (RB9 Phase C1b-1: the block that PRODUCED the vote is read from it, so a vote released by a HoldUntil is judged at its release).
	RoleSyntheticChain PageRole = "synthetic-chain"
	// RoleSystemLedger: a partition's system ledger (<partition>/ledger), proven at the partition's block: its ExecutorVersion is the executor version in force there
	// (RB9 Phase C1b-2, g1_executor_version_unsupported). The role is derived from the proven account itself.
	RoleSystemLedger PageRole = "system-ledger"
)

// KnownRoles are the roles evidence 2.1 may carry, in canonical order.
var KnownRoles = []PageRole{RolePrincipalChain, RoleAuthorityBook, RoleAuthorityPage, RoleHeaderAuthority,
	RoleDelegateBook, RoleDelegatePage, RoleVoter, RoleInitiatorSigner, RoleCertifiedKeyPage, RoleSyntheticChain, RoleSystemLedger}

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
// verifier re-evaluates every book's vote on the certified timeline, per arrival event, with the executor's rule and requires
// Origin and Vote to equal these, then requires readiness; it never trusts a vote it did not recompute. The principal's vote
// carries no delegation path (the last hop's Delegator is empty): the path is rebuilt from Hops.
type Vote struct {
	Authority string        `json:"authority"`       // the key book the vote is for
	Origin    string        `json:"origin"`          // the page that decided it (a page URL; the authority itself for an abstain of a missing authority)
	Vote      string        `json:"vote"`            // accept, reject, abstain or suggest
	Cause     string        `json:"cause,omitempty"` // the transaction id of the signature that caused it (AuthoritySignature.Cause)
	Transport VoteTransport `json:"transport"`
	Message   string        `json:"message"` // the vote's entry hash in the principal's signature chain, hex32
	Receipt   string        `json:"receipt"` // from Message to the anchor of the principal's signature chain as bound at the anchor block (binary merkle.Receipt, hex)

	// Hops follow Cause back, from the message the vote answers to the key signature: each is a signature message recorded in a
	// page's own signature chain, on that page's partition. The key signature's own Delegator list is the delegation path
	// (delegators[0] is nearest the key page).
	Hops []VoteHop `json:"hops,omitempty"`

	// Counted are the other signatures the pages on the cause chain counted for this transaction (a page whose threshold needs more
	// than the signature that completed it): each recorded in its page's signature chain like a hop, with its arrival derived the same
	// way. Evidence 2.1 timeline only.
	Counted []VoteHop `json:"counted,omitempty"`

	// Evidence 2.1 timeline (RB9 Phase C1b-1); omitted when empty. Produced establishes the block that PRODUCED the vote, so a vote
	// released later by a HoldUntil is judged at the block that released it: for a sequenced vote the SequencedMessage's entry in the
	// source partition's synthetic ledger main chain, for an inline vote the vote's own entry in the principal's signature chain.
	// Absent, the production block is not established and the report says g1_vote_held for it.
	Produced *Production `json:"produced,omitempty"`
}

// VoteHop is one signature message of a vote's cause chain: an AuthoritySignature a delegating page produced, or the key
// signature that started it. Page is the page whose signature chain records it.
type VoteHop struct {
	Page      string `json:"page"`
	Message   string `json:"message"`   // the message's entry hash in Page's signature chain, hex32
	Signature string `json:"signature"` // the signature's binary encoding, hex
	Block     uint64 `json:"block"`     // the block of Page's partition it arrived in, as claimed; the verifier derives it from Receipt
	Receipt   string `json:"receipt"`   // from Message to Page's signature chain root as bound at that partition's block (binary merkle.Receipt, hex)

	// Arrival, in evidence 2.1 with a timeline, proves the exact block the signature arrived in from the page's signature-index chain
	// (Arrival). Block is then DERIVED from it and must equal it; without it Block is a claim the verifier does not rely on.
	Arrival *Arrival `json:"arrival,omitempty"`
}

// IndexProof is one entry of a chain's index chain (<chain>-index) with the receipt placing it in that chain as bound at B_Y. An index
// entry is written at the end of every block that wrote to the chain: Source is the position of the chain's last entry then, BlockIndex
// the block (protocol.IndexEntry; internal/core/execute/v2/block/utils.go addChainAnchor).
type IndexProof struct {
	Position uint64 `json:"position"` // the entry's position in the index chain; checked against what its receipt allows
	Entry    string `json:"entry"`    // the index chain entry: the IndexEntry's binary encoding padded to 32 bytes, hex
	Receipt  string `json:"receipt"`  // from Entry to the index chain's root as bound at B_Y (binary merkle.Receipt, hex)
}

// Arrival derives the block a chain entry at position p was written in: p lies after the previous block's index entry (Before:
// Source < p) and at or before this block's (At: Source >= p), the two entries adjacent in the index chain.
type Arrival struct {
	Before *IndexProof `json:"before,omitempty"` // absent only when At is the index chain's first entry
	At     IndexProof  `json:"at"`
}

// Production proves the block that produced a vote (see Vote.Produced). Account is the proven account whose Chain records Message
// (the source partition's synthetic ledger and "main" for a sequenced vote; the principal and "signature" for an inline one).
type Production struct {
	Account string  `json:"account"`
	Chain   string  `json:"chain"`
	Message string  `json:"message"` // the entry's hash in Account's Chain, hex32
	Receipt string  `json:"receipt"` // from Message to Chain's root as bound at B_Y (binary merkle.Receipt, hex)
	Arrival Arrival `json:"arrival"`
}

// HistoryEntry is one entry of a key page's main chain: the transaction whose hash the chain holds. Initiator is the initiating
// signature (binary, hex) of an UpdateKey, which rotates the initiator's own entry.
type HistoryEntry struct {
	Transaction string `json:"transaction"`
	Initiator   string `json:"initiator,omitempty"`
}

// PageHistory is a key page's main chain from its first entry to its height at B_Y, and its main-index chain in full (PROOF_V2 5.2
// steps 2-3). The verifier folds the entries' hashes to the main chain root bound in PageState.Chains, and the index entries to the
// main-index root: no entry inserted, omitted or reordered. Each entry's block is read from the folded index; the replay of the
// entries must end in the proven state.
type PageHistory struct {
	Entries []HistoryEntry `json:"entries"`
	Index   []string       `json:"index"` // the main-index chain's entries, each as in IndexProof.Entry
}

// ProvenPage is one proven page in the report: where it was proven and why it is there.
type ProvenPage struct {
	URL       string
	Partition string     // the partition whose anchor the page is proven through, as that anchor's Source names it
	Block     uint64     // that partition's block B_Y
	Roles     []PageRole // re-derived from the proven states and equal to the recorded ones
	// Declared are the recorded roles whose justification is a fact outside the evidence - the transaction's header and the
	// intent certificate (header-authority, initiator-signer, certified-key-page): listed, not proven here; BindProofV2 requires them.
	Declared []PageRole
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
	// StateCertifiedPageUnproven: the certified key page cannot be resolved, or is not among the proven pages (D1(f)).
	StateCertifiedPageUnproven = "g1_certified_page_unproven"
	// StateExecutorOverrideUnsupported: the body type has an executor override the default authority rules do not describe (D6).
	StateExecutorOverrideUnsupported = "g1_executor_override_unsupported"
	// StateClosureExceedsBudget: the governing set is larger than the evidence budget (the consensus block size) allows (D6).
	StateClosureExceedsBudget = "g1_closure_exceeds_budget"
	// StateRoutingHistoryUnproven: the routing table has more than its genesis write, so its state at each B_Y is not proven (D5).
	StateRoutingHistoryUnproven = "g1_routing_history_unproven"
	// StateDirectoryPartitionUnsupported: a governing page is on the Directory; D2b/D2c capture is not built (a named state, not a read).
	StateDirectoryPartitionUnsupported = "g1_directory_partition_unsupported"
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

// StateEvidence21Required is the interim name the build answered with while evidence 2.1 could be verified but not assembled (RB9 Phase
// C1a/C1b-1). SUPERSEDED 2026-10-18 (RB9 Phase C1b-2): Build21 assembles a 2.1 document from a capture (anchors, vote receipts and arrival
// proofs, history, the carried transaction, the routing proof) and verifies it, so nothing emits this name any more; a certificate proof
// for a cross-partition intent is StateEvidence21NotInForce until the rules that accept 2.1 are in force. The constant stays so a stored
// shadow row that carries it still decodes and is read as the state it was.
const StateEvidence21Required = "g1_evidence_21_required"
