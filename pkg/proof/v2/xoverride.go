// Copyright 2026 Certen Protocol
//
// The transaction types whose executor decides who may sign, or when the transaction is ready, by itself (docs/proof/G1_CROSS_PARTITION.md
// D6 g1_executor_override_unsupported; RB9 verifier round VA, finding DEF-1).
//
// The re-evaluation of a vote (xtimeline.go) implements the DEFAULT authorization rule of the executor, plus the two things the default
// rule is extended by that the verifier models explicitly: the authorities a transaction adds (Header.Authorities and
// protocol.Transaction.GetAdditionalAuthorities) and protocol.TransactionType.RequireAuthorization. A body type whose executor replaces
// the rule (an AuthorityIsAccepted / TransactionIsReady that does not fall back, a SignerCanSign that refuses a signer the default rule
// accepts, an AuthorityWillVote) is judged by a rule this verifier does not implement, so a document about it is refused by name, at the
// partition and block it was judged at, BEFORE any vote is re-evaluated. This table is the single source: the capture
// (pkg/proofv2shadow collect.go) and the verifier (verify21) both read it.
//
// Audit of the executor at the pinned Accumulate commit e1d1db9ebb7c (internal/core/execute/v2/chain; every type that implements
// SignerValidator, SignerCanSignValidator or AuthorityValidator):
//
//	CreateIdentity         create_identity.go:24-77   SignerCanSign, AuthorityIsAccepted, TransactionIsReady: anyone may sign for a root identity
//	CreateLiteTokenAccount create_lite_token_account.go:49-66   anyone may create a lite token account (no authority is asked)
//	CreateKeyBook          create_key_book.go:23-38   additionalAuthorities(body.Authorities)
//	CreateTokenAccount     create_token_account.go:29-44   additionalAuthorities(body.Authorities)
//	CreateDataAccount      create_data_account.go:25-40   additionalAuthorities(body.Authorities)
//	CreateToken            create_token.go:23-38   additionalAuthorities(body.Authorities)
//	ReleaseLockedOperation release_locked_operation.go:37-71   a lite principal is authorized by its lite identity alone
//	UpdateKey              update_key.go:28-100   AuthorityIsAccepted refuses every origin but the principal and its delegates, AuthorityWillVote,
//	                       TransactionIsReady: the initiator decides
//	UpdateKeyPage          update_key_page.go:27-78   SignerCanSign refuses a lower-priority page of the same book and an own-allowed-operations
//	                       change; AuthorityIsAccepted/TransactionIsReady for the delegates it adds
//	NetworkMaintenance     network_maintenance.go:21-70   dn.acme/operators authorizes a partition ADI's transaction when the ADI's authority set
//	                       is exactly one enabled partition book (it falls back otherwise): the rule depends on a fact about the principal ADI
//	                       the verifier does not re-derive, and the authority that votes is not in the principal's list
//	WriteData              write_data.go:35-60   lite data account: one vote suffices. NOT an override here: principalAuthorities returns no
//	                       authority for a lite data account, which is the all-authorities-disabled rule the verifier implements (any one
//	                       vote), and a non-lite WriteData falls back to the default rule.
//	UpdateAccountAuth      update_account_auth.go:26-50   additionalAuthorities(the authorities the operations add), then the default rule.
//	                       NOT an override by TYPE: that is exactly Transaction.GetAdditionalAuthorities (protocol/transaction.go), which the verifier
//	                       evaluates as required voters, and RequireAuthorization (protocol/access_control.go) is the only type for which it is true,
//	                       which the verifier implements (an authority listed as disabled still has to accept). But it is the one modelled type
//	                       whose body REWRITES the set the verifier reads: the executor required the principal's authority set BEFORE the
//	                       transaction (the signatures were admitted, and the transaction found ready, against it), whereas the verifier reads the
//	                       principal from the account proven at the anchor block, which is the set AFTER it executed (RB9-K, verifier round VR).
//	                       What is modelled and what is refused, by operation kind (update_account_auth.go Execute; protocol.AccountAuthOperation
//	                       has exactly these four kinds):
//	                         AddAccountAuthority     MODELLED. The authority is new (a duplicate fails the transaction), so the set before is the
//	                                                 set after without it, and the requirement (before-set plus the added authorities) equals the
//	                                                 after-set the verifier reads. One case cannot be derived: when the before-set is EMPTY the
//	                                                 principal inherited its parent's authorities, which the document does not carry (the after-set
//	                                                 is exactly the added authorities): refused by name (refuseUpdateAccountAuthInherited).
//	                         EnableAccountAuthority  MODELLED. They change only the authority's Disabled flag. RequireAuthorization is true for this
//	                         DisableAccountAuthority type, so the executor (transaction.go ignoreDisabled) and the verifier (xtimeline.go require) both
//	                                                 require every listed authority, disabled or not: the flag is not read, and the all-disabled
//	                                                 mode never applies, so before and after give one requirement.
//	                         RemoveAccountAuthority  REFUSED by name. The authority was required before and is gone after, and its entry (and so
//	                                                 the pages the document would have to carry for it) cannot be recovered from the body;
//	                                                 removing the last authority also makes the principal inherit. refuseExecutorOverride.
//	                         any other kind          REFUSED by name (a kind the executor adds later is not modelled until it is audited).
//
// CreateKeyBook, CreateTokenAccount, CreateDataAccount and CreateToken are the same additionalAuthorities extension as UpdateAccountAuth;
// they stay refused by name, exactly as the capture has refused them since RB9-B, until their documents are modelled (finding
// RB9-J1-F1 in the check-in): raising them is a separate change that needs a vector per type.
package proofv2

import (
	"slices"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// executorOverrides are the body types of the audit above that are refused by name.
var executorOverrides = map[protocol.TransactionType]bool{
	protocol.TransactionTypeCreateIdentity:         true,
	protocol.TransactionTypeCreateLiteTokenAccount: true,
	protocol.TransactionTypeCreateKeyBook:          true,
	protocol.TransactionTypeCreateTokenAccount:     true,
	protocol.TransactionTypeCreateDataAccount:      true,
	protocol.TransactionTypeCreateToken:            true,
	protocol.TransactionTypeReleaseLockedOperation: true,
	protocol.TransactionTypeUpdateKey:              true,
	protocol.TransactionTypeUpdateKeyPage:          true,
	protocol.TransactionTypeNetworkMaintenance:     true,
}

// HasExecutorOverride says whether the executor decides who may sign a transaction of this body type by a rule other than the default
// one (the table above). It is the one function the capture and the verifier ask.
func HasExecutorOverride(t protocol.TransactionType) bool { return executorOverrides[t] }

// ExecutorOverrideTypes returns the refused body types (a copy), in ascending order of the type's number, for a test that must cover
// every one: the same list, in the same order, on every call (RB9-L).
func ExecutorOverrideTypes() []protocol.TransactionType {
	out := make([]protocol.TransactionType, 0, len(executorOverrides))
	for t := range executorOverrides {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// refuseExecutorOverride is the verifier's gate (D6): a carried transaction of an override type is refused before the vote is
// re-evaluated, with the partition and block of the transaction.
func refuseExecutorOverride(txn *protocol.Transaction, x xAnchor) error {
	if txn == nil || txn.Body == nil {
		return nil
	}
	if executorOverrides[txn.Body.Type()] {
		return refusal21(StateExecutorOverrideUnsupported, x.id, x.block,
			"%v has an executor override of who may sign; the default rule is not what judged it (see xoverride.go)", txn.Body.Type())
	}
	// UpdateAccountAuth rewrites the authority set the verifier reads: only the operations that can be inverted from the body are modelled.
	if body, ok := txn.Body.(*protocol.UpdateAccountAuth); ok {
		for _, op := range body.Operations {
			switch op.(type) {
			case *protocol.AddAccountAuthorityOperation, *protocol.EnableAccountAuthOperation, *protocol.DisableAccountAuthOperation:
			default:
				return refusal21(StateExecutorOverrideUnsupported, x.id, x.block,
					"UpdateAccountAuth operation %v rewrites the principal's authority set in the transaction, and the set the executor required (before it) cannot be derived from the set proven at the anchor block (see xoverride.go)", op.Type())
			}
		}
	}
	return nil
}

// refuseUpdateAccountAuthInherited is the one case of a modelled UpdateAccountAuth the proven principal cannot give the requirement of: the
// principal's own authority list, as proven after the transaction, holds only authorities the transaction added. It listed none before, so
// the executor required the authorities it inherited from its parent (internal/core/block/shared), which the document does not carry.
func refuseUpdateAccountAuthInherited(txn *protocol.Transaction, own []protocol.AuthorityEntry, x xAnchor) error {
	if txn == nil {
		return nil
	}
	body, ok := txn.Body.(*protocol.UpdateAccountAuth)
	if !ok {
		return nil
	}
	added := map[string]bool{}
	for _, op := range body.Operations {
		if a, ok := op.(*protocol.AddAccountAuthorityOperation); ok && a.Authority != nil {
			added[lk(a.Authority)] = true
		}
	}
	if len(added) == 0 || len(own) == 0 {
		return nil
	}
	for _, e := range own {
		if !added[lk(e.Url)] {
			return nil
		}
	}
	return refusal21(StateExecutorOverrideUnsupported, x.id, x.block,
		"UpdateAccountAuth adds the first authorities of an account that listed none: the executor required the authorities it inherited from its parent, which the document does not carry (see xoverride.go)")
}
