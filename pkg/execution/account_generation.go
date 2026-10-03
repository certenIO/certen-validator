// Copyright 2026 Certen Protocol

package execution

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// memberAccount is a member's account as the batch path reads and settles it, of the generation its chain is on
// (AccountLeafVersionOf, RB5-F57): CertenAccountV7_2 on a v3 chain, CertenAccountV7_3 on a v4 chain. Exactly one
// generation is bound per chain; an account of the other generation fails its LEAF_DOMAIN check by name.
type memberAccount interface {
	Address() common.Address
	LeafDomain(opts *bind.CallOpts) (string, error)
	IsKeylessOwner(opts *bind.CallOpts) (bool, error)
	ADIURLHash(opts *bind.CallOpts) ([32]byte, error)
	AuthorityLevelOfPage(opts *bind.CallOpts, book [32]byte, page uint64) (uint8, error)
	IsLeafConsumed(opts *bind.CallOpts, leaf [32]byte) (bool, error)
	// MemberLeaf is the account's own leaf for the member's leaf input.
	MemberLeaf(opts *bind.CallOpts, in BatchLeafInput) ([32]byte, error)
	// Settle sends the member's execution: its legs under proof, which for a v4 account also carries the window of in.
	Settle(opts *bind.TransactOpts, legs []LegExecution, proof contracts.AccountProofV7_2, in BatchLeafInput) (*types.Transaction, error)
}

// bindMemberAccount binds the member's account as the generation its chain is on.
func bindMemberAccount(chainID int64, account common.Address, backend bind.ContractBackend) (memberAccount, AccountLeafVersion, error) {
	version, err := AccountLeafVersionOf(chainID)
	if err != nil {
		return nil, "", err
	}
	switch version {
	case AccountLeafV3:
		a, err := contracts.NewCertenAccountV7_2(account, backend)
		if err != nil {
			return nil, "", err
		}
		return accountV7_2{a}, version, nil
	case AccountLeafV4:
		a, err := contracts.NewCertenAccountV7_3(account, backend)
		if err != nil {
			return nil, "", err
		}
		return accountV7_3{a}, version, nil
	default:
		return nil, "", fmt.Errorf("%w: %q on chain %d", ErrUnknownAccountLeafVersion, version, chainID)
	}
}

type accountV7_2 struct{ *contracts.CertenAccountV7_2 }

func (a accountV7_2) MemberLeaf(opts *bind.CallOpts, in BatchLeafInput) ([32]byte, error) {
	if in.NotBefore != 0 || in.NotAfter != 0 {
		return [32]byte{}, fmt.Errorf("member %s carries a window, which a CertenAccountV7_2 (v3) leaf does not bind", in.IntentID)
	}
	return a.ComputeLeaf(opts, in.ExecutionCommitment, in.OperationID, in.AuthorityBook, in.AuthorityPage)
}

func (a accountV7_2) Settle(opts *bind.TransactOpts, legs []LegExecution, proof contracts.AccountProofV7_2, in BatchLeafInput) (*types.Transaction, error) {
	if in.NotBefore != 0 || in.NotAfter != 0 {
		return nil, fmt.Errorf("member %s carries a window, which a CertenAccountV7_2 (v3) proof does not carry", in.IntentID)
	}
	if len(legs) > 1 {
		targets, values, datas := legArrays(legs)
		return a.BatchExecuteGovernanceProofDirect(opts, targets, values, datas, proof)
	}
	if len(legs) == 0 {
		return nil, fmt.Errorf("member %s has no legs", in.IntentID)
	}
	leg := legs[0]
	return a.ExecuteGovernanceProofDirect(opts, leg.Target, callValue(leg.Value), leg.Data, proof)
}

type accountV7_3 struct{ *contracts.CertenAccountV7_3 }

func (a accountV7_3) MemberLeaf(opts *bind.CallOpts, in BatchLeafInput) ([32]byte, error) {
	if in.NotAfter == 0 {
		return [32]byte{}, fmt.Errorf("%w: member %s has no notAfter for its v4 leaf", ErrNoMemberWindow, in.IntentID)
	}
	return a.ComputeLeaf(opts, in.ExecutionCommitment, in.OperationID, in.AuthorityBook, in.AuthorityPage, in.NotBefore, in.NotAfter)
}

func (a accountV7_3) Settle(opts *bind.TransactOpts, legs []LegExecution, proof contracts.AccountProofV7_2, in BatchLeafInput) (*types.Transaction, error) {
	if in.NotAfter == 0 {
		return nil, fmt.Errorf("%w: member %s has no notAfter for its v4 proof", ErrNoMemberWindow, in.IntentID)
	}
	p := contracts.AccountProofV7_3Of(proof, in.NotBefore, in.NotAfter)
	if len(legs) > 1 {
		targets, values, datas := legArrays(legs)
		return a.BatchExecuteGovernanceProofDirect(opts, targets, values, datas, p)
	}
	if len(legs) == 0 {
		return nil, fmt.Errorf("member %s has no legs", in.IntentID)
	}
	leg := legs[0]
	return a.ExecuteGovernanceProofDirect(opts, leg.Target, callValue(leg.Value), leg.Data, p)
}
