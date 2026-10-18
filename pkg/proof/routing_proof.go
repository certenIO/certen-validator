// Copyright 2026 Certen Protocol
//
// The Directory's routing table, proven (docs/proof/G1_CROSS_PARTITION.md D5).
//
// A page of evidence 2.1 names the partition it is proven through. That name is DERIVED from the partition anchor the page's
// receipt ends at, and must equal the partition the network routes the page's URL to. The routing table is the Directory's
// acc://dn.acme/routing data account, proven here with the machinery that proves dn.acme/network and dn.acme/globals: an
// AccountStateProof into the state tree root of the same quorum-certified anchor.

package proof

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RoutingAccountURL is the account the routing table lives in.
const RoutingAccountURL = "acc://dn.acme/routing"

// BuildRoutingProofAt proves acc://dn.acme/routing as of a Directory block into the state tree root a quorum-certified anchor
// carries for that block (the root BuildValidatorSetProofAt proves the network and globals accounts into). A state receipt for a
// past block runs from the account's state through that block's state tree root and on to a later root; the part up to stateRoot
// is the proof. A receipt that never passes through stateRoot is refused: it was not read at the certified block. The built
// proof is verified before it is returned, so a malformed proof never reaches storage.
func BuildRoutingProofAt(ctx context.Context, q AccumulateQuerier, block uint64, stateRoot [32]byte) (*AccountStateProof, error) {
	root := hex.EncodeToString(stateRoot[:])
	a, err := fetchAccountStateProofWith(ctx, q, RoutingAccountURL, false, map[string]any{"forHeight": block})
	if err != nil {
		return nil, fmt.Errorf("routing account: %w", err)
	}
	r, ok := ReceiptPrefixTo(a.StateReceipt, root)
	if !ok {
		return nil, fmt.Errorf("%s as of DN %d: the state receipt never passes through the certified state root %s", RoutingAccountURL, block, short(root))
	}
	a.StateReceipt = r
	if _, _, err := VerifyRoutingProof(a, root); err != nil {
		return nil, fmt.Errorf("built a routing proof that does not verify: %w", err)
	}
	return a, nil
}

// ProvenRoot is the state tree root the account is proven into: the state hashes to the proven leaf, the path recomputes, and
// the account's chain roots are bound to the receipt.
func (a *AccountStateProof) ProvenRoot() (string, error) { return a.verify() }

// VerifyRoutingProof checks a routing account proof offline against the state tree root a certified anchor commits to (hex32)
// and returns the routing table it proves with the height of the account's main chain. The account must be the routing
// account, proven into exactly that root, holding one data entry that decodes as a RoutingTable. A main chain of height 1 is
// the genesis write: the table has never changed, so it holds at every block (R9 M10). Any other height means the table was
// rewritten after genesis, and what it was at an earlier partition block is not proven here.
func VerifyRoutingProof(a *AccountStateProof, boundStateRoot string) (*protocol.RoutingTable, uint64, error) {
	if a == nil {
		return nil, 0, fmt.Errorf("routing proof: absent")
	}
	if !strings.EqualFold(a.AccountURL, RoutingAccountURL) {
		return nil, 0, fmt.Errorf("routing proof is for %s, not %s", a.AccountURL, RoutingAccountURL)
	}
	proven, err := a.ProvenRoot()
	if err != nil {
		return nil, 0, fmt.Errorf("routing proof: %w", err)
	}
	bound, err := chained_proof.MustHex32Lower(boundStateRoot, "boundStateRoot")
	if err != nil {
		return nil, 0, fmt.Errorf("routing proof: %w", err)
	}
	if proven != bound {
		return nil, 0, fmt.Errorf("routing proof: the account is proven into %s, not the certified state root %s", short(proven), short(bound))
	}
	raw, err := hexBytes(a.AccountState, "routing.accountState")
	if err != nil {
		return nil, 0, err
	}
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("routing proof: %w", err)
	}
	if !strings.EqualFold(acct.GetUrl().String(), RoutingAccountURL) {
		return nil, 0, fmt.Errorf("routing proof: the proven state is %v, not %s", acct.GetUrl(), RoutingAccountURL)
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok || da.Entry == nil || len(da.Entry.GetData()) != 1 {
		return nil, 0, fmt.Errorf("routing proof: %s is %T, not a one-entry data account", RoutingAccountURL, acct)
	}
	table := new(protocol.RoutingTable)
	if err := table.UnmarshalBinary(da.Entry.GetData()[0]); err != nil {
		return nil, 0, fmt.Errorf("routing proof: the entry is not a routing table: %w", err)
	}
	if len(table.Routes) == 0 {
		return nil, 0, fmt.Errorf("routing proof: the table has no routes")
	}
	height, ok := MainChainHeight(a.Chains)
	if !ok {
		return nil, 0, fmt.Errorf("routing proof: no main chain on the routing account")
	}
	return table, height, nil
}
