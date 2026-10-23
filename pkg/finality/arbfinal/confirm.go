// Copyright 2026 Certen Protocol

package arbfinal

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Confirmed is the proven confirmation of the assertion: the route the transaction took (the Rollup called directly, or through
// a ValidatorWallet) and its hash. Only an honest confirmation is returned; every other outcome is a named state.
type Confirmed struct {
	Route  string
	TxHash [32]byte
}

// The routes of an honest confirmation.
const (
	RouteDirect = "direct"
	RouteWallet = "wallet"
)

// proveLeaf verifies that root commits to a leaf at key (rlp(index)) using the shared node set and returns the leaf bytes. A
// missing or inconsistent node, an absent key, or a leaf that differs from the carried raw bytes is a failure.
func proveLeaf(root common.Hash, index uint32, nodes [][]byte, carried []byte) bool {
	db := memorydb.New()
	for _, n := range nodes {
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			return false
		}
	}
	key, err := rlp.EncodeToBytes(uint64(index))
	if err != nil {
		return false
	}
	v, err := trie.VerifyProof(root, key, db)
	if err != nil || v == nil {
		return false
	}
	return bytes.Equal(v, carried)
}

// classifyConfirmation is 5.7 O4. The transaction at confTxIndex and its receipt are MPT-proven under K's transactionsRoot and
// receiptsRoot; the receipt status is 1; it holds a log of the Rollup with topic0 AssertionConfirmed and topic1 the assertion
// hash. The path is honest iff the Rollup was called with confirmAssertion and no AssertionForceConfirmed log exists, or a callee
// PROVEN to be a ValidatorWallet (ProveWallet, at K) was called through an entry point that carries a call to the Rollup with
// confirmAssertion, the receipt holds no force log and anyTrustFastConfirmer is the zero address at K. A force selector or the force
// log is confirmed_by_owner_force{force}; the fast selectors are confirmed_by_owner_force{fast}, both also through a proven wallet; a
// callee that is not proven a ValidatorWallet, whatever its calldata decodes to, and anything else, is confirmation_path_unproven{indirect}.
func classifyConfirmation(arb *Pins, kb ethl1.L1Block, kHeader finality.HeaderFields, acctK *ethproof.AccountState, assertion [32]byte, e Evidence) (Confirmed, error) {
	var out Confirmed
	if !proveLeaf(common.Hash(kHeader.TransactionRoot), e.ConfTxIndex, e.Nodes, e.ConfTxRaw) {
		return out, TxProofInvalid("tx")
	}
	if !proveLeaf(common.Hash(kHeader.ReceiptsRoot), e.ConfTxIndex, e.Nodes, e.ConfReceiptRaw) {
		return out, TxProofInvalid("receipt")
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(e.ConfTxRaw); err != nil {
		return out, TxProofInvalid("tx")
	}
	var rc types.Receipt
	if err := rc.UnmarshalBinary(e.ConfReceiptRaw); err != nil {
		return out, TxProofInvalid("receipt")
	}
	txHash := [32]byte(tx.Hash())
	out.TxHash = txHash
	if rc.Status != types.ReceiptStatusSuccessful {
		return out, ConfirmationUnproven(ConfirmReceiptStatus, txHash, kb.Number)
	}
	var confirmed, forced bool
	for _, l := range rc.Logs {
		if l.Address != arb.Rollup || len(l.Topics) == 0 {
			continue
		}
		switch {
		case l.Topics[0] == arb.Topic.Confirmed && len(l.Topics) > 1 && l.Topics[1] == common.Hash(assertion):
			confirmed = true
		case l.Topics[0] == arb.Topic.ForceConfirmed:
			forced = true
		}
	}
	if !confirmed {
		return out, ConfirmationUnproven(ConfirmLogMissing, txHash, kb.Number)
	}
	if forced {
		return out, ConfirmedByOwnerForce(PathForce, txHash, kb.Number)
	}
	// [r2:E1FIX L1] a contract creation has no callee: its data is init code, not calldata, so no selector of it names an entry point
	// of the Rollup or of a ValidatorWallet.
	if tx.To() == nil {
		return out, ConfirmationUnproven(ConfirmIndirect, txHash, kb.Number)
	}
	input := tx.Data()
	sel, _ := selectorOf(input) // below four bytes sel is zero, which LoadPins forbids as a pinned selector, so nothing matches
	if *tx.To() == arb.Rollup {
		switch sel {
		case arb.Sel.Confirm:
			out.Route = RouteDirect
			return out, nil
		case arb.Sel.Force:
			return out, ConfirmedByOwnerForce(PathForce, txHash, kb.Number)
		case arb.Sel.Fast, arb.Sel.FastNew:
			return out, ConfirmedByOwnerForce(PathFast, txHash, kb.Number)
		}
		return out, ConfirmationUnproven(ConfirmIndirect, txHash, kb.Number)
	}
	// The wallet route. The calldata of a transaction that has a callee is a ValidatorWallet entry point only if the callee IS one:
	// [r3:E1RAISE] that is proven, not read from the calldata. The callee's account is proven under K's state root, its code hash must
	// be the pinned ValidatorWallet proxy code, its EIP-1967 implementation slot must hold the pinned implementation, and that
	// implementation's account (proven under the same root) must have the pinned ValidatorWallet logic code hash. Anything not
	// established is confirmation_path_unproven{indirect}: a statement about code the verifier has not identified, never a weaker
	// level and never the label "wallet".
	calls, ok := decodeWalletCalls(arb, sel, input)
	if !ok {
		if arb.isWalletSelector(sel) {
			return out, ConfirmationUnproven(ConfirmWalletUndecodable, txHash, kb.Number)
		}
		return out, ConfirmationUnproven(ConfirmIndirect, txHash, kb.Number)
	}
	if !ProveWallet(arb, common.Hash(kb.StateRoot), *tx.To(), e.Nodes) {
		return out, ConfirmationUnproven(ConfirmIndirect, txHash, kb.Number)
	}
	var found bool
	for _, c := range calls {
		cs, hasCS := selectorOf(c.Data)
		if c.Dest != arb.Rollup || !hasCS {
			continue
		}
		switch cs {
		case arb.Sel.Confirm:
			found = true
		case arb.Sel.Force:
			return out, ConfirmedByOwnerForce(PathForce, txHash, kb.Number)
		case arb.Sel.Fast, arb.Sel.FastNew:
			return out, ConfirmedByOwnerForce(PathFast, txHash, kb.Number)
		}
	}
	if !found {
		return out, ConfirmationUnproven(ConfirmWalletNoConfirm, txHash, kb.Number)
	}
	// A wallet confirmation is honest only while no fast confirmer exists at K (annex A3, spec r2:L6).
	fw, err := ethproof.VerifySlot(acctK.StorageRoot, w32(arb.Layout.FastConfirmerSlot), e.Nodes)
	if err != nil {
		return out, StateProofInvalid("slot")
	}
	v := new(big.Int).SetBytes(fw[:])
	v.Rsh(v, uint(arb.Layout.FastConfirmerShiftBits))
	v.And(v, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1)))
	if v.Sign() != 0 {
		return out, ConfirmationUnproven(ConfirmFastConfirmerSet, txHash, kb.Number)
	}
	out.Route = RouteWallet
	return out, nil
}

// ProveWallet is the identity rule of the wallet route (V2_SPEC_S7 5.7 O4, amendment r3): wallet is a ValidatorWallet at the state
// whose root is stateRoot, proven from nodes, iff
//
//  1. the account proof of wallet resolves from stateRoot to an existing account whose code hash has the logic_pins role
//     validator_wallet_proxy (the exact runtime code of the OpenZeppelin TransparentUpgradeableProxy that
//     ValidatorWalletCreator.createWallet deploys: it has no immutables, so one code hash covers every wallet);
//  2. the storage proof of the EIP-1967 implementation slot (proxy_slots.wallet_impl) resolves from that account's storage root to
//     exactly the 32-byte word of the pinned implementation address (confirm_path.validator_wallet_impl, high 12 bytes zero);
//  3. the account proof of that implementation resolves from stateRoot to an existing account whose code hash has the role
//     validator_wallet_logic (the exact runtime code of the template, which embeds its own address, so it names one deployment).
//
// A wallet account that is not proven, a missing or foreign proof node, an externally owned account, any other contract, a proxy of
// the same code over another implementation, and an implementation of other code all fail. It is exported for the builder, which
// must capture exactly the nodes this reads.
func ProveWallet(arb *Pins, stateRoot common.Hash, wallet common.Address, nodes [][]byte) bool {
	acct, err := ethproof.VerifyAccount(stateRoot, wallet, nodes)
	if err != nil || !acct.Exists || arb.roleOf(acct.CodeHash) != RoleWalletProxy {
		return false
	}
	word, err := ethproof.VerifySlot(acct.StorageRoot, arb.WalletImplSlot, nodes)
	if err != nil || word != common.BytesToHash(arb.WalletImpl[:]) {
		return false
	}
	impl, err := ethproof.VerifyAccount(stateRoot, arb.WalletImpl, nodes)
	return err == nil && impl.Exists && arb.roleOf(impl.CodeHash) == RoleWalletLogic
}

// WalletCallee is the callee of a confirmation transaction that takes the wallet route's decoding: a transaction with a callee other
// than the Rollup whose calldata decodes, canonically, as one of the four ValidatorWallet entry points. The builder captures the
// proofs ProveWallet reads for exactly this address; it is not an identity claim.
func WalletCallee(arb *Pins, tx *types.Transaction) (common.Address, bool) {
	if tx == nil || tx.To() == nil || *tx.To() == arb.Rollup {
		return common.Address{}, false
	}
	sel, _ := selectorOf(tx.Data())
	if _, ok := decodeWalletCalls(arb, sel, tx.Data()); !ok {
		return common.Address{}, false
	}
	return *tx.To(), true
}

// selectorOf is the first four bytes of calldata; ok is false when there are fewer (no selector).
func selectorOf(b []byte) (sel [4]byte, ok bool) {
	if len(b) < 4 {
		return sel, false
	}
	copy(sel[:], b[:4])
	return sel, true
}

func (p *Pins) isWalletSelector(sel [4]byte) bool {
	return sel == p.Sel.WalletTx || sel == p.Sel.WalletTxs || sel == p.Sel.WalletTxRefund || sel == p.Sel.WalletTxsRef
}

// WalletCall is one call of a ValidatorWallet entry point.
type WalletCall struct {
	Dest   common.Address
	Data   []byte
	Amount *big.Int
}

var (
	tBytes     = mustType("bytes")
	tAddress   = mustType("address")
	tUint      = mustType("uint256")
	tBytesArr  = mustType("bytes[]")
	tAddrArr   = mustType("address[]")
	tUintArr   = mustType("uint256[]")
	argsTx     = abi.Arguments{{Type: tBytes}, {Type: tAddress}, {Type: tUint}}
	argsTxRef  = abi.Arguments{{Type: tAddress}, {Type: tBytes}, {Type: tAddress}, {Type: tUint}}
	argsTxs    = abi.Arguments{{Type: tBytesArr}, {Type: tAddrArr}, {Type: tUintArr}}
	argsTxsRef = abi.Arguments{{Type: tAddress}, {Type: tBytesArr}, {Type: tAddrArr}, {Type: tUintArr}}
)

func mustType(s string) abi.Type {
	t, err := abi.NewType(s, "", nil)
	if err != nil {
		panic(err)
	}
	return t
}

// decodeWalletCalls decodes the calls of a ValidatorWallet entry point (nitro-contracts v3.1.0 src/rollup/ValidatorWallet.sol):
// executeTransaction(bytes,address,uint256), executeTransactions(bytes[],address[],uint256[]) and the two gas-refunder variants
// that prepend an address. ok is false when sel is not an entry point or the arguments do not decode (the encoding must be
// canonical: re-encoding the decoded arguments reproduces the input).
func decodeWalletCalls(arb *Pins, sel [4]byte, input []byte) ([]WalletCall, bool) {
	var args abi.Arguments
	switch sel {
	case arb.Sel.WalletTx:
		args = argsTx
	case arb.Sel.WalletTxRefund:
		args = argsTxRef
	case arb.Sel.WalletTxs:
		args = argsTxs
	case arb.Sel.WalletTxsRef:
		args = argsTxsRef
	default:
		return nil, false
	}
	if len(input) < 4 {
		return nil, false
	}
	vals, err := args.Unpack(input[4:])
	if err != nil {
		return nil, false
	}
	if re, err := args.Pack(vals...); err != nil || !bytes.Equal(re, input[4:]) {
		return nil, false
	}
	switch sel {
	case arb.Sel.WalletTx:
		return []WalletCall{{Data: vals[0].([]byte), Dest: vals[1].(common.Address), Amount: vals[2].(*big.Int)}}, true
	case arb.Sel.WalletTxRefund:
		return []WalletCall{{Data: vals[1].([]byte), Dest: vals[2].(common.Address), Amount: vals[3].(*big.Int)}}, true
	}
	off := 0
	if sel == arb.Sel.WalletTxsRef {
		off = 1
	}
	data, dest, amt := vals[off].([][]byte), vals[off+1].([]common.Address), vals[off+2].([]*big.Int)
	if len(data) != len(dest) || len(data) != len(amt) {
		return nil, false
	}
	out := make([]WalletCall, len(data))
	for i := range data {
		out[i] = WalletCall{Data: data[i], Dest: dest[i], Amount: amt[i]}
	}
	return out, true
}
