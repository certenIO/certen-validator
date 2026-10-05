// Copyright 2026 Certen Protocol
//
// G1(a), the key pages as they were (docs/proof/PROOF_V2.md §5.2), bound to the transaction's own block.
//
// The partition's anchor for block B (the block the transaction executed in) carries B, the partition's root chain
// anchor and its state tree anchor together. That anchor transaction is proven into the same certified Directory root
// as the transaction, so the verifier learns B and both roots from what the Directory executed, without trusting a
// partition signer set. The transaction's receipt must pass through the anchor's root chain anchor (it executed in B),
// and each page's receipt must end at the anchor's state tree anchor (it is the page as of B). Measured live
// 2026-10-04: the state as of B passes through that root; the state as of B-1 or B+1 does not.
//
// A page's state as of B is served only inside the public node's ~900-block retention, so it is captured at discovery
// (CapturePage) with the receipt the node returns, and trimmed to the anchor's state root when the proof is built.

package proofv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// PartitionAnchor is the transaction's partition's anchor for its block, and the receipt proving the anchor
// transaction into the certified Directory root.
type PartitionAnchor struct {
	Message string `json:"message"` // the delivered messaging.SequencedMessage, binary, hex
	Receipt string `json:"receipt"` // from the anchor transaction's hash to the certified root (binary merkle.Receipt, hex)
}

// PageState is an account's main state as of the transaction's block, with a receipt to that block's state root.
type PageState struct {
	URL     string `json:"url"`
	State   string `json:"state"`   // the account's binary encoding, hex
	Receipt string `json:"receipt"` // from sha256(State) (binary merkle.Receipt, hex)
}

// CapturePage reads an account's state as of block, with the node's receipt. It must run while block is inside the
// node's retention; the receipt is trimmed to the block's state root when the proof is built.
func (b *Builder) CapturePage(ctx context.Context, account string, block uint64) (*PageState, error) {
	u, err := url.Parse(account)
	if err != nil {
		return nil, err
	}
	q, err := b.C.Query(ctx, u, &api.DefaultQuery{IncludeReceipt: &api.ReceiptOptions{ForHeight: block}})
	if err != nil {
		return nil, fmt.Errorf("%s as of block %d: %w", account, block, err)
	}
	ar, ok := q.(*api.AccountRecord)
	if !ok || ar.Receipt == nil {
		return nil, fmt.Errorf("%s as of block %d: got %T without a receipt", account, block, q)
	}
	if !ar.Receipt.StartsAtMainState {
		return nil, fmt.Errorf("%s as of block %d: the receipt does not start at the account's main state", account, block)
	}
	state, err := ar.Account.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(state)
	if !bytes.Equal(ar.Receipt.Start, sum[:]) || !ar.Receipt.Validate(nil) {
		return nil, fmt.Errorf("%s as of block %d: the receipt does not prove the served state", account, block)
	}
	rb, err := ar.Receipt.Receipt.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &PageState{URL: account, State: hex.EncodeToString(state), Receipt: hex.EncodeToString(rb)}, nil
}

// trimPage cuts a captured page receipt at the state root, refusing one that never passes through it.
func trimPage(p *PageState, stateRoot []byte) (*PageState, error) {
	r, err := decodeReceipt(p.Receipt)
	if err != nil {
		return nil, err
	}
	t := prefixTo(r, stateRoot)
	if t == nil {
		return nil, fmt.Errorf("%s: the captured state never passes through the block's state root %x: it is not the state as of the transaction's block", p.URL, stateRoot)
	}
	rb, err := t.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &PageState{URL: p.URL, State: p.State, Receipt: hex.EncodeToString(rb)}, nil
}

// anchorBody decodes a delivered partition anchor and returns its body and transaction hash.
func anchorBody(msgHex string) (*protocol.BlockValidatorAnchor, *messaging.SequencedMessage, []byte, error) {
	raw, err := hex.DecodeString(msgHex)
	if err != nil {
		return nil, nil, nil, err
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return nil, nil, nil, fmt.Errorf("partition anchor: %w", err)
	}
	txm, ok := seq.Message.(*messaging.TransactionMessage)
	if !ok {
		return nil, nil, nil, fmt.Errorf("partition anchor is %T, not a transaction", seq.Message)
	}
	body, ok := txm.Transaction.Body.(*protocol.BlockValidatorAnchor)
	if !ok {
		return nil, nil, nil, fmt.Errorf("partition anchor is %v, not a block validator anchor", txm.Transaction.Body.Type())
	}
	if !protocol.DnUrl().Equal(seq.Destination) || !protocol.DnUrl().JoinPath(protocol.AnchorPool).Equal(txm.Transaction.Header.Principal) {
		return nil, nil, nil, fmt.Errorf("partition anchor is not delivered to the Directory's anchor pool")
	}
	return body, seq, txm.Transaction.GetHash(), nil
}

// verifyPage checks one page against the block's state root and returns the account as proven.
func verifyPage(p *PageState, stateRoot []byte) (protocol.Account, error) {
	state, err := hex.DecodeString(p.State)
	if err != nil {
		return nil, err
	}
	r, err := decodeReceipt(p.Receipt)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(state)
	if !bytes.Equal(r.Start, sum[:]) {
		return nil, fmt.Errorf("%s: the receipt does not start at the state's hash", p.URL)
	}
	if !bytes.Equal(r.Anchor, stateRoot) {
		return nil, fmt.Errorf("%s: the receipt ends at %x, not the block's state root %x", p.URL, r.Anchor, stateRoot)
	}
	if !r.Validate(nil) {
		return nil, fmt.Errorf("%s: the receipt does not validate", p.URL)
	}
	acct, err := protocol.UnmarshalAccount(state)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.URL, err)
	}
	if !strings.EqualFold(acct.GetUrl().String(), p.URL) {
		return nil, fmt.Errorf("the proven state is %v, not %s", acct.GetUrl(), p.URL)
	}
	return acct, nil
}

// prefixTo returns the leading steps of r ending at value, or nil when no intermediate value equals it.
func prefixTo(r *merkle.Receipt, value []byte) *merkle.Receipt {
	h := append([]byte(nil), r.Start...)
	for i := 0; ; i++ {
		if bytes.Equal(h, value) {
			return &merkle.Receipt{Start: r.Start, Anchor: append([]byte(nil), h...), Entries: r.Entries[:i]}
		}
		if i == len(r.Entries) {
			return nil
		}
		e := r.Entries[i]
		var s [32]byte
		if e.Right {
			s = sha256.Sum256(append(append([]byte(nil), h...), e.Hash...))
		} else {
			s = sha256.Sum256(append(append([]byte(nil), e.Hash...), h...))
		}
		h = s[:]
	}
}

// TxBlock returns the block on the transaction's partition whose root chain anchor its receipt first reaches: the
// block to capture its pages at.
func (b *Builder) TxBlock(ctx context.Context, account, txHash string) (uint64, error) {
	l1, err := chained_proof.NewLayer1Builder(b.C, false).Build(ctx, account, txHash)
	if err != nil {
		return 0, err
	}
	return l1.BVNMinorBlockIndex, nil
}
