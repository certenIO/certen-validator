// Copyright 2026 Certen Protocol
//
// The pending component of an account's state hash, recomputed from what the network serves (AGT-F81).
//
// Accumulate's state hasher is [main, secondary, chains, pending] (accumulate-core internal/database/observer_prod.go hashState). A page whose
// pending component is not empty used to be named unbound: the capture assumed 32 zero bytes. The component is a merkle hash of:
//   - each transaction pending on the account: its txid (AddTxID), then hashPendingV2 of it;
//   - when the account is a key page, each transaction pending on its KEY BOOK: hashPendingV2 of it (no txid);
// where hashPendingV2(txid) is, over the account's own record of that transaction, its validator signatures (each signature hash, ordered by public key),
// its credit payments (each hash, ordered by hash), its authority votes (each VoteEntry, ordered by authority) and its active signatures (each
// SignatureSetEntry, ordered by key index then delegation path). The API serves exactly those messages as the account's NON-historical messages of the
// transaction (internal/api/v3/load.go: Historical = !active), so the component can be rebuilt. It is still only a CANDIDATE: the capture accepts it
// only when H(chains || pending) is the receipt's second sibling, so the receipt proves it.

package proofv2

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/encoding"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// pendingSource is what the pending component needs from the network.
type pendingSource interface {
	// Pending lists the transactions pending on an account.
	Pending(ctx context.Context, account *url.URL) ([]*url.TxID, error)
	// Record is the transaction's record with its signature sets.
	Record(ctx context.Context, txid *url.TxID) (*api.MessageRecord[messaging.Message], error)
}

// pendingComponent rebuilds the pending component of account's state hash, hex. An empty component is 32 zero bytes (merkle.Hasher.MerkleHash).
func pendingComponent(ctx context.Context, src pendingSource, account protocol.Account) (string, error) {
	u := account.GetUrl()
	page, _ := account.(*protocol.KeyPage)
	var h merkle.Hasher
	own, err := src.Pending(ctx, u)
	if err != nil {
		return "", fmt.Errorf("pending on %v: %w", u, err)
	}
	for _, id := range own {
		h.AddTxID(id)
		if err := addPendingV2(ctx, src, &h, u, page, id); err != nil {
			return "", err
		}
	}
	if page != nil {
		book, err := src.Pending(ctx, page.GetAuthority())
		if err != nil {
			return "", fmt.Errorf("pending on %v: %w", page.GetAuthority(), err)
		}
		for _, id := range book {
			if err := addPendingV2(ctx, src, &h, u, page, id); err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.MerkleHash()), nil
}

type pendingVote struct {
	authority *url.URL
	hash      [32]byte
}

type pendingSigEntry struct {
	keyIndex uint64
	version  uint64
	path     []*url.URL
	hash     [32]byte
}

// addPendingV2 is hashPendingV2 over account's own record of txid, from the account's active messages as the API serves them.
func addPendingV2(ctx context.Context, src pendingSource, h *merkle.Hasher, account *url.URL, page *protocol.KeyPage, txid *url.TxID) error {
	rec, err := src.Record(ctx, txid)
	if err != nil {
		return fmt.Errorf("record of %v: %w", txid, err)
	}
	var validators []protocol.KeySignature
	var payments [][32]byte
	var votes []pendingVote
	var sigs []pendingSigEntry
	if rec.Signatures != nil {
		for _, set := range rec.Signatures.Records {
			if set == nil || set.Account == nil || !set.Account.GetUrl().Equal(account) || set.Signatures == nil {
				continue
			}
			for _, m := range set.Signatures.Records {
				if m == nil || m.Historical {
					continue
				}
				if m.Message == nil {
					return fmt.Errorf("%v: an active message of %v could not be read", txid, account)
				}
				hash := m.Message.Hash()
				switch msg := m.Message.(type) {
				case *messaging.CreditPayment:
					payments = append(payments, hash)
				case *messaging.BlockAnchor:
					ks, ok := msg.Signature.(protocol.KeySignature)
					if !ok {
						return fmt.Errorf("%v: a validator signature of %v is %T", txid, account, msg.Signature)
					}
					validators = append(validators, ks)
				case *messaging.SignatureMessage:
					if as, ok := msg.Signature.(*protocol.AuthoritySignature); ok {
						votes = append(votes, pendingVote{as.Authority, hash})
						continue
					}
					var path []*url.URL
					inner := msg.Signature
					for {
						d, ok := inner.(*protocol.DelegatedSignature)
						if !ok {
							break
						}
						path = append(path, d.Delegator)
						inner = d.Signature
					}
					ks, ok := inner.(protocol.KeySignature)
					if !ok {
						return fmt.Errorf("%v: an active signature of %v is %T", txid, account, inner)
					}
					if page == nil {
						return fmt.Errorf("%v: an active key signature is recorded on %v, which is not a key page", txid, account)
					}
					kh, err := protocol.PublicKeyHash(ks.GetPublicKey(), ks.Type())
					if err != nil {
						return fmt.Errorf("%v: key hash: %w", txid, err)
					}
					idx := -1
					for i, k := range page.Keys {
						if bytes.Equal(k.PublicKeyHash, kh) {
							idx = i
							break
						}
					}
					if idx < 0 {
						return fmt.Errorf("%v: the key of an active signature is not an entry of %v", txid, account)
					}
					sigs = append(sigs, pendingSigEntry{uint64(idx), ks.GetSignerVersion(), path, hash})
				default:
					return fmt.Errorf("%v: an active message of %v is %T, which the pending component does not cover", txid, account, msg)
				}
			}
		}
	}

	sort.Slice(validators, func(i, j int) bool {
		return bytes.Compare(validators[i].GetPublicKey(), validators[j].GetPublicKey()) < 0
	})
	sort.Slice(payments, func(i, j int) bool { return bytes.Compare(payments[i][:], payments[j][:]) < 0 })
	sort.Slice(votes, func(i, j int) bool { return votes[i].authority.Compare(votes[j].authority) < 0 })
	sort.Slice(sigs, func(i, j int) bool { return comparePendingSig(sigs[i], sigs[j]) < 0 })

	for _, v := range validators {
		h.AddHash((*[32]byte)(v.Hash()))
	}
	for _, p := range payments {
		h.AddHash2(p)
	}
	for _, v := range votes {
		var buf bytes.Buffer
		w := encoding.NewWriter(&buf)
		w.WriteUrl(1, v.authority)
		w.WriteHash(2, &v.hash)
		if _, _, err := w.Reset(nil); err != nil {
			return fmt.Errorf("vote entry: %w", err)
		}
		h.AddBytes(buf.Bytes())
	}
	for _, s := range sigs {
		var buf bytes.Buffer
		w := encoding.NewWriter(&buf)
		w.WriteUint(1, s.keyIndex)
		if s.version != 0 {
			w.WriteUint(2, s.version)
		}
		for _, p := range s.path {
			w.WriteUrl(3, p)
		}
		if s.hash != ([32]byte{}) {
			w.WriteHash(4, &s.hash)
		}
		if _, _, err := w.Reset(nil); err != nil {
			return fmt.Errorf("signature set entry: %w", err)
		}
		h.AddBytes(buf.Bytes())
	}
	return nil
}

// comparePendingSig is core's compareSignatureSetEntries: key index, then delegation path length, then the path.
func comparePendingSig(a, b pendingSigEntry) int {
	if a.keyIndex != b.keyIndex {
		if a.keyIndex < b.keyIndex {
			return -1
		}
		return 1
	}
	if len(a.path) != len(b.path) {
		return len(a.path) - len(b.path)
	}
	for i := range a.path {
		if c := a.path[i].Compare(b.path[i]); c != 0 {
			return c
		}
	}
	return 0
}

// apiPending is the live pendingSource over a v3 querier.
type apiPending struct{ c api.Querier }

func (a apiPending) Pending(ctx context.Context, account *url.URL) ([]*url.TxID, error) {
	var out []*url.TxID
	var start uint64
	for {
		count := uint64(100)
		r, err := a.c.Query(ctx, account, &api.PendingQuery{Range: &api.RangeOptions{Start: start, Count: &count}})
		if err != nil {
			return nil, err
		}
		var n int
		var total uint64
		switch rr := r.(type) {
		case *api.RecordRange[*api.TxIDRecord]:
			for _, x := range rr.Records {
				out = append(out, x.Value)
			}
			n, total = len(rr.Records), rr.Total
		case *api.RecordRange[api.Record]:
			for _, x := range rr.Records {
				t, ok := x.(*api.TxIDRecord)
				if !ok {
					return nil, fmt.Errorf("pending of %v: record %T", account, x)
				}
				out = append(out, t.Value)
			}
			n, total = len(rr.Records), rr.Total
		default:
			return nil, fmt.Errorf("pending of %v: answer %T", account, r)
		}
		start += uint64(n)
		if n == 0 || start >= total {
			return out, nil
		}
	}
}

func (a apiPending) Record(ctx context.Context, txid *url.TxID) (*api.MessageRecord[messaging.Message], error) {
	r, err := a.c.Query(ctx, txid.AsUrl(), &api.DefaultQuery{})
	if err != nil {
		return nil, err
	}
	mr, ok := r.(*api.MessageRecord[messaging.Message])
	if !ok {
		return nil, fmt.Errorf("record of %v: answer %T", txid, r)
	}
	return mr, nil
}
