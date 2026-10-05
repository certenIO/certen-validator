// Copyright 2026 Certen Protocol
//
// The validator-set evidence as of a certified block (proof v2, docs/proof/PROOF_V2.md §4.3-§4.5).

package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// BuildValidatorSetProofAt proves acc://dn.acme/network and acc://dn.acme/globals as of a Directory block into the
// state tree root a quorum-certified anchor carries for that block.
//
// A state receipt for a past block runs from the account's state through that block's state tree root and on to a
// later root; the part up to stateRoot is the proof, and is all that is kept. A receipt that never passes through
// stateRoot is refused: it was not read at the certified block.
func BuildValidatorSetProofAt(ctx context.Context, q AccumulateQuerier, incarnation [32]byte, block uint64, stateRoot [32]byte) (*ValidatorSetProof, error) {
	if incarnation == ([32]byte{}) {
		return nil, fmt.Errorf("incarnation: required")
	}
	root := hex.EncodeToString(stateRoot[:])
	read := func(url string) (*AccountStateProof, error) {
		a, err := fetchAccountStateProofWith(ctx, q, url, false, map[string]any{"forHeight": block})
		if err != nil {
			return nil, err
		}
		r, ok := ReceiptPrefixTo(a.StateReceipt, root)
		if !ok {
			return nil, fmt.Errorf("%s as of DN %d: the state receipt never passes through the certified state root %s", url, block, short(root))
		}
		a.StateReceipt = r
		return a, nil
	}
	network, err := read("acc://dn.acme/network")
	if err != nil {
		return nil, fmt.Errorf("network account: %w", err)
	}
	globals, err := read("acc://dn.acme/globals")
	if err != nil {
		return nil, fmt.Errorf("globals account: %w", err)
	}
	p := &ValidatorSetProof{Incarnation: hex.EncodeToString(incarnation[:]), Network: *network, Globals: *globals}
	if _, _, err := p.DerivedSet(); err != nil {
		return nil, fmt.Errorf("built a proof whose accounts do not decode: %w", err)
	}
	if err := p.Network.verifyChainBinding(); err != nil {
		return nil, fmt.Errorf("built a proof whose network chain binding fails: %w", err)
	}
	if err := p.Globals.verifyChainBinding(); err != nil {
		return nil, fmt.Errorf("built a proof whose globals chain binding fails: %w", err)
	}
	return p, nil
}

// ReceiptPrefixTo returns the leading steps of r that end at root (hex32), with Anchor set to root, and whether any
// intermediate value of r equals it.
func ReceiptPrefixTo(r chained_proof.Receipt, root string) (chained_proof.Receipt, bool) {
	root = strings.ToLower(root)
	h, err := hex.DecodeString(r.Start)
	if err != nil {
		return chained_proof.Receipt{}, false
	}
	for i := 0; ; i++ {
		if hex.EncodeToString(h) == root {
			out := chained_proof.Receipt{Start: r.Start, Anchor: root, LocalBlock: r.LocalBlock, Entries: append([]chained_proof.ReceiptStep(nil), r.Entries[:i]...)}
			return out, true
		}
		if i == len(r.Entries) {
			return chained_proof.Receipt{}, false
		}
		e, err := hex.DecodeString(r.Entries[i].Hash)
		if err != nil {
			return chained_proof.Receipt{}, false
		}
		var s [32]byte
		if r.Entries[i].Right {
			s = sha256.Sum256(append(append([]byte(nil), h...), e...))
		} else {
			s = sha256.Sum256(append(append([]byte(nil), e...), h...))
		}
		h = s[:]
	}
}

// FetchChainRoots reads an account's chains, each with the merkle state the state hasher folds (proof v2 G1).
func FetchChainRoots(ctx context.Context, q AccumulateQuerier, url string) ([]ChainRoot, error) {
	return fetchChainRoots(ctx, q, url, false)
}

// VerifyChainBinding proves an account's chain roots against a state receipt that starts at the account's main state:
// the state hasher is [main, secondary, chains, pending], so the receipt's second sibling must be
// H(merkle(chain anchors) || pending). The first sibling is the secondary component, taken from the receipt itself.
// pendingHash is the pending component; 32 zero bytes when nothing is pending.
func VerifyChainBinding(r chained_proof.Receipt, chains []ChainRoot, pendingHash string) error {
	if len(r.Entries) < 2 {
		return fmt.Errorf("state receipt has %d steps; the state hasher needs at least 2", len(r.Entries))
	}
	a := AccountStateProof{StateReceipt: r, Chains: chains, SecondaryHash: r.Entries[0].Hash, PendingHash: pendingHash}
	return a.verifyChainBinding()
}

// MainChainHeight returns the height of the chain named main, and whether there is one.
func MainChainHeight(chains []ChainRoot) (uint64, bool) {
	for _, c := range chains {
		if c.Name == "main" {
			count, _, err := c.derive()
			return count, err == nil
		}
	}
	return 0, false
}

// FetchChainRootsAt reads an account's chain roots as they were at the end of a block on its partition. Each chain's
// index chain records, per block that wrote to the chain, the position of the last entry written (source) and the
// block (blockIndex); every chain entry is served with the chain's merkle state as of that entry. So the root of chain
// X at block B is the state served with X's entry at the source of X-index's last entry at or before B, and an index
// chain's own root at B is the state of its last entry at or before B. Nothing here is trusted: the roots are proven
// against the state receipt by VerifyChainBinding, which these served values either satisfy or fail.
func FetchChainRootsAt(ctx context.Context, q AccumulateQuerier, url string, block uint64) ([]ChainRoot, error) {
	current, err := fetchChainRoots(ctx, q, url, false)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, c := range current {
		names[c.Name] = true
	}
	out := make([]ChainRoot, 0, len(current))
	for _, c := range current {
		indexChain := c.Name + "-index"
		isIndex := strings.HasSuffix(c.Name, "-index")
		if isIndex {
			indexChain = c.Name
		} else if !names[indexChain] {
			return nil, fmt.Errorf("%s chain %q has no index chain to locate block %d", url, c.Name, block)
		}
		pos, ok, err := lastIndexEntryAtOrBefore(ctx, q, url, indexChain, block)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, ChainRoot{Name: c.Name, Count: 0, Anchor: hex.EncodeToString(make([]byte, 32))})
			continue
		}
		at := pos.index // an index chain's own last entry at B
		if !isIndex {
			at = pos.source // the indexed chain's last entry written at or before B
		}
		state, err := chainEntryState(ctx, q, url, c.Name, at)
		if err != nil {
			return nil, err
		}
		cr := ChainRoot{Name: c.Name, Pending: state}
		count, anchor, err := cr.compute()
		if err != nil {
			return nil, fmt.Errorf("%s chain %q at %d: %w", url, c.Name, at, err)
		}
		if count != at+1 {
			return nil, fmt.Errorf("%s chain %q: the state served with entry %d is for %d entries", url, c.Name, at, count)
		}
		cr.Count, cr.Anchor = count, hex.EncodeToString(anchor)
		out = append(out, cr)
	}
	return out, nil
}

type indexPos struct{ index, source uint64 }

// lastIndexEntryAtOrBefore walks an index chain back from its end to the last entry whose block is at or before block.
func lastIndexEntryAtOrBefore(ctx context.Context, q AccumulateQuerier, url, chain string, block uint64) (indexPos, bool, error) {
	const page = 50
	var start uint64
	first := true
	var height uint64
	for {
		query := map[string]any{"queryType": "chain", "name": chain, "range": map[string]any{"fromEnd": true, "count": page, "expand": true}}
		if !first {
			if start == 0 {
				return indexPos{}, false, nil
			}
			from := uint64(0)
			if start > page {
				from = start - page
			}
			query["range"] = map[string]any{"start": from, "count": start - from, "expand": true}
		}
		raw, err := q.Query(ctx, map[string]any{"scope": url, "query": query})
		if err != nil {
			return indexPos{}, false, fmt.Errorf("%s %s: %w", url, chain, err)
		}
		var rr struct {
			Total   uint64 `json:"total"`
			Records []struct {
				Index uint64 `json:"index"`
				Value struct {
					Value struct {
						Source     uint64 `json:"source"`
						BlockIndex uint64 `json:"blockIndex"`
					} `json:"value"`
				} `json:"value"`
			} `json:"records"`
		}
		if err := json.Unmarshal(raw, &rr); err != nil {
			return indexPos{}, false, err
		}
		if first {
			height = rr.Total
		}
		if len(rr.Records) == 0 {
			return indexPos{}, false, nil
		}
		for i := len(rr.Records) - 1; i >= 0; i-- {
			r := rr.Records[i]
			if r.Index >= height {
				return indexPos{}, false, fmt.Errorf("%s %s: entry %d beyond height %d", url, chain, r.Index, height)
			}
			if r.Value.Value.BlockIndex <= block {
				return indexPos{index: r.Index, source: r.Value.Value.Source}, true, nil
			}
		}
		start = rr.Records[0].Index
		first = false
	}
}

// chainEntryState returns the merkle state a chain entry is served with: the chain as of that entry.
func chainEntryState(ctx context.Context, q AccumulateQuerier, url, chain string, index uint64) ([]*string, error) {
	raw, err := q.Query(ctx, map[string]any{"scope": url, "query": map[string]any{"queryType": "chain", "name": chain, "index": index}})
	if err != nil {
		return nil, fmt.Errorf("%s %s[%d]: %w", url, chain, index, err)
	}
	var r struct {
		Index uint64    `json:"index"`
		State []*string `json:"state"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Index != index || len(r.State) == 0 {
		return nil, fmt.Errorf("%s %s[%d]: served entry %d with no merkle state", url, chain, index, r.Index)
	}
	return r.State, nil
}
