// Copyright 2026 Certen Protocol
//
// The validator-set evidence as of a certified block (proof v2, docs/proof/PROOF_V2.md §4.3-§4.5).

package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
