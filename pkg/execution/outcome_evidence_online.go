// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// OutcomeOnlineCheck is what VerifyOutcomeEvidenceOnline read from the chain.
type OutcomeOnlineCheck struct {
	// Established are the facts read and matched.
	Established []string
	// SetRotated: the anchor's CERTEN validator set is no longer the one that certified the outcome. The record stands;
	// the keys the evidence states are then compared with the current registry only where it still holds them.
	SetRotated bool
	// ConsumedAfterClaim: a member recorded NOT SETTLED has since been consumed (the deadline is not enforced on chain,
	// RB5-F57). The record states a true historical fact that no longer describes the leaf.
	ConsumedAfterClaim bool
}

// VerifyOutcomeEvidenceOnline is the online half of the outcome evidence: at rpcURL, the registry records exactly this
// outcome root for the anchor in the stated block; the record transaction and every block the evidence names are the
// chain's canonical blocks; the anchor's record is the commitment the evidence states; the validator registry holds the
// stated keys and authorizes the signers' aggregate key commitment. It reads the chain at rpcURL; nothing else. Call it
// on evidence that verified offline.
func VerifyOutcomeEvidenceOnline(ctx context.Context, rpcURL string, e *OutcomeEvidence) (*OutcomeOnlineCheck, error) {
	if e == nil {
		return nil, ErrNoOutcomeEvidence
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", rpcURL, err)
	}
	defer client.Close()
	return verifyOutcomeEvidenceOnline(ctx, client, e)
}

// outcomeOnlineClient is the part of ethclient the online check uses.
type outcomeOnlineClient interface {
	ethereum.ChainReader
	ethereum.ContractCaller
	ethereum.TransactionReader
	ChainID(ctx context.Context) (*big.Int, error)
}

func verifyOutcomeEvidenceOnline(ctx context.Context, client outcomeOnlineClient, e *OutcomeEvidence) (*OutcomeOnlineCheck, error) {
	out := &OutcomeOnlineCheck{}
	fail := func(format string, a ...interface{}) (*OutcomeOnlineCheck, error) {
		return nil, fmt.Errorf("%w: online: %s", ErrOutcomeEvidence, fmt.Sprintf(format, a...))
	}
	id, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain id: %w", err)
	}
	if id.Int64() != e.ChainID {
		return fail("the endpoint serves chain %s, the evidence is of chain %d", id, e.ChainID)
	}
	registry, anchor := common.HexToAddress(e.Registry), common.HexToAddress(e.Anchor.Address)
	bundle, root := common.HexToHash(e.Anchor.BundleID), common.HexToHash(e.Record.OutcomeRoot)
	call := func(parsed abi.ABI, to common.Address, method string, args ...interface{}) ([]interface{}, error) {
		data, err := parsed.Pack(method, args...)
		if err != nil {
			return nil, err
		}
		ret, err := client.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
		if err != nil {
			return nil, fmt.Errorf("%s on %s: %w", method, to.Hex(), err)
		}
		return parsed.Unpack(method, ret)
	}

	// The registry: bound to the anchor on this chain, recording exactly this root in the stated block.
	r, err := call(outcomeRegistryABI, registry, "anchor")
	if err != nil {
		return nil, err
	}
	if a, _ := r[0].(common.Address); a != anchor {
		return fail("the registry %s records outcomes of anchor %s, the evidence names %s", registry.Hex(), a.Hex(), anchor.Hex())
	}
	r, err = call(outcomeRegistryABI, registry, "outcomeRoots", bundle)
	if err != nil {
		return nil, err
	}
	if got, _ := r[0].([32]byte); common.Hash(got) != root {
		return fail("the registry records outcome root %x for anchor %s, the evidence %s", got, bundle.Hex(), root.Hex())
	}
	r, err = call(outcomeRegistryABI, registry, "recordedInBlock", bundle)
	if err != nil {
		return nil, err
	}
	recordedIn, _ := r[0].(*big.Int)
	if recordedIn == nil || !recordedIn.IsUint64() {
		return fail("the registry's recordedInBlock is %v", r[0])
	}
	if contractBlockIsL1(e.ChainID) {
		// On Arbitrum the registry's block.number was the L1 block number, which the record block's header carries.
		h, err := client.HeaderByNumber(ctx, new(big.Int).SetUint64(e.Record.BlockNumber))
		if err != nil {
			return nil, fmt.Errorf("the record's block %d: %w", e.Record.BlockNumber, err)
		}
		if arbitrumL1Block(h) != recordedIn.Uint64() {
			return fail("the registry recorded the outcome at L1 block %d, the evidence's block %d carries L1 block %d", recordedIn,
				e.Record.BlockNumber, arbitrumL1Block(h))
		}
	} else if recordedIn.Uint64() != e.Record.BlockNumber {
		return fail("the registry recorded the outcome in block %d, the evidence names %d", recordedIn, e.Record.BlockNumber)
	}
	canonical := func(number uint64, hash, what string) error {
		h, err := client.HeaderByNumber(ctx, new(big.Int).SetUint64(number))
		if err != nil {
			return fmt.Errorf("%s block %d: %w", what, number, err)
		}
		if !strings.EqualFold(h.Hash().Hex(), hash) {
			return fmt.Errorf("%w: online: %s block %d is %s on chain, the evidence names %s", ErrOutcomeEvidence, what, number,
				h.Hash().Hex(), hash)
		}
		return nil
	}
	if err := canonical(e.Record.BlockNumber, e.Record.BlockHash, "the record's"); err != nil {
		return nil, err
	}
	rcpt, err := client.TransactionReceipt(ctx, common.HexToHash(e.Record.Tx))
	if err != nil {
		return nil, fmt.Errorf("the record transaction %s: %w", e.Record.Tx, err)
	}
	if !strings.EqualFold(rcpt.BlockHash.Hex(), e.Record.BlockHash) {
		return fail("the record transaction %s is in block %s, the evidence names %s", e.Record.Tx, rcpt.BlockHash.Hex(), e.Record.BlockHash)
	}
	out.Established = append(out.Established, fmt.Sprintf("registry %s (anchor %s) records outcome root %s… for anchor %s… in "+
		"block %d, canonical, by transaction %s", registry.Hex(), anchor.Hex(), root.Hex()[:18], bundle.Hex()[:18], e.Record.BlockNumber, e.Record.Tx))

	// The anchor's own record is the commitment the evidence states.
	ret, err := client.CallContract(ctx, ethereum.CallMsg{To: &anchor, Data: contracts.AnchorsCallData(bundle)}, nil)
	if err != nil {
		return nil, fmt.Errorf("anchors(%s): %w", bundle.Hex(), err)
	}
	st, err := contracts.DecodeAnchorsReturn(ret)
	if err != nil {
		return nil, err
	}
	if !st.Valid || !st.ProofExecuted || !strings.EqualFold(common.Hash(st.MerkleRoot).Hex(), e.Anchor.BatchRoot) ||
		!strings.EqualFold(common.Hash(st.OperationID).Hex(), e.Anchor.BatchOperationID) ||
		!strings.EqualFold(common.Hash(st.AccumulateSetRoot).Hex(), e.Anchor.AccumulateSetRoot) ||
		!strings.EqualFold(common.Hash(st.Incarnation).Hex(), e.Anchor.Incarnation) || st.AccumulateBlockHeight == nil ||
		st.AccumulateBlockHeight.Uint64() != e.Anchor.AccumulateBlockHeight {
		return fail("anchors(%s) holds valid=%v proofExecuted=%v root %x op %x height %v, not the commitment the evidence states",
			bundle.Hex(), st.Valid, st.ProofExecuted, st.MerkleRoot, st.OperationID, st.AccumulateBlockHeight)
	}
	r, err = call(outcomeAnchorABI, anchor, "batchLeafCount", bundle)
	if err != nil {
		return nil, err
	}
	if n, _ := r[0].(*big.Int); n == nil || n.Uint64() != e.Anchor.LeafCount {
		return fail("the anchor holds %v leaves, the evidence %d", r[0], e.Anchor.LeafCount)
	}
	out.Established = append(out.Established, "the anchor's own record (anchors, batchLeafCount) is the commitment the evidence states, valid and executed")

	// The registry: the keys the evidence states, and the signers' aggregate key commitment authorized.
	r, err = call(outcomeAnchorABI, anchor, "currentValidatorSetRoot")
	if err != nil {
		return nil, err
	}
	if cur, _ := r[0].([32]byte); !strings.EqualFold(common.Hash(cur).Hex(), e.Anchor.CertenSetRoot) {
		out.SetRotated = true
	}
	reg, err := readQuorumRegistry(func(method string, args ...interface{}) ([]interface{}, error) {
		return call(outcomeQuorumABI, anchor, method, args...)
	})
	if err != nil {
		return nil, fmt.Errorf("the anchor's validator registry: %w", err)
	}
	current := map[string]string{}
	for _, v := range reg.Validators {
		current[strings.ToLower(v.Address)] = strings.ToLower(v.BLSPublicKey)
	}
	for _, v := range e.Quorum.Validators {
		key, held := current[strings.ToLower(v.Address)]
		switch {
		case !held && out.SetRotated:
			continue
		case !held:
			return fail("validator %s of the evidence is not in the anchor's registry, whose set root is unchanged", v.Address)
		case key != "0x"+strings.TrimPrefix(strings.ToLower(v.BLSPublicKey), "0x"):
			return fail("validator %s's registered BLS key is %s, the evidence states %s", v.Address, key, v.BLSPublicKey)
		}
	}
	pi, err := bls_zkp.DecodeV2PublicInputs(e.Quorum.ZKProof)
	if err != nil {
		return nil, err
	}
	r, err = call(outcomeQuorumABI, anchor, "pubkeyBindingEnforced")
	if err != nil {
		return nil, err
	}
	if enforced, _ := r[0].(bool); enforced {
		r, err = call(outcomeQuorumABI, anchor, "authorizedPubkeyCommitments", pi.PubkeyCommitment)
		if err != nil {
			return nil, err
		}
		if ok, _ := r[0].(bool); !ok && !out.SetRotated {
			return fail("the anchor does not authorize the signers' aggregate key commitment %x", pi.PubkeyCommitment)
		}
		out.Established = append(out.Established, fmt.Sprintf("the anchor's registry holds every stated validator key and authorizes "+
			"the signers' aggregate key commitment %x…", pi.PubkeyCommitment[:8]))
	} else {
		out.Established = append(out.Established, "the anchor's registry holds every stated validator key (the anchor does not enforce "+
			"its authorized key commitments)")
	}

	// The member's block, and its leaf now.
	if e.Member.Leaf.BlockNumber != 0 {
		if err := canonical(e.Member.Leaf.BlockNumber, e.Member.Leaf.BlockHash, "the member's"); err != nil {
			return nil, err
		}
		out.Established = append(out.Established, fmt.Sprintf("the member's block %d is canonical", e.Member.Leaf.BlockNumber))
		if OutcomeStatus(e.Member.Leaf.Status) == OutcomeNotSettled {
			account := common.HexToAddress(e.Member.Account)
			r, err := call(outcomeAccountABI, account, "isLeafConsumed", common.HexToHash(e.Member.Leaf.BatchLeaf))
			if err != nil {
				return nil, err
			}
			if consumed, _ := r[0].(bool); consumed {
				out.ConsumedAfterClaim = true
			} else {
				out.Established = append(out.Established, "the member's leaf is still unconsumed at the chain's latest block")
			}
		}
	}
	return out, nil
}
