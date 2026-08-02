package execution

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch orchestrator: mempool -> tree -> anchor -> N branch-carrying calls
// =============================================================================
//
// Ordering is not cosmetic. The anchor must exist and be quorum-verified BEFORE any account
// call, because CertenAccountV7 refuses an anchor whose proofExecuted flag is false. And the
// tree must be fully self-verified BEFORE the anchor is paid for, because a bad branch only
// surfaces at TX3 — by which point createBatchAnchor and executeComprehensiveProof have both
// been paid and every other member is stuck behind the failure.
//
// So the orchestrator verifies at four separate points, each catching a different class of
// error while it is still free to fix:
//
//   1. Locally, before any transaction: every branch verifies against its own root.
//   2. Against DEPLOYED bytecode, before the anchor: each account's own computeLeaf agrees
//      with the Go leaf. This is the cross-language contract checked against production code
//      rather than a test fixture.
//   3. After createBatchAnchor: read back isBatchAnchor / batchLeafCount, and have the real
//      anchor verifyProof EVERY member leaf against what it actually stored.
//   4. Before each account call: the leaf is not already consumed.

// QuorumProver supplies the BLS/ZK proof over a batch root. Implemented by the consensus
// layer, which owns the validator keys; kept as an interface so the orchestrator has no
// dependency on consensus (which already imports this package).
type QuorumProver interface {
	// ProveBatchRoot obtains quorum attestation for a batch anchor and submits
	// executeComprehensiveProof. It must not return until the anchor's proofExecuted flag
	// is set, or return an error.
	//
	// It takes the TREE, not loose fields: peers are asked to attest by (chainID,
	// cutoffHeight) and reply with the bundleId they independently derived, so the prover
	// needs the same object the branches came from or the comparison means nothing.
	// cutoffHeight is the period boundary that defined membership — peers reconstruct from
	// it, and it is also the accumulateBlockHeight bound into the bundleId.
	ProveBatchRoot(ctx context.Context, tree *BatchTree, cutoffHeight, periodBlocks uint64) error
}

// BatchFlushResult reports what happened to one tree.
type BatchFlushResult struct {
	ChainID      int64
	BundleID     [32]byte
	Root         [32]byte
	MemberCount  int
	AnchorTxHash string

	Settled []*PendingBatchIntent
	Failed  []*PendingBatchIntent
	// Dropped members left the batch path entirely and MUST be routed to the per-intent
	// on_demand path by the caller. They are not requeued and will never reappear in a batch,
	// so a caller that ignores this field strands them.
	Dropped []*PendingBatchIntent
	// AlreadySettled members were found under an anchor a previous leader had already attested.
	// They are removed from the pool and must NOT be attested or fallen back to — the leader
	// that landed the batch already did both. Reported so the condition is visible rather than
	// looking like members silently vanishing.
	AlreadySettled []*PendingBatchIntent
	TxHashes       map[string]string // intentID -> account tx hash

	GasAnchor uint64
}

// BatchOrchestrator forms and settles batches for one chain's contract manager.
type BatchOrchestrator struct {
	ecm      *EthereumContractManager
	anchorV7 common.Address
	prover   QuorumProver
	mempool  *BatchMempool
	logf     func(string, ...interface{})
}

// NewBatchOrchestrator wires an orchestrator to a chain.
func NewBatchOrchestrator(
	ecm *EthereumContractManager,
	anchorV7 common.Address,
	prover QuorumProver,
	mempool *BatchMempool,
	logf func(string, ...interface{}),
) *BatchOrchestrator {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &BatchOrchestrator{
		ecm: ecm, anchorV7: anchorV7, prover: prover, mempool: mempool, logf: logf,
	}
}

// FlushChain forms ONE tree from the chain's pool and settles it end to end.
//
// # MEMBERSHIP IS DETERMINISTIC, NOT TIMER-DRIVEN
//
// cutoffHeight selects members via TakeForPeriod: every intent whose BFT round committed at or
// below the cutoff, ordered by (CommitHeight, IntentID). This is the property the whole quorum
// design rests on — an honest peer holding the same committed intents derives a byte-identical
// tree, root and bundleId, so its independent reconstruction is a meaningful check rather than
// a coin flip.
//
// It replaces mempool.Take(chainID), which took whatever had arrived locally by the time a
// 1-minute wall-clock timer fired. That is why validator-2 flushed bundleId 0xe4c950df… while
// validator-3 flushed 0x5e71d83a… in the same window on Sepolia: nothing made them agree.
//
// # FAILURE HANDLING
//
// Before the anchor is created, members are requeued untouched — nothing has been spent.
// After the anchor exists they are never requeued: re-forming the identical tree derives the
// same bundleId and reverts with AnchorAlreadyExists, which hides the real fault. A quorum
// failure past that point DROPS the members so the caller can route them to the per-intent
// on_demand path (approved policy: fall back, never requeue).
func (o *BatchOrchestrator) FlushChain(
	ctx context.Context,
	chainID int64,
	cutoffHeight uint64,
	periodBlocks uint64,
) (*BatchFlushResult, error) {
	// Defensive: a misconstructed orchestrator must ERROR, never panic. This runs inside the
	// flush loop, and a panic there would take the whole validator down rather than skipping
	// one chain.
	if o == nil || o.mempool == nil || o.ecm == nil {
		return nil, fmt.Errorf("batch orchestrator for chain %d is not properly constructed "+
			"(use NewBatchOrchestrator)", chainID)
	}
	// Height 0 is not a period. Forming a batch at it would bind accumulateBlockHeight=0 into
	// the bundleId on every validator that happened to have a different local view, and
	// TakeForPeriod would select nothing anyway.
	if cutoffHeight == 0 {
		return nil, fmt.Errorf("chain %d: cutoff height 0 is not a valid period; the consensus "+
			"height source is not wired", chainID)
	}

	members := o.mempool.TakeForPeriod(chainID, cutoffHeight, periodBlocks)
	if len(members) == 0 {
		return nil, nil
	}

	res := &BatchFlushResult{
		ChainID:     chainID,
		MemberCount: len(members),
		TxHashes:    make(map[string]string, len(members)),
	}

	// ---- Build the tree -----------------------------------------------------
	inputs := make([]BatchLeafInput, 0, len(members))
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			o.mempool.Requeue(members)
			return nil, fmt.Errorf("building leaf for %s: %w", p.IntentID, err)
		}
		inputs = append(inputs, in)
	}

	tree, err := BuildBatchTree(chainID, inputs, cutoffHeight)
	if err != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("building batch tree: %w", err)
	}
	res.BundleID = tree.BundleID
	res.Root = tree.Root

	o.logf("[BATCH] chain=%d forming tree: %d members, root=0x%x, bundleId=0x%x",
		chainID, tree.Size(), tree.Root[:8], tree.BundleID[:8])

	// ---- ALREADY SETTLED ELSEWHERE? ----------------------------------------
	// Leadership rotates per period and the flush loop picks up stragglers, so two different
	// nodes can legitimately reach the same period. bundleId is deterministic, so an anchor
	// that already exists AND is attested means the batch settled under a previous leader.
	//
	// This MUST short-circuit. Continuing would re-submit executeComprehensiveProof, which
	// reverts on usedCommitments replay protection; the quorum step would then report failure
	// and route every member to the per-intent fallback — RE-EXECUTING intents that already
	// moved funds. A double-spend produced by a retry is far worse than a skipped flush.
	if settled, serr := o.anchorAlreadyAttested(ctx, tree.BundleID); serr != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("checking whether anchor 0x%x already settled: %w", tree.BundleID[:8], serr)
	} else if settled {
		o.logf("[BATCH] chain=%d period %d already settled under anchor 0x%x by a previous leader "+
			"— releasing %d member(s) without re-executing",
			chainID, cutoffHeight, tree.BundleID[:8], len(members))
		res.AlreadySettled = members
		return res, nil
	}

	// ---- VERIFY 2: every account's own leaf agrees with ours ----------------
	// Checked against DEPLOYED bytecode, not a fixture. A drift here would mint an anchor
	// whose leaves no account can reproduce — unspendable, and paid for.
	if err := o.verifyLeavesAgainstAccounts(ctx, members, tree); err != nil {
		o.mempool.Requeue(members)
		return nil, err
	}

	// ---- Create the anchor --------------------------------------------------
	anchorTx, gasUsed, err := o.createBatchAnchor(ctx, tree)
	if err != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("createBatchAnchor: %w", err)
	}
	res.AnchorTxHash = anchorTx
	res.GasAnchor = gasUsed
	o.logf("[BATCH] chain=%d anchor created tx=%s gas=%d", chainID, anchorTx, gasUsed)

	// ---- VERIFY 3: the deployed anchor accepts every member leaf ------------
	if err := o.verifyLeavesAgainstAnchor(ctx, tree); err != nil {
		// The anchor exists but is unusable. Do NOT requeue: re-forming the identical tree
		// would derive the same bundleId and revert with "Anchor already exists", hiding
		// the real fault. Drop to the per-intent path and surface the cause.
		o.mempool.DropMembers(members)
		res.Dropped = members
		return res, fmt.Errorf("anchor created but membership verification failed (%d member(s) "+
			"dropped to the per-intent path): %w", len(members), err)
	}

	// ---- Quorum attestation over the root -----------------------------------
	if o.prover == nil {
		return res, fmt.Errorf("no quorum prover configured; anchor 0x%x is created but not verified "+
			"and no account will accept it", tree.BundleID[:8])
	}
	if err := o.prover.ProveBatchRoot(ctx, tree, cutoffHeight, periodBlocks); err != nil {
		// APPROVED FALLBACK: drop, never requeue. The anchor is already mined, so re-forming
		// this tree would derive the same bundleId and revert with AnchorAlreadyExists.
		// Dropping costs the anchor gas and routes the members to the per-intent on_demand
		// path — more gas, but they settle. Requeueing risks a permanently stuck batch.
		o.mempool.DropMembers(members)
		res.Dropped = members
		return res, fmt.Errorf("quorum attestation over batch root failed (%d member(s) dropped "+
			"to the per-intent path): %w", len(members), err)
	}
	o.logf("[BATCH] chain=%d quorum verified root 0x%x", chainID, tree.Root[:8])

	// ---- Settle each member -------------------------------------------------
	for i, p := range members {
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			res.Failed = append(res.Failed, p)
			o.logf("[BATCH] member %s: branch error: %v", p.IntentID, berr)
			continue
		}

		txHash, serr := o.settleMember(ctx, p, tree, branch)
		if serr != nil {
			res.Failed = append(res.Failed, p)
			o.logf("[BATCH] member %s FAILED: %v", p.IntentID, serr)
			continue
		}
		res.Settled = append(res.Settled, p)
		res.TxHashes[p.IntentID] = txHash
	}

	o.logf("[BATCH] chain=%d complete: %d settled, %d failed (anchor amortised across %d)",
		chainID, len(res.Settled), len(res.Failed), tree.Size())

	return res, nil
}

// verifyLeavesAgainstAccounts asks each deployed account to compute its own leaf and compares.
func (o *BatchOrchestrator) verifyLeavesAgainstAccounts(
	ctx context.Context,
	members []*PendingBatchIntent,
	tree *BatchTree,
) error {
	for i, p := range members {
		acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
		if err != nil {
			return fmt.Errorf("binding account for %s: %w", p.IntentID, err)
		}

		// The account must be the keyless V7 for this ADI, or its leaf identity half is
		// something other than what we hashed.
		keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
		if err != nil {
			return fmt.Errorf("account %s is not a CertenAccountV7 (%s): %w",
				p.Account.Hex(), p.IntentID, err)
		}
		if !keyless {
			return fmt.Errorf("account %s reports a non-keyless owner; refusing to anchor %s",
				p.Account.Hex(), p.IntentID)
		}

		onChainADIHash, err := acct.ADIURLHash(&bind.CallOpts{Context: ctx})
		if err != nil {
			return fmt.Errorf("reading adiURLHash for %s: %w", p.IntentID, err)
		}
		if onChainADIHash != tree.Inputs[i].ADIURLHash() {
			return fmt.Errorf(
				"account %s is bound to a different ADI than intent %s claims "+
					"(on-chain 0x%x, intent %s)",
				p.Account.Hex(), p.IntentID, onChainADIHash[:8], p.ADIURL)
		}

		exec := tree.Inputs[i].ExecutionCommitment
		onChainLeaf, err := acct.ComputeLeaf(&bind.CallOpts{Context: ctx}, exec, p.OperationID)
		if err != nil {
			return fmt.Errorf("computeLeaf on %s: %w", p.Account.Hex(), err)
		}
		if onChainLeaf != tree.Leaves[i] {
			return fmt.Errorf(
				"leaf mismatch for %s: Go computed 0x%x, deployed account computed 0x%x — "+
					"cross-language drift between the validator and CertenAccountV7",
				p.IntentID, tree.Leaves[i], onChainLeaf)
		}
	}
	return nil
}

// anchorAlreadyAttested reports whether this bundleId already exists on chain with its quorum
// attestation landed — i.e. the batch settled under a previous leader.
//
// Reads the `anchors` struct getter directly rather than anchorExists + a second call, because
// only the combination matters: an anchor that exists but is NOT attested is a stranded
// createBatchAnchor from a failed flush, and that one SHOULD be retried.
func (o *BatchOrchestrator) anchorAlreadyAttested(ctx context.Context, bundleID [32]byte) (bool, error) {
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return false, err
	}
	bound := bind.NewBoundContract(o.anchorV7, parsed, o.ecm.client, o.ecm.client, o.ecm.client)
	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return false, err
	}
	const proofExecutedIndex = 12
	if len(out) <= proofExecutedIndex {
		return false, fmt.Errorf("anchors() returned %d fields, need at least %d",
			len(out), proofExecutedIndex+1)
	}
	executed, ok := out[proofExecutedIndex].(bool)
	if !ok {
		return false, fmt.Errorf("proofExecuted has unexpected type %T", out[proofExecutedIndex])
	}
	return executed, nil
}

// verifyLeavesAgainstAnchor confirms the deployed anchor stored what we think it did and
// accepts every member's branch.
func (o *BatchOrchestrator) verifyLeavesAgainstAnchor(ctx context.Context, tree *BatchTree) error {
	anchor, err := contracts.NewCertenAnchorV7Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return fmt.Errorf("binding anchor: %w", err)
	}
	opts := &bind.CallOpts{Context: ctx}

	isBatch, err := anchor.IsBatchAnchor(opts, tree.BundleID)
	if err != nil {
		return fmt.Errorf("reading isBatchAnchor: %w", err)
	}
	if !isBatch {
		return fmt.Errorf("anchor 0x%x is not flagged as a batch anchor", tree.BundleID[:8])
	}

	count, err := anchor.BatchLeafCount(opts, tree.BundleID)
	if err != nil {
		return fmt.Errorf("reading batchLeafCount: %w", err)
	}
	if count == nil || count.Int64() != int64(tree.Size()) {
		return fmt.Errorf("anchor records %v leaves but the tree has %d", count, tree.Size())
	}

	for i := range tree.Leaves {
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			return berr
		}
		ok, verr := anchor.VerifyProof(opts, tree.BundleID, branch, tree.Leaves[i])
		if verr != nil {
			return fmt.Errorf("verifyProof for member %d: %w", i, verr)
		}
		if !ok {
			return fmt.Errorf("deployed anchor rejects member %d's branch", i)
		}
	}
	return nil
}

// createBatchAnchor submits the anchor and waits for it to mine.
func (o *BatchOrchestrator) createBatchAnchor(
	ctx context.Context,
	tree *BatchTree,
) (string, uint64, error) {
	anchor, err := contracts.NewCertenAnchorV7Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return "", 0, err
	}

	// Idempotence: a retry after a timeout must not revert with "Anchor already exists"
	// and lose the batch. bundleId is deterministic, so an existing anchor for this exact
	// tree is a SUCCESS, not a conflict.
	if exists, eerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID); eerr == nil && exists {
		o.logf("[BATCH] anchor 0x%x already exists — treating as created", tree.BundleID[:8])
		return "already-exists", 0, nil
	}

	o.ecm.auth.GasLimit = 500000
	tx, err := anchor.CreateBatchAnchor(
		o.ecm.auth,
		tree.BundleID,
		tree.Root,
		big.NewInt(int64(tree.Size())),
		tree.BatchOperationID,
		new(big.Int).SetUint64(tree.BlockHeight),
	)
	if err != nil {
		return "", 0, err
	}

	receipt, err := bind.WaitMined(ctx, o.ecm.client, tx)
	if err != nil {
		return tx.Hash().Hex(), 0, fmt.Errorf("waiting for anchor: %w", err)
	}
	if receipt.Status == 0 {
		return tx.Hash().Hex(), receipt.GasUsed, fmt.Errorf("createBatchAnchor reverted")
	}
	return tx.Hash().Hex(), receipt.GasUsed, nil
}

// settleMember submits one member's account call carrying its Merkle branch.
func (o *BatchOrchestrator) settleMember(
	ctx context.Context,
	p *PendingBatchIntent,
	tree *BatchTree,
	branch [][32]byte,
) (string, error) {
	acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
	if err != nil {
		return "", err
	}

	exec, err := p.ExecutionCommitment()
	if err != nil {
		return "", err
	}
	leaf := ComputeBatchLeaf(p.ChainID, BatchLeafInput{
		ADIURL: p.ADIURL, ExecutionCommitment: exec, OperationID: p.OperationID,
	})

	// VERIFY 4: a consumed leaf means this member already settled. Reporting that plainly
	// beats paying gas to hit "leaf already consumed" on-chain.
	consumed, err := acct.IsLeafConsumed(&bind.CallOpts{Context: ctx}, leaf)
	if err != nil {
		return "", fmt.Errorf("reading isLeafConsumed: %w", err)
	}
	if consumed {
		return "", fmt.Errorf("leaf 0x%x already consumed — member %s has already settled",
			leaf[:8], p.IntentID)
	}

	proof := contracts.AccountProofV7{
		AdiURL:      p.ADIURL, // advisory; the contract uses its own immutable adiURL
		AnchorId:    tree.BundleID,
		MerkleProof: branch,
		OperationID: p.OperationID,
		Timestamp:   big.NewInt(time.Now().Unix() - 60), // clock-skew allowance
		ExpiresAt:   big.NewInt(time.Now().Add(time.Hour).Unix()),
		Nonce:       big.NewInt(0),
		// Must cover the most demanding leg or the contract rejects the whole call.
		RequiredLevel: requiredLevelForLegs(p.Legs),
	}

	var tx *types.Transaction
	if p.IsMultiLeg() {
		targets, values, datas := legArrays(p.Legs)
		o.ecm.auth.GasLimit = 400000 + uint64(len(p.Legs))*250000
		tx, err = acct.BatchExecuteGovernanceProofDirect(o.ecm.auth, targets, values, datas, proof)
	} else {
		leg := p.Legs[0]
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		o.ecm.auth.GasLimit = 500000
		tx, err = acct.ExecuteGovernanceProofDirect(o.ecm.auth, leg.Target, v, leg.Data, proof)
	}
	if err != nil {
		return "", err
	}

	txHash := tx.Hash().Hex()
	receipt, err := bind.WaitMined(ctx, o.ecm.client, tx)
	if err != nil {
		return txHash, fmt.Errorf("waiting for member tx: %w", err)
	}
	if receipt.Status == 0 {
		// Only THIS member failed. Its leaf was rolled back with the rest of the tx, so it
		// stays spendable — the other members are unaffected, which is the point of giving
		// each its own leaf rather than sharing one anchor-wide consumption flag.
		return txHash, fmt.Errorf("member execution reverted on-chain (leaf still spendable)")
	}
	return txHash, nil
}

// legArrays splits legs into the three parallel arrays the contract takes.
func legArrays(legs []LegExecution) ([]common.Address, []*big.Int, [][]byte) {
	targets := make([]common.Address, 0, len(legs))
	values := make([]*big.Int, 0, len(legs))
	datas := make([][]byte, 0, len(legs))
	for _, leg := range legs {
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		targets = append(targets, leg.Target)
		values = append(values, v)
		datas = append(datas, leg.Data)
	}
	return targets, values, datas
}
