package execution

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch tree — the cross-language contract with CertenAnchorV7 / CertenAccountV7
// =============================================================================
//
// One anchor covers N intents, each committed as a Merkle leaf. Measured on live Sepolia,
// createAnchor + executeComprehensiveProof are 802,128 of the 987,644 gas an intent costs
// (81.2%), so amortising those two across a batch is where essentially all the saving is.
//
// EVERY function here must agree bit-for-bit with Solidity. If it does not, the validator
// mints anchors that no account can ever spend — after the gas for them has already been
// paid. TestBatchTree_MatchesSolidityVectors pins the whole schema against vectors emitted
// by certen-contracts/evm/test/CertenBatchTreeVector.t.sol.

const (
	// BatchLeafDomain must equal CertenAccountV7.LEAF_DOMAIN.
	BatchLeafDomain = "certen:batchleaf:v1"

	// BatchBundleDomain is the V8.1 (and V7) createBatchAnchor literal. Batches are formed for CertenAnchorV8_2
	// (contracts.DeriveV8_2BatchBundleID, "certen:batchbundle:v2"); v1 remains to verify anchors created before it.
	BatchBundleDomain = "certen:batchbundle:v1"
)

// BatchLeafInput is one intent's contribution to a batch.
type BatchLeafInput struct {
	ADIURL              string   // the owning ADI; hashed, never sent raw
	ExecutionCommitment [32]byte // single-call OR multi-leg batch commitment
	OperationID         [32]byte // the Accumulate 4-blob intent hash

	// GovernanceCommitment is the commitment to who decided the intent (proof.GovernanceCommitment of its
	// governance decision record, RB4-F66). NOT part of the leaf - the account reconstructs the leaf and never sees
	// governance - but part of the batch operation id the quorum signs and the anchor stores.
	GovernanceCommitment [32]byte

	// AccumulateSetRoot is the root of the Accumulate validator set this member's L4 Directory leg was verified
	// against, under the process's incarnation (pkg/accumulateset, RB5 design D2). NOT part of the leaf or the
	// operation id: every member of a tree must share it, and the tree's V8.2 anchor commits it once.
	AccumulateSetRoot [32]byte

	// IntentMessage is the member's quorum-certified intent message (RB5 D3), zero for a member committed before a
	// BLS registry was in force. NOT part of the leaf; part of the v3 batch operation id, so the anchor commits every
	// member's certified intent - its govRoot v2, Accumulate set, incarnation, governance commitment and CERTEN set.
	IntentMessage [32]byte

	// AuthorityBook and AuthorityPage are the key book (keccak256 of its canonical URL) and the 1-based index of its page
	// that CERTEN's quorum certified as authorizing the intent (PendingBatchIntent.Authority). PART of the v3 leaf
	// (ComputeBatchLeafV3): CertenAccountV7_2 derives every leg's authority level from the pair (RB3-F39, RB5-F29/F30).
	AuthorityBook [32]byte
	AuthorityPage uint64

	// LegacyNoGovernance marks a member admitted before governance commitments existed (restored from a mempool
	// written by an earlier binary). Its batch was, or will be, formed with the v1 operation id - the id its anchor
	// may already carry - and records that its governance is not committed. Only restore sets it.
	LegacyNoGovernance bool

	// Provenance is what the database records ABOUT this member: which Accumulate transaction carried
	// it, and the leg it settles. Evidence only — see MemberProvenance.
	Provenance MemberProvenance

	// IntentID identifies the member for EVIDENCE only. It is deliberately NOT part of the leaf —
	// the leaf hashes (domain, chainId, adiURLHash, executionCommitment, operationID, authorityBook,
	// authorityPage) and nothing else, so adding it here cannot move a root or a bundle id.
	//
	// It is here because both lanes build their leaves through PendingBatchIntent.LeafInput, so carrying
	// it on the input is what gives the cadence lane the same member identity the on-demand lane passes
	// explicitly. Without it a cadence canonical row records members with an empty intent_id, the
	// layer-5 binding cannot find them, and layer 5 falls back to the settlement observation — the exact
	// false binding this work removed, reappearing on the other lane.
	IntentID string
}

// IsTransactionHash reports whether s is a 0x-prefixed 32-byte hex transaction hash.
//
// createBatchAnchor returns the sentinel "already-exists" when the anchor is already on chain, created by
// another validator. That is a correct idempotence signal and a correct thing to log — and a catastrophic
// thing to STORE, because anchor_create_tx is read as "the transaction that published this root" and
// travels into layer 5 as `anchorTx`. Live on 2026-09-18 a layer-5 row published
// `anchorTx: "already-exists"`: a claim that a root appears in a transaction that is not a transaction.
//
// A node that did not create the anchor does not know which transaction did. Empty says that. A sentinel
// does not — it says something false in a field that is read as evidence, which is the same defect class
// as the d2d24ab3 binding this work exists to remove.
func IsTransactionHash(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// MemberProvenance is everything recorded ABOUT a batch member that is not part of its leaf.
//
// NONE OF IT IS HASHED. The leaf covers (domain, chainId, adiURLHash, executionCommitment, operationID,
// authorityBook, authorityPage) and nothing else, so adding or changing a field here cannot move a root or a bundle id.
// TestIntentIdOverrideAndLeafStability pins that.
//
// It exists because the canonical anchor row was, until now, strictly poorer than the shadow row it
// replaced. A canonical member carried the operation id in a column named accumulate_tx_hash and nothing
// else; the retired per-validator shadow row carried the real Accumulate transaction and the leg's
// from/to/amount. Retiring that pipeline while the canonical row was thinner would have silently emptied
// the Transaction Center. So the canonical row has to carry what it replaces before the old writer can go.
type MemberProvenance struct {
	// AccumTxHash is the Accumulate transaction that carried this intent — the WriteData hash, not the
	// operation id. It is the key layer 5 historically joined on, and writing anything else into a column
	// named accumulate_tx_hash is the same mislabelling as storing a ZK blob in aggregated_signature.
	AccumTxHash string

	// The settled leg, for display and for answering "what did this member actually do".
	FromChain   string
	ToChain     string
	FromAddress string
	ToAddress   string
	Amount      string
	TokenSymbol string
	UserID      string
}

// ADIURLHash is keccak256(adiURL) — the same value CertenAccountV7.adiURLHash() returns.
func (l BatchLeafInput) ADIURLHash() [32]byte {
	return ethcrypto.Keccak256Hash([]byte(l.ADIURL))
}

// ComputeBatchLeaf mirrors CertenAccountV7.computeLeaf - the V8.1 generation's v1 leaf, which proofs anchored
// under V8.1 carry. A V8.2 tree is built of v3 leaves (ComputeBatchLeafV3, RB5-F29/F30):
//
//	keccak256(abi.encodePacked(
//	    "certen:batchleaf:v1", chainId, adiURLHash, executionCommitment, operationID
//	))
//
// abi.encodePacked layout (147 bytes):
//
//	domain   : 19 raw ASCII bytes (string is NOT length-prefixed under encodePacked)
//	chainId  : uint256  -> 32 bytes big-endian
//	adiHash  : bytes32  -> 32 bytes
//	execComm : bytes32  -> 32 bytes
//	opID     : bytes32  -> 32 bytes
//
// The domain tag is also the second-preimage defence: an internal Merkle node is
// keccak256(32||32) with no attacker-controlled prefix, so it can never be passed off as a
// leaf whose preimage must begin with this literal.
func ComputeBatchLeaf(chainID int64, in BatchLeafInput) [32]byte {
	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)

	adiHash := in.ADIURLHash()

	packed := make([]byte, 0, len(BatchLeafDomain)+128)
	packed = append(packed, []byte(BatchLeafDomain)...)
	packed = append(packed, chainIDBytes...)
	packed = append(packed, adiHash[:]...)
	packed = append(packed, in.ExecutionCommitment[:]...)
	packed = append(packed, in.OperationID[:]...)

	return ethcrypto.Keccak256Hash(packed)
}

// hashPair mirrors CertenAnchorV7._sortedHash / the loop in _verifyMerkleProof:
// the smaller value is written first, so the tree is order-independent at each node.
func hashPair(a, b [32]byte) [32]byte {
	var out [32]byte
	if bytesLess(a, b) {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, a[:]...), b[:]...))
	} else {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, b[:]...), a[:]...))
	}
	return out
}

func bytesLess(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// MerkleRoot builds the batch root.
//
// Pairing rule (must match the Solidity test helper AND be walkable by
// CertenAnchorV7._verifyMerkleProof): adjacent pairs are sorted-hashed; an odd trailing node
// is PROMOTED unchanged to the next level rather than duplicated. Duplicating it would create
// two distinct leaf multisets with the same root.
//
// N=1 returns the leaf itself, which is why a single intent needs no special case anywhere:
// its root equals its leaf and its branch is empty.
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, fmt.Errorf("cannot build a Merkle root over zero leaves")
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, level[i]) // odd node promotes
			}
		}
		level = next
	}
	return level[0], nil
}

// MerkleBranch returns the sibling path proving leaves[index] is in MerkleRoot(leaves).
// The result is exactly what CertenAccountV7 passes as proof.merkleProof.
func MerkleBranch(leaves [][32]byte, index int) ([][32]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range (%d leaves)", index, len(leaves))
	}
	var branch [][32]byte
	level := append([][32]byte(nil), leaves...)
	idx := index

	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		sib := idx ^ 1
		if sib < len(level) {
			branch = append(branch, level[sib])
		}
		idx /= 2
		level = next
	}
	return branch, nil
}

// VerifyBranch replays CertenAnchorV7._verifyMerkleProof exactly.
//
// The validator runs this on every leaf before spending gas on createBatchAnchor. A branch
// that fails here would fail on-chain too — after the anchor had been paid for.
func VerifyBranch(branch [][32]byte, root, leaf [32]byte) bool {
	computed := leaf
	for _, el := range branch {
		computed = hashPair(computed, el)
	}
	return computed == root
}

// DeriveBatchBundleID is the V8.1 (and V7) batch anchor id, kept to verify anchors created before V8.2. New batches
// derive contracts.DeriveV8_2BatchBundleID (BuildBatchTree). It mirrors CertenAnchorV7.createBatchAnchor's derivation:
//
//	keccak256(abi.encodePacked(
//	    "certen:batchbundle:v1", chainId, batchRoot, leafCount, batchOperationID, height
//	))
//
// The contract REQUIRES the submitted bundleId to equal this. That is EVM-004 in batch form:
// a rogue validator front-running with a different root, or restating the batch as a smaller
// one, produces a different id — which the honest quorum's BLS signature does not cover.
func DeriveBatchBundleID(
	chainID int64,
	batchRoot [32]byte,
	leafCount uint64,
	batchOperationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	return contracts.DeriveV8_1BatchBundleID(chainID, batchRoot, leafCount, batchOperationID, accumulateBlockHeight)
}

// DeriveBatchOperationID is the v1 batch operation id: the member operationIDs alone. Batches are formed with
// DeriveBatchOperationIDV2 (RB4-F66); v1 is kept to verify anchors created before it, which committed no governance.
//
// DeriveBatchOperationID aggregates the member operationIDs into the batch's own id.
//
// Sorted before hashing so the value depends only on the SET of members, not on the order
// they happened to arrive in the mempool — two validators forming the same batch must derive
// the same id or they cannot agree on the anchor.
//
// Third-party verifiability survives batching: anyone holding the member 4-blob intents can
// recompute each operationID, re-derive this aggregate, and check it against the anchor.
func DeriveBatchOperationID(operationIDs [][32]byte) [32]byte {
	sorted := append([][32]byte(nil), operationIDs...)
	sort.Slice(sorted, func(i, j int) bool { return bytesLess(sorted[i], sorted[j]) })

	packed := make([]byte, 0, 32+len(sorted)*32)
	packed = append(packed, []byte("certen:batchopid:v1")...)
	for _, id := range sorted {
		packed = append(packed, id[:]...)
	}
	return ethcrypto.Keccak256Hash(packed)
}

// =============================================================================
// Assembled batch
// =============================================================================

// BatchTree is a fully-formed batch ready to be anchored.
type BatchTree struct {
	ChainID          int64
	Leaves           [][32]byte
	Inputs           []BatchLeafInput
	Root             [32]byte
	BatchOperationID [32]byte
	// BatchOperationIDVersion is how BatchOperationID was derived: "v2" commits to every member's governance
	// decision, "v1" is the operation ids alone - a batch of members admitted before commitments (RB4-F66).
	BatchOperationIDVersion string
	BundleID                [32]byte
	BlockHeight             uint64

	// AccumulateSetRoot and Incarnation are the Accumulate half CertenAnchorV8_2 commits for this tree: the one
	// validator-set root every member's L4 was verified against, and which Accumulate chain that is. Both are in the
	// V8.2 bundle id and in the pre-exec message the quorum signs.
	AccumulateSetRoot [32]byte
	Incarnation       [32]byte

	// AnchorCreateTx is the transaction that PUBLISHED this root — createBatchAnchor's own transaction,
	// set by the orchestrator once it returns and before the quorum proves the root.
	//
	// It travels on the tree because it is the one fact about a batch that only the creating step knows
	// and that layer 5 must state: "this root is in THIS transaction". Layer 5 previously fell back to
	// whatever observation the settlement produced, which published a real transaction hash next to a
	// root that transaction never contained. Empty only on a tree that has not been anchored yet: an anchor
	// another validator created is located on chain (RB3-F33) - it used to be left empty, and 235 of 289
	// canonical rows never learned their create transaction.
	AnchorCreateTx string
	// AnchorCreateBlock is the block AnchorCreateTx was mined in; zero with it.
	AnchorCreateBlock uint64
	// AnchorCreateSender is the address that signed AnchorCreateTx, lower-case (RB3-F127).
	AnchorCreateSender string
}

// BuildBatchTree assembles the tree and self-verifies every branch before returning.
//
// The self-verification is not paranoia: a silently wrong branch would only surface as a
// revert at TX3, after the anchor and its BLS proof had already been paid for, with the
// batch's other members stuck behind it.
func BuildBatchTree(
	chainID int64,
	inputs []BatchLeafInput,
	blockHeight uint64,
	incarnation [32]byte,
) (*BatchTree, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("cannot build a batch with no members")
	}
	if incarnation == ([32]byte{}) {
		return nil, fmt.Errorf("cannot build a V8.2 batch without the Accumulate incarnation")
	}
	// One anchor commits one Accumulate set root, so every member must have been verified against the same set
	// (periodChunks forms trees per root). A member without one has no committable set.
	accRoot := inputs[0].AccumulateSetRoot
	for i, in := range inputs {
		if in.AccumulateSetRoot == ([32]byte{}) {
			return nil, fmt.Errorf("%w: member %d (%s)", ErrNoAccumulateSetRoot, i, in.ADIURL)
		}
		if in.AccumulateSetRoot != accRoot {
			return nil, fmt.Errorf("member %d (%s) was verified against Accumulate validator set %x, member 0 against %x; "+
				"one anchor commits one set", i, in.ADIURL, in.AccumulateSetRoot[:8], accRoot[:8])
		}
	}

	leaves := make([][32]byte, 0, len(inputs))
	seen := make(map[[32]byte]int, len(inputs))

	for i, in := range inputs {
		if in.ADIURL == "" {
			return nil, fmt.Errorf("member %d has no ADI URL", i)
		}
		if in.OperationID == ([32]byte{}) {
			return nil, fmt.Errorf("member %d (%s) has a zero operationID; the anchor rejects it", i, in.ADIURL)
		}
		if in.ExecutionCommitment == ([32]byte{}) {
			return nil, fmt.Errorf("member %d (%s) has a zero executionCommitment", i, in.ADIURL)
		}

		// A V8.2 tree settles CertenAccountV7_2 accounts, whose leaf binds the certified key book and page (RB5-F29/F30).
		if in.AuthorityPage == 0 || in.AuthorityBook == ([32]byte{}) {
			return nil, fmt.Errorf("member %d (%s) has no certified authority book and page; its v3 leaf cannot be formed",
				i, in.ADIURL)
		}
		leaf := ComputeBatchLeafV3(chainID, in)

		// Duplicate leaves would be indistinguishable on-chain: the second could never be
		// consumed, because CertenAccountV7 keys single-use on the leaf itself. Catch it
		// here rather than stranding an intent.
		if prev, dup := seen[leaf]; dup {
			return nil, fmt.Errorf(
				"members %d and %d produce an identical leaf (same ADI, commitment and operationID); "+
					"the second could never be consumed", prev, i)
		}
		seen[leaf] = i

		leaves = append(leaves, leaf)
	}

	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}

	batchOpID, opVersion, err := batchOperationIDOf(inputs)
	if err != nil {
		return nil, err
	}
	bundleID := contracts.DeriveV8_2BatchBundleID(chainID, root, uint64(len(leaves)), batchOpID, blockHeight, accRoot, incarnation)

	tree := &BatchTree{
		ChainID:                 chainID,
		Leaves:                  leaves,
		Inputs:                  inputs,
		Root:                    root,
		BatchOperationID:        batchOpID,
		BatchOperationIDVersion: opVersion,
		BundleID:                bundleID,
		BlockHeight:             blockHeight,
		AccumulateSetRoot:       accRoot,
		Incarnation:             incarnation,
	}

	// Self-verify every branch against the algorithm the anchor will actually run.
	for i := range leaves {
		branch, berr := MerkleBranch(leaves, i)
		if berr != nil {
			return nil, berr
		}
		if !VerifyBranch(branch, root, leaves[i]) {
			return nil, fmt.Errorf("internal error: branch for member %d does not verify against its own root", i)
		}
	}

	return tree, nil
}

// BranchFor returns the Merkle branch for one member, by index.
func (t *BatchTree) BranchFor(index int) ([][32]byte, error) {
	return MerkleBranch(t.Leaves, index)
}

// BranchForADI returns the branch for the first member owned by adiURL.
func (t *BatchTree) BranchForADI(adiURL string) ([][32]byte, int, error) {
	for i, in := range t.Inputs {
		if in.ADIURL == adiURL {
			b, err := t.BranchFor(i)
			return b, i, err
		}
	}
	return nil, -1, fmt.Errorf("ADI %s is not a member of this batch", adiURL)
}

// Size returns the member count.
func (t *BatchTree) Size() int { return len(t.Leaves) }

// MerkleProofForContract converts a branch to the [][32]byte form the bindings expect.
func MerkleProofForContract(branch [][32]byte) [][32]byte {
	out := make([][32]byte, len(branch))
	copy(out, branch)
	return out
}

// AccountAddressForADI is a convenience for logging which account a leaf belongs to.
func AccountAddressForADI(adiURL string) common.Address {
	h := ethcrypto.Keccak256([]byte(adiURL))
	return common.BytesToAddress(h[12:])
}

// bigZero is a shared zero used where a nil *big.Int must encode as 0, matching how the
// Solidity side treats an absent value.
func bigZero() *big.Int { return new(big.Int) }

// batchOperationIDOf is the operation id a batch is formed with: v3 for members whose intent CERTEN's quorum
// certified, v2 for members committed before a BLS registry was in force that commit to their governance decision,
// v1 for members admitted before that existed (LegacyNoGovernance) - the id their anchors carry. The classes are
// never mixed in one batch (memberClass partitions periods), and a member that is none is refused.
func batchOperationIDOf(inputs []BatchLeafInput) ([32]byte, string, error) {
	certified := 0
	for _, in := range inputs {
		if in.IntentMessage != ([32]byte{}) {
			certified++
		}
	}
	switch {
	case certified == len(inputs) && certified > 0:
		id, err := DeriveBatchOperationIDV3(inputs)
		return id, BatchOperationIDV3, err
	case certified > 0:
		return [32]byte{}, "", fmt.Errorf("a batch cannot mix %d member(s) with a certified intent and %d without",
			certified, len(inputs)-certified)
	}
	legacy := 0
	for _, in := range inputs {
		if in.LegacyNoGovernance {
			if in.GovernanceCommitment != ([32]byte{}) {
				return [32]byte{}, "", fmt.Errorf("member %s is marked legacy but carries a governance commitment", in.ADIURL)
			}
			legacy++
		}
	}
	switch legacy {
	case 0:
		id, err := DeriveBatchOperationIDV2(inputs)
		return id, BatchOperationIDV2, err
	case len(inputs):
		ids := make([][32]byte, 0, len(inputs))
		for _, in := range inputs {
			ids = append(ids, in.OperationID)
		}
		return DeriveBatchOperationID(ids), BatchOperationIDV1, nil
	default:
		return [32]byte{}, "", fmt.Errorf("a batch cannot mix %d member(s) admitted before governance commitments with %d "+
			"that commit to theirs", legacy, len(inputs)-legacy)
	}
}

// BatchOperationIDV1 and BatchOperationIDV2 name how a batch operation id was derived (BatchTree).
const (
	BatchOperationIDV1 = "v1"
	BatchOperationIDV2 = "v2"
	BatchOperationIDV3 = "v3"
)

// BatchOperationIDDomainV3 opens the v3 batch operation id.
const BatchOperationIDDomainV3 = "certen:batchopid:v3"

// DeriveBatchOperationIDV3 is the batch's id over every member's operation, governance decision AND quorum-certified
// intent message (RB5 D3):
//
//	keccak256("certen:batchopid:v3" || for each member, sorted by (operationID, governanceCommitment, intentMessage):
//	          operationID || governanceCommitment || intentMessage)
//
// The anchor stores it and the quorum's batch message covers it, so CERTEN's on-chain anchor commits to the per-intent
// certificate of every member - govRoot v2 over its full proof among it. A member without a governance commitment or
// a certified message is refused, never committed as zero.
func DeriveBatchOperationIDV3(inputs []BatchLeafInput) ([32]byte, error) {
	type triple struct{ op, gov, msg [32]byte }
	ts := make([]triple, 0, len(inputs))
	for i, in := range inputs {
		switch {
		case in.OperationID == ([32]byte{}):
			return [32]byte{}, fmt.Errorf("member %d (%s) has a zero operationID", i, in.ADIURL)
		case in.GovernanceCommitment == ([32]byte{}):
			return [32]byte{}, fmt.Errorf("member %d (%s, operation %x) has no governance decision to commit to",
				i, in.ADIURL, in.OperationID[:8])
		case in.IntentMessage == ([32]byte{}):
			return [32]byte{}, fmt.Errorf("member %d (%s, operation %x) has no certified intent message",
				i, in.ADIURL, in.OperationID[:8])
		}
		ts = append(ts, triple{in.OperationID, in.GovernanceCommitment, in.IntentMessage})
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].op != ts[j].op {
			return bytesLess(ts[i].op, ts[j].op)
		}
		if ts[i].gov != ts[j].gov {
			return bytesLess(ts[i].gov, ts[j].gov)
		}
		return bytesLess(ts[i].msg, ts[j].msg)
	})
	packed := make([]byte, 0, len(BatchOperationIDDomainV3)+len(ts)*96)
	packed = append(packed, []byte(BatchOperationIDDomainV3)...)
	for _, t := range ts {
		packed = append(packed, t.op[:]...)
		packed = append(packed, t.gov[:]...)
		packed = append(packed, t.msg[:]...)
	}
	return ethcrypto.Keccak256Hash(packed), nil
}

// BatchOperationIDDomainV2 opens the v2 batch operation id.
const BatchOperationIDDomainV2 = "certen:batchopid:v2"

// DeriveBatchOperationIDV2 is the batch's own id, committing to each member's operation AND to who decided it
// (RB4-F66):
//
//	keccak256("certen:batchopid:v2" || for each member, sorted by (operationID, governanceCommitment):
//	          operationID || governanceCommitment)
//
// The anchor stores it as its operationID and the quorum's BLS message covers it, so the quorum signature and the
// anchor commit to every member's governance decision - with no contract change: the anchor only requires it to be
// non-zero and derives the bundle id from it, and the account never reads it. The v1 id aggregated the operation ids
// alone. Sorted so it depends only on the SET of members; a member without a governance commitment has no decision
// to commit to, and is refused rather than committed as zero.
func DeriveBatchOperationIDV2(inputs []BatchLeafInput) ([32]byte, error) {
	type pair struct{ op, gov [32]byte }
	pairs := make([]pair, 0, len(inputs))
	for i, in := range inputs {
		if in.OperationID == ([32]byte{}) {
			return [32]byte{}, fmt.Errorf("member %d (%s) has a zero operationID", i, in.ADIURL)
		}
		if in.GovernanceCommitment == ([32]byte{}) {
			return [32]byte{}, fmt.Errorf("member %d (%s, operation %x) has no governance decision to commit to",
				i, in.ADIURL, in.OperationID[:8])
		}
		pairs = append(pairs, pair{in.OperationID, in.GovernanceCommitment})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].op != pairs[j].op {
			return bytesLess(pairs[i].op, pairs[j].op)
		}
		return bytesLess(pairs[i].gov, pairs[j].gov)
	})
	packed := make([]byte, 0, len(BatchOperationIDDomainV2)+len(pairs)*64)
	packed = append(packed, []byte(BatchOperationIDDomainV2)...)
	for _, p := range pairs {
		packed = append(packed, p.op[:]...)
		packed = append(packed, p.gov[:]...)
	}
	return ethcrypto.Keccak256Hash(packed), nil
}
