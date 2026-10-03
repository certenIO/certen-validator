package execution

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The outcome of a V8.2 batch anchor (RB5 D4): one leaf per anchor leaf, stating the member's FINAL state as its chain
// proves it, under one root that CERTEN's quorum signs and CertenOutcomeRegistryV1 records, write-once. The encoding is
// pinned in Go (here), in Solidity and in the shared vectors of certen-contracts (RB5_CLOSEOUT_PLAN.md §1b).

// OutcomeStatus is a member's final state.
type OutcomeStatus uint8

const (
	// OutcomeExecuted: a status-1 receipt from the member's account executing exactly its committed calls consumed
	// its leaf under this anchor, and every committed effect is proven.
	OutcomeExecuted OutcomeStatus = 1
	// OutcomeEffectsNotProven: as OutcomeExecuted, with a committed effect proven ABSENT (RB3-F67).
	OutcomeEffectsNotProven OutcomeStatus = 2
	// OutcomeNotSettled: at a finalized block past the member's deadline its leaf is unconsumed.
	OutcomeNotSettled OutcomeStatus = 3
	// OutcomeConsumedElsewhere: the leaf was consumed under another anchor (a leaf carries no anchor id).
	OutcomeConsumedElsewhere OutcomeStatus = 4
)

func (s OutcomeStatus) valid() bool { return s >= OutcomeExecuted && s <= OutcomeConsumedElsewhere }

// ErrOutcome is wrapped by every refusal to state an outcome.
var ErrOutcome = errors.New("batch outcome")

// OutcomeLeaf is one member's outcome.
type OutcomeLeaf struct {
	ChainID     int64
	BundleID    [32]byte
	LeafIndex   uint64
	BatchLeaf   [32]byte // the anchor leaf
	OperationID [32]byte
	Status      OutcomeStatus
	// Tx: the settlement (1, 2), the last reverted attempt or zero (3), the consuming transaction (4).
	Tx [32]byte
	// The finalized block that proves the outcome: the settlement's (1, 2), the pinned claim block (3), the
	// consuming transaction's (4).
	BlockNumber  uint64
	BlockHash    [32]byte
	ReceiptsRoot [32]byte
	EffectsHash  [32]byte
}

func word(b []byte) [32]byte {
	var w [32]byte
	copy(w[32-len(b):], b)
	return w
}

func uintWord(v uint64) [32]byte { return word(new(big.Int).SetUint64(v).Bytes()) }

func tagWord(tag string) [32]byte {
	var w [32]byte
	copy(w[:], tag)
	return w
}

func keccakWords(ws ...[32]byte) [32]byte {
	buf := make([]byte, 0, 32*len(ws))
	for _, w := range ws {
		buf = append(buf, w[:]...)
	}
	return crypto.Keccak256Hash(buf)
}

// Validate refuses a leaf whose fields do not fit its status.
func (l OutcomeLeaf) Validate() error {
	var zero [32]byte
	switch {
	case l.ChainID <= 0:
		return fmt.Errorf("%w: leaf %d has no chain", ErrOutcome, l.LeafIndex)
	case l.BundleID == zero || l.BatchLeaf == zero || l.OperationID == zero:
		return fmt.Errorf("%w: leaf %d lacks its anchor, leaf or operation id", ErrOutcome, l.LeafIndex)
	case !l.Status.valid():
		return fmt.Errorf("%w: leaf %d has status %d", ErrOutcome, l.LeafIndex, l.Status)
	case l.BlockNumber == 0 || l.BlockHash == zero || l.ReceiptsRoot == zero:
		return fmt.Errorf("%w: leaf %d names no finalized block", ErrOutcome, l.LeafIndex)
	case (l.Status == OutcomeExecuted || l.Status == OutcomeEffectsNotProven || l.Status == OutcomeConsumedElsewhere) && l.Tx == zero:
		return fmt.Errorf("%w: leaf %d (status %d) names no transaction", ErrOutcome, l.LeafIndex, l.Status)
	case l.Status == OutcomeEffectsNotProven && l.EffectsHash == zero:
		return fmt.Errorf("%w: leaf %d claims a shortfall without its effects hash", ErrOutcome, l.LeafIndex)
	case (l.Status == OutcomeNotSettled || l.Status == OutcomeConsumedElsewhere) && l.EffectsHash != zero:
		return fmt.Errorf("%w: leaf %d (status %d) carries an effects hash", ErrOutcome, l.LeafIndex, l.Status)
	}
	return nil
}

// Hash is the leaf: keccak256(abi.encode("certen:outcomeleaf:v1", chainId, bundleId, leafIndex, batchLeaf,
// operationID, status, tx, blockNumber, blockHash, receiptsRoot, effectsHash)).
func (l OutcomeLeaf) Hash() ([32]byte, error) {
	if err := l.Validate(); err != nil {
		return [32]byte{}, err
	}
	return keccakWords(tagWord("certen:outcomeleaf:v1"), uintWord(uint64(l.ChainID)), l.BundleID, uintWord(l.LeafIndex),
		l.BatchLeaf, l.OperationID, uintWord(uint64(l.Status)), l.Tx, uintWord(l.BlockNumber), l.BlockHash,
		l.ReceiptsRoot, l.EffectsHash), nil
}

// OutcomeRoot is the root over a batch anchor's outcome leaves: exactly one per anchor leaf, in tree order (leaf i
// at index i), under MerkleRoot - the batch tree's own construction.
func OutcomeRoot(leaves []OutcomeLeaf, batchLeafCount uint64) ([32]byte, error) {
	if uint64(len(leaves)) != batchLeafCount || batchLeafCount == 0 {
		return [32]byte{}, fmt.Errorf("%w: %d outcome leaves for an anchor of %d leaves", ErrOutcome, len(leaves), batchLeafCount)
	}
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		if l.LeafIndex != uint64(i) {
			return [32]byte{}, fmt.Errorf("%w: outcome %d is for leaf %d; leaves must be in tree order", ErrOutcome, i, l.LeafIndex)
		}
		if i > 0 && (l.ChainID != leaves[0].ChainID || l.BundleID != leaves[0].BundleID) {
			return [32]byte{}, fmt.Errorf("%w: outcome %d is of another anchor", ErrOutcome, i)
		}
		h, err := l.Hash()
		if err != nil {
			return [32]byte{}, err
		}
		hashes[i] = h
	}
	return MerkleRoot(hashes)
}

// CommittedEffect identifies one committed effect by its leg and its index within that leg.
type CommittedEffect struct{ Leg, Index uint64 }

// CommittedEffectsHash is keccak(abi.encode("certen:outcome-effects:v1", eventsHash, stateHash)) over the effects the
// member's legs committed, in leg order then effect order; zero when the legs committed none.
func CommittedEffectsHash(events [][]ExpectedEvent, state [][]ExpectedStateSlot) [32]byte {
	var ev, st []byte
	for li, leg := range events {
		for ei, e := range leg {
			w := []([32]byte){uintWord(uint64(li)), uintWord(uint64(ei)), word(e.Contract.Bytes()), e.Topic0, e.DataHash}
			for _, x := range w {
				ev = append(ev, x[:]...)
			}
		}
	}
	for li, leg := range state {
		for si, s := range leg {
			w := []([32]byte){uintWord(uint64(li)), uintWord(uint64(si)), word(s.Account.Bytes()), s.Slot, s.Value}
			for _, x := range w {
				st = append(st, x[:]...)
			}
		}
	}
	if len(ev) == 0 && len(st) == 0 {
		return [32]byte{}
	}
	return keccakWords(tagWord("certen:outcome-effects:v1"), crypto.Keccak256Hash(ev), crypto.Keccak256Hash(st))
}

// ShortfallEffectsHash is keccak(abi.encode("certen:outcome-shortfall:v1", committedEffectsHash, missingEventsHash,
// unsetStateHash)): the committed effects and which of them were proven absent, by (leg, index) in order.
func ShortfallEffectsHash(committed [32]byte, missingEvents, unsetState []CommittedEffect) ([32]byte, error) {
	if committed == ([32]byte{}) {
		return [32]byte{}, fmt.Errorf("%w: a shortfall of a member that committed no effects", ErrOutcome)
	}
	if len(missingEvents) == 0 && len(unsetState) == 0 {
		return [32]byte{}, fmt.Errorf("%w: a shortfall that names no missing effect", ErrOutcome)
	}
	enc := func(list []CommittedEffect) [32]byte {
		sorted := append([]CommittedEffect(nil), list...)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Leg != sorted[j].Leg {
				return sorted[i].Leg < sorted[j].Leg
			}
			return sorted[i].Index < sorted[j].Index
		})
		var b []byte
		for _, e := range sorted {
			l, x := uintWord(e.Leg), uintWord(e.Index)
			b = append(b, l[:]...)
			b = append(b, x[:]...)
		}
		return crypto.Keccak256Hash(b)
	}
	return keccakWords(tagWord("certen:outcome-shortfall:v1"), committed, enc(missingEvents), enc(unsetState)), nil
}

// outcomeHex renders a word for the shared vectors.
func outcomeHex(w [32]byte) string { return common.Hash(w).Hex() }
