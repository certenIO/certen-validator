package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
)

// The Accumulate validator-set spine as consensus state (rules v13, docs/proof/GOVROOT_V3.md, PROOF_V2.md).
//
// # WHY A TRANSACTION
//
// A proof v2 is judged inside FinalizeBlock, which may read only committed state and the block: never an Accumulate
// RPC, never a node's own archive. The proof's validator set has to be traced from the incarnation's genesis through
// every Accumulate major block that could have changed it, and a node walking that history over its own RPC would judge
// against whatever its server told it. So the walk is done ONCE, by the chain: a genesis transaction fixes the starting
// set, extension transactions carry the major-block records after it, and every validator verifies each of them
// deterministically (pkg/proof/v2 consensus_spine.go) when it is committed. A proof is then judged against these
// checkpoints, identically on every node and on replay.
//
// # WHAT MAKES IT SAFE
//
//   - The genesis is accepted only if its facts recompute the Accumulate incarnation of the BLS registry IN FORCE for
//     its block (proofv2.AcceptSpineGenesis): the registry, signed by the admin quorum, already names the incarnation
//     the quorum attests under, so the spine starts from exactly that network's genesis set and from nothing a
//     submitter chose. Anyone may submit it; nothing about it is theirs.
//   - An extension carries the next major blocks in sequence after the last checkpoint (first = checkpoints + 1), and
//     every record must verify from the spine as the chain already holds it (proofv2.ExtendSpine) - signatures by the
//     set in force, anchors chained - or the whole extension is refused. Anyone may submit one: a record that does not
//     verify cannot enter, and one that does is the same for every submitter.
//   - The spine follows the registry's incarnation, and only it. An Accumulate restart is a governed CERTEN change: the
//     admins sign a registry with the new accumulate_incarnation. While the recorded genesis is the incarnation of the
//     registry in force, no other genesis is accepted (the same genesis again within its own block is the accepted
//     no-op), so the spine's starting point never moves under a registry. Once the registry has moved, a genesis for
//     the new incarnation REPLACES the log - a new genesis, its set, no checkpoints - and the dead incarnation's spine
//     is kept only as the replaced log's Previous, for reading the chain's past state back. Proofs under the dead
//     incarnation can no longer be judged in consensus, which is right: the registry no longer attests under it.
//   - An extension is judged only against a spine of the registry's incarnation; against any other it is refused.
//   - Both kinds are bound to the chain id; neither carries a signature, because neither needs an authority: what they
//     add is fixed by Accumulate's own consensus and the committed registry.

// The transaction kinds on the wire.
const (
	AccumulateSpineGenesisKind = "certen.accumulate.spine.genesis/v1"
	AccumulateSpineExtendKind  = "certen.accumulate.spine.extend/v1"
)

// The result codes of refused spine transactions (rules v13). Codes 9-12 are the BLS registry, the intent certificate,
// the admin re-seal and the admin rotation; these are the next free ones, and no earlier rules version returns them.
const (
	// codeSpineGenesisRefused: a spine genesis refused - another chain, no registry in force, a spine of the registry's
	// incarnation already recorded, or facts that do not recompute the registry's incarnation.
	codeSpineGenesisRefused uint32 = 13
	// codeSpineExtendRefused: a spine extension refused - another chain, no genesis, a spine that is not the registry's
	// incarnation, a gap in the sequence, or a record that does not verify.
	codeSpineExtendRefused uint32 = 14
	// codeSpineExtendStale: a spine extension whose first major block the chain has already verified. Its own code,
	// because it is the expected outcome of two submitters racing to extend from the same checkpoint - not an invalid
	// transaction - and tools tell the two apart by it.
	codeSpineExtendStale uint32 = 15
)

// maxSpineExtensionRecords bounds the major blocks one extension carries: every record is verified in FinalizeBlock
// (signatures and anchors), so a block's cost has to be bounded, and an Accumulate major block is a day of the network.
// 100 is over three months of Accumulate per transaction; the spine catches up from genesis in a few transactions.
const maxSpineExtensionRecords = 100

// maxSpineRecordBytes bounds one encoded record - a major header record, or a genesis network definition or globals
// record. Kermit's largest major header record is 1,770 bytes; a record carrying network-definition updates is larger,
// and 64 KiB leaves room for a large validator set's while bounding what one record makes FinalizeBlock decode.
const maxSpineRecordBytes = 64 << 10

// maxSpineExtensionBytes bounds the decoded records of one extension together (Kermit: about 70 KiB per 100), so the
// hex transaction stays under CometBFT's default 1 MiB mempool transaction limit with room for its JSON.
const maxSpineExtensionBytes = 448 << 10

// AccumulateSpineGenesisTx sets the spine's genesis: the incarnation's genesis facts (proof.IncarnationInputs).
// Hex fields are lowercase without a 0x prefix - one spelling per value, so one genesis has one id.
type AccumulateSpineGenesisTx struct {
	Kind            string `json:"kind"`
	ChainID         string `json:"chain_id"`
	MinorBlockIndex uint64 `json:"minor_block_index"`
	RootChainAnchor string `json:"root_chain_anchor"` // hex32
	StateTreeAnchor string `json:"state_tree_anchor"` // hex32
	TimeUnix        uint64 `json:"time_unix"`
	NetworkRecord   string `json:"network_record"` // hex, the NetworkDefinition record exactly as stored on chain
	GlobalsRecord   string `json:"globals_record"` // hex, the NetworkGlobals record exactly as stored on chain
}

// AccumulateSpineExtendTx carries the major blocks First, First+1, ... after the spine's last checkpoint.
type AccumulateSpineExtendTx struct {
	Kind    string   `json:"kind"`
	ChainID string   `json:"chain_id"`
	First   uint64   `json:"first"`   // the major block index of Records[0]
	Records []string `json:"records"` // hex, each an api.MajorHeaderRecord's binary encoding, lowercase
}

// GenesisID is what an accepted genesis contributes to the app hash: "accumulate-spine-genesis:" and the hex sha256 of
// the transaction's canonical bytes - every field in the order above, length-prefixed (lengthPrefixed), integers in
// decimal. The encoding is injective and the hex fields have one spelling, so two geneses share an id only if they are
// the same genesis.
func (t *AccumulateSpineGenesisTx) GenesisID() string {
	sum := sha256.Sum256(lengthPrefixed(AccumulateSpineGenesisKind, t.ChainID, strconv.FormatUint(t.MinorBlockIndex, 10),
		t.RootChainAnchor, t.StateTreeAnchor, strconv.FormatUint(t.TimeUnix, 10), t.NetworkRecord, t.GlobalsRecord))
	return "accumulate-spine-genesis:" + hex.EncodeToString(sum[:])
}

// ExtensionID is what an accepted extension contributes to the app hash: "accumulate-spine-extend:" and the hex sha256
// of its canonical bytes - the kind, the chain, First and the number of records in decimal, then every record,
// length-prefixed.
func (t *AccumulateSpineExtendTx) ExtensionID() string {
	fields := []string{AccumulateSpineExtendKind, t.ChainID, strconv.FormatUint(t.First, 10), strconv.Itoa(len(t.Records))}
	fields = append(fields, t.Records...)
	sum := sha256.Sum256(lengthPrefixed(fields...))
	return "accumulate-spine-extend:" + hex.EncodeToString(sum[:])
}

// DecodeAccumulateSpineGenesis returns the transaction if these bytes are one. The discriminator is the explicit kind;
// bytes of the kind that do not decode are still the kind, refused by CheckShape, never judged as a ValidatorBlock.
func DecodeAccumulateSpineGenesis(tx []byte) (*AccumulateSpineGenesisTx, bool) {
	if txKind(tx) != AccumulateSpineGenesisKind {
		return nil, false
	}
	var t AccumulateSpineGenesisTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &AccumulateSpineGenesisTx{Kind: AccumulateSpineGenesisKind}, true
	}
	return &t, true
}

// DecodeAccumulateSpineExtend returns the transaction if these bytes are one, as DecodeAccumulateSpineGenesis.
func DecodeAccumulateSpineExtend(tx []byte) (*AccumulateSpineExtendTx, bool) {
	if txKind(tx) != AccumulateSpineExtendKind {
		return nil, false
	}
	var t AccumulateSpineExtendTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind}, true
	}
	return &t, true
}

// txKind is a transaction's explicit kind, "" when it names none or is not JSON.
func txKind(tx []byte) string {
	var probe struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(tx, &probe) != nil {
		return ""
	}
	return probe.Kind
}

// canonicalHex decodes s, which must be non-empty lowercase hex without a prefix, of at most max bytes.
func canonicalHex(what, s string, max int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 || s != strings.ToLower(s) {
		return nil, fmt.Errorf("%s is not non-empty lowercase hex", what)
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s is %d bytes, over the %d a spine transaction may carry", what, len(b), max)
	}
	return b, nil
}

// Inputs is the genesis as the incarnation's inputs. It checks the shape of every field, nothing else.
func (t *AccumulateSpineGenesisTx) Inputs() (proof.IncarnationInputs, error) {
	var in proof.IncarnationInputs
	root, err := canonicalHex("root_chain_anchor", t.RootChainAnchor, 32)
	if err != nil {
		return in, err
	}
	state, err := canonicalHex("state_tree_anchor", t.StateTreeAnchor, 32)
	if err != nil {
		return in, err
	}
	if len(root) != 32 || len(state) != 32 {
		return in, fmt.Errorf("the root chain anchor and state tree anchor are 32 bytes each")
	}
	if in.NetworkRecord, err = canonicalHex("network_record", t.NetworkRecord, maxSpineRecordBytes); err != nil {
		return in, err
	}
	if in.GlobalsRecord, err = canonicalHex("globals_record", t.GlobalsRecord, maxSpineRecordBytes); err != nil {
		return in, err
	}
	in.GenesisMinorBlockIndex, in.GenesisTimeUnix = t.MinorBlockIndex, t.TimeUnix
	copy(in.GenesisRootChainAnchor[:], root)
	copy(in.GenesisStateTreeAnchor[:], state)
	return in, nil
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except the chain,
// the registry in force and whether a genesis is recorded. The incarnation is judged in FinalizeBlock, against the
// registry in force for the block.
func (t *AccumulateSpineGenesisTx) CheckShape() error {
	if t.Kind != AccumulateSpineGenesisKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, AccumulateSpineGenesisKind)
	}
	if strings.TrimSpace(t.ChainID) == "" {
		return fmt.Errorf("a spine genesis names its chain")
	}
	if t.MinorBlockIndex == 0 || t.TimeUnix == 0 {
		return fmt.Errorf("a spine genesis names its minor block index and time")
	}
	_, err := t.Inputs()
	return err
}

// MajorRecords decodes the records. It checks the shape of every record and the extension's size, nothing else.
func (t *AccumulateSpineExtendTx) MajorRecords() ([]*api.MajorHeaderRecord, error) {
	n := len(t.Records)
	if n == 0 || n > maxSpineExtensionRecords {
		return nil, fmt.Errorf("an extension carries %d major blocks; it carries 1 to %d", n, maxSpineExtensionRecords)
	}
	out := make([]*api.MajorHeaderRecord, n)
	total := 0
	for i, s := range t.Records {
		b, err := canonicalHex(fmt.Sprintf("record %d (major block %d)", i, t.First+uint64(i)), s, maxSpineRecordBytes)
		if err != nil {
			return nil, err
		}
		if total += len(b); total > maxSpineExtensionBytes {
			return nil, fmt.Errorf("the extension's records exceed %d bytes", maxSpineExtensionBytes)
		}
		what := fmt.Sprintf("record %d (major block %d)", i, t.First+uint64(i))
		r := new(api.MajorHeaderRecord)
		if err := refusePanic(what+" could not be decoded", func() error { return r.UnmarshalBinary(b) }); err != nil {
			return nil, fmt.Errorf("%s is not a major header record: %w", what, err)
		}
		// One encoding per record: bytes that decode but do not re-encode to themselves (trailing or unknown fields)
		// are refused, so a record's bytes are the record.
		var again []byte
		if err := refusePanic(what+" could not be re-encoded", func() (err error) { again, err = r.MarshalBinary(); return err }); err != nil {
			return nil, err
		}
		if !bytes.Equal(again, b) {
			return nil, fmt.Errorf("%s is not a major header record in its canonical encoding", what)
		}
		out[i] = r
	}
	return out, nil
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except the chain,
// the sequence and whether the records verify from the spine the chain holds.
func (t *AccumulateSpineExtendTx) CheckShape() error {
	if t.Kind != AccumulateSpineExtendKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, AccumulateSpineExtendKind)
	}
	if strings.TrimSpace(t.ChainID) == "" || t.First == 0 {
		return fmt.Errorf("a spine extension names its chain and a first major block above zero")
	}
	_, err := t.MajorRecords()
	return err
}

// spineBelow is the spine as committed below height h: the genesis if it was accepted below h, the checkpoints accepted
// below h - a prefix, since checkpoints are appended in block order; it stops at the first one accepted at h or above -
// and the sets those reference, in the order the log holds them. A set enters the log in the block whose genesis or
// checkpoint first references it, so these are exactly the sets the log held below h. A log whose genesis was accepted
// at h or above replaced its Previous there, so below h the spine is the one Previous holds.
func spineBelow(stored *ledger.AccumulateSpineLog, h int64) *ledger.AccumulateSpineLog {
	out := &ledger.AccumulateSpineLog{}
	if stored == nil || stored.Genesis == nil {
		return out
	}
	if stored.Genesis.Height >= h {
		return spineBelow(stored.Previous, h)
	}
	g := *stored.Genesis
	out.Genesis = &g
	out.Previous = stored.Previous
	used := map[string]bool{g.SetHash: true}
	for _, c := range stored.Checkpoints {
		if c.Height >= h {
			break
		}
		out.Checkpoints = append(out.Checkpoints, c)
		used[c.SetHash] = true
	}
	for _, s := range stored.Sets {
		if used[s.Hash] {
			out.Sets = append(out.Sets, s)
		}
	}
	return out
}

// spineAcceptances are the spine transactions THIS execution of a block accepted, in order. The kinds are judged
// against the spine committed below the block plus these - never against what an earlier execution of the same block
// wrote - so executing a block again decides every transaction of it as the first execution did.
type spineAcceptances struct {
	height       int64
	genesisID    string
	genesis      *ledger.AccumulateSpineGenesis
	extensionIDs []string
	checkpoints  []ledger.AccumulateSpineCheckpoint
	sets         []ledger.AccumulateSpineSet // in the order they were added: the genesis set first, if it was accepted here
}

// spineView is the spine a transaction of the block at height h is judged against: the log as committed below h plus
// this execution's own acceptances in the block (a), when a is for h. A genesis accepted in the block starts the spine
// afresh - a first genesis, or one replacing a dead incarnation's - so the view is then that genesis and what the block
// accepted after it (processAccumulateSpineGenesis resets a's checkpoints and sets when it accepts one), with the
// committed spine as its Previous when it replaced one.
func spineView(stored *ledger.AccumulateSpineLog, h int64, a *spineAcceptances) *ledger.AccumulateSpineLog {
	v := spineBelow(stored, h)
	if a == nil || a.height != h {
		return v
	}
	if a.genesis != nil {
		g := *a.genesis
		fresh := &ledger.AccumulateSpineLog{Genesis: &g}
		if v.Genesis != nil {
			fresh.Previous = v
		}
		v = fresh
	}
	v.Checkpoints = append(v.Checkpoints, a.checkpoints...)
	v.Sets = append(v.Sets, a.sets...)
	return v
}

// incarnationHex is an incarnation as a spine genesis records it ("0x" + lowercase hex).
func incarnationHex(inc [32]byte) string { return "0x" + hex.EncodeToString(inc[:]) }

// refusePanic runs f, which decodes or verifies bytes a submitter chose, and returns a panic inside it as an error that
// names it. Accumulate's decoders and the spine's verification dereference fields a crafted record can leave nil (the
// accumulate v1.4.7 MajorHeaderRecord decoder, and proofv2's Spine.Advance via checkDirectorySelfAnchor, both panic on
// such input), and a panic in CheckTx or FinalizeBlock stops the node - every node, for a transaction in a block: the
// chain would halt on one malformed transaction. The code is deterministic, so every node panics on the same input and
// every node refuses it, with the same log.
func refusePanic(what string, f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s: malformed input (%v)", what, p)
		}
	}()
	return f()
}

// registryIncarnation is the Accumulate incarnation a registry record attests under, as recorded ("0x" + hex32).
func registryIncarnation(r *ledger.BLSRegistryRecord) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(r.AccumulateIncarnation, "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("BLS registry version %d records incarnation %q, which is not a hex32", r.Version, r.AccumulateIncarnation)
	}
	copy(out[:], b)
	return out, nil
}
