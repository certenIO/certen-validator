// Copyright 2026 Certen Protocol
//
// Proof v2, Accumulate side (docs/proof/PROOF_V2.md §3 S1-S2, §4): a transaction proven by ONE continuous receipt into
// a Directory root, that root certified by walking the Directory's validator-set spine forward from the genesis of a
// pinned incarnation, and the validator set the walk derives cross-checked against the network accounts as proven at
// a certified state root. Nothing in the evidence is trusted: every value is recomputed here, offline.

package proofv2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/certen/independant-validator/pkg/ledger"
	"strings"

	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Version is the proof_version a v2 proof is stored under; proofverify dispatches on it.
const Version = "2.0"

// errNoMajors is the refusal of evidence whose certification builds on no major block (majors 0 or absent). Major blocks are 1-based and
// the certification's minor-root runs extend a spine that has verified at least the first, so there is nothing to extend: every entry point
// (VerifyFromGenesis, Verify21FromGenesis, VerifyFromSpine, VerifyEvidence21FromSpine) refuses it with this one text, before any spine is
// built, and the document is never read further.
var errNoMajors = errors.New("evidence builds on 0 major blocks: the certification needs at least the first")

// Evidence is the Accumulate side of one v2 proof. The spine's major records are shared by every proof and carried
// once, in an Archive; Evidence names how many of them it builds on.
type Evidence struct {
	Version string `json:"version"`
	Account string `json:"account"`
	TxHash  string `json:"txHash"` // hex32

	// Receipt runs from the transaction hash to the certified Directory root (binary merkle.Receipt, hex).
	Receipt string `json:"receipt"`

	// Certify extends the spine, from its first Majors major records, through one or more minor-root runs (each bounded
	// by the server) to the Directory anchor whose root chain anchor
	// the receipt ends at (binary api.MinorRootRecord, hex).
	Majors  uint64   `json:"majors"`
	Certify []string `json:"certify"`

	// Anchor is the partition's anchor for the block the transaction's receipt passes through: it names that block
	// and the partition's state root at it, which every page must be proven into.
	Anchor PartitionAnchor `json:"anchor"`

	// Pages are the governing key pages and the principal account as of the anchor's block (G1(a)). In evidence 2.1 each
	// page is as of ITS partition's block, proven through Anchors[its partition].
	Pages []PageState `json:"pages,omitempty"`

	// Evidence 2.1 only (docs/proof/G1_CROSS_PARTITION.md D3, D4); empty, and so absent from the encoding, in 2.0.
	//
	// Anchors holds, for the transaction's partition and for every other partition that holds a proven page, that
	// partition's BlockValidatorAnchor for the block its pages are proven at (B_Y) and the receipt proving the anchor
	// into the certified Directory root, keyed by the anchor message's Source ("acc://bvn-BVN2.acme"). Anchors[X] is the
	// 2.0 field Anchor.
	Anchors map[string]PartitionAnchor `json:"anchors,omitempty"`
	// Votes are the authority votes copied from the principal's proven signature chain (D3).
	Votes []Vote `json:"votes,omitempty"`
	// Transaction is the governed transaction, binary, hex (2.1 timeline): its type decides the page blacklist and which authorities must vote,
	// and its hash must be TxHash. Absent, the votes are not re-evaluated (named in the report).
	Transaction string `json:"transaction,omitempty"`

	// Check proves the validator set in force at a certified block at or after the certified one.
	Check SetCheck `json:"check"`
}

// SetCheck extends the spine from its first Majors major records through Hops (binary api.MinorRootRecord, hex) to a
// certified anchor, and proves the network and globals accounts into that anchor's state tree root.
type SetCheck struct {
	Majors uint64                  `json:"majors"`
	Hops   []string                `json:"hops"`
	Set    proof.ValidatorSetProof `json:"set"`

	// Routing, in evidence 2.1, is the Directory's routing table (acc://dn.acme/routing) proven into the same state root as
	// the network and globals accounts, so a verifier can check Partition == route(URL) for every page (design D5). Absent
	// in 2.0; absent in 2.1 only with the named state g1_routing_unproven.
	Routing *proof.AccountStateProof `json:"routing,omitempty"`
}

// Report is what Verify established.
type Report struct {
	Incarnation    [32]byte
	Majors         uint64
	CertifiedBlock uint64
	CertifiedRoot  [32]byte
	CheckBlock     uint64

	// Partition and AnchorBlock are the transaction's partition and the block of its anchor the transaction's receipt
	// passes through: the transaction executed at or before AnchorBlock, and every page is its state as of
	// AnchorBlock. That AnchorBlock is exactly the execution block is not proven here (see page.go).
	Partition   string
	AnchorBlock uint64
	Pages       []protocol.Account
	PageChains  []PageChain // per page, in the same order: whether its chains are proven at AnchorBlock
	// Proven lists every proven page as (partition, block, roles), in the same order as Pages. Evidence 2.0 leaves it
	// empty (every page is the transaction's partition's, at AnchorBlock); 2.1 fills it (design D4).
	Proven     []ProvenPage
	SetVerdict proof.Verdict
	Validators int
	Threshold  uint64

	// Version is the evidence version verified and Tag the domain tag its commitments are made under: empty for 2.0, certen:g1:v4
	// for 2.1. Unproven lists, for 2.1, every fact the verifier could not establish with the partition and block it was judged at
	// (design D6): a report with any entry is not a verified S3. RoutingHeight is the main chain height of the proven routing
	// table (1: never rewritten since genesis; 0: no routing proof carried).
	Version       string
	Tag           string
	Unproven      []NamedState
	RoutingHeight uint64

	// Timeline results (2.1 with a timeline; zero otherwise). AuthorizationMode is "authorities_required" or "all_authorities_disabled"
	// (design D3). Disclosures are verified facts that are not refusals (design D6). Arrivals lists, per counted signature, the block it
	// arrived in as the verifier derived it from the page's signature-index chain.
	AuthorizationMode string
	Disclosures       []NamedState
	Arrivals          []ArrivalReport

	// TxHash is the transaction the receipt starts at; AnchorTxHash the partition anchor transaction proven into the
	// certified root, and AnchorStateRoot that anchor's StateTreeAnchor: the partition's state root at AnchorBlock,
	// which every page is proven into. govRoot v3 commits all three (docs/proof/GOVROOT_V3.md L1, L3).
	TxHash          [32]byte
	AnchorTxHash    [32]byte
	AnchorStateRoot [32]byte
	// AnchorRootChainAnchor is that anchor's RootChainAnchor: the partition's root at AnchorBlock, which the
	// transaction's receipt passes through. G0's execution witness must be exactly it (intentcert.BindG0ToProofV2).
	AnchorRootChainAnchor [32]byte

	// AccumulateSetRoot is the certen:accval:v1 root of the validator set the spine derived (proven equal to the
	// network account at the check block), with its threshold, under the pinned incarnation: the value a V8.2 anchor
	// must have committed for the proof to be about this set (RB6 acceptance: spine-derived L4 equals committed accRoot).
	AccumulateSetRoot [32]byte
}

// Archive is the Directory's major-block records from major block 1, shared by every proof.
type Archive struct {
	Majors []*api.MajorHeaderRecord
}

// Verify checks ev offline against the archive and the incarnation evidence, which must re-derive the pinned
// incarnation. Any error means the evidence does not prove what it claims; there is no weaker answer for S1-S2. The
// set check's verdict is reported as is: validator_set_asserted (the set changed after genesis and its history is not
// yet accounted for) is a named state, not success.
func Verify(ev *Evidence, ar *Archive, inc *proof.IncarnationEvidence, pinned [32]byte) (*Report, error) {
	if ev == nil || ev.Version != Version {
		return nil, fmt.Errorf("not a v2 Accumulate proof")
	}
	// The trust base: the genesis network values of the pinned incarnation.
	ir, err := inc.Verify()
	if err != nil {
		return nil, fmt.Errorf("incarnation evidence: %w", err)
	}
	return VerifyFromGenesis(ev, ar, ir.Inputs, pinned)
}

// VerifyFromGenesis is Verify given the incarnation's inputs rather than its full evidence. The genesis network and
// globals records the spine starts from are bound to the pin by the incarnation identity itself: it is a keccak over
// the inputs including sha256 of both records, so records other than the pinned genesis's cannot reproduce it. That
// is the binding the spine needs; the full evidence additionally proves the genesis anchor's quorum and the records'
// chain history.
func VerifyFromGenesis(ev *Evidence, ar *Archive, in proof.IncarnationInputs, pinned [32]byte) (*Report, error) {
	if ev == nil || ev.Version != Version {
		return nil, fmt.Errorf("not a v2 Accumulate proof")
	}
	return verifyFromGenesis(ev, ar, in, pinned)
}

// Verify21FromGenesis verifies evidence 2.1 (docs/proof/G1_CROSS_PARTITION.md; pages on more than one partition) from the
// incarnation's genesis. It is a separate entry point on purpose: Verify, VerifyFromGenesis and VerifyFromSpine - the ones
// consensus and the execution check call - refuse 2.1 by version exactly as before, so no 2.1 document is accepted anywhere
// until the rules switch that activates it (design D7, RB9 Phase C2). The report it returns carries Unproven: a report with an
// entry is not a verified S3.
func Verify21FromGenesis(ev *Evidence, ar *Archive, in proof.IncarnationInputs, pinned [32]byte) (*Report, error) {
	if ev == nil || ev.Version != Version21 {
		return nil, fmt.Errorf("not a v2.1 Accumulate proof")
	}
	return verifyFromGenesis(ev, ar, in, pinned)
}

func verifyFromGenesis(ev *Evidence, ar *Archive, in proof.IncarnationInputs, pinned [32]byte) (*Report, error) {
	rep := &Report{}
	id, err := proof.ComputeIncarnation(in)
	if err != nil {
		return nil, err
	}
	if id != pinned {
		return nil, fmt.Errorf("incarnation evidence is for %x, not the pinned %x", id, pinned)
	}
	rep.Incarnation = id
	g, err := genesisValues(in.NetworkRecord, in.GlobalsRecord)
	if err != nil {
		return nil, err
	}

	// The spine to the larger of the two starting points, keeping the state at each. The certification builds on at least the first major
	// block (errNoMajors, the same refusal VerifyFromSpine makes); the set check may build on none, as it may from a spine log
	// (SpineAt(l, 0) is the genesis spine), so the genesis spine is kept as the state after 0 major blocks.
	if ev.Majors == 0 {
		return nil, errNoMajors
	}
	need := max(ev.Majors, ev.Check.Majors)
	if need > uint64(len(ar.Majors)) {
		return nil, fmt.Errorf("evidence builds on %d major blocks; the archive has %d", need, len(ar.Majors))
	}
	sp, err := NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	at := map[uint64]*Spine{0: sp.Clone()}
	for i := uint64(0); i < need; i++ {
		if err := sp.Advance(ar.Majors[i]); err != nil {
			return nil, fmt.Errorf("spine: %w", err)
		}
		if i+1 == ev.Majors || i+1 == ev.Check.Majors {
			at[i+1] = sp.Clone()
		}
	}
	rep.Majors = need
	return verifyFrom(ev, rep, at, pinned)
}

// VerifyFromSpine verifies ev against the validator-set spine as CERTEN's consensus state holds it (the spine log a
// FinalizeBlock reads): the evidence's starting checkpoints are taken from the log, never walked from local state, so
// every validator judging the same block reaches the same verdict with no I/O. The log's genesis must be the pinned
// incarnation's.
func VerifyFromSpine(ev *Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*Report, error) {
	if ev == nil || ev.Version != Version {
		return nil, fmt.Errorf("not a v2 Accumulate proof")
	}
	return verifyFromSpine(ev, l, pinned)
}

// VerifyEvidence21FromSpine is VerifyFromSpine for evidence 2.1 (docs/proof/G1_CROSS_PARTITION.md; pages on more than one
// partition): the entry point consensus calls for a 2.1 certificate, with the starting checkpoints taken from the chain's spine log
// and no I/O, so every validator judging the same block reaches the same verdict. It is a separate function on purpose:
// VerifyFromSpine (like Verify and VerifyFromGenesis) refuses 2.1 by version exactly as before, so a 2.0 call site can never accept a
// 2.1 document; pkg/consensus reaches this function only for a certificate that carries 2.1 AND only when the rules v15 activation is
// in force at the block (intentInputs checks that first and refuses a 2.1 certificate before it by name). The report it returns
// carries Unproven: BindProofV21 refuses a report that is not complete for the intent's governing set.
func VerifyEvidence21FromSpine(ev *Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*Report, error) {
	if ev == nil || ev.Version != Version21 {
		return nil, fmt.Errorf("not a v2.1 Accumulate proof")
	}
	return verifyFromSpine(ev, l, pinned)
}

// verifyFromSpine is the spine walk the 2.0 and 2.1 entry points share, each of which has checked its own version.
func verifyFromSpine(ev *Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*Report, error) {
	if l == nil || l.Genesis == nil {
		return nil, fmt.Errorf("the chain has no Accumulate spine")
	}
	if !strings.EqualFold(strings.TrimPrefix(l.Genesis.Incarnation, "0x"), hex.EncodeToString(pinned[:])) {
		return nil, fmt.Errorf("the chain's spine is incarnation %s, not the pinned %x", l.Genesis.Incarnation, pinned)
	}
	if ev.Majors == 0 {
		return nil, errNoMajors
	}
	need := max(ev.Majors, ev.Check.Majors)
	if need > uint64(len(l.Checkpoints)) {
		return nil, fmt.Errorf("evidence builds on %d major blocks; the chain has verified %d", need, len(l.Checkpoints))
	}
	at := map[uint64]*Spine{}
	for _, n := range []uint64{ev.Majors, ev.Check.Majors} {
		if _, ok := at[n]; ok {
			continue
		}
		sp, err := SpineAt(l, n)
		if err != nil {
			return nil, err
		}
		at[n] = sp
	}
	return verifyFrom(ev, &Report{Incarnation: pinned, Majors: need}, at, pinned)
}

// verifyFrom checks everything after the spine's starting points: at holds the spine after ev.Majors and after
// ev.Check.Majors major blocks.
func verifyFrom(ev *Evidence, rep *Report, at map[uint64]*Spine, pinned [32]byte) (*Report, error) {
	var err error
	is21 := ev.Version == Version21
	if !is21 {
		// A 2.0 document carries none of the 2.1 members; one that does would have them silently ignored.
		if ev.Anchors != nil || ev.Votes != nil || ev.Check.Routing != nil {
			return nil, fmt.Errorf("evidence 2.0 carries 2.1 members (anchors, votes or a routing proof)")
		}
		for _, p := range ev.Pages {
			if p.Partition != "" || p.Roles != nil {
				return nil, fmt.Errorf("evidence 2.0 page %s carries a partition or roles", p.URL)
			}
		}
	}
	// S1-S2: the receipt from the transaction to a certified root.
	cert := at[ev.Majors].Clone()
	if len(ev.Certify) == 0 {
		return nil, fmt.Errorf("certify: no minor-root run")
	}
	for i, h := range ev.Certify {
		mr, err := decodeMinorRoot(h)
		if err != nil {
			return nil, fmt.Errorf("certify run %d: %w", i, err)
		}
		if err := cert.AdvanceEpoch(mr); err != nil {
			return nil, fmt.Errorf("certify run %d: %w", i, err)
		}
	}
	r, err := decodeReceipt(ev.Receipt)
	if err != nil {
		return nil, err
	}
	tx, err := hex.DecodeString(ev.TxHash)
	if err != nil || len(tx) != 32 {
		return nil, fmt.Errorf("txHash is not 32 bytes of hex")
	}
	if !bytes.Equal(r.Start, tx) {
		return nil, fmt.Errorf("receipt starts at %x, not the transaction %x", r.Start, tx)
	}
	if !bytes.Equal(r.Anchor, cert.RootChainAnchor[:]) {
		return nil, fmt.Errorf("receipt ends at %x, not the root %x certified at DN %d", r.Anchor, cert.RootChainAnchor, cert.LastMinorBlock)
	}
	if !r.Validate(nil) {
		return nil, fmt.Errorf("receipt does not validate")
	}
	rep.CertifiedBlock, rep.CertifiedRoot = cert.LastMinorBlock, cert.RootChainAnchor
	copy(rep.TxHash[:], tx)

	// The partition anchor: executed by the Directory, proven into the same certified root, naming the block whose
	// root chain the transaction's receipt passes through and whose state root the pages are proven into.
	body, seq, anchorTx, err := anchorOf(ev.Anchor.Message, is21)
	if err != nil {
		return nil, err
	}
	ar2, err := decodeReceipt(ev.Anchor.Receipt)
	if err != nil {
		return nil, fmt.Errorf("partition anchor: %w", err)
	}
	if !bytes.Equal(ar2.Start, anchorTx) || !bytes.Equal(ar2.Anchor, cert.RootChainAnchor[:]) || !ar2.Validate(nil) {
		return nil, fmt.Errorf("partition anchor: its receipt does not prove the anchor transaction into the certified root")
	}
	if prefixTo(r, body.RootChainAnchor[:]) == nil {
		return nil, fmt.Errorf("the transaction's receipt does not pass through the anchor's root chain anchor %x", body.RootChainAnchor)
	}
	if len(anchorTx) != 32 {
		return nil, fmt.Errorf("partition anchor: its transaction hash is %d bytes, not 32", len(anchorTx))
	}
	srcURL := seq.Source
	if is21 {
		srcURL = body.Source // the committed value; anchorOf has required the wrapper to agree (xdirectory.go partition)
	}
	rep.Partition, rep.AnchorBlock = srcURL.String(), body.MinorBlockIndex
	copy(rep.AnchorTxHash[:], anchorTx)
	rep.AnchorStateRoot, rep.AnchorRootChainAnchor = body.StateTreeAnchor, body.RootChainAnchor
	for i := 0; i < len(ev.Pages) && !is21; i++ {
		acct, pc, err := verifyPage(&ev.Pages[i], body.StateTreeAnchor[:])
		if err != nil {
			return nil, fmt.Errorf("page: %w", err)
		}
		rep.Pages = append(rep.Pages, acct)
		rep.PageChains = append(rep.PageChains, pc)
	}
	xin := xIn{certRoot: append([]byte(nil), cert.RootChainAnchor[:]...), setRoot: [32]byte{}}
	xin.x = xAnchor{source: srcURL.String(), block: body.MinorBlockIndex, stateRoot: append([]byte(nil), body.StateTreeAnchor[:]...)}
	xin.x.id, _ = protocol.ParsePartitionUrl(srcURL)

	// The validator set: walked to a certified block at or after the certified one, proven there, equal to the set
	// the walk derived. Every write the walk applied must be accounted for by the network account's main chain.
	// The set is checked either at the certified block itself (no runs: the check reuses the certification, which
	// keeps a proof small enough to travel in a consensus block) or at a later certified block reached by its own runs.
	var chk *Spine
	if len(ev.Check.Hops) == 0 {
		if ev.Check.Majors != ev.Majors {
			return nil, fmt.Errorf("set check has no minor-root run of its own but builds on %d major blocks, not the certification's %d", ev.Check.Majors, ev.Majors)
		}
		chk = cert.Clone()
	} else {
		chk = at[ev.Check.Majors].Clone()
	}
	for i, h := range ev.Check.Hops {
		mr, err := decodeMinorRoot(h)
		if err != nil {
			return nil, fmt.Errorf("set check hop %d: %w", i, err)
		}
		if err := chk.AdvanceEpoch(mr); err != nil {
			return nil, fmt.Errorf("set check hop %d: %w", i, err)
		}
	}
	if chk.LastMinorBlock < cert.LastMinorBlock {
		return nil, fmt.Errorf("the set is checked at DN %d, before the certified DN %d: updates between are unaccounted", chk.LastMinorBlock, cert.LastMinorBlock)
	}
	rep.CheckBlock = chk.LastMinorBlock

	set := ev.Check.Set
	derived, thr, err := set.DerivedSet()
	if err != nil {
		return nil, fmt.Errorf("set check: %w", err)
	}
	pinnedHex := hex.EncodeToString(pinned[:])
	verdict, err := set.Verify(proof.VerifyInput{
		AssertedSet:          derived,
		AssertedThreshold:    thr,
		BoundStateTreeAnchor: hex.EncodeToString(chk.StateTreeAnchor[:]),
		PinnedIncarnation:    &pinnedHex,
	})
	if err != nil {
		return nil, fmt.Errorf("set check: %w", err)
	}
	rep.SetVerdict = verdict

	// The proven accounts must hold exactly what the walk derived.
	if err := sameEntry(set.Network.AccountState, chk.Globals().Network.MarshalBinary); err != nil {
		return nil, fmt.Errorf("set check: network: %w", err)
	}
	if err := sameEntry(set.Globals.AccountState, chk.Globals().Globals.MarshalBinary); err != nil {
		return nil, fmt.Errorf("set check: globals: %w", err)
	}
	height, ok := set.MainChainHeight()
	if !ok {
		return nil, fmt.Errorf("set check: no main chain on the network account")
	}
	applied := chk.NetworkUpdates()
	if height != 1+applied {
		return nil, fmt.Errorf("set check: the network account's main chain has %d entries but the walk applied %d updates after genesis", height, applied)
	}
	if rep.AccumulateSetRoot, err = accumulateset.AccumulateSetRoot(derived, thr, pinned); err != nil {
		return nil, fmt.Errorf("set check: the accumulate set root: %w", err)
	}
	rep.Validators = len(chk.Globals().Network.Validators)
	rep.Threshold = chk.Globals().ValidatorThreshold(protocol.Directory)
	if is21 {
		xin.setRoot = chk.StateTreeAnchor
		xin.network = chk.Globals().Network.NetworkName
		if err := verify21(ev, rep, xin); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

func genesisValues(networkRecord, globalsRecord []byte) (*network.GlobalValues, error) {
	def := new(protocol.NetworkDefinition)
	if err := def.UnmarshalBinary(networkRecord); err != nil {
		return nil, fmt.Errorf("genesis network record: %w", err)
	}
	glob := new(protocol.NetworkGlobals)
	if err := glob.UnmarshalBinary(globalsRecord); err != nil {
		return nil, fmt.Errorf("genesis globals record: %w", err)
	}
	// The oracle and routing table play no part in the quorum check; they are set empty only because
	// GlobalValues.Copy cannot copy nil members.
	return &network.GlobalValues{Network: def, Globals: glob, Oracle: new(protocol.AcmeOracle), Routing: new(protocol.RoutingTable)}, nil
}

// sameEntry checks that a proven data account's single entry is byte-for-byte the record the walk derived.
func sameEntry(accountStateHex string, derived func() ([]byte, error)) error {
	raw, err := hex.DecodeString(accountStateHex)
	if err != nil {
		return err
	}
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return err
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok || da.Entry == nil || len(da.Entry.GetData()) != 1 {
		return fmt.Errorf("is %T, not a one-entry data account", acct)
	}
	want, err := derived()
	if err != nil {
		return err
	}
	if !bytes.Equal(da.Entry.GetData()[0], want) {
		return fmt.Errorf("the proven record differs from the one the walk derived")
	}
	return nil
}

func decodeMinorRoot(h string) (*api.MinorRootRecord, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	r := new(api.MinorRootRecord)
	if err := r.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return r, nil
}

func decodeReceipt(h string) (*merkle.Receipt, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	r := new(merkle.Receipt)
	if err := r.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	return r, nil
}

// MarshalArchive encodes an archive as JSON: one hex string per major record, in the records' binary encoding.
func MarshalArchive(ar *Archive) ([]byte, error) {
	out := make([]string, len(ar.Majors))
	for i, r := range ar.Majors {
		b, err := r.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("major %d: %w", i+1, err)
		}
		out[i] = hex.EncodeToString(b)
	}
	return json.Marshal(out)
}

// UnmarshalArchive decodes what MarshalArchive wrote.
func UnmarshalArchive(j []byte) (*Archive, error) {
	var in []string
	if err := json.Unmarshal(j, &in); err != nil {
		return nil, err
	}
	recs := make([][]byte, len(in))
	for i, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("major %d: %w", i+1, err)
		}
		recs[i] = b
	}
	return ArchiveFromRecords(recs)
}

// ArchiveFromRecords decodes major records in their binary encoding, from major block 1, as the validator stores them.
func ArchiveFromRecords(recs [][]byte) (*Archive, error) {
	ar := &Archive{Majors: make([]*api.MajorHeaderRecord, len(recs))}
	for i, b := range recs {
		r := new(api.MajorHeaderRecord)
		if err := r.UnmarshalBinary(b); err != nil {
			return nil, fmt.Errorf("major %d: %w", i+1, err)
		}
		ar.Majors[i] = r
	}
	return ar, nil
}
