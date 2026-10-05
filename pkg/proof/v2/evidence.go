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
	"fmt"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Version is the proof_version a v2 proof is stored under; proofverify dispatches on it.
const Version = "2.0"

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

	// Pages are the governing key pages and the principal account as of the anchor's block (G1(a)).
	Pages []PageState `json:"pages,omitempty"`

	// Check proves the validator set in force at a certified block at or after the certified one.
	Check SetCheck `json:"check"`
}

// SetCheck extends the spine from its first Majors major records through Hops (binary api.MinorRootRecord, hex) to a
// certified anchor, and proves the network and globals accounts into that anchor's state tree root.
type SetCheck struct {
	Majors uint64                  `json:"majors"`
	Hops   []string                `json:"hops"`
	Set    proof.ValidatorSetProof `json:"set"`
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
	SetVerdict  proof.Verdict
	Validators  int
	Threshold   uint64
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

	// The spine to the larger of the two starting points, keeping the state at each.
	need := max(ev.Majors, ev.Check.Majors)
	if need == 0 || need > uint64(len(ar.Majors)) {
		return nil, fmt.Errorf("evidence builds on %d major blocks; the archive has %d", need, len(ar.Majors))
	}
	sp, err := NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	at := map[uint64]*Spine{}
	for i := uint64(0); i < need; i++ {
		if err := sp.Advance(ar.Majors[i]); err != nil {
			return nil, fmt.Errorf("spine: %w", err)
		}
		if i+1 == ev.Majors || i+1 == ev.Check.Majors {
			at[i+1] = sp.Clone()
		}
	}
	rep.Majors = need

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

	// The partition anchor: executed by the Directory, proven into the same certified root, naming the block whose
	// root chain the transaction's receipt passes through and whose state root the pages are proven into.
	body, seq, anchorTx, err := anchorBody(ev.Anchor.Message)
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
	rep.Partition, rep.AnchorBlock = seq.Source.String(), body.MinorBlockIndex
	for i := range ev.Pages {
		acct, pc, err := verifyPage(&ev.Pages[i], body.StateTreeAnchor[:])
		if err != nil {
			return nil, fmt.Errorf("page: %w", err)
		}
		rep.Pages = append(rep.Pages, acct)
		rep.PageChains = append(rep.PageChains, pc)
	}

	// The validator set: walked to a certified block at or after the certified one, proven there, equal to the set
	// the walk derived. Every write the walk applied must be accounted for by the network account's main chain.
	chk := at[ev.Check.Majors].Clone()
	if len(ev.Check.Hops) == 0 {
		return nil, fmt.Errorf("set check has no minor-root run")
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
	applied := uint64(0)
	for _, a := range chk.Applied {
		if a.Principal == protocol.DnUrl().JoinPath(protocol.Network).String() {
			applied++
		}
	}
	if height != 1+applied {
		return nil, fmt.Errorf("set check: the network account's main chain has %d entries but the walk applied %d updates after genesis", height, applied)
	}
	rep.Validators = len(chk.Globals().Network.Validators)
	rep.Threshold = chk.Globals().ValidatorThreshold(protocol.Directory)
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
	ar := &Archive{Majors: make([]*api.MajorHeaderRecord, len(in))}
	for i, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("major %d: %w", i+1, err)
		}
		r := new(api.MajorHeaderRecord)
		if err := r.UnmarshalBinary(b); err != nil {
			return nil, fmt.Errorf("major %d: %w", i+1, err)
		}
		ar.Majors[i] = r
	}
	return ar, nil
}
