// Copyright 2026 Certen Protocol
//
// The portable form of a v2 Accumulate proof: everything the verifier needs, as Accumulate's own JSON, so a verifier
// in another language can check it without a binary decoder. Such a verifier rebuilds each object from its JSON and
// re-encodes it with its own encoder; every hash and signature is then computed over bytes it produced itself, so a
// decoding it was handed is never trusted, only reproduced. The Go and TypeScript verifiers both verify these files
// (docs/proof/PROOF_V2.md §9: two implementations, one contract).
//
// Byte strings that are hashed as they stand (the genesis records) travel as hex beside their JSON; a verifier must
// confirm the JSON re-encodes to exactly those bytes.

package proofv2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// PortableFormat names this layout; a verifier refuses any other.
const PortableFormat = "certen-proof-v2-accumulate-portable/1"

type Portable struct {
	Format   string            `json:"format"`
	Pin      string            `json:"pin"` // the incarnation the verifier pins, hex32
	Genesis  PortableGenesis   `json:"genesis"`
	Majors   []json.RawMessage `json:"majors"` // api.MajorHeaderRecord from major block 1
	Evidence PortableEvidence  `json:"evidence"`
}

type PortableGenesis struct {
	MinorBlockIndex uint64          `json:"minorBlockIndex"`
	RootChainAnchor string          `json:"rootChainAnchor"`
	StateTreeAnchor string          `json:"stateTreeAnchor"`
	TimeUnix        uint64          `json:"timeUnix"`
	NetworkRecord   string          `json:"networkRecord"` // the genesis NetworkDefinition record, hex
	GlobalsRecord   string          `json:"globalsRecord"` // the genesis NetworkGlobals record, hex
	Network         json.RawMessage `json:"network"`       // protocol.NetworkDefinition
	Globals         json.RawMessage `json:"globals"`       // protocol.NetworkGlobals
}

type PortableEvidence struct {
	Version string            `json:"version"`
	Account string            `json:"account"`
	TxHash  string            `json:"txHash"`
	Receipt json.RawMessage   `json:"receipt"` // merkle.Receipt
	Majors  uint64            `json:"majors"`
	Certify []json.RawMessage `json:"certify"` // api.MinorRootRecord
	Anchor  struct {
		Message json.RawMessage `json:"message"` // messaging.SequencedMessage
		Receipt json.RawMessage `json:"receipt"` // merkle.Receipt
	} `json:"anchor"`
	Pages []PortablePage `json:"pages,omitempty"`
	Check PortableCheck  `json:"check"`
}

type PortablePage struct {
	URL     string          `json:"url"`
	Account json.RawMessage `json:"account"` // protocol.Account
	Receipt json.RawMessage `json:"receipt"` // merkle.Receipt
}

type PortableCheck struct {
	Majors      uint64            `json:"majors"`
	Hops        []json.RawMessage `json:"hops"` // api.MinorRootRecord
	Incarnation string            `json:"incarnation"`
	Network     PortableAccount   `json:"network"`
	Globals     PortableAccount   `json:"globals"`
}

// PortableAccount is proof.AccountStateProof with the account as JSON, and the record its single data entry holds
// (a NetworkDefinition or NetworkGlobals) as JSON too.
type PortableAccount struct {
	AccountURL    string            `json:"accountUrl"`
	Account       json.RawMessage   `json:"account"` // protocol.DataAccount
	Record        json.RawMessage   `json:"record"`  // the entry, decoded
	StateReceipt  json.RawMessage   `json:"stateReceipt"`
	Chains        []proof.ChainRoot `json:"chains"`
	SecondaryHash string            `json:"secondaryHash"`
	PendingHash   string            `json:"pendingHash"`
}

// Export writes the portable form of ev.
func Export(ev *Evidence, ar *Archive, in proof.IncarnationInputs, pin [32]byte) (*Portable, error) {
	p := &Portable{Format: PortableFormat, Pin: hex.EncodeToString(pin[:])}
	p.Genesis = PortableGenesis{
		MinorBlockIndex: in.GenesisMinorBlockIndex,
		RootChainAnchor: hex.EncodeToString(in.GenesisRootChainAnchor[:]),
		StateTreeAnchor: hex.EncodeToString(in.GenesisStateTreeAnchor[:]),
		TimeUnix:        in.GenesisTimeUnix,
		NetworkRecord:   hex.EncodeToString(in.NetworkRecord),
		GlobalsRecord:   hex.EncodeToString(in.GlobalsRecord),
	}
	g, err := genesisValues(in.NetworkRecord, in.GlobalsRecord)
	if err != nil {
		return nil, err
	}
	if p.Genesis.Network, err = json.Marshal(g.Network); err != nil {
		return nil, err
	}
	if p.Genesis.Globals, err = json.Marshal(g.Globals); err != nil {
		return nil, err
	}
	for _, m := range ar.Majors[:max(ev.Majors, ev.Check.Majors)] {
		j, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		p.Majors = append(p.Majors, j)
	}

	e := &p.Evidence
	e.Version, e.Account, e.TxHash, e.Majors = ev.Version, ev.Account, ev.TxHash, ev.Majors
	if e.Receipt, err = receiptJSON(ev.Receipt); err != nil {
		return nil, err
	}
	for _, h := range ev.Certify {
		j, err := minorRootJSON(h)
		if err != nil {
			return nil, err
		}
		e.Certify = append(e.Certify, j)
	}
	raw, err := hex.DecodeString(ev.Anchor.Message)
	if err != nil {
		return nil, err
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	if e.Anchor.Message, err = json.Marshal(seq); err != nil {
		return nil, err
	}
	if e.Anchor.Receipt, err = receiptJSON(ev.Anchor.Receipt); err != nil {
		return nil, err
	}
	for _, pg := range ev.Pages {
		acct, err := accountJSON(pg.State)
		if err != nil {
			return nil, err
		}
		r, err := receiptJSON(pg.Receipt)
		if err != nil {
			return nil, err
		}
		e.Pages = append(e.Pages, PortablePage{URL: pg.URL, Account: acct, Receipt: r})
	}

	e.Check.Majors, e.Check.Incarnation = ev.Check.Majors, ev.Check.Set.Incarnation
	for _, h := range ev.Check.Hops {
		j, err := minorRootJSON(h)
		if err != nil {
			return nil, err
		}
		e.Check.Hops = append(e.Check.Hops, j)
	}
	if e.Check.Network, err = exportAccount(&ev.Check.Set.Network, new(protocol.NetworkDefinition)); err != nil {
		return nil, fmt.Errorf("set check network: %w", err)
	}
	if e.Check.Globals, err = exportAccount(&ev.Check.Set.Globals, new(protocol.NetworkGlobals)); err != nil {
		return nil, fmt.Errorf("set check globals: %w", err)
	}
	return p, nil
}

// Import reads the portable form back into the evidence, archive and incarnation inputs Verify takes. Every binary
// value is re-encoded from its JSON, as another language's verifier must do.
func Import(p *Portable) (*Evidence, *Archive, proof.IncarnationInputs, [32]byte, error) {
	var in proof.IncarnationInputs
	var pin [32]byte
	fail := func(err error) (*Evidence, *Archive, proof.IncarnationInputs, [32]byte, error) {
		return nil, nil, in, pin, err
	}
	if p.Format != PortableFormat {
		return fail(fmt.Errorf("portable format %q is not %q", p.Format, PortableFormat))
	}
	if err := hex32(p.Pin, pin[:]); err != nil {
		return fail(fmt.Errorf("pin: %w", err))
	}
	in.GenesisMinorBlockIndex, in.GenesisTimeUnix = p.Genesis.MinorBlockIndex, p.Genesis.TimeUnix
	if err := hex32(p.Genesis.RootChainAnchor, in.GenesisRootChainAnchor[:]); err != nil {
		return fail(err)
	}
	if err := hex32(p.Genesis.StateTreeAnchor, in.GenesisStateTreeAnchor[:]); err != nil {
		return fail(err)
	}
	var err error
	if in.NetworkRecord, err = hex.DecodeString(p.Genesis.NetworkRecord); err != nil {
		return fail(err)
	}
	if in.GlobalsRecord, err = hex.DecodeString(p.Genesis.GlobalsRecord); err != nil {
		return fail(err)
	}
	if err := sameEncoding(p.Genesis.Network, new(protocol.NetworkDefinition), in.NetworkRecord); err != nil {
		return fail(fmt.Errorf("genesis network: %w", err))
	}
	if err := sameEncoding(p.Genesis.Globals, new(protocol.NetworkGlobals), in.GlobalsRecord); err != nil {
		return fail(fmt.Errorf("genesis globals: %w", err))
	}

	ar := &Archive{}
	for i, j := range p.Majors {
		m := new(api.MajorHeaderRecord)
		if err := json.Unmarshal(j, m); err != nil {
			return fail(fmt.Errorf("major %d: %w", i+1, err))
		}
		ar.Majors = append(ar.Majors, m)
	}

	e := &p.Evidence
	ev := &Evidence{Version: e.Version, Account: e.Account, TxHash: e.TxHash, Majors: e.Majors}
	if ev.Receipt, err = receiptHex(e.Receipt); err != nil {
		return fail(err)
	}
	for _, j := range e.Certify {
		h, err := minorRootHex(j)
		if err != nil {
			return fail(err)
		}
		ev.Certify = append(ev.Certify, h)
	}
	seq := new(messaging.SequencedMessage)
	if err := json.Unmarshal(e.Anchor.Message, seq); err != nil {
		return fail(fmt.Errorf("anchor message: %w", err))
	}
	b, err := seq.MarshalBinary()
	if err != nil {
		return fail(err)
	}
	ev.Anchor.Message = hex.EncodeToString(b)
	if ev.Anchor.Receipt, err = receiptHex(e.Anchor.Receipt); err != nil {
		return fail(err)
	}
	for _, pg := range e.Pages {
		acct, err := protocol.UnmarshalAccountJSON(pg.Account)
		if err != nil {
			return fail(fmt.Errorf("page %s: %w", pg.URL, err))
		}
		st, err := acct.MarshalBinary()
		if err != nil {
			return fail(err)
		}
		r, err := receiptHex(pg.Receipt)
		if err != nil {
			return fail(err)
		}
		ev.Pages = append(ev.Pages, PageState{URL: pg.URL, State: hex.EncodeToString(st), Receipt: r})
	}

	ev.Check.Majors, ev.Check.Set.Incarnation = e.Check.Majors, e.Check.Incarnation
	for _, j := range e.Check.Hops {
		h, err := minorRootHex(j)
		if err != nil {
			return fail(err)
		}
		ev.Check.Hops = append(ev.Check.Hops, h)
	}
	if err := importAccount(&e.Check.Network, &ev.Check.Set.Network, new(protocol.NetworkDefinition)); err != nil {
		return fail(fmt.Errorf("set check network: %w", err))
	}
	if err := importAccount(&e.Check.Globals, &ev.Check.Set.Globals, new(protocol.NetworkGlobals)); err != nil {
		return fail(fmt.Errorf("set check globals: %w", err))
	}
	return ev, ar, in, pin, nil
}

// VerifyPortable verifies a portable proof, as a verifier in another language reads it.
func VerifyPortable(p *Portable) (*Report, error) {
	ev, ar, in, pin, err := Import(p)
	if err != nil {
		return nil, err
	}
	return VerifyFromGenesis(ev, ar, in, pin)
}

type binaryValue interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

// sameEncoding checks that JSON decodes into v and re-encodes to exactly want.
func sameEncoding(j json.RawMessage, v binaryValue, want []byte) error {
	if err := json.Unmarshal(j, v); err != nil {
		return err
	}
	got, err := v.MarshalBinary()
	if err != nil {
		return err
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		return fmt.Errorf("the JSON does not re-encode to the record's bytes")
	}
	return nil
}

func exportAccount(a *proof.AccountStateProof, record binaryValue) (PortableAccount, error) {
	out := PortableAccount{AccountURL: a.AccountURL, Chains: a.Chains, SecondaryHash: a.SecondaryHash, PendingHash: a.PendingHash}
	var err error
	if out.Account, err = accountJSON(a.AccountState); err != nil {
		return out, err
	}
	raw, _ := hex.DecodeString(a.AccountState)
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return out, err
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok || da.Entry == nil || len(da.Entry.GetData()) != 1 {
		return out, fmt.Errorf("%s is %T, not a one-entry data account", a.AccountURL, acct)
	}
	if err := record.UnmarshalBinary(da.Entry.GetData()[0]); err != nil {
		return out, err
	}
	if out.Record, err = json.Marshal(record); err != nil {
		return out, err
	}
	out.StateReceipt, err = json.Marshal(a.StateReceipt)
	return out, err
}

func importAccount(pa *PortableAccount, a *proof.AccountStateProof, record binaryValue) error {
	acct, err := protocol.UnmarshalAccountJSON(pa.Account)
	if err != nil {
		return err
	}
	st, err := acct.MarshalBinary()
	if err != nil {
		return err
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok || da.Entry == nil || len(da.Entry.GetData()) != 1 {
		return fmt.Errorf("%s is %T, not a one-entry data account", pa.AccountURL, acct)
	}
	if err := sameEncoding(pa.Record, record, da.Entry.GetData()[0]); err != nil {
		return fmt.Errorf("%s: record: %w", pa.AccountURL, err)
	}
	*a = proof.AccountStateProof{AccountURL: pa.AccountURL, AccountState: hex.EncodeToString(st), Chains: pa.Chains,
		SecondaryHash: pa.SecondaryHash, PendingHash: pa.PendingHash}
	return json.Unmarshal(pa.StateReceipt, &a.StateReceipt)
}

func receiptJSON(h string) (json.RawMessage, error) {
	r, err := decodeReceipt(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func receiptHex(j json.RawMessage) (string, error) {
	r := new(merkle.Receipt)
	if err := json.Unmarshal(j, r); err != nil {
		return "", fmt.Errorf("receipt: %w", err)
	}
	b, err := r.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func minorRootJSON(h string) (json.RawMessage, error) {
	r, err := decodeMinorRoot(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func minorRootHex(j json.RawMessage) (string, error) {
	r := new(api.MinorRootRecord)
	if err := json.Unmarshal(j, r); err != nil {
		return "", fmt.Errorf("minor-root run: %w", err)
	}
	b, err := r.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func accountJSON(stateHex string) (json.RawMessage, error) {
	raw, err := hex.DecodeString(stateHex)
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(acct)
}

func hex32(s string, out []byte) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("%q is not 32 bytes of hex", s)
	}
	copy(out, b)
	return nil
}
