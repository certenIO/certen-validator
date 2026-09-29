// Copyright 2026 Certen Protocol
//
// The Accumulate INCARNATION identity (RB5 Phase A, owner decision D1 2026-09-29).
//
// # WHY IT EXISTS
//
// Accumulate has restarted more than once, re-creating every account at a new genesis, and nothing Accumulate's
// validators sign names the chain they are on: an anchor signature covers a SequencedMessage over a PartitionAnchor,
// and every URL in it (acc://dn.acme, acc://bvn-BVN1.acme) is a protocol constant identical on MainNet, on Kermit and
// on every incarnation of both. The genesis transaction is no help either: SystemGenesis is an empty struct, so its
// hash (e43be90e...) is the same everywhere. A permanent record that cannot say which chain it is about is worth less
// than it looks, so CERTEN commits an incarnation identity in every V8.2 anchor.
//
// # WHAT IT IS
//
// A keccak256 over the Directory's genesis, reduced to facts the public v3 API serves and this file checks:
//
//	keccak256(
//	    "certen:incarnation:v1"                  21 bytes, literal
//	 || uint64BE(genesisMinorBlockIndex)          must be 1 (protocol.GenesisBlock)
//	 || genesisRootChainAnchor                    32  anchor(directory)-root[0]
//	 || genesisStateTreeAnchor                    32  anchor(directory)-bpt[0]  - the genesis BPT root
//	 || uint64BE(genesisTimeUnix)                  8  acc://dn.acme/ledger/1 .time
//	 || sha256(genesis NetworkDefinition record)  32  acc://dn.acme/network, in force since genesis
//	 || sha256(genesis NetworkGlobals record)     32  acc://dn.acme/globals, in force since genesis
//	)
//
// Each input is the chain-state counterpart of a CometBFT genesis field: the BPT root is the application state
// (app_hash), ledger/1's time is genesis_time, and the network definition carries the network name (chain_id's base)
// and the initial validators; globals carries the accept threshold. The CometBFT genesis document itself is not used:
// no public Accumulate endpoint serves it (measured on Kermit 2026-09-29), and CometBFT is being replaced by DAG-BFT,
// under which the same chain must keep the same identity.
//
// # WHAT IT IS NOT
//
// It is a DISTINGUISHER bound to quorum-signed genesis roots and to the genesis trust base (validators + threshold)
// that RB6's validator-set walk starts from. It is not a proof that two incarnations differ: an operator who replayed a
// byte-identical genesis at the same second would produce the same value.
//
// # HOW STRONG EACH INPUT IS (what IncarnationEvidence.Verify establishes offline)
//
//   - The genesis roots: quorum-signed. The first DirectoryAnchor (minorBlockIndex 1) carries both, and its delivered
//     copy's ed25519 signatures are verified by the same Layer4 code every CERTEN proof uses, against the set in force
//     at delivery - which must equal the genesis network record's set and threshold.
//   - The genesis records and ledger/1: proven into the serving node's BPT root by merkle path from the account's own
//     bytes, with each account's chain heights bound; /network and /globals must have a main chain of height ONE whose
//     only entry is the systemGenesis transaction, so the record in force is the genesis record. That BPT root is the
//     endpoint's current one and is NOT certified by a quorum here; certifying it (a continuous receipt to a certified
//     Directory root) is RB6 §3. The verdict names this rather than hiding it.
package proof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// IncarnationDomain is the literal domain tag of the v1 encoding.
const IncarnationDomain = "certen:incarnation:v1"

// SystemGenesisTxHash is the hash of the (empty) systemGenesis transaction every system account's main chain starts
// with. It is a protocol constant, identical on every network - which is exactly why it cannot identify one.
const SystemGenesisTxHash = "e43be90e349210456662d8b8bdc9cc9e5e46ccb07f2129e7b57a8195e5e916d5"

// IncarnationInputs are the six values the identity commits to.
type IncarnationInputs struct {
	GenesisMinorBlockIndex uint64
	GenesisRootChainAnchor [32]byte
	GenesisStateTreeAnchor [32]byte
	GenesisTimeUnix        uint64
	NetworkRecord          []byte // the NetworkDefinition record, exactly as stored in the data entry
	GlobalsRecord          []byte // the NetworkGlobals record, exactly as stored in the data entry
}

// ComputeIncarnation returns the v1 incarnation identity. It refuses inputs that cannot describe a genesis.
func ComputeIncarnation(in IncarnationInputs) ([32]byte, error) {
	var zero [32]byte
	if in.GenesisMinorBlockIndex != protocol.GenesisBlock {
		return zero, fmt.Errorf("incarnation: the genesis anchor is for block %d, not the genesis block %d",
			in.GenesisMinorBlockIndex, protocol.GenesisBlock)
	}
	if in.GenesisRootChainAnchor == zero || in.GenesisStateTreeAnchor == zero {
		return zero, fmt.Errorf("incarnation: the genesis root chain anchor and state tree anchor are both required")
	}
	if in.GenesisTimeUnix == 0 {
		return zero, fmt.Errorf("incarnation: the genesis time is required")
	}
	if len(in.NetworkRecord) == 0 || len(in.GlobalsRecord) == 0 {
		return zero, fmt.Errorf("incarnation: the genesis network definition and globals records are both required")
	}
	netHash := sha256.Sum256(in.NetworkRecord)
	globHash := sha256.Sum256(in.GlobalsRecord)

	buf := make([]byte, 0, len(IncarnationDomain)+8+32+32+8+32+32)
	buf = append(buf, IncarnationDomain...)
	buf = binary.BigEndian.AppendUint64(buf, in.GenesisMinorBlockIndex)
	buf = append(buf, in.GenesisRootChainAnchor[:]...)
	buf = append(buf, in.GenesisStateTreeAnchor[:]...)
	buf = binary.BigEndian.AppendUint64(buf, in.GenesisTimeUnix)
	buf = append(buf, netHash[:]...)
	buf = append(buf, globHash[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out, nil
}

// ChainEntryEvidence is one chain entry fetched by index, with its receipt.
type ChainEntryEvidence struct {
	Account string                `json:"account"`
	Chain   string                `json:"chain"`
	Index   uint64                `json:"index"`
	Entry   string                `json:"entry"` // hex32
	Receipt chained_proof.Receipt `json:"receipt"`
}

// IncarnationEvidence is everything a third party needs to re-derive the identity offline.
type IncarnationEvidence struct {
	// Endpoint is where it was fetched from. Informational: nothing below trusts it.
	Endpoint string `json:"endpoint"`

	// GenesisAnchorTx is the binary encoding (hex) of anchor-sequence[0] on acc://dn.acme/anchors - the Directory's
	// first anchor, for the genesis block. GenesisAnchorEntry is that chain entry's hash.
	GenesisAnchorTx    string `json:"genesisAnchorTx"`
	GenesisAnchorEntry string `json:"genesisAnchorEntry"`

	// RootAnchor and BptAnchor are anchor(directory)-root[0] and anchor(directory)-bpt[0], fetched BY INDEX (the
	// by-hash form fails for genesis-era entries on every node), each with its receipt.
	RootAnchor ChainEntryEvidence `json:"rootAnchor"`
	BptAnchor  ChainEntryEvidence `json:"bptAnchor"`

	// GenesisLeg is the genesis anchor as delivered, with the Directory quorum's signatures: the same Layer4 shape
	// every CERTEN proof carries, verified by the same code.
	GenesisLeg *chained_proof.Layer4 `json:"genesisLeg"`

	// Ledger1 is acc://dn.acme/ledger/1, the genesis block's ledger, which records its time.
	Ledger1 AccountStateProof `json:"ledger1"`

	// Network and Globals are acc://dn.acme/network and /globals, each with its main chain's only entry.
	Network      AccountStateProof  `json:"network"`
	NetworkMain0 ChainEntryEvidence `json:"networkMain0"`
	NetworkTx0   string             `json:"networkTx0"` // binary transaction at main[0], hex
	Globals      AccountStateProof  `json:"globals"`
	GlobalsMain0 ChainEntryEvidence `json:"globalsMain0"`
	GlobalsTx0   string             `json:"globalsTx0"`

	// Incarnation restates the result for readers. Verify recomputes it and refuses a disagreement.
	Incarnation string `json:"incarnation"`
}

// IncarnationReport is what Verify establishes, including every input, for printing.
type IncarnationReport struct {
	Incarnation [32]byte
	Inputs      IncarnationInputs
	NetworkName string
	Validators  []chained_proof.ValidatorKey
	Threshold   chained_proof.Rational
	GenesisTime string
	// GenesisQuorum is the number of distinct Directory validators whose signatures on the genesis anchor verified,
	// against the threshold in force.
	GenesisSigners   int
	GenesisThreshold uint64
	// RecordsRoot is the BPT root the genesis records, ledger/1 and the chain heights were proven into. It is the
	// serving node's current root and is NOT certified by a quorum here (see the file comment).
	RecordsRoot string
}

// Verify re-derives the incarnation from the evidence alone. It performs no network access. Any error means the
// evidence does not establish an incarnation; there is no weaker answer.
func (e *IncarnationEvidence) Verify() (*IncarnationReport, error) {
	if e == nil {
		return nil, fmt.Errorf("no incarnation evidence")
	}
	rep := &IncarnationReport{}
	in := &rep.Inputs

	// 1. The genesis anchor: its bytes hash to the chain entry, it is a DirectoryAnchor from the Directory, for block 1.
	txRaw, err := hexBytes(e.GenesisAnchorTx, "genesisAnchorTx")
	if err != nil {
		return nil, err
	}
	var tx protocol.Transaction
	if err := tx.UnmarshalBinary(txRaw); err != nil {
		return nil, fmt.Errorf("genesis anchor: does not decode as a transaction: %w", err)
	}
	entry, err := chained_proof.MustHex32Lower(e.GenesisAnchorEntry, "genesisAnchorEntry")
	if err != nil {
		return nil, err
	}
	if got := hex.EncodeToString(tx.GetHash()); got != entry {
		return nil, fmt.Errorf("genesis anchor: the transaction hashes to %s, not the anchor-sequence[0] entry %s", got, entry)
	}
	da, ok := tx.Body.(*protocol.DirectoryAnchor)
	if !ok {
		return nil, fmt.Errorf("genesis anchor: anchor-sequence[0] is a %v, not a directoryAnchor", tx.Body.Type())
	}
	if da.Source == nil || !da.Source.Equal(protocol.DnUrl()) {
		return nil, fmt.Errorf("genesis anchor: source is %v, not %v", da.Source, protocol.DnUrl())
	}
	in.GenesisMinorBlockIndex = da.MinorBlockIndex
	in.GenesisRootChainAnchor = da.RootChainAnchor
	in.GenesisStateTreeAnchor = da.StateTreeAnchor
	if da.MinorBlockIndex != protocol.GenesisBlock {
		return nil, fmt.Errorf("genesis anchor: minorBlockIndex is %d, not the genesis block %d",
			da.MinorBlockIndex, protocol.GenesisBlock)
	}

	// 2. The Directory's own record of those roots: index 0 of its root and BPT anchor chains.
	if err := e.RootAnchor.verify("acc://dn.acme/anchors", "anchor(directory)-root", 0); err != nil {
		return nil, err
	}
	if err := e.BptAnchor.verify("acc://dn.acme/anchors", "anchor(directory)-bpt", 0); err != nil {
		return nil, err
	}
	if e.RootAnchor.Entry != hex.EncodeToString(da.RootChainAnchor[:]) {
		return nil, fmt.Errorf("anchor(directory)-root[0] is %s, but the genesis anchor carries %x",
			e.RootAnchor.Entry, da.RootChainAnchor)
	}
	if e.BptAnchor.Entry != hex.EncodeToString(da.StateTreeAnchor[:]) {
		return nil, fmt.Errorf("anchor(directory)-bpt[0] is %s, but the genesis anchor carries %x",
			e.BptAnchor.Entry, da.StateTreeAnchor)
	}

	// 3. The genesis records: proven, height ONE, genesis entry only.
	netAnchor, err := e.Network.verify()
	if err != nil {
		return nil, fmt.Errorf("network account: %w", err)
	}
	globAnchor, err := e.Globals.verify()
	if err != nil {
		return nil, fmt.Errorf("globals account: %w", err)
	}
	ledAnchor, err := e.Ledger1.verify()
	if err != nil {
		return nil, fmt.Errorf("ledger/1 account: %w", err)
	}
	if netAnchor != globAnchor || netAnchor != ledAnchor {
		return nil, fmt.Errorf("the genesis records were proven into different BPT roots (network=%s globals=%s "+
			"ledger/1=%s); they must be read at one block", short(netAnchor), short(globAnchor), short(ledAnchor))
	}
	rep.RecordsRoot = netAnchor
	if err := verifyGenesisOnly(&e.Network, &e.NetworkMain0, e.NetworkTx0, "acc://dn.acme/network"); err != nil {
		return nil, err
	}
	if err := verifyGenesisOnly(&e.Globals, &e.GlobalsMain0, e.GlobalsTx0, "acc://dn.acme/globals"); err != nil {
		return nil, err
	}
	netRaw, err := hexBytes(e.Network.AccountState, "network.accountState")
	if err != nil {
		return nil, err
	}
	globRaw, err := hexBytes(e.Globals.AccountState, "globals.accountState")
	if err != nil {
		return nil, err
	}
	if in.NetworkRecord, err = dataEntryOf(netRaw, "network account"); err != nil {
		return nil, err
	}
	if in.GlobalsRecord, err = dataEntryOf(globRaw, "globals account"); err != nil {
		return nil, err
	}
	var nd protocol.NetworkDefinition
	if err := nd.UnmarshalBinary(in.NetworkRecord); err != nil {
		return nil, fmt.Errorf("network record is not a NetworkDefinition: %w", err)
	}
	rep.NetworkName = nd.NetworkName
	if rep.Validators, err = decodeValidators(netRaw); err != nil {
		return nil, err
	}
	num, den, err := decodeAcceptThreshold(globRaw)
	if err != nil {
		return nil, err
	}
	rep.Threshold = chained_proof.Rational{Numerator: num, Denominator: den}

	// 4. The genesis time: ledger/1 is the genesis block's ledger.
	ledRaw, err := hexBytes(e.Ledger1.AccountState, "ledger1.accountState")
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccount(ledRaw)
	if err != nil {
		return nil, fmt.Errorf("ledger/1: does not decode as an account: %w", err)
	}
	bl, ok := acct.(*protocol.BlockLedger)
	if !ok {
		return nil, fmt.Errorf("ledger/1: expected a blockLedger, got %v", acct.Type())
	}
	if bl.Url == nil || !bl.Url.Equal(protocol.DnUrl().JoinPath(protocol.Ledger, "1")) {
		return nil, fmt.Errorf("ledger/1: the account is %v", bl.Url)
	}
	if bl.Index != protocol.GenesisBlock {
		return nil, fmt.Errorf("ledger/1: index is %d, not the genesis block", bl.Index)
	}
	if bl.Time.Unix() <= 0 {
		return nil, fmt.Errorf("ledger/1: no time recorded")
	}
	in.GenesisTimeUnix = uint64(bl.Time.Unix())
	rep.GenesisTime = bl.Time.UTC().Format("2006-01-02T15:04:05Z")

	// 5. The genesis anchor was signed by a quorum of the genesis Directory validators.
	leg := e.GenesisLeg
	if leg == nil {
		return nil, fmt.Errorf("genesis anchor: no signed delivery (genesisLeg) carried")
	}
	if err := leg.VerifyOffline(); err != nil {
		return nil, fmt.Errorf("genesis anchor: the quorum signatures do not verify: %w", err)
	}
	if !strings.EqualFold(leg.Partition, protocol.Directory) {
		return nil, fmt.Errorf("genesis anchor: the signed leg is for partition %s, not the Directory", leg.Partition)
	}
	if leg.MinorBlockIndex != protocol.GenesisBlock ||
		leg.RootChainAnchor != hex.EncodeToString(da.RootChainAnchor[:]) ||
		leg.StateTreeAnchor != hex.EncodeToString(da.StateTreeAnchor[:]) {
		return nil, fmt.Errorf("genesis anchor: the signed leg (block %d root %s state %s) is not the genesis anchor",
			leg.MinorBlockIndex, short(leg.RootChainAnchor), short(leg.StateTreeAnchor))
	}
	if err := sameValidatorSet(rep.Validators, leg.ValidatorSet); err != nil {
		return nil, fmt.Errorf("genesis anchor: the set its signatures were checked against is not the genesis "+
			"network record's: %w", err)
	}
	if leg.AcceptThreshold != rep.Threshold {
		return nil, fmt.Errorf("genesis anchor: checked against threshold %d/%d, the genesis globals say %d/%d",
			leg.AcceptThreshold.Numerator, leg.AcceptThreshold.Denominator, num, den)
	}
	distinct := map[string]bool{}
	for _, s := range leg.Signatures {
		distinct[strings.ToLower(s.PublicKey)] = true
	}
	rep.GenesisSigners, rep.GenesisThreshold = len(distinct), leg.Threshold

	// 6. The identity.
	if rep.Incarnation, err = ComputeIncarnation(*in); err != nil {
		return nil, err
	}
	if e.Incarnation != "" {
		restated, err := chained_proof.MustHex32Lower(e.Incarnation, "incarnation")
		if err != nil {
			return nil, err
		}
		if restated != hex.EncodeToString(rep.Incarnation[:]) {
			return nil, fmt.Errorf("the restated incarnation %s is not what the evidence produces (%x)",
				restated, rep.Incarnation)
		}
	}
	return rep, nil
}

// verify checks a chain entry's receipt and where it was read from.
func (c *ChainEntryEvidence) verify(account, chain string, index uint64) error {
	if !strings.EqualFold(c.Account, account) || c.Chain != chain || c.Index != index {
		return fmt.Errorf("expected %s %s[%d], the evidence is %s %s[%d]", account, chain, index, c.Account, c.Chain, c.Index)
	}
	entry, err := chained_proof.MustHex32Lower(c.Entry, account+" "+chain+" entry")
	if err != nil {
		return err
	}
	c.Entry = entry
	start, err := chained_proof.MustHex32Lower(c.Receipt.Start, account+" "+chain+" receipt.start")
	if err != nil {
		return err
	}
	if start != entry {
		return fmt.Errorf("%s %s[%d]: the receipt starts at %s, not the entry %s", account, chain, index, short(start), short(entry))
	}
	got, err := recomputeReceipt(c.Receipt)
	if err != nil {
		return err
	}
	if want, err := chained_proof.MustHex32Lower(c.Receipt.Anchor, "receipt.anchor"); err != nil || got != want {
		return fmt.Errorf("%s %s[%d]: the receipt does not recompute (got %s)", account, chain, index, short(got))
	}
	return nil
}

// verifyGenesisOnly requires the account's main chain to hold exactly one entry - the systemGenesis transaction - so
// the record in force is the one genesis wrote.
func verifyGenesisOnly(a *AccountStateProof, main0 *ChainEntryEvidence, txHex, account string) error {
	if !strings.EqualFold(a.AccountURL, account) {
		return fmt.Errorf("expected %s, the evidence proves %s", account, a.AccountURL)
	}
	var mainChain *ChainRoot
	for i := range a.Chains {
		if a.Chains[i].Name == "main" {
			mainChain = &a.Chains[i]
		}
	}
	if mainChain == nil {
		return fmt.Errorf("%s: no main chain in the proven chain set", account)
	}
	count, anchor, err := mainChain.derive()
	if err != nil {
		return fmt.Errorf("%s: %w", account, err)
	}
	if count != 1 {
		return fmt.Errorf("%s: the main chain has %d entries, so the record has changed since genesis; the genesis "+
			"record is established only from a historical state proof, which this evidence does not carry "+
			"(genesis_record_not_served)", account, count)
	}
	// A one-entry merkle chain's root is that entry.
	if err := main0.verify(account, "main", 0); err != nil {
		return err
	}
	if main0.Entry != hex.EncodeToString(anchor) {
		return fmt.Errorf("%s: main[0] is %s, but the proven main chain's only entry is %x", account, main0.Entry, anchor)
	}
	txRaw, err := hexBytes(txHex, account+" main[0] transaction")
	if err != nil {
		return err
	}
	var tx protocol.Transaction
	if err := tx.UnmarshalBinary(txRaw); err != nil {
		return fmt.Errorf("%s main[0]: does not decode as a transaction: %w", account, err)
	}
	if got := hex.EncodeToString(tx.GetHash()); got != main0.Entry {
		return fmt.Errorf("%s main[0]: the transaction hashes to %s, not the entry %s", account, got, main0.Entry)
	}
	if tx.Body.Type() != protocol.TransactionTypeSystemGenesis {
		return fmt.Errorf("%s main[0]: the only entry is a %v, not systemGenesis", account, tx.Body.Type())
	}
	return nil
}

// =====================================================================================================================
// Building the evidence from a live network
// =====================================================================================================================

// GenesisLegBuilder builds the signed Layer4 leg for the Directory's genesis anchor as delivered to a BVN. It is an
// interface so the offline tests can supply a recorded leg; cmd/incarnation wires chained_proof.Layer4Builder.
type GenesisLegBuilder interface {
	BuildGenesisDNLeg(ctx context.Context, bvn string, rootChainAnchor, stateTreeAnchor string) (*chained_proof.Layer4, error)
}

// BuildIncarnationEvidence fetches and self-verifies the evidence. deliveryBVN names the BVN whose anchor pool the
// genesis anchor's signed delivery is read from ("BVN1" on Kermit).
func BuildIncarnationEvidence(ctx context.Context, q AccumulateQuerier, legs GenesisLegBuilder, endpoint, deliveryBVN string) (*IncarnationEvidence, error) {
	e := &IncarnationEvidence{Endpoint: endpoint}

	// The genesis anchor, by index.
	raw, err := q.Query(ctx, map[string]any{
		"scope": "acc://dn.acme/anchors",
		"query": map[string]any{"queryType": "chain", "name": "anchor-sequence", "index": 0},
	})
	if err != nil {
		return nil, fmt.Errorf("anchor-sequence[0]: %w", err)
	}
	var seq struct {
		Entry string `json:"entry"`
		Value struct {
			Message struct {
				Transaction json.RawMessage `json:"transaction"`
			} `json:"message"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &seq); err != nil {
		return nil, fmt.Errorf("anchor-sequence[0]: %w", err)
	}
	var tx protocol.Transaction
	if err := json.Unmarshal(seq.Value.Message.Transaction, &tx); err != nil {
		return nil, fmt.Errorf("anchor-sequence[0]: transaction does not decode: %w", err)
	}
	txBin, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	e.GenesisAnchorTx, e.GenesisAnchorEntry = hex.EncodeToString(txBin), strings.ToLower(seq.Entry)
	da, ok := tx.Body.(*protocol.DirectoryAnchor)
	if !ok {
		return nil, fmt.Errorf("anchor-sequence[0] is a %v, not a directoryAnchor", tx.Body.Type())
	}

	if e.RootAnchor, err = fetchChainEntry(ctx, q, "acc://dn.acme/anchors", "anchor(directory)-root", 0); err != nil {
		return nil, err
	}
	if e.BptAnchor, err = fetchChainEntry(ctx, q, "acc://dn.acme/anchors", "anchor(directory)-bpt", 0); err != nil {
		return nil, err
	}

	// The three accounts must be proven into one BPT root; the chain moves, so retry until they agree.
	const attempts = 8
	var lastErr error
	for i := 0; i < attempts; i++ {
		net, err := fetchAccountStateProof(ctx, q, "acc://dn.acme/network")
		if err != nil {
			return nil, fmt.Errorf("network account: %w", err)
		}
		glob, err := fetchAccountStateProof(ctx, q, "acc://dn.acme/globals")
		if err != nil {
			return nil, fmt.Errorf("globals account: %w", err)
		}
		led, err := fetchAccountStateProofOpt(ctx, q, "acc://dn.acme/ledger/1", true)
		if err != nil {
			return nil, fmt.Errorf("ledger/1 account: %w", err)
		}
		if strings.EqualFold(net.StateReceipt.Anchor, glob.StateReceipt.Anchor) &&
			strings.EqualFold(net.StateReceipt.Anchor, led.StateReceipt.Anchor) {
			e.Network, e.Globals, e.Ledger1 = *net, *glob, *led
			lastErr = nil
			break
		}
		lastErr = fmt.Errorf("the accounts landed on different BPT roots (network=%s globals=%s ledger/1=%s)",
			short(net.StateReceipt.Anchor), short(glob.StateReceipt.Anchor), short(led.StateReceipt.Anchor))
	}
	if lastErr != nil {
		return nil, fmt.Errorf("could not read the genesis records at one block after %d attempts: %w", attempts, lastErr)
	}
	for _, acc := range []struct {
		url   string
		main0 *ChainEntryEvidence
		tx    *string
	}{{"acc://dn.acme/network", &e.NetworkMain0, &e.NetworkTx0}, {"acc://dn.acme/globals", &e.GlobalsMain0, &e.GlobalsTx0}} {
		ce, txHex, err := fetchChainEntryWithTx(ctx, q, acc.url, "main", 0)
		if err != nil {
			return nil, err
		}
		*acc.main0, *acc.tx = ce, txHex
	}

	if e.GenesisLeg, err = legs.BuildGenesisDNLeg(ctx, deliveryBVN,
		hex.EncodeToString(da.RootChainAnchor[:]), hex.EncodeToString(da.StateTreeAnchor[:])); err != nil {
		return nil, fmt.Errorf("genesis anchor's signed delivery to %s: %w", deliveryBVN, err)
	}

	// The producer proves its own output: never emit evidence the verifier refuses.
	rep, err := e.Verify()
	if err != nil {
		return nil, fmt.Errorf("the built evidence does not verify: %w", err)
	}
	e.Incarnation = hex.EncodeToString(rep.Incarnation[:])
	return e, nil
}

func fetchChainEntry(ctx context.Context, q AccumulateQuerier, account, chain string, index uint64) (ChainEntryEvidence, error) {
	ce, _, err := fetchChainEntryWithTx(ctx, q, account, chain, index)
	return ce, err
}

// fetchChainEntryWithTx reads a chain entry by index with its receipt and, when the entry is a transaction, its
// binary encoding.
func fetchChainEntryWithTx(ctx context.Context, q AccumulateQuerier, account, chain string, index uint64) (ChainEntryEvidence, string, error) {
	out := ChainEntryEvidence{Account: account, Chain: chain, Index: index}
	raw, err := q.Query(ctx, map[string]any{
		"scope": account,
		"query": map[string]any{"queryType": "chain", "name": chain, "index": index,
			"includeReceipt": map[string]any{"forAny": true}},
	})
	if err != nil {
		return out, "", fmt.Errorf("%s %s[%d]: %w", account, chain, index, err)
	}
	var rec struct {
		Index   uint64                `json:"index"`
		Entry   string                `json:"entry"`
		Receipt chained_proof.Receipt `json:"receipt"`
		Value   struct {
			Message struct {
				Transaction json.RawMessage `json:"transaction"`
			} `json:"message"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return out, "", fmt.Errorf("%s %s[%d]: %w", account, chain, index, err)
	}
	if rec.Index != index {
		return out, "", fmt.Errorf("%s %s[%d]: the node returned index %d", account, chain, index, rec.Index)
	}
	out.Entry, out.Receipt = strings.ToLower(rec.Entry), rec.Receipt
	if len(rec.Value.Message.Transaction) == 0 {
		return out, "", nil
	}
	var tx protocol.Transaction
	if err := json.Unmarshal(rec.Value.Message.Transaction, &tx); err != nil {
		return out, "", fmt.Errorf("%s %s[%d]: transaction does not decode: %w", account, chain, index, err)
	}
	bin, err := tx.MarshalBinary()
	if err != nil {
		return out, "", err
	}
	return out, hex.EncodeToString(bin), nil
}
