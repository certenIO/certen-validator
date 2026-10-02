package consensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ledger"
)

// The per-intent quorum certificate (RB5 D3).
//
// Every committed ValidatorBlock carrying an intent certificate contributes its validator's signature over the
// intent message to its operation's record. Signatures over one message under one registry version form a group;
// the first time a group's signers hold the registry's threshold of power, their signatures are aggregated - by
// AggregateBatchAttestations, the one aggregation the batch quorum uses, against the registry as its registry - and
// the certificate recorded. "bls_aggregate_signature" then names what it says: CERTEN's quorum over what the intent
// proves.
//
// It is recorded in Commit from the block's accepted ValidatorBlocks, so every node records the same certificate,
// and re-recording the same block changes nothing.

// registryAsQuorumRegistry is the registry in the form the quorum aggregation takes: EVM address -> key and power.
func registryAsQuorumRegistry(reg *ledger.BLSRegistryRecord) map[string]ValidatorRegistryEntry {
	out := make(map[string]ValidatorRegistryEntry, len(reg.Members))
	for _, m := range reg.Members {
		addr := strings.ToLower(m.EVMAddress)
		out[addr] = ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: m.BLSPubKey,
			VotingPower: new(big.Int).SetUint64(m.Power)}
	}
	return out
}

// recordIntentSignatures adds the certified blocks committed at height to their operations' records and certifies
// every group that reaches its quorum. It may read only committed state and the blocks; an unreadable or unwritable
// ledger stops the node, as a fork would follow from continuing.
func (app *ValidatorApp) recordIntentSignatures(height int64, vbs []ValidatorBlock) {
	if app.ledgerStore == nil {
		return
	}
	var regLog *ledger.BLSRegistryLog
	for i := range vbs {
		vb := &vbs[i]
		ev := vb.IntentCertificate
		if ev == nil {
			continue
		}
		if regLog == nil {
			l, err := app.ledgerStore.LoadBLSRegistry()
			if err != nil {
				app.logger.Fatalf("❌ [INTENT-QC] the BLS registry could not be read at height %d: %v", height, err)
			}
			regLog = l
		}
		reg := RegistryAt(regLog, height)
		if reg == nil || reg.Version != ev.RegistryVersion {
			// FinalizeBlock accepted it under exactly this registry; anything else is a broken invariant.
			app.logger.Fatalf("❌ [INTENT-QC] block %s committed at %d under registry v%d, which is not the one in force",
				vb.BundleID, height, ev.RegistryVersion)
		}
		op := strings.ToLower(vb.CrossChainProof.OperationID)
		ql, err := app.ledgerStore.LoadIntentQuorum(op)
		if err != nil {
			app.logger.Fatalf("❌ [INTENT-QC] the intent quorum of %s could not be read: %v", op, err)
		}
		msg := strings.ToLower(ev.Message)
		g := groupFor(ql, msg, reg.Version)
		if hasPartial(g, vb.ValidatorID) {
			continue // replay of a block already recorded, or a second block from the same validator (refused by v9's rule)
		}
		g.Partials = append(g.Partials, ledger.IntentPartial{ValidatorID: vb.ValidatorID, Signature: ev.Signature, Height: height})
		if g.Certificate == nil {
			cert, err := certifyGroup(op, g, reg, height)
			switch {
			case err == nil:
				g.Certificate = cert
				app.logger.Printf("🏅 [INTENT-QC] operation %s certified at height %d: %s of %s power over message %s (%d signers)",
					op, height, cert.SignedPower, cert.TotalPower, msg, len(cert.Signers))
			case errors.Is(err, errQuorumNotYetMet):
			default:
				app.logger.Fatalf("❌ [INTENT-QC] operation %s: committed signatures do not aggregate: %v", op, err)
			}
		}
		if len(ql.Groups) > 1 {
			app.logger.Printf("⚠️ [INTENT-QC] operation %s: validators signed %d different intent messages - their proofs of "+
				"the same operation disagree", op, len(ql.Groups))
		}
		if err := app.ledgerStore.SaveIntentQuorum(ql); err != nil {
			app.logger.Fatalf("❌ [INTENT-QC] the intent quorum of %s could not be written: %v", op, err)
		}
	}
}

func groupFor(ql *ledger.IntentQuorumLog, msg string, version uint64) *ledger.IntentQuorumGroup {
	for i := range ql.Groups {
		if ql.Groups[i].Message == msg && ql.Groups[i].RegistryVersion == version {
			return &ql.Groups[i]
		}
	}
	ql.Groups = append(ql.Groups, ledger.IntentQuorumGroup{Message: msg, RegistryVersion: version})
	return &ql.Groups[len(ql.Groups)-1]
}

func hasPartial(g *ledger.IntentQuorumGroup, validatorID string) bool {
	for _, p := range g.Partials {
		if p.ValidatorID == validatorID {
			return true
		}
	}
	return false
}

var errQuorumNotYetMet = errors.New("quorum not yet met")

// certifyGroup aggregates a group's signatures when its signers hold the registry's threshold.
func certifyGroup(op string, g *ledger.IntentQuorumGroup, reg *ledger.BLSRegistryRecord, height int64) (*ledger.IntentQuorumCertificate, error) {
	quorumReg := registryAsQuorumRegistry(reg)
	total, signed := new(big.Int), new(big.Int)
	for _, m := range reg.Members {
		total.Add(total, new(big.Int).SetUint64(m.Power))
	}
	byID := map[string]ledger.BLSRegistryMember{}
	for _, m := range reg.Members {
		byID[m.ValidatorID] = m
	}
	var atts []BatchAttestationEntry
	for _, p := range g.Partials {
		m, ok := byID[p.ValidatorID]
		if !ok {
			return nil, fmt.Errorf("committed signature from %s, which registry v%d does not hold", p.ValidatorID, reg.Version)
		}
		signed.Add(signed, new(big.Int).SetUint64(m.Power))
		atts = append(atts, BatchAttestationEntry{ValidatorID: p.ValidatorID, EVMAddress: strings.ToLower(m.EVMAddress),
			SignatureHex: p.Signature, PublicKeyHex: m.BLSPubKey})
	}
	if new(big.Int).Mul(signed, new(big.Int).SetUint64(reg.ThresholdDenominator)).Cmp(
		new(big.Int).Mul(total, new(big.Int).SetUint64(reg.ThresholdNumerator))) < 0 {
		return nil, errQuorumNotYetMet
	}
	msg, err := hex32(g.Message)
	if err != nil {
		return nil, err
	}
	agg, err := AggregateBatchAttestations(atts, quorumReg, msg, int64(reg.ThresholdNumerator), int64(reg.ThresholdDenominator))
	if err != nil {
		return nil, err
	}
	addrToID := map[string]string{}
	for _, m := range reg.Members {
		addrToID[strings.ToLower(m.EVMAddress)] = m.ValidatorID
	}
	ids := make([]string, len(agg.Signers))
	for i, a := range agg.Signers {
		ids[i] = addrToID[strings.ToLower(a)]
	}
	return &ledger.IntentQuorumCertificate{OperationID: op, Message: g.Message, RegistryVersion: reg.Version,
		CertenSetRoot: reg.CertenSetRoot, Height: height, Signers: ids, SignerAddresses: agg.Signers,
		AggregateSignature: agg.AggregateSignatureHex, AggregatePublicKey: agg.AggregatePublicKeyHex,
		SignedPower: agg.SignedVotingPower.String(), TotalPower: agg.TotalVotingPower.String(),
		ThresholdNumerator: reg.ThresholdNumerator, ThresholdDenominator: reg.ThresholdDenominator}, nil
}

// VerifyIntentQuorumCertificate checks a certificate offline against the registry it names: the signers are
// registered members, distinct, holding the threshold; the aggregate key is exactly theirs; the aggregate signature
// verifies over the message under it; and the CERTEN set root is the registry's.
func VerifyIntentQuorumCertificate(c *ledger.IntentQuorumCertificate, reg *ledger.BLSRegistryRecord) error {
	if c == nil || reg == nil {
		return fmt.Errorf("a certificate and its registry are both required")
	}
	if c.RegistryVersion != reg.Version || !strings.EqualFold(c.CertenSetRoot, reg.CertenSetRoot) {
		return fmt.Errorf("the certificate names registry v%d (set %s), not v%d (set %s)", c.RegistryVersion,
			c.CertenSetRoot, reg.Version, reg.CertenSetRoot)
	}
	if c.ThresholdNumerator != reg.ThresholdNumerator || c.ThresholdDenominator != reg.ThresholdDenominator {
		return fmt.Errorf("the certificate states threshold %d/%d, the registry %d/%d", c.ThresholdNumerator,
			c.ThresholdDenominator, reg.ThresholdNumerator, reg.ThresholdDenominator)
	}
	if len(c.Signers) == 0 || len(c.Signers) != len(c.SignerAddresses) {
		return fmt.Errorf("the certificate names no signers, or names them inconsistently")
	}
	byAddr := map[string]ledger.BLSRegistryMember{}
	total := new(big.Int)
	for _, m := range reg.Members {
		byAddr[strings.ToLower(m.EVMAddress)] = m
		total.Add(total, new(big.Int).SetUint64(m.Power))
	}
	if !sort.StringsAreSorted(c.SignerAddresses) {
		return fmt.Errorf("the signers are not in ascending address order")
	}
	signed := new(big.Int)
	var pubs []*bls.PublicKey
	for i, a := range c.SignerAddresses {
		m, ok := byAddr[strings.ToLower(a)]
		if !ok || m.ValidatorID != c.Signers[i] {
			return fmt.Errorf("signer %s (%s) is not a member of registry v%d", c.Signers[i], a, reg.Version)
		}
		if i > 0 && strings.EqualFold(a, c.SignerAddresses[i-1]) {
			return fmt.Errorf("signer %s is counted twice", a)
		}
		raw, err := hex.DecodeString(m.BLSPubKey)
		if err != nil {
			return err
		}
		pub, err := bls.PublicKeyFromBytes(raw)
		if err != nil {
			return err
		}
		pubs = append(pubs, pub)
		signed.Add(signed, new(big.Int).SetUint64(m.Power))
	}
	if signed.String() != c.SignedPower || total.String() != c.TotalPower {
		return fmt.Errorf("the certificate states %s of %s power; its signers hold %s of %s", c.SignedPower, c.TotalPower, signed, total)
	}
	if new(big.Int).Mul(signed, new(big.Int).SetUint64(reg.ThresholdDenominator)).Cmp(
		new(big.Int).Mul(total, new(big.Int).SetUint64(reg.ThresholdNumerator))) < 0 {
		return fmt.Errorf("the signers hold %s of %s power, under the threshold %d/%d", signed, total,
			reg.ThresholdNumerator, reg.ThresholdDenominator)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimPrefix(c.AggregatePublicKey, "0x"), aggPub.Hex()) {
		return fmt.Errorf("the aggregate public key is not the signers' keys aggregated")
	}
	sigRaw, err := hex.DecodeString(strings.TrimPrefix(c.AggregateSignature, "0x"))
	if err != nil || bls.ValidateBLSSignatureSubgroup(sigRaw) != nil {
		return fmt.Errorf("the aggregate signature is not a valid G1 point")
	}
	sig, err := bls.SignatureFromBytes(sigRaw)
	if err != nil {
		return err
	}
	msg, err := hex32(c.Message)
	if err != nil {
		return err
	}
	if !aggPub.VerifyG1(sig, bls_zkp.HashMessageToG1V2(msg)) {
		return fmt.Errorf("the aggregate signature does not verify over the intent message")
	}
	return nil
}

// IntentMessageInputs are the inputs a certified message was computed from, as stored beside its certificate so a
// verifier recomputes each from the stored proof.
type IntentMessageInputs struct {
	CertenChainID        string `json:"certen_chain_id"`
	OperationID          string `json:"operation_id"`
	GovRootV2            string `json:"gov_root_v2"`
	AccumulateSetRoot    string `json:"accumulate_set_root"`
	Incarnation          string `json:"incarnation"`
	GovernanceCommitment string `json:"governance_commitment"`
	CertenSetRoot        string `json:"certen_set_root"`
	KeyPageURL           string `json:"key_page_url"`
	KeyBookURL           string `json:"key_book_url"`
}

// intentCertificateRows is the persister's source of certificates: those the commit of height completed, for the
// operations of its accepted blocks, read from committed state. The block that completed a certificate carries the
// certified message, so its evidence gives the message's inputs.
func (app *ValidatorApp) intentCertificateRows(height int64, blocks []ValidatorBlock) ([]database.IntentQuorumCertificateRow, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return nil, nil
	}
	var rows []database.IntentQuorumCertificateRow
	var regLog *ledger.BLSRegistryLog
	seen := map[string]bool{}
	for i := range blocks {
		vb := &blocks[i]
		ev := vb.IntentCertificate
		op := strings.ToLower(vb.CrossChainProof.OperationID)
		if ev == nil || seen[op] {
			continue
		}
		ql, err := app.ledgerStore.LoadIntentQuorum(op)
		if err != nil {
			return nil, err
		}
		for _, g := range ql.Groups {
			c := g.Certificate
			if c == nil || c.Height != height || !strings.EqualFold(g.Message, ev.Message) {
				continue
			}
			seen[op] = true
			if regLog == nil {
				if regLog, err = app.ledgerStore.LoadBLSRegistry(); err != nil {
					return nil, err
				}
			}
			var reg *ledger.BLSRegistryRecord
			for j := range regLog.Versions {
				if regLog.Versions[j].Version == c.RegistryVersion {
					reg = &regLog.Versions[j]
				}
			}
			if reg == nil {
				return nil, fmt.Errorf("operation %s was certified under registry v%d, which the ledger does not hold", op, c.RegistryVersion)
			}
			in, govRoot, accRoot, err := intentInputs(vb, app.cometChainID, reg)
			if err != nil {
				return nil, fmt.Errorf("operation %s: the inputs of its certified message: %w", op, err)
			}
			inputs := IntentMessageInputs{CertenChainID: in.CertenChainID, OperationID: op,
				GovRootV2: "0x" + hex.EncodeToString(govRoot[:]), AccumulateSetRoot: "0x" + hex.EncodeToString(accRoot[:]),
				Incarnation: "0x" + hex.EncodeToString(in.Incarnation[:]), GovernanceCommitment: "0x" + hex.EncodeToString(in.GovernanceCommitment[:]),
				CertenSetRoot: "0x" + hex.EncodeToString(in.CertenSetRoot[:]), KeyPageURL: ev.KeyPageURL, KeyBookURL: ev.KeyBookURL}
			certJSON, err := json.Marshal(c)
			if err != nil {
				return nil, err
			}
			regJSON, err := json.Marshal(reg)
			if err != nil {
				return nil, err
			}
			inJSON, err := json.Marshal(inputs)
			if err != nil {
				return nil, err
			}
			rows = append(rows, database.IntentQuorumCertificateRow{OperationID: op, Message: strings.ToLower(c.Message),
				RegistryVersion: int64(c.RegistryVersion), CertenChainID: app.cometChainID, Certificate: certJSON,
				Registry: regJSON, MessageInputs: inJSON, CertifiedHeight: height})
		}
	}
	return rows, nil
}

// IntentCertifiedHeight is, for an operation, the message CERTEN's quorum certified and the CERTEN height whose commit
// completed the certificate, and whether there is one - the committed record batch members with a certified intent
// are placed by. One operation has at most one certificate (an honest validator signs one block per operation, so two
// quorums over different messages cannot form). An unreadable ledger stops the node: answering "not certified" for it
// would place members differently from every other node.
func (app *ValidatorApp) IntentCertifiedHeight(operationID [32]byte) (uint64, [32]byte, bool) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return 0, [32]byte{}, false
	}
	ql, err := app.ledgerStore.LoadIntentQuorum("0x" + hex.EncodeToString(operationID[:]))
	if err != nil {
		app.logger.Fatalf("❌ [INTENT-QC] the intent quorum of 0x%x could not be read: %v", operationID, err)
	}
	var found *ledger.IntentQuorumCertificate
	for _, g := range ql.Groups {
		if g.Certificate == nil || g.Certificate.Height <= 0 {
			continue
		}
		if found != nil {
			app.logger.Fatalf("❌ [INTENT-QC] operation 0x%x has two quorum certificates (%s, %s): two quorums signed "+
				"different messages", operationID, found.Message, g.Certificate.Message)
		}
		found = g.Certificate
	}
	if found == nil {
		return 0, [32]byte{}, false
	}
	msg, err := hex32(found.Message)
	if err != nil {
		app.logger.Fatalf("❌ [INTENT-QC] operation 0x%x: its certificate's message: %v", operationID, err)
	}
	return uint64(found.Height), msg, true
}
