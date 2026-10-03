// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F15: a member's recorded batch outcome verifies OFFLINE, from its evidence alone.
//
// The fixtures are REAL: testdata/outcome_evidence/outcome_evidence_<chain>.json is the evidence of the member of each
// 55d23cb0 anchor (one per chain), built from the chain and the signed intent on Kermit by
// TestLiveOutcomeEvidenceOfAResolvedMember, against the outcome the deployed CertenOutcomeRegistryV1 records - its
// record transaction, its block header, the anchor's validator registry, the Groth16 proof the registry verified, the
// settlement and its receipt with their trie proofs.

var outcomeFixtureChains = []int64{11155111, 84532, 421614}

func loadOutcomeFixture(t *testing.T, chain int64) *OutcomeEvidence {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "outcome_evidence", fmt.Sprintf("outcome_evidence_%d.json", chain)))
	if err != nil {
		t.Fatal(err)
	}
	ev := new(OutcomeEvidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestTheRecordedOutcomeOfEachChainVerifiesOffline(t *testing.T) {
	for _, chain := range outcomeFixtureChains {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			ev := loadOutcomeFixture(t, chain)
			chk, err := ev.VerifyOffline()
			if err != nil {
				t.Fatal(err)
			}
			if chk.Leaf.Status != OutcomeExecuted || chk.Signers != 5 || chk.SignedPower.Int64() != 500 || chk.TotalPower.Int64() != 700 ||
				chk.ConsumedUnder != chk.BundleID || chk.BLSAggregate {
				t.Fatalf("established %+v", chk)
			}
			for _, want := range []string{"re-derives from its commitment", "recordBatchOutcome", "outcome message", "Groth16",
				"outcome leaf 0 (status 1)", "batch leaf", "LeafConsumed"} {
				if !strings.Contains(strings.Join(chk.Established, "\n"), want) {
					t.Fatalf("the check does not say it established %q:\n%s", want, strings.Join(chk.Established, "\n"))
				}
			}
			// What it cannot establish is said, never dropped.
			for _, want := range []string{"canonical and final", "BLS keys are the ones the anchor registered", "BLS aggregate signature itself",
				"runs CertenAccountV7_2 code"} {
				if !strings.Contains(strings.Join(chk.NotEstablished, "\n"), want) {
					t.Fatalf("the check does not state it did not establish %q", want)
				}
			}
		})
	}
}

func flipHexByte(s string, at int) string {
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	b[at] ^= 0x01
	return "0x" + hex.EncodeToString(b)
}

// Each tamper of the evidence is a FAILURE (ErrOutcomeEvidence), named by the check that catches it.
func TestATamperedOutcomeEvidenceFails(t *testing.T) {
	otherKey := func(t *testing.T) string {
		_, pk, err := bls.GenerateKeyPairFromSeed(bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return "0x" + pk.Hex()
	}
	cases := []struct {
		name   string
		tamper func(t *testing.T, e *OutcomeEvidence)
		want   string
	}{
		{"leaf field: effects hash", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Leaf.EffectsHash = "0x" + strings.Repeat("11", 32) },
			"does not reach the recorded outcome root"},
		{"leaf field: settlement tx", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Leaf.Tx = flipHexByte(e.Member.Leaf.Tx, 31) },
			"does not reach the recorded outcome root"},
		{"leaf field: block number", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Leaf.BlockNumber++ },
			"does not reach the recorded outcome root"},
		{"status", func(_ *testing.T, e *OutcomeEvidence) {
			e.Member.Leaf.Status = uint8(OutcomeConsumedElsewhere)
			e.Member.Leaf.EffectsHash = zeroHex
		},
			"does not reach the recorded outcome root"},
		{"branch", func(_ *testing.T, e *OutcomeEvidence) {
			e.Member.OutcomeBranch = append(e.Member.OutcomeBranch, "0x"+strings.Repeat("22", 32))
		}, "does not reach the recorded outcome root"},
		{"root", func(_ *testing.T, e *OutcomeEvidence) { e.Record.OutcomeRoot = flipHexByte(e.Record.OutcomeRoot, 0) },
			"the outcome message recomputes"},
		{"root and message together", func(_ *testing.T, e *OutcomeEvidence) {
			e.Record.OutcomeRoot = flipHexByte(e.Record.OutcomeRoot, 0)
			a := e.Anchor
			msg := computeOutcomeMessage(e.ChainID, a.BundleID, e.Record.OutcomeRoot, a.CertenSetRoot, a.AccumulateSetRoot, a.Incarnation)
			e.Record.MessageHash = msg
		}, "submitted anchor"},
		{"signer", func(_ *testing.T, e *OutcomeEvidence) {
			for _, v := range e.Quorum.Validators { // a validator that did not sign takes a signer's place
				if !containsFold(e.Quorum.Signers, v.Address) {
					e.Quorum.Signers[0] = v.Address
					return
				}
			}
		}, "the record transaction submitted"},
		{"signer power", func(_ *testing.T, e *OutcomeEvidence) { e.Quorum.SignerPowers[0] = "200" }, "the record transaction submitted"},
		{"signed power", func(_ *testing.T, e *OutcomeEvidence) { e.Quorum.SignedVotingPower = "600" }, "the record transaction submitted"},
		{"validator power", func(_ *testing.T, e *OutcomeEvidence) {
			for i, v := range e.Quorum.Validators {
				if containsFold(e.Quorum.Signers, v.Address) {
					e.Quorum.Validators[i].VotingPower = "200"
					return
				}
			}
		}, "its registered power is 200"},
		{"validator set threshold", func(_ *testing.T, e *OutcomeEvidence) { e.Quorum.ThresholdNumerator = 1 }, "derives set root"},
		{"validator key", func(t *testing.T, e *OutcomeEvidence) {
			for i, v := range e.Quorum.Validators {
				if containsFold(e.Quorum.Signers, v.Address) {
					e.Quorum.Validators[i].BLSPublicKey = otherKey(t)
					return
				}
			}
		}, "commits key"},
		{"aggregate: the quorum proof", func(_ *testing.T, e *OutcomeEvidence) { e.Quorum.ZKProof[5] ^= 1 },
			"is not the one the record transaction submitted"},
		{"aggregate: a BLS aggregate that is not the quorum's", func(t *testing.T, e *OutcomeEvidence) {
			sk, _, err := bls.GenerateKeyPairFromSeed(bytes.Repeat([]byte{0x43}, 32))
			if err != nil {
				t.Fatal(err)
			}
			e.Quorum.AggregateSignature = "0x" + bls_zkp.SignV6_1PreExec(sk, common.HexToHash(e.Record.MessageHash)).Hex()
			e.Quorum.AggregatePublicKey = "0x" + signersAggregateKey(t, e).Hex()
		}, "BLS aggregate signature does not verify"},
		{"aggregate: an aggregate key that is not the signers'", func(t *testing.T, e *OutcomeEvidence) {
			e.Quorum.AggregateSignature = "0x" + bls_zkp.SignV6_1PreExec(mustKey(t, 0x44), common.HexToHash(e.Record.MessageHash)).Hex()
			e.Quorum.AggregatePublicKey = otherKey(t)
		}, "not the aggregate of the signers' keys"},
		{"receipt proof", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Transaction.ReceiptProof[0][3] ^= 1 },
			"receipt is not proven"},
		{"receipt", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Transaction.Receipt[10] ^= 1 }, "receipt is not proven"},
		{"transaction proof", func(_ *testing.T, e *OutcomeEvidence) {
			e.Member.Transaction.TransactionProof = e.Member.Transaction.TransactionProof[:len(e.Member.Transaction.TransactionProof)-1]
		}, "transaction is not proven"},
		{"proof index", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Transaction.Index++ }, "not proven at index"},
		{"settlement header", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Transaction.Header[40] ^= 1 }, "header hashes to"},
		{"record header", func(_ *testing.T, e *OutcomeEvidence) { e.Record.Inclusion.Header[40] ^= 1 }, "header hashes to"},
		{"record receipt proof", func(_ *testing.T, e *OutcomeEvidence) { e.Record.Inclusion.ReceiptProof[0][3] ^= 1 },
			"receipt is not proven"},
		{"record block hash", func(_ *testing.T, e *OutcomeEvidence) { e.Record.BlockHash = flipHexByte(e.Record.BlockHash, 31) },
			"header hashes to"},
		{"recorder", func(_ *testing.T, e *OutcomeEvidence) {
			for _, v := range e.Quorum.Validators {
				if !strings.EqualFold(v.Address, e.Record.Recorder) {
					e.Record.Recorder = v.Address
					return
				}
			}
		}, "was signed by"},
		{"anchor commitment", func(_ *testing.T, e *OutcomeEvidence) {
			e.Anchor.BatchOperationID = flipHexByte(e.Anchor.BatchOperationID, 0)
		},
			"derives bundle id"},
		{"anchor set root", func(_ *testing.T, e *OutcomeEvidence) {
			e.Anchor.CertenSetRoot = flipHexByte(e.Anchor.CertenSetRoot, 0)
		},
			"the outcome message recomputes"},
		{"member ADI", func(_ *testing.T, e *OutcomeEvidence) { e.Member.ADIURL += "x" }, "recompute batch leaf"},
		{"member committed call", func(_ *testing.T, e *OutcomeEvidence) {
			e.Member.Legs[0].Value = (*hexutil.Big)(new(big.Int).Add(e.Member.Legs[0].Value.ToInt(), big.NewInt(1)))
		}, "recompute batch leaf"},
		{"member account", func(_ *testing.T, e *OutcomeEvidence) { e.Member.Account = e.Registry }, "no LeafConsumed"},
		{"version", func(_ *testing.T, e *OutcomeEvidence) { e.Version = "certen:outcome-evidence:v0" }, "this verifier reads"},
	}
	for _, chain := range outcomeFixtureChains {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%d/%s", chain, c.name), func(t *testing.T) {
				ev := loadOutcomeFixture(t, chain)
				c.tamper(t, ev)
				_, err := ev.VerifyOffline()
				if !errors.Is(err, ErrOutcomeEvidence) {
					t.Fatalf("a tampered evidence: %v", err)
				}
				if !strings.Contains(err.Error(), c.want) {
					t.Fatalf("caught, but not by the check that names %q: %v", c.want, err)
				}
			})
		}
	}
}

const zeroHex = "0x0000000000000000000000000000000000000000000000000000000000000000"

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func computeOutcomeMessage(chain int64, bundle, root, set, acc, inc string) string {
	m := contractsOutcomeMessage(chain, common.HexToHash(bundle), common.HexToHash(root), common.HexToHash(set), common.HexToHash(acc),
		common.HexToHash(inc))
	return "0x" + hex.EncodeToString(m[:])
}

func mustKey(t *testing.T, seed byte) *bls.PrivateKey {
	t.Helper()
	sk, _, err := bls.GenerateKeyPairFromSeed(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func signersAggregateKey(t *testing.T, e *OutcomeEvidence) *bls.PublicKey {
	t.Helper()
	var pubs []*bls.PublicKey
	for _, s := range e.Quorum.Signers {
		for _, v := range e.Quorum.Validators {
			if strings.EqualFold(v.Address, s) {
				pk, err := bls.PublicKeyFromHex(strings.TrimPrefix(v.BLSPublicKey, "0x"))
				if err != nil {
					t.Fatal(err)
				}
				pubs = append(pubs, pk)
			}
		}
	}
	agg, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		t.Fatal(err)
	}
	return agg
}

// The proof the record transaction submitted is checked under the deployed verification key, not taken from the
// calldata on trust: a proof that does not verify fails the quorum even with the calldata bypassed.
func TestAQuorumProofThatDoesNotVerifyFailsTheQuorum(t *testing.T) {
	ev := loadOutcomeFixture(t, 11155111)
	msg := common.HexToHash(ev.Record.MessageHash)
	set := common.HexToHash(ev.Anchor.CertenSetRoot)
	if err := ev.Quorum.verify(set, msg, ev.Record, &OutcomeEvidenceCheck{}); err != nil {
		t.Fatalf("the real proof: %v", err)
	}
	ev.Quorum.ZKProof[40] ^= 1 // inside proof point A; the public inputs are unchanged
	err := ev.Quorum.verify(set, msg, ev.Record, &OutcomeEvidenceCheck{})
	if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "does not verify under the deployed verification key") {
		t.Fatalf("a proof that does not verify: %v", err)
	}
	// And a proof for another message is refused before it is run.
	ev = loadOutcomeFixture(t, 11155111)
	if err := ev.Quorum.verify(set, [32]byte{1}, ev.Record, &OutcomeEvidenceCheck{}); err == nil || !strings.Contains(err.Error(), "is over message") {
		t.Fatalf("a proof of another message: %v", err)
	}
}

// The quorum's own rules, checked even where the record transaction's calldata would already refuse the tamper: the
// signers at their registered powers, the signed and total power, the threshold.
func TestTheQuorumsPowersAndThresholdAreCheckedOnTheirOwn(t *testing.T) {
	signerIdx := func(e *OutcomeEvidence, signer bool) int {
		for i, v := range e.Quorum.Validators {
			if containsFold(e.Quorum.Signers, v.Address) == signer {
				return i
			}
		}
		return -1
	}
	cases := []struct {
		name   string
		tamper func(e *OutcomeEvidence)
		want   string
	}{
		{"a signer credited more than its registered power", func(e *OutcomeEvidence) { e.Quorum.SignerPowers[0] = "200" }, "is credited 200"},
		{"a signed power the signers do not sum to", func(e *OutcomeEvidence) { e.Quorum.SignedVotingPower = "600" }, "sum to 500"},
		{"a total the set does not sum to", func(e *OutcomeEvidence) { e.Quorum.Validators[signerIdx(e, false)].VotingPower = "200" },
			"powers sum to 800"},
		{"a signer counted twice", func(e *OutcomeEvidence) { e.Quorum.Signers[1] = e.Quorum.Signers[0] }, "counted twice"},
		{"a signer outside the set", func(e *OutcomeEvidence) { e.Quorum.Signers[0] = "0x00000000000000000000000000000000000000f1" },
			"is not in the validator set"},
		{"fewer signers than the threshold", func(e *OutcomeEvidence) {
			e.Quorum.Signers, e.Quorum.SignerPowers, e.Quorum.SignedVotingPower = e.Quorum.Signers[:3], e.Quorum.SignerPowers[:3], "300"
		}, "the anchor requires 466"},
		{"the set out of order", func(e *OutcomeEvidence) {
			v := e.Quorum.Validators
			v[0], v[1] = v[1], v[0]
		}, "ascending address order"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := loadOutcomeFixture(t, 11155111)
			c.tamper(ev)
			err := ev.Quorum.verify(common.HexToHash(ev.Anchor.CertenSetRoot), common.HexToHash(ev.Record.MessageHash), ev.Record,
				&OutcomeEvidenceCheck{})
			if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a failure naming %q, got %v", c.want, err)
			}
		})
	}
}

// The BLS aggregate the recording validator holds verifies under exactly the signers' aggregate key over the message.
func TestTheRecordersBLSAggregateIsCheckedUnderTheSignersKeys(t *testing.T) {
	msg := [32]byte{0x0c, 0x5e}
	var sigs []*bls.Signature
	var pubs []*bls.PublicKey
	for i := byte(0); i < 5; i++ {
		sk := mustKey(t, 0x50+i)
		sigs = append(sigs, bls_zkp.SignV6_1PreExec(sk, msg))
		pubs = append(pubs, sk.PublicKey())
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOutcomeAggregate(aggPub, aggSig.Hex(), aggPub.Hex(), msg); err != nil {
		t.Fatalf("the quorum's aggregate: %v", err)
	}
	four, _ := bls.AggregatePublicKeys(pubs[:4])
	if err := verifyOutcomeAggregate(four, aggSig.Hex(), aggPub.Hex(), msg); err == nil {
		t.Fatal("an aggregate key of five accepted for four signers")
	}
	if err := verifyOutcomeAggregate(aggPub, aggSig.Hex(), aggPub.Hex(), [32]byte{1}); err == nil {
		t.Fatal("the aggregate verified over another message")
	}
}

// =============================================================================
// The status must be what the chain evidence shows (synthetic blocks)
// =============================================================================

type synthBlock struct {
	header  *types.Header
	incl    *ChainInclusionEvidence
	txHash  common.Hash
	account common.Address
}

// synthSettlement is a one-transaction block: a call to account whose receipt has the given status and logs.
func synthSettlement(t *testing.T, chainID int64, number, time uint64, parent common.Hash, account common.Address, status uint64, logs []*types.Log) synthBlock {
	t.Helper()
	key, _ := crypto.ToECDSA(bytes.Repeat([]byte{0x07}, 32))
	tx := signedCall(t, chainID, key, account)
	txBytes, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	r := &types.Receipt{Type: types.DynamicFeeTxType, Status: status, CumulativeGasUsed: 50_000, Logs: logs}
	r.Bloom = types.CreateBloom(r)
	rBytes, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	h := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Time: time, Difficulty: big.NewInt(0),
		TxHash: trieRoot([][]byte{txBytes}), ReceiptHash: trieRoot([][]byte{rBytes}), Root: common.Hash{0x5}}
	txp, err := proveIndex([][]byte{txBytes}, 0, h.TxHash)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := proveIndex([][]byte{rBytes}, 0, h.ReceiptHash)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	incl := &ChainInclusionEvidence{Header: raw, Index: 0, Transaction: txBytes, Receipt: rBytes}
	for _, n := range txp.ProofNodes {
		incl.TransactionProof = append(incl.TransactionProof, n)
	}
	for _, n := range rp.ProofNodes {
		incl.ReceiptProof = append(incl.ReceiptProof, n)
	}
	return synthBlock{header: h, incl: incl, txHash: tx.Hash(), account: account}
}

func signedCall(t *testing.T, chainID int64, key *ecdsa.PrivateKey, to common.Address) *types.Transaction {
	t.Helper()
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(chainID)), &types.DynamicFeeTx{ChainID: big.NewInt(chainID),
		Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 100_000, To: &to, Data: []byte{0xde, 0xad}})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// synthMember is a one-member anchor whose member's batch leaf is recomputed from its inputs, its outcome leaf the
// outcome root.
type synthMember struct {
	chainID int64
	anchor  *anchorFacts
	ev      OutcomeMemberEvidence
	leaf    OutcomeLeaf
}

func newSynthMember(t *testing.T, events []outcomeTreeEvent) *synthMember {
	t.Helper()
	const chainID = 84532
	account := common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC")
	legs := []OutcomeTreeLeg{{Target: common.HexToAddress("0x00000000000000000000000000000000000000aa"), Value: (*hexutil.Big)(big.NewInt(1)),
		Data: hexutil.Bytes{}, Events: events}}
	calls, _ := memberLegCalls(legs)
	op := [32]byte{0x0b}
	book := [32]byte{0xb0}
	batchLeaf := ComputeBatchLeafV3(chainID, BatchLeafInput{ADIURL: "acc://synth.acme", ExecutionCommitment: memberExecutionCommitment(chainID, calls),
		OperationID: op, AuthorityBook: book, AuthorityPage: 1})
	m := &synthMember{chainID: chainID, anchor: &anchorFacts{bundleID: [32]byte{0xa1}, batchRoot: batchLeaf, leafCount: 1}}
	m.ev = OutcomeMemberEvidence{Account: account.Hex(), ADIURL: "acc://synth.acme", AuthorityBook: common.Hash(book).Hex(), AuthorityPage: 1,
		Legs: legs, Deadline: 1_790_000_000, FinalityMargin: int64(nonSettlementFinality.Seconds())}
	m.leaf = OutcomeLeaf{ChainID: chainID, BundleID: m.anchor.bundleID, BatchLeaf: batchLeaf, OperationID: op}
	return m
}

func (m *synthMember) consumedLog(anchor [32]byte) *types.Log {
	return &types.Log{Address: common.HexToAddress(m.ev.Account), Topics: []common.Hash{leafConsumedTopic, anchor, m.leaf.BatchLeaf},
		Data: append([]byte(nil), m.leaf.OperationID[:]...)}
}

// settle names blk as the member's transaction and its block in the leaf.
func (m *synthMember) settle(blk synthBlock, status OutcomeStatus, effects [32]byte) {
	m.ev.Transaction = blk.incl
	m.leaf.Status, m.leaf.Tx, m.leaf.BlockNumber = status, blk.txHash, blk.header.Number.Uint64()
	m.leaf.BlockHash, m.leaf.ReceiptsRoot, m.leaf.EffectsHash = blk.header.Hash(), blk.header.ReceiptHash, effects
}

func (m *synthMember) verify() error {
	h := func(b [32]byte) string { return common.Hash(b).Hex() }
	m.ev.Leaf = OutcomeLeafEvidence{LeafIndex: 0, BatchLeaf: h(m.leaf.BatchLeaf), OperationID: h(m.leaf.OperationID), Status: uint8(m.leaf.Status),
		Tx: h(m.leaf.Tx), BlockNumber: m.leaf.BlockNumber, BlockHash: h(m.leaf.BlockHash), ReceiptsRoot: h(m.leaf.ReceiptsRoot),
		EffectsHash: h(m.leaf.EffectsHash)}
	root, err := m.leaf.Hash()
	if err != nil {
		return err
	}
	return m.ev.verify(m.chainID, m.anchor, root, &OutcomeEvidenceCheck{})
}

func TestARecordedStatusMustBeWhatTheChainEvidenceShows(t *testing.T) {
	event := outcomeTreeEvent{Contract: common.HexToAddress("0x00000000000000000000000000000000000000aa"), Topic0: common.Hash{0xe1},
		DataHash: crypto.Keccak256Hash([]byte("paid"))}
	emitted := &types.Log{Address: event.Contract, Topics: []common.Hash{event.Topic0}, Data: []byte("paid")}
	committed := CommittedEffectsHash([][]ExpectedEvent{{{Contract: event.Contract, Topic0: event.Topic0, DataHash: event.DataHash}}}, nil)

	type tc struct {
		name string
		run  func(t *testing.T) error
		want string // "" = verifies
	}
	cases := []tc{
		{"executed, its event present", func(t *testing.T) error {
			m := newSynthMember(t, []outcomeTreeEvent{event})
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID), emitted}), OutcomeExecuted, committed)
			return m.verify()
		}, ""},
		{"executed, but the settlement reverted", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 0, nil), OutcomeExecuted, [32]byte{})
			return m.verify()
		}, "receipt is status 0"},
		{"executed, but its leaf consumed under another anchor", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog([32]byte{0xff})}), OutcomeExecuted, [32]byte{})
			return m.verify()
		}, "consumed under 0x"},
		{"executed, but its committed event absent", func(t *testing.T) error {
			m := newSynthMember(t, []outcomeTreeEvent{event})
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID)}), OutcomeExecuted, committed)
			return m.verify()
		}, "proves 1 event(s) absent"},
		{"effects not proven, the shortfall proven", func(t *testing.T) error {
			m := newSynthMember(t, []outcomeTreeEvent{event})
			sh, _ := ShortfallEffectsHash(committed, []CommittedEffect{{Leg: 0, Index: 0}}, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID)}), OutcomeEffectsNotProven, sh)
			return m.verify()
		}, ""},
		{"effects not proven, but every effect present", func(t *testing.T) error {
			m := newSynthMember(t, []outcomeTreeEvent{event})
			sh, _ := ShortfallEffectsHash(committed, []CommittedEffect{{Leg: 0, Index: 0}}, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID), emitted}), OutcomeEffectsNotProven, sh)
			return m.verify()
		}, "every committed effect is proven present"},
		{"executed, the wrong effects hash", func(t *testing.T) error {
			m := newSynthMember(t, []outcomeTreeEvent{event})
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID), emitted}), OutcomeExecuted, [32]byte{0x99})
			return m.verify()
		}, "the committed effects hash to"},
		{"consumed elsewhere, under another anchor", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog([32]byte{0xff})}), OutcomeConsumedElsewhere, [32]byte{})
			return m.verify()
		}, ""},
		{"consumed elsewhere, but consumed under this anchor", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
				[]*types.Log{m.consumedLog(m.anchor.bundleID)}), OutcomeConsumedElsewhere, [32]byte{})
			return m.verify()
		}, "consumed under this anchor"},
		{"not settled, at the first block past the deadline", func(t *testing.T) error {
			return stateNotSettled(t, newSynthMember(t, nil), 1_790_000_100, 1_790_000_130, nil)
		}, ""},
		{"not settled, at a block before the deadline and margin", func(t *testing.T) error {
			return stateNotSettled(t, newSynthMember(t, nil), 1_790_000_100, 1_790_000_110, nil)
		}, "is not past the deadline"},
		{"not settled, at a block that is not the first past the horizon", func(t *testing.T) error {
			return stateNotSettled(t, newSynthMember(t, nil), 1_790_000_125, 1_790_000_140, nil)
		}, "is not the FIRST past the horizon"},
		{"not settled, its last attempt reverted", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			return stateNotSettled(t, m, 1_790_000_100, 1_790_000_130, func(blk *synthBlock) {
				*blk = synthSettlement(t, m.chainID, 90, 1_790_000_000, common.Hash{}, common.HexToAddress(m.ev.Account), 0, nil)
			})
		}, ""},
		{"not settled, but its named attempt succeeded", func(t *testing.T) error {
			m := newSynthMember(t, nil)
			return stateNotSettled(t, m, 1_790_000_100, 1_790_000_130, func(blk *synthBlock) {
				*blk = synthSettlement(t, m.chainID, 90, 1_790_000_000, common.Hash{}, common.HexToAddress(m.ev.Account), 1, nil)
			})
		}, "did not revert"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("consistent evidence refused: %v", err)
			case c.want != "" && (!errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("want a failure naming %q, got %v", c.want, err)
			}
		})
	}
}

// stateNotSettled states the member NOT SETTLED at a claim block of time claimTime whose parent has time parentTime (the
// member's deadline is 1_790_000_000, the margin 120 s), with an attempt when attempt sets one.
func stateNotSettled(t *testing.T, m *synthMember, parentTime, claimTime uint64, attempt func(*synthBlock)) error {
	t.Helper()
	parent := &types.Header{Number: big.NewInt(199), Time: parentTime, Difficulty: big.NewInt(0)}
	claim := &types.Header{ParentHash: parent.Hash(), Number: big.NewInt(200), Time: claimTime, Difficulty: big.NewInt(0),
		ReceiptHash: common.Hash{0xcc}}
	var err error
	if m.ev.ClaimHeader, err = rlp.EncodeToBytes(claim); err != nil {
		t.Fatal(err)
	}
	if m.ev.ClaimParentHeader, err = rlp.EncodeToBytes(parent); err != nil {
		t.Fatal(err)
	}
	m.leaf.Status, m.leaf.BlockNumber, m.leaf.BlockHash, m.leaf.ReceiptsRoot = OutcomeNotSettled, 200, claim.Hash(), claim.ReceiptHash
	if attempt != nil {
		var blk synthBlock
		attempt(&blk)
		m.ev.Transaction, m.leaf.Tx = blk.incl, blk.txHash
	}
	return m.verify()
}

func contractsOutcomeMessage(chain int64, bundle, root, set, acc, inc common.Hash) [32]byte {
	return contracts.ComputeEvmMessageHashV8_2_Outcome(chain, bundle, root, set, acc, inc)
}
