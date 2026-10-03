package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5 D4: a peer co-signs an anchor's outcome root only when its own derivation, over the tree IT kept and its own
// reads of the chain, reproduces it - and only under the CERTEN set the anchor will check the partial against.

// fakeOutcomeReader is a fakeOutcomeChain with an anchor and its registry.
type fakeOutcomeReader struct {
	*fakeOutcomeChain
	view       OutcomeAnchorView
	viewErr    error
	registryOK bool // the registry's outcomeMessage equals the Go message (false: it signs something else)
	setRoot    [32]byte
}

func (f *fakeOutcomeReader) AnchorView(context.Context, [32]byte) (*OutcomeAnchorView, error) {
	if f.viewErr != nil {
		return nil, f.viewErr
	}
	v := f.view
	return &v, nil
}

func (f *fakeOutcomeReader) OutcomeMessage(_ context.Context, bundle, root [32]byte, _ *types.Header) ([32]byte, error) {
	if !f.registryOK {
		return [32]byte{0xee}, nil
	}
	a := f.view.Anchor
	return contracts.ComputeEvmMessageHashV8_2_Outcome(f.chainID, bundle, root, f.view.CurrentSetRoot, a.AccumulateSetRoot, a.Incarnation), nil
}

var peerSetRoot = [32]byte{0x5e, 0x70}

// peerFixture is a peer holding a two-member tree whose members both executed, the anchor on the chain being that tree.
func peerFixture(t *testing.T) (*OutcomePeer, *fakeOutcomeReader, *OutcomeTree, *OutcomeRequest) {
	t.Helper()
	kept, f := derivationFixture(t)
	f.consumeAt(kept.Members[0].Leaf, kept.BundleID, common.HexToHash("0x5e771e"), 900)
	f.consumeAt(kept.Members[1].Leaf, kept.BundleID, common.HexToHash("0x5e772e"), 901)
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(kept); err != nil {
		t.Fatal(err)
	}
	reader := &fakeOutcomeReader{fakeOutcomeChain: f, registryOK: true, view: OutcomeAnchorView{
		At: f.header(2005),
		Anchor: &contracts.AnchorState{Version: contracts.BatchAnchorV8_2, Valid: true, ProofExecuted: true, MerkleRoot: kept.Root,
			AccumulateSetRoot: kept.AccumulateSetRoot, Incarnation: kept.Incarnation},
		LeafCount: uint64(len(kept.Members)), CurrentSetRoot: peerSetRoot,
	}}
	sk, _, err := bls.GenerateKeyPairFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	peer := &OutcomePeer{Trees: store, Chains: map[int64]OutcomeChainReader{84532: reader},
		Key: func() *bls.PrivateKey { return sk }, SetRoot: func() ([32]byte, error) { return peerSetRoot, nil }}
	derived, err := DeriveOutcome(context.Background(), f, kept, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := &OutcomeRequest{ChainID: 84532, BundleID: hex32(kept.BundleID), OutcomeRoot: hex32(derived.Root), ProposerID: "validator-2"}
	return peer, reader, kept, req
}

func TestAPeerCertifiesTheOutcomeItReproduces(t *testing.T) {
	peer, reader, kept, req := peerFixture(t)
	resp := peer.HandleOutcomeRequest(context.Background(), req, odIdentity())
	if resp.Error != "" || resp.SignatureHex == "" {
		t.Fatalf("a reproduced outcome was not certified: %+v", resp)
	}
	root, _ := parseHex32(req.OutcomeRoot)
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, kept.BundleID, root, peerSetRoot, kept.AccumulateSetRoot, kept.Incarnation)
	if resp.MessageHash != hex32(msg) || resp.OutcomeRoot != req.OutcomeRoot || resp.SetRoot != hex32(peerSetRoot) {
		t.Fatalf("signed %s over root %s", resp.MessageHash, resp.OutcomeRoot)
	}
	// The partial is a signature over the outcome message under this peer's registered key: the quorum fold accepts it.
	sk := peer.Key()
	registry := map[string]consensus.ValidatorRegistryEntry{
		strings.ToLower(odIdentity().EVMAddress): {EVMAddress: odIdentity().EVMAddress, PublicKeyHex: sk.PublicKey().Hex(), VotingPower: big.NewInt(100)},
	}
	if _, err := consensus.AggregateBatchAttestations([]consensus.BatchAttestationEntry{{ValidatorID: resp.ValidatorID,
		EVMAddress: resp.EVMAddress, SignatureHex: resp.SignatureHex, PublicKeyHex: resp.PublicKeyHex}}, registry, msg, 2, 3); err != nil {
		t.Fatalf("the partial does not verify over the outcome message: %v", err)
	}
	_ = reader
}

func TestAPeerRefusesWhatItCannotCertify(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		set  func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest)
		code AttestationRefusalCode
		says string
	}{
		"tree not held": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			q.BundleID = hex32([32]byte{0xbb})
		}, CodeMemberNotHeld, "holds no tree"},
		"anchor commits another root": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.Anchor.MerkleRoot = [32]byte{0x01}
		}, CodeAnchorMismatch, "commits root"},
		"anchor commits another leaf count": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.LeafCount = 3
		}, CodeAnchorMismatch, "leaves"},
		"anchor commits another Accumulate set": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.Anchor.AccumulateSetRoot = [32]byte{0x02}
		}, CodeAnchorMismatch, "Accumulate set"},
		"proof not executed": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.Anchor.ProofExecuted = false
		}, CodeOutcomeNotFinal, "has not executed"},
		"set root drift": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.CurrentSetRoot = [32]byte{0x03}
		}, CodeSetRootDrift, "currentValidatorSetRoot"},
		"member not final": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.fin = 900 // the second member's consumption at 901 is not final here
		}, CodeOutcomeNotFinal, "not final"},
		"outcome mismatch": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			q.OutcomeRoot = hex32([32]byte{0x77})
		}, CodeOutcomeMismatch, "outcome mismatch"},
		"already recorded": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.view.RecordedRoot, r.view.RecordedIn = [32]byte{0x44}, 2001
		}, CodeOutcomeRecorded, "DIFFERENT root"},
		"the registry signs another message": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.registryOK = false
		}, CodeRefused, "the registry signs"},
		"another chain": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			q.ChainID = 1
		}, CodeConfigMismatch, "not a settlement chain"},
		"the anchor cannot be read": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			r.viewErr = errors.New("providers disagree")
		}, CodeOutcomeNotFinal, "reading anchor"},
		"a tampered kept tree": {func(p *OutcomePeer, r *fakeOutcomeReader, k *OutcomeTree, q *OutcomeRequest) {
			path := filepath.Join(p.Trees.Dir(), fmt.Sprintf("84532_%x.json", k.BundleID))
			blob, _ := os.ReadFile(path)
			_ = os.WriteFile(path, bytes.Replace(blob, []byte(strings.ToLower(f77Payee[2:])), []byte(strings.Repeat("cd", 20)), 1), 0o600)
		}, CodeRefused, "rebuild"},
	} {
		t.Run(name, func(t *testing.T) {
			peer, reader, kept, req := peerFixture(t)
			c.set(peer, reader, kept, req)
			resp := peer.HandleOutcomeRequest(ctx, req, odIdentity())
			if resp.SignatureHex != "" || resp.Code != c.code || !strings.Contains(resp.Error, c.says) {
				t.Fatalf("code %q error %q signed=%v; want %q naming %q", resp.Code, resp.Error, resp.SignatureHex != "", c.code, c.says)
			}
		})
	}
}

// On a mismatch the peer says where: its own root, its leaves, and the reverted attempts it considered - so the
// recorder can converge on attempts it did not know of.
func TestAMismatchingPeerReportsItsLeavesAndAttempts(t *testing.T) {
	peer, reader, kept, req := peerFixture(t)
	// The first member never settled; this peer knows a reverted attempt the recorder did not offer.
	delete(reader.consumed, kept.Members[0].Leaf)
	attempt := common.HexToHash("0xa7")
	reader.attempts[attempt] = &ExternalChainResult{TxHash: attempt, BlockNumber: big.NewInt(950)}
	peer.Attempts = fixedAttempts{kept.Members[0].OperationID: {attempt}}
	resp := peer.HandleOutcomeRequest(context.Background(), req, odIdentity())
	if resp.Code != CodeOutcomeMismatch || len(resp.LeafHashes) != 2 || len(resp.Attempts) != 1 ||
		resp.Attempts[0].Attempts[0] != strings.ToLower(attempt.Hex()) {
		t.Fatalf("%+v", resp)
	}
	// Offered that attempt and the root it implies, the peer certifies.
	derived, err := DeriveOutcome(context.Background(), reader, kept, map[[32]byte][]common.Hash{kept.Members[0].OperationID: {attempt}})
	if err != nil {
		t.Fatal(err)
	}
	req.OutcomeRoot = "0x" + hex.EncodeToString(derived.Root[:])
	req.Members = resp.Attempts
	peer.Attempts = nil
	if resp := peer.HandleOutcomeRequest(context.Background(), req, odIdentity()); resp.SignatureHex == "" {
		t.Fatalf("not certified with the attempt offered: %+v", resp)
	}
}

type fixedAttempts map[[32]byte][]common.Hash

func (f fixedAttempts) AttemptsFor(_ context.Context, _ int64, m OutcomeTreeMember) ([]common.Hash, error) {
	return f[m.OperationID], nil
}

// The recorder folds in only partials over exactly the proposed root and message; refusals are counted by code, and the
// attempts peers report are carried to the next round.
func TestTheRecorderCollectsOnlyAgreeingPartials(t *testing.T) {
	msg := [32]byte{0x3a}
	req := &OutcomeRequest{ChainID: 84532, BundleID: hex32([32]byte{1}), OutcomeRoot: hex32([32]byte{2})}
	serve := func(resp OutcomeResponse) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != OutcomeRequestEndpoint {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	agree := OutcomeResponse{EVMAddress: "0x1", SignatureHex: "aa", BundleID: req.BundleID, OutcomeRoot: req.OutcomeRoot, MessageHash: hex32(msg)}
	otherMsg := agree
	otherMsg.MessageHash = hex32([32]byte{0x3b})
	mismatch := OutcomeResponse{Error: "outcome mismatch", Code: CodeOutcomeMismatch,
		Attempts: []OutcomeMemberHint{{OperationID: hex32([32]byte{9}), Attempts: []string{hex32([32]byte{8})}}}}
	notFinal := OutcomeResponse{Error: "not final", Code: CodeOutcomeNotFinal}
	res := CollectOutcomeAttestations(context.Background(), nil,
		[]string{serve(agree), serve(otherMsg), serve(mismatch), serve(notFinal), "http://127.0.0.1:1"}, req, msg, 5*time.Second)
	if len(res.Responses) != 1 || res.Refusals[CodeRefused] != 1 || res.Refusals[CodeOutcomeMismatch] != 1 ||
		res.Refusals[CodeOutcomeNotFinal] != 1 || res.Unreachable != 1 || len(res.Attempts) != 1 || res.Retryable() {
		t.Fatalf("%+v", res)
	}
}
