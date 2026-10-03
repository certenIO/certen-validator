package execution

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F57: on a chain switched to v4 (CertenAccountV7_3), the batch tree, the settlement calldata, the D4 kept tree and
// the backfill all carry the member's window. Each test below states the property through the pre-F57 API (PendingBatch-
// Intent, BuildBatchTree, NewOutcomeTree, OutcomeBackfill) against a v4 leaf computed here by hand from the member's own
// commit time and Deadline; only the two helpers at the bottom use the F57 API. Run against the pre-F57 code with those
// helpers replaced by what that code did (no version; settlement through the V7_2 binding), every one of them fails.

// f57ManualV4Leaf is the member's v4 leaf, computed by hand:
// keccak256("certen:batchleaf:v4" || uint256 chainId || keccak256(adiURL) || executionCommitment || operationID ||
// authorityBook || uint64 page || uint64 commitTime || uint64 Deadline()).
func f57ManualV4Leaf(t *testing.T, p *PendingBatchIntent) [32]byte {
	t.Helper()
	exec, err := p.ExecutionCommitment()
	if err != nil {
		t.Fatal(err)
	}
	book, page, err := p.Authority()
	if err != nil {
		t.Fatal(err)
	}
	deadline, ok := p.Deadline()
	if !ok || p.CommitTime.IsZero() {
		t.Fatalf("member %s has no window", p.IntentID)
	}
	u64 := func(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
	chain := make([]byte, 32)
	big.NewInt(p.ChainID).FillBytes(chain)
	return ethcrypto.Keccak256Hash([]byte("certen:batchleaf:v4"), chain, ethcrypto.Keccak256([]byte(p.ADIURL)), exec[:],
		p.OperationID[:], book[:], u64(page), u64(uint64(p.CommitTime.Unix())), u64(uint64(deadline.Unix())))
}

func f57Member(id string, opID uint64, deadline time.Time, legs int) *PendingBatchIntent {
	var ls []LegExecution
	for i := 0; i < legs; i++ {
		l := oneLeg(84532, dst, int64(i+1))
		l.Deadline = deadline.Unix()
		ls = append(ls, l)
	}
	p := pending(id, "acc://"+id+".acme", 84532, acct1, opID, ls...)
	p.CommitTime = time.Unix(1_790_000_000, 0).UTC()
	return p
}

func f57Tree(t *testing.T, chainID int64, members ...*PendingBatchIntent) *BatchTree {
	t.Helper()
	var inputs []BatchLeafInput
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}
	tree, err := BuildBatchTree(chainID, withAccSet(inputs), 105, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// The batch tree of a v4 chain holds each member's v4 leaf: a member's deadline is in its leaf, so the same member with
// another deadline is another leaf. A v3 chain's tree is unchanged.
func TestF57BatchTreeReadsTheChainsLeafVersion(t *testing.T) {
	f57SetVersions(t, "84532=v4")
	commit := time.Unix(1_790_000_000, 0).UTC()
	early := f57Member("f57-tree", 901, commit.Add(20*time.Minute), 1)
	late := f57Member("f57-tree", 901, commit.Add(30*time.Minute), 1)
	te, tl := f57Tree(t, 84532, early), f57Tree(t, 84532, late)
	if te.Leaves[0] != f57ManualV4Leaf(t, early) || tl.Leaves[0] != f57ManualV4Leaf(t, late) {
		t.Fatalf("the Base tree holds 0x%x, not the member's v4 leaf 0x%x", te.Leaves[0], f57ManualV4Leaf(t, early))
	}
	if te.Leaves[0] == tl.Leaves[0] || te.Root == tl.Root {
		t.Fatal("two deadlines, one leaf: the tree does not bind the member's deadline")
	}
	// Sepolia stays on v3.
	sep := pending("f57-sep", "acc://f57-sep.acme", 11155111, acct1, 902, oneLeg(11155111, dst, 1))
	in, err := sep.LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	if ts := f57Tree(t, 11155111, sep); ts.Leaves[0] != ComputeBatchLeafV3(11155111, in) {
		t.Fatal("the Sepolia tree is not v3")
	}
}

// The settlement a v4 chain's member is sent with calls CertenAccountV7_3 with the window its leaf binds - on the single
// and the batch entry point. Sent through CertenAccountV7_2's entry points it would carry no window, and a V7_3 account
// has no such function.
func TestF57SettlementCalldataReadsTheChainsLeafVersion(t *testing.T) {
	f57SetVersions(t, "84532=v4")
	const v73Proof = "(string,bytes32,bytes32[],bytes32,bytes,bytes,bytes,uint256,uint256,bytes,uint256,bytes32,uint64,uint64,uint64)"
	parsed, err := abi.JSON(strings.NewReader(`[` +
		`{"type":"function","name":"executeGovernanceProofDirect","inputs":[{"name":"target","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},{"name":"proof","type":"tuple","components":[{"name":"adiURL","type":"string"},{"name":"anchorId","type":"bytes32"},{"name":"merkleProof","type":"bytes32[]"},{"name":"operationID","type":"bytes32"},{"name":"keyBookProof","type":"bytes"},{"name":"roleProof","type":"bytes"},{"name":"thresholdProof","type":"bytes"},{"name":"timestamp","type":"uint256"},{"name":"expiresAt","type":"uint256"},{"name":"validatorSignatures","type":"bytes"},{"name":"nonce","type":"uint256"},{"name":"authorityBook","type":"bytes32"},{"name":"authorityPage","type":"uint64"},{"name":"notBefore","type":"uint64"},{"name":"notAfter","type":"uint64"}]}],"outputs":[]},` +
		`{"type":"function","name":"batchExecuteGovernanceProofDirect","inputs":[{"name":"targets","type":"address[]"},{"name":"values","type":"uint256[]"},{"name":"datas","type":"bytes[]"},{"name":"proof","type":"tuple","components":[{"name":"adiURL","type":"string"},{"name":"anchorId","type":"bytes32"},{"name":"merkleProof","type":"bytes32[]"},{"name":"operationID","type":"bytes32"},{"name":"keyBookProof","type":"bytes"},{"name":"roleProof","type":"bytes"},{"name":"thresholdProof","type":"bytes"},{"name":"timestamp","type":"uint256"},{"name":"expiresAt","type":"uint256"},{"name":"validatorSignatures","type":"bytes"},{"name":"nonce","type":"uint256"},{"name":"authorityBook","type":"bytes32"},{"name":"authorityPage","type":"uint64"},{"name":"notBefore","type":"uint64"},{"name":"notAfter","type":"uint64"}]}],"outputs":[]}]`))
	if err != nil {
		t.Fatal(err)
	}
	commit := time.Unix(1_790_000_000, 0).UTC()
	for _, c := range []struct {
		legs int
		sig  string
	}{
		{1, "executeGovernanceProofDirect(address,uint256,bytes," + v73Proof + ")"},
		{3, "batchExecuteGovernanceProofDirect(address[],uint256[],bytes[]," + v73Proof + ")"},
	} {
		p := f57Member(fmt.Sprintf("f57-settle-%d", c.legs), uint64(910+c.legs), commit.Add(20*time.Minute), c.legs)
		tree := f57Tree(t, 84532, p)
		data := f57SettlementCalldata(t, p, tree, nil)
		if want := ethcrypto.Keccak256([]byte(c.sig))[:4]; string(data[:4]) != string(want) {
			t.Fatalf("%d leg(s): the settlement calls selector %x, not CertenAccountV7_3's %x (%s)", c.legs, data[:4], want, c.sig)
		}
		m, err := parsed.MethodById(data[:4])
		if err != nil {
			t.Fatal(err)
		}
		args, err := m.Inputs.Unpack(data[4:])
		if err != nil {
			t.Fatal(err)
		}
		tuple := reflect.ValueOf(args[3])
		proof := struct {
			AnchorId  [32]byte
			NotBefore uint64
			NotAfter  uint64
		}{tuple.FieldByName("AnchorId").Interface().([32]byte), tuple.FieldByName("NotBefore").Interface().(uint64),
			tuple.FieldByName("NotAfter").Interface().(uint64)}
		deadline, _ := p.Deadline()
		if proof.NotBefore != uint64(commit.Unix()) || proof.NotAfter != uint64(deadline.Unix()) || proof.AnchorId != tree.BundleID {
			t.Fatalf("%d leg(s): the settlement names window [%d, %d], the member's is [%d, %d]", c.legs, proof.NotBefore,
				proof.NotAfter, commit.Unix(), deadline.Unix())
		}
	}
}

// The tree a validator keeps for D4 holds each member's v4 leaf on a v4 chain, and re-derives it from what it keeps.
func TestF57KeptOutcomeTreeReadsTheChainsLeafVersion(t *testing.T) {
	f57SetVersions(t, "84532=v4")
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	a := outcomeTestMember(t, 84532, "f57kept-a", f77NativeLeg(84532, "1000"), f77CallLeg(84532, true))
	b := outcomeTestMember(t, 84532, "f57kept-b", f77NativeLeg(84532, "7"))
	tree, byOp := outcomeTestTree(t, 84532, a, b)
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range []*PendingBatchIntent{a, b} {
		if want := f57ManualV4Leaf(t, p); kept.Members[i].Leaf != want {
			t.Fatalf("kept member %d holds leaf 0x%x, its v4 leaf is 0x%x", i, kept.Members[i].Leaf[:8], want[:8])
		}
	}
	if err := kept.Verify(); err != nil {
		t.Fatalf("the kept v4 tree does not re-derive itself: %v", err)
	}
}

// The backfill rebuilds a v4 chain's anchor from the hints and the signed intents with each member's v4 leaf, so it
// matches the anchor's root - computed here by hand, independently of the code that forms trees.
func TestF57BackfillReadsTheChainsLeafVersion(t *testing.T) {
	f57SetVersions(t, "84532=v4")
	f := newTreeBackfillFixture(t)
	var leaves [][32]byte
	for i, h := range f.hints.hints.Members {
		p := f.byOp[[32]byte(common.HexToHash(h.OperationID))]
		l := f57ManualV4Leaf(t, p)
		leaves = append(leaves, l)
		f.hints.hints.Members[i].Leaf = l[:]
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	bundle := contracts.DeriveV8_2BatchBundleID(84532, root, uint64(len(leaves)), f.tree.BatchOperationID, f.tree.BlockHeight,
		f.tree.AccumulateSetRoot, f.tree.Incarnation)
	f.reader.view.Anchor.MerkleRoot = root
	f.hints.bundles = []string{hex32(bundle)}
	f.b.Apply = true
	res, err := f.b.Run(context.Background())
	if err != nil || len(res) != 1 || res[0].Outcome != "kept" {
		t.Fatalf("the backfill did not rebuild the v4 anchor: %+v %v", res, err)
	}
	kept, err := f.store.Load(84532, bundle)
	if err != nil {
		t.Fatal(err)
	}
	for i := range leaves {
		if kept.Members[i].Leaf != leaves[i] {
			t.Fatalf("kept member %d holds 0x%x", i, kept.Members[i].Leaf[:8])
		}
	}
}

// ---------------------------------------------------------------- the F57 API the tests above use

func f57SetVersions(t *testing.T, spec string) { withAccountLeafVersions(t, spec) }

// f57SettlementCalldata is the calldata settleMember sends for p under tree: its account bound as the chain's generation,
// the proof it builds, through memberAccount.Settle - sent nowhere.
func f57SettlementCalldata(t *testing.T, p *PendingBatchIntent, tree *BatchTree, branch [][32]byte) []byte {
	t.Helper()
	in, err := p.LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	acct, _, err := bindMemberAccount(p.ChainID, p.Account, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := settlementProofFields(p, tree, branch, in.AuthorityBook, in.AuthorityPage, p.CommitTime.Unix()+60,
		p.CommitTime.Unix()+600)
	tx, err := acct.Settle(f57NoSend(), p.Legs, proof, in)
	if err != nil {
		t.Fatal(err)
	}
	return tx.Data()
}

func f57NoSend() *bind.TransactOpts {
	return &bind.TransactOpts{From: common.HexToAddress("0xf57"), Nonce: big.NewInt(0), GasPrice: big.NewInt(1),
		GasLimit: 2_000_000, NoSend: true,
		Signer: func(_ common.Address, tx *types.Transaction) (*types.Transaction, error) { return tx, nil }}
}
