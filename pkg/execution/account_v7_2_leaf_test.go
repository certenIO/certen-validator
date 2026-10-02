package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F29/F30: the V8.2 rollout's factory V10 creates CertenAccountV7_2 accounts, whose leaf binds the key book and page
// that authorized the intent. Every tree leaf is that v3 leaf, over the book and page CERTEN's quorum certified - never
// the v1 leaf a CertenAccountV7 verifies, which no V7_2 account holds.
func TestAV8_2TreeBindsTheCertifiedAuthority(t *testing.T) {
	p := certifiedForTest(pending("f29", "acc://F29.acme", 84532, common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"), 29,
		LegExecution{LegID: "l0", ChainID: 84532, Target: tgt(1), Value: big.NewInt(1)}))
	p.CertifiedKeyPage, p.CertifiedKeyBook = "acc://f29.acme/book/3", "acc://f29.acme/book" // spelling differs only in case
	in, err := p.LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	book := contracts.HashURLString("acc://f29.acme/book")
	if in.AuthorityPage != 3 || in.AuthorityBook != book {
		t.Fatalf("the leaf input binds (%x, %d), want the certified (book, 3)", in.AuthorityBook, in.AuthorityPage)
	}
	tree, err := BuildBatchTree(84532, []BatchLeafInput{in}, 100, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	want := ComputeBatchLeafV3(84532, in)
	if tree.Leaves[0] != want {
		t.Fatalf("the tree's leaf is %x, want the V7_2 account's v3 leaf %x", tree.Leaves[0], want)
	}
	if tree.Leaves[0] == ComputeBatchLeaf(84532, in) || tree.Leaves[0] == ComputeBatchLeafV2(84532, in, 3) {
		t.Fatal("the tree holds a v1 or v2 leaf, which a CertenAccountV7_2 never holds")
	}
	if leaf, err := p.Leaf(); err != nil || leaf != want {
		t.Fatalf("the member's own leaf is %x (%v), not its tree leaf", leaf, err)
	}

	// A page of another identity's book is named as that book's page - the account gives it no authority unless its
	// governance granted it (the account screen asks) - and binds another leaf.
	foreign := *p
	foreign.CertifiedKeyPage, foreign.CertifiedKeyBook = "acc://someone-else.acme/book/1", "acc://someone-else.acme/book"
	fin, err := foreign.LeafInput()
	if err != nil || fin.AuthorityBook != contracts.HashURLString("acc://someone-else.acme/book") || ComputeBatchLeafV3(84532, fin) == want {
		t.Fatalf("a page of another book: (%x, %v)", fin.AuthorityBook, err)
	}
	// The certified page must be a page OF the certified book.
	stray := *p
	stray.CertifiedKeyPage = "acc://f29.acme/ops/1"
	if _, err := stray.LeafInput(); err == nil || !strings.Contains(err.Error(), "is not a page of key book") {
		t.Fatalf("a page outside its certified book was bound: %v", err)
	}
	uncertified := *p
	uncertified.IntentMessage, uncertified.CertifiedMessage, uncertified.CertifiedKeyPage, uncertified.CertifiedKeyBook =
		[32]byte{}, [32]byte{}, "", ""
	if _, err := uncertified.LeafInput(); !errors.Is(err, ErrNoCertifiedAuthorityPage) {
		t.Fatalf("a leaf was formed for an intent CERTEN's quorum never certified: %v", err)
	}
	if _, err := BuildBatchTree(84532, []BatchLeafInput{{ADIURL: in.ADIURL, ExecutionCommitment: in.ExecutionCommitment,
		OperationID: in.OperationID, GovernanceCommitment: testGov, AccumulateSetRoot: testAccSet, AuthorityPage: 3}}, 100,
		testIncarnation); err == nil {
		t.Fatal("a tree was formed for a member with no authority book")
	}
}

// The settlement call carries the certified book and page in the proof's last fields - what the account checks the leaf
// against and derives each leg's level from - and no declared level.
func TestTheSettlementCallCarriesTheCertifiedPage(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(contracts.CertenAccountV7_2ABI))
	if err != nil {
		t.Fatal(err)
	}
	proof := contracts.AccountProofV7_2{AdiURL: "acc://f29.acme", AnchorId: fill32(1), MerkleProof: [][32]byte{fill32(2)},
		OperationID: fill32(3), Timestamp: big.NewInt(10), ExpiresAt: big.NewInt(20), Nonce: big.NewInt(0),
		AuthorityBook: fill32(0x0b), AuthorityPage: 3}
	data, err := parsed.Pack("executeGovernanceProofDirect", tgt(1), big.NewInt(1), []byte{0xde}, proof)
	if err != nil {
		t.Fatal(err)
	}
	args, err := parsed.Methods["executeGovernanceProofDirect"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatal(err)
	}
	got := abi.ConvertType(args[3], new(contracts.AccountProofV7_2)).(*contracts.AccountProofV7_2)
	if got.AuthorityPage != 3 || got.AuthorityBook != fill32(0x0b) || got.OperationID != fill32(3) || got.AnchorId != fill32(1) {
		t.Fatalf("decoded proof %+v", got)
	}
}

// accountNode is a chain serving one account: its code and its LEAF_DOMAIN / isKeylessOwner / adiURLHash /
// authorityLevelOfPage answers.
type accountNode struct {
	domain  string
	adiHash [32]byte
	level   uint8
}

func (n *accountNode) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(contracts.CertenAccountV7_2ABI))
	if err != nil {
		t.Fatal(err)
	}
	strT, _ := abi.NewType("string", "", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(result string) { _, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result) }
		switch req.Method {
		case "eth_getCode":
			reply(`"0x6080"`)
		case "eth_call":
			var call struct {
				Data  string `json:"data"`
				Input string `json:"input"`
			}
			_ = json.Unmarshal(req.Params[0], &call)
			in := call.Input
			if in == "" {
				in = call.Data
			}
			sel := common.FromHex(in)[:4]
			switch {
			case string(sel) == string(parsed.Methods["LEAF_DOMAIN"].ID):
				out, _ := abi.Arguments{{Type: strT}}.Pack(n.domain)
				reply(`"0x` + hex.EncodeToString(out) + `"`)
			case string(sel) == string(parsed.Methods["isKeylessOwner"].ID):
				reply(`"0x` + fmt.Sprintf("%064x", 1) + `"`)
			case string(sel) == string(parsed.Methods["adiURLHash"].ID):
				reply(`"0x` + hex.EncodeToString(n.adiHash[:]) + `"`)
			case string(sel) == string(parsed.Methods["authorityLevelOfPage"].ID):
				reply(`"0x` + fmt.Sprintf("%064x", n.level) + `"`)
			default:
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":3,"message":"execution reverted"}}`, req.ID)
			}
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"not stubbed: %s"}}`, req.ID, req.Method)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A V8.2 tree holds v3 leaves only: an account of an earlier generation (CertenAccountV7, v1 leaf, self-declared level)
// is refused by name; a CertenAccountV7_2 for the member's ADI passes only when it gives the certified (book, page) some
// authority (RB5-F30) - one that gives it none could execute nothing.
func TestTheAccountScreenTakesOnlyACertenAccountV7_2(t *testing.T) {
	p := certifiedForTest(pending("f29s", "acc://f29s.acme", 84532, common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"), 291,
		LegExecution{LegID: "l0", ChainID: 84532, Target: tgt(1), Value: big.NewInt(1)}))
	adiHash := crypto.Keccak256Hash([]byte(p.ADIURL))
	screen := func(domain string, level uint8) error {
		node := &accountNode{domain: domain, adiHash: adiHash, level: level}
		o := &BatchOrchestrator{ecm: &EthereumContractManager{client: node.serve(t)}, logf: t.Logf}
		return o.memberAccountUsable(context.Background(), p)
	}
	if err := screen(contracts.LeafDomainV7_2, 3); err != nil {
		t.Fatalf("a CertenAccountV7_2 for the member's ADI, its page ROOT, was refused: %v", err)
	}
	err := screen("certen:batchleaf:v1", 3)
	if err == nil || !strings.Contains(err.Error(), "not a CertenAccountV7_2") {
		t.Fatalf("a CertenAccountV7 was taken into a V8.2 tree: %v", err)
	}
	if IsChainReadError(err) {
		t.Fatal("the account's generation is a verdict, not a read to retry")
	}
	if err := screen("certen:batchleaf:v2", 3); err == nil {
		t.Fatal("an account of the never-deployed v2 leaf was taken into a V8.2 tree")
	}
	err = screen(contracts.LeafDomainV7_2, 0)
	if err == nil || !strings.Contains(err.Error(), "no authority") || IsChainReadError(err) {
		t.Fatalf("a member whose certified (book, page) the account gives no authority passed the screen: %v", err)
	}
	uncertified := *p
	uncertified.IntentMessage, uncertified.CertifiedMessage, uncertified.CertifiedKeyPage, uncertified.CertifiedKeyBook =
		[32]byte{}, [32]byte{}, "", ""
	o := &BatchOrchestrator{logf: t.Logf}
	if err := o.memberAccountUsable(context.Background(), &uncertified); !errors.Is(err, ErrNoCertifiedAuthorityPage) {
		t.Fatalf("an uncertified member passed the screen before any read: %v", err)
	}
}
