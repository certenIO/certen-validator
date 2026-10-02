package execution

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

func fill32(b byte) (out [32]byte) {
	for i := range out {
		out[i] = b
	}
	return
}

// Pinned against an independent computation (Python, pycryptodome keccak), with the members given out of order.
func TestTheV3BatchOperationIDIsPinned(t *testing.T) {
	inputs := []BatchLeafInput{
		{ADIURL: "b", OperationID: fill32(4), GovernanceCommitment: fill32(5), IntentMessage: fill32(6)},
		{ADIURL: "a", OperationID: fill32(1), GovernanceCommitment: fill32(2), IntentMessage: fill32(3)},
	}
	id, version, err := batchOperationIDOf(inputs)
	if err != nil || version != BatchOperationIDV3 {
		t.Fatalf("(%s, %v)", version, err)
	}
	if want := "170e376fce2533a40cdb9b61bfcc1d9f558dbf43fe94474b57d01a68703d94b2"; hex.EncodeToString(id[:]) != want {
		t.Fatalf("v3 id %x, want %s", id, want)
	}
	// Every member's message is bound.
	inputs[1].IntentMessage = fill32(7)
	if other, _, _ := batchOperationIDOf(inputs); other == id {
		t.Fatal("a member's certified message is not bound")
	}
}

func TestAV3BatchRefusesWhatItCannotCommit(t *testing.T) {
	v3 := BatchLeafInput{ADIURL: "a", OperationID: fill32(1), GovernanceCommitment: fill32(2), IntentMessage: fill32(3)}
	v2 := BatchLeafInput{ADIURL: "b", OperationID: fill32(4), GovernanceCommitment: fill32(5)}
	if _, _, err := batchOperationIDOf([]BatchLeafInput{v3, v2}); err == nil {
		t.Fatal("a batch mixing certified and uncertified members was formed")
	}
	noGov := v3
	noGov.GovernanceCommitment = [32]byte{}
	if _, err := DeriveBatchOperationIDV3([]BatchLeafInput{noGov}); err == nil {
		t.Fatal("a v3 member without a governance commitment was committed")
	}
	noMsg := v3
	noMsg.IntentMessage = [32]byte{}
	if _, err := DeriveBatchOperationIDV3([]BatchLeafInput{noMsg}); err == nil {
		t.Fatal("a v3 member without a certified message was committed")
	}
	if _, version, err := batchOperationIDOf([]BatchLeafInput{v2}); err != nil || version != BatchOperationIDV2 {
		t.Fatalf("an uncertified member formed (%s, %v)", version, err)
	}
}

// fakeCert is one intent certificate: its height, the message certified and the key page it certifies.
type fakeCert struct {
	height uint64
	msg    [32]byte
	page   string
	book   string
}

// fakeCerts is a record of intent certificates keyed by operation.
type fakeCerts map[[32]byte]fakeCert

func (f fakeCerts) IntentCertified(op [32]byte) (consensus.CertifiedIntent, bool) {
	c, ok := f[op]
	return consensus.CertifiedIntent{Height: c.height, Message: c.msg, KeyPageURL: c.page, KeyBookURL: c.book}, ok
}

func certifiedMember(id string, op byte, own [32]byte) *PendingBatchIntent {
	return &PendingBatchIntent{AccumulateSetRoot: testAccSet, GovernanceCommitment: testGov, IntentMessage: own,
		IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: 11155111,
		Account:     common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
		OperationID: fill32(op),
		Legs:        []LegExecution{{LegID: "l0", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
		// A commit height that would place it in period 0 - it must be placed by its certificate instead.
		CommitHeight: 5,
	}
}

// A member with a certified intent waits for its certificate, is then placed by the certificate's height - the same
// on every validator - and commits the CERTIFIED message, even when this validator's own block signed another.
func TestACertifiedMemberIsPlacedByItsCertificate(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	own := fill32(0xaa)
	if err := m.Add(certifiedMember("x", 9, own)); !errors.Is(err, consensus.ErrBatchUnavailable) {
		t.Fatalf("a certified member admitted with no certificate record: %v", err)
	}
	certs := fakeCerts{}
	m.SetIntentCertificates(certs)
	p := certifiedMember("x", 9, own)
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}
	if got := m.PeriodMembers(11155111, 0, 100); len(got) != 0 {
		t.Fatal("an uncertified member was placed by its commit height")
	}
	if got := m.UncertifiedPending(11155111); len(got) != 1 {
		t.Fatalf("waiting members: %d", len(got))
	}
	if err := m.RequireCertified(p); !errors.Is(err, ErrIntentNotYetCertified) {
		t.Fatalf("one-member lanes: %v", err)
	}

	certified := fill32(0xbb) // the quorum certified another message than this validator signed
	certs[fill32(9)] = fakeCert{height: 250, msg: certified, page: "acc://x.acme/book/1", book: "acc://x.acme/book"}
	if got := m.PeriodMembers(11155111, 0, 100); len(got) != 0 {
		t.Fatal("placed in the period of its commit height")
	}
	got := m.PeriodMembers(11155111, 200, 100)
	if len(got) != 1 {
		t.Fatal("not placed in the period of its certificate's height")
	}
	in, err := got[0].LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	if in.IntentMessage != certified {
		t.Fatalf("the leaf commits %x, the certified message is %x", in.IntentMessage[:4], certified[:4])
	}
	if len(m.UncertifiedPending(11155111)) != 0 || m.RequireCertified(p) != nil {
		t.Fatal("a certified member still counted as waiting")
	}
}

// Members are cut apart by operation id class, so a tree never mixes certified and uncertified members.
func TestCertifiedAndUncertifiedMembersAreNeverOneTree(t *testing.T) {
	a := certifiedMember("a", 1, fill32(1))
	b := certifiedMember("b", 2, [32]byte{})
	c := certifiedMember("c", 3, fill32(3))
	groups := groupByAccumulateSet([]*PendingBatchIntent{a, b, c})
	if len(groups) != 2 || len(groups[0]) != 2 || groups[0][0] != a || groups[0][1] != c || groups[1][0] != b {
		t.Fatalf("groups: %v", groups)
	}
}

// The persisted queue keeps a member's own intent message across a restart, and a restored certified member is
// placed by its certificate.
func TestTheQueueKeepsTheIntentMessage(t *testing.T) {
	path := t.TempDir() + "/mempool.json"
	certs := fakeCerts{fill32(9): {height: 250, msg: fill32(0xbb), page: "acc://x.acme/book/1", book: "acc://x.acme/book"}}
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	m.SetIntentCertificates(certs)
	st, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetStore(st, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(certifiedMember("x", 9, fill32(0xaa))); err != nil {
		t.Fatal(err)
	}

	again := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	again.SetIntentCertificates(certs)
	st2, err := NewBatchMempoolStore(path, jsonCodec{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.SetStore(st2, nil); err != nil {
		t.Fatal(err)
	}
	got := again.PeriodMembers(11155111, 200, 100)
	if len(got) != 1 || got[0].IntentMessage != fill32(0xaa) {
		t.Fatalf("restored: %+v", got)
	}
	if in, _ := got[0].LeafInput(); in.IntentMessage != fill32(0xbb) {
		t.Fatal("a restored member does not commit the certified message")
	}
}

// Layer 5 re-derives a v3 batch operation id from its members and binds this proof's certified message.
func TestLayer5VerifiesAV3Batch(t *testing.T) {
	h := func(b byte) string { return "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), 32) }
	members := []database.BatchMemberGovernance{
		{OperationID: h(1), GovernanceCommitment: h(2), CertifiedIntentMessage: h(3)},
		{OperationID: h(4), GovernanceCommitment: h(5), CertifiedIntentMessage: h(6)},
	}
	g := func() *BatchGovernance {
		return &BatchGovernance{Version: BatchOperationIDV3,
			BatchOperationID: "0x170e376fce2533a40cdb9b61bfcc1d9f558dbf43fe94474b57d01a68703d94b2",
			OperationID:      h(1), GovernanceCommitment: h(2), CertifiedIntentMessage: h(3),
			Members: append([]database.BatchMemberGovernance(nil), members...)}
	}
	if err := g().Verify(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(x *BatchGovernance){
		"another certified message for this member": func(x *BatchGovernance) { x.CertifiedIntentMessage = h(9) },
		"a member's message changed":                func(x *BatchGovernance) { x.Members[1].CertifiedIntentMessage = h(9) },
		"a member without a message":                func(x *BatchGovernance) { x.Members[1].CertifiedIntentMessage = "" },
		"stated as v2":                              func(x *BatchGovernance) { x.Version = BatchOperationIDV2 },
		"this member without a message":             func(x *BatchGovernance) { x.CertifiedIntentMessage = "" },
	} {
		x := g()
		mut(x)
		if err := x.Verify(); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// A peer names an intent-certificate disagreement, member and both messages, instead of an anonymous mismatch.
func TestAPeerNamesAnIntentCertificateDisagreement(t *testing.T) {
	op := fill32(1)
	theirs := []MemberGovernance{{OperationID: "0x" + hex.EncodeToString(op[:]),
		CertifiedIntentMessage: "0x" + strings.Repeat("aa", 32)}}
	if why := intentCertificateDisagreement(theirs, map[[32]byte][32]byte{op: fill32(0xaa)}); why != "" {
		t.Fatalf("agreement named as a disagreement: %s", why)
	}
	if why := intentCertificateDisagreement(theirs, map[[32]byte][32]byte{op: fill32(0xbb)}); !strings.Contains(why, "aaaaaaaa") ||
		!strings.Contains(why, "bbbbbbbb") {
		t.Fatalf("disagreement: %q", why)
	}
}
