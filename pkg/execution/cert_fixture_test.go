package execution

import (
	"sync"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/consensus"
)

// Every V8.2 tree member is a quorum-certified intent whose leaf binds the certified key page (RB5 D3, RB5-F29). The
// fixtures below give the tests' members that standing: a certificate per operation, at the member's own commit height
// (so the tests' period placement is unchanged), over a fixed per-operation message, certifying page 1 of the member's
// own ADI book.

// testCertRecord answers the certificate of every member certifiedForTest registered.
type testCertRecord struct {
	mu   sync.Mutex
	byOp map[[32]byte]*PendingBatchIntent
}

var testCerts = &testCertRecord{byOp: map[[32]byte]*PendingBatchIntent{}}

// testIntentMessage is the message a test operation's certificate certifies.
func testIntentMessage(op [32]byte) (msg [32]byte) {
	copy(msg[:], ethcrypto.Keccak256([]byte("certen:test:intent"), op[:]))
	return msg
}

// testKeyPage and testKeyBook are what a test member's certificate certifies: page 1 of its own ADI's book.
func testKeyPage(adiURL string) string { return testKeyBook(adiURL) + "/1" }
func testKeyBook(adiURL string) string { return govvote.CanonicalAccSpelling(adiURL) + "/book" }

func (r *testCertRecord) IntentCertified(op [32]byte) (consensus.CertifiedIntent, bool) {
	r.mu.Lock()
	p, ok := r.byOp[op]
	r.mu.Unlock()
	if !ok || p.CommitHeight == 0 {
		return consensus.CertifiedIntent{}, false
	}
	return consensus.CertifiedIntent{Height: p.CommitHeight, Message: testIntentMessage(op), KeyPageURL: testKeyPage(p.ADIURL),
		KeyBookURL: testKeyBook(p.ADIURL)}, true
}

// certifiedForTest makes p a certified member and registers its certificate.
func certifiedForTest(p *PendingBatchIntent) *PendingBatchIntent {
	p.IntentMessage = testIntentMessage(p.OperationID)
	p.CertifiedMessage = p.IntentMessage
	p.CertifiedKeyPage = testKeyPage(p.ADIURL)
	p.CertifiedKeyBook = testKeyBook(p.ADIURL)
	testCerts.mu.Lock()
	testCerts.byOp[p.OperationID] = p
	testCerts.mu.Unlock()
	return p
}

// newTestMempool is NewBatchMempool reading the test certificate record.
func newTestMempool(cfg BatchMempoolConfig) *BatchMempool {
	m := NewBatchMempool(cfg)
	m.SetIntentCertificates(testCerts)
	return m
}
