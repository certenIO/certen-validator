// Copyright 2026 Certen Protocol

package adiri_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-F1-FIX: findings 2 (VerifyCommitteeChain re-validation), 3 (the zero Verifier) and 4 (the genesis committee words) of the completeness review V-F1-A1 on adiri/finalized/v1.
// Test keys are random per run (crypto/rand): no key material is committed.

// ---- D2: VerifyCommitteeChain is exported and re-validates what DecodeCFA1 checks ----

type f1Fix struct {
	sks  []*bls.PrivateKey
	keys [][]byte
}

func newF1Fix(t *testing.T, n int) *f1Fix {
	t.Helper()
	f := &f1Fix{}
	for i := 0; i < n; i++ {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		sk, pk, err := bls.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		f.sks = append(f.sks, sk)
		f.keys = append(f.keys, pk.Bytes())
	}
	return f
}

// chain is a one-record chain over a table of all the fixture's keys: a record whose committee and next committee are table
// committeeIdx / nextIdx, signed by the listed signer positions in the order given (a position may repeat or exceed the table: the
// signature is then over the positions that exist, which is what an attacker who holds the keys can produce).
func (f *f1Fix) chain(t *testing.T, committeeIdx, nextIdx uint8, signers []uint8) (*adiri.Params, *adiri.CFA1) {
	t.Helper()
	cf := &adiri.CFA1{Tables: [][][]byte{f.keys}, Records: []adiri.Record{{
		FinalState: adiri.NumHash{Number: 5, Hash: [32]byte{1}}, FinalConsensus: adiri.NumHash{Number: 6, Hash: [32]byte{2}}, Signers: signers,
	}}}
	digest := mustDigests(t, cf)[0]
	var sigs []*bls.Signature
	for _, s := range signers {
		sk := f.sks[0]
		if int(s) < len(f.sks) {
			sk = f.sks[s]
		}
		sigs = append(sigs, sk.Sign(adiri.SignedMessage(digest)))
	}
	agg, err := bls.AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	copy(cf.Records[0].Signature[:], agg.Bytes())
	// the indices are set after the digest is computed: RecordDigests refuses an index outside the tables
	cf.Records[0].CommitteeIdx, cf.Records[0].NextIdx = committeeIdx, nextIdx
	par := &adiri.Params{ChainID: 2017, Codec: adiri.Codec, GenesisCommittee: f.keys, Epoch0FinalState: cf.Records[0].FinalState, MinCommittee: 4, MaxHeaders: 16}
	return par, cf
}

var bothModes = []struct {
	name string
	mode adiri.Mode
}{{"one-by-one", adiri.ModeOneByOne}, {"batched", adiri.ModeBatched}}

func verifyChainNoPanic(t *testing.T, par *adiri.Params, cf *adiri.CFA1, mode adiri.Mode) (res *adiri.ChainResult, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("VerifyCommitteeChain panicked: %v", r)
			err = errors.New("panic")
		}
	}()
	return adiri.VerifyCommitteeChain(par, cf, mode, nil)
}

func TestVerifyCommitteeChainRefusesASignerListDecodeWouldRefuse(t *testing.T) {
	f := newF1Fix(t, 5)
	for _, m := range bothModes {
		t.Run(m.name, func(t *testing.T) {
			// control: strictly increasing, in range, at quorum (floor(2*5/3)+1 = 4)
			par, cf := f.chain(t, 0, 0, []uint8{0, 1, 2, 3})
			res, err := verifyChainNoPanic(t, par, cf, m.mode)
			if err != nil || res == nil || res.Signers != 4 || res.Epoch != 0 {
				t.Fatalf("control: %v %+v", err, res)
			}
			for _, c := range []struct {
				name    string
				signers []uint8
				index   int
				signer  int
			}{
				{"a repeated signer counted twice", []uint8{0, 0, 1, 1}, 1, 0},
				{"descending signers", []uint8{3, 2, 1, 0}, 1, 2},
				{"a signer index equal to the committee size", []uint8{0, 1, 2, 5}, 3, 5},
				{"a signer index far outside the committee", []uint8{0, 1, 2, 200}, 3, 200},
			} {
				par, cf := f.chain(t, 0, 0, c.signers)
				_, err := verifyChainNoPanic(t, par, cf, m.mode)
				if err == nil {
					t.Errorf("%s: accepted", c.name)
					continue
				}
				gateNamed(t, err, adiri.CodeCommitteeBroken, "epoch", 0, "check", adiri.CheckSignerIndexInvalid, "index", c.index, "signer", c.signer, "committee_size", 5)
			}
		})
	}
}

func TestVerifyCommitteeChainRefusesATableIndexOutsideTheTables(t *testing.T) {
	f := newF1Fix(t, 5)
	for _, m := range bothModes {
		t.Run(m.name, func(t *testing.T) {
			for _, c := range []struct {
				name           string
				committee, nxt uint8
				got            int
			}{
				{"committee index past the tables", 1, 0, 1},
				{"next index past the tables on the last record", 0, 1, 1},
				{"both indices far past the tables", 200, 7, 200},
			} {
				par, cf := f.chain(t, c.committee, c.nxt, []uint8{0, 1, 2, 3})
				_, err := verifyChainNoPanic(t, par, cf, m.mode)
				if err == nil {
					t.Errorf("%s: accepted", c.name)
					continue
				}
				gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.record", "index", 0, "reason", finality.ReasonCFA1TableIndexOutOfRange, "got_len", c.got, "want_len", 1)
			}
		})
	}
}

// ---- D3: the zero Verifier is the batched verifier its documentation says ----

type f1NoRandomness struct{}

func (f1NoRandomness) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

func TestAZeroVerifierVerifiesBatchedAsItsDocumentationSays(t *testing.T) {
	var zero adiri.Verifier
	if zero.Mode != adiri.ModeBatched {
		t.Fatalf("the zero Verifier has mode %d, ModeBatched is %d", zero.Mode, adiri.ModeBatched)
	}
	if got := adiri.NewVerifier().Mode; got != adiri.ModeBatched {
		t.Fatalf("NewVerifier has mode %d", got)
	}
	_, _, _, leg, pins := liveParts(t, "syn-rotation")
	ev := mustEvidence(t, "syn-rotation")
	// batched mode draws its scalars from Rand; one-by-one never reads it
	if _, err := (&adiri.Verifier{Mode: adiri.ModeOneByOne, Rand: f1NoRandomness{}}).Verify(pins, leg, ev); err != nil {
		t.Fatalf("one-by-one reads no randomness: %v", err)
	}
	_, err := (&adiri.Verifier{Rand: f1NoRandomness{}}).Verify(pins, leg, ev)
	gateNamed(t, err, finality.CodeRandomnessUnavailable, "kind", adiri.Name)
	if st, ok := finality.AsNamed(err); !ok || !finality.IsEnvironment(st) {
		t.Fatalf("a randomness failure is a fact about the process (environment), not a verdict: %v", err)
	}
	if _, err := (&adiri.Verifier{}).Verify(pins, leg, ev); err != nil {
		t.Fatalf("the zero Verifier with crypto/rand: %v", err)
	}
}

// ---- D4: spec 4.4 / A7 step 2, the committee words are in the genesis ConsensusRegistry storage ----

// testdata/pins/tn_genesis.json is the node's tn_genesis (served by every public endpoint). The separate module
// pinsderive/genesis recomputes this very file to the pinned genesis_hash (TestTNGenesisRecomputesToThePinnedHash; it is its own
// module and is not run by go test ./pkg/finality/adiri/...); the digest below ties this test to those bytes.
const (
	tnGenesisSHA256   = "8b2b2c3b8a82178ca72b560c68bb5a512bc23f7afcf67dafa0dedfbddddf9bb6"
	consensusRegistry = "0x07e17e17e17e17e17e17e17e17e17e17e17e17e1"
)

func TestEveryPinnedCommitteeKeyWordIsInTheGenesisConsensusRegistryStorage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "pins", "tn_genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != tnGenesisSHA256 {
		t.Fatalf("tn_genesis.json hashes to %s, this test is bound to %s", got, tnGenesisSHA256)
	}
	var g struct {
		Alloc map[string]struct {
			Storage map[string]string `json:"storage"`
		} `json:"alloc"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	words := map[string]bool{}
	slots := 0
	for addr, a := range g.Alloc {
		if strings.EqualFold(strings.TrimPrefix(addr, "0x"), strings.TrimPrefix(consensusRegistry, "0x")) {
			for _, v := range a.Storage {
				words[strings.ToLower(strings.TrimPrefix(v, "0x"))] = true
			}
			slots += len(a.Storage)
		}
	}
	if slots != 115 {
		t.Fatalf("ConsensusRegistry %s holds %d genesis storage slots, annex A7 records 115", consensusRegistry, slots)
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	par, err := adiri.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	if len(par.GenesisCommittee) != 5 {
		t.Fatalf("%d pinned genesis keys", len(par.GenesisCommittee))
	}
	found := 0
	for i, k := range par.GenesisCommittee {
		for w := 0; w < adiri.KeyBytes/32; w++ {
			word := hex.EncodeToString(k[32*w : 32*w+32])
			if flipped := append([]byte(nil), k[32*w:32*w+32]...); words[hex.EncodeToString(append(flipped[:31], flipped[31]^1))] {
				t.Errorf("key %d word %d: a word one bit away is also a storage value, the membership test proves nothing", i, w)
			}
			if !words[word] {
				t.Errorf("key %d word %d (%s) is not a value in the genesis ConsensusRegistry storage", i, w, word)
				continue
			}
			found++
		}
	}
	if found != 15 {
		t.Fatalf("%d of 15 committee words found in the genesis ConsensusRegistry storage", found)
	}
}
