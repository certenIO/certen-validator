// Command g1fixture captures, from the live network, everything an app-level test of a cross-partition intent needs and no stored
// proof holds (RB9-J2-F1): for one transaction, the L1-L4 chained proof, G0-G2, the G1 vote record with its evidence - each built by
// the production code path, not reconstructed - and the evidence 2.1 document built from the validators' own capture of the same
// transaction, with the Directory major records it builds on. The file has the shape cmd/prooffixture writes for a stored proof, so
// the consensus tests read it the same way. It reads only.
//
// A cross-partition intent is not certified before the rules v15 activation (g1_evidence_21_not_in_force), so no proof of it is ever
// stored: the production prover is driven here exactly as the BFT stage drives it (pkg/consensus bft_integration.go: the chained proof,
// the signing key page resolved from the transaction's signatures, G0 bound to the chained proof, G1, G2, and the decision record
// derived from G1 and again from G2), and anything that stage would refuse is refused here by the same name.
//
//	g1fixture -account acc://pv2-cust-508.acme/data -tx <hex> -keybook acc://pv2-cust-508.acme/book -keypage acc://pv2-cust-508.acme/book/1 \
//	    -capture capture.json -govproof ./bin/govproof -txhash ./bin/txhash -incarnation-evidence kermit.json -archive archive.json.gz -out dir -name x2y3
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// Fixture is the file this command writes: the shape of cmd/prooffixture's, plus the 2.1 report and where it came from.
type Fixture struct {
	Format        string                      `json:"format"`
	Name          string                      `json:"name"`
	ProofID       string                      `json:"proof_id"` // empty: no proof of this intent is stored (it was never certified)
	Account       string                      `json:"account"`
	TxHash        string                      `json:"tx_hash"`
	KeyBook       string                      `json:"key_book"`
	KeyPage       string                      `json:"key_page"` // the page the intent's signatures resolve to (ResolveSigningKeyPage)
	BuiltAt       string                      `json:"built_at"`
	ChainedProof  *chained_proof.ChainedProof `json:"chained_proof"`
	G0            json.RawMessage             `json:"g0"`
	G1            json.RawMessage             `json:"g1"`
	G2            json.RawMessage             `json:"g2"`
	Authorization json.RawMessage             `json:"authorization"`
	VoteEvidence  json.RawMessage             `json:"vote_evidence"`
	ProofV2       json.RawMessage             `json:"proof_v2"`
	Archive       json.RawMessage             `json:"archive,omitempty"` // the Directory major records the document builds on; empty with -shared-archive (they are in <out>/archive.json.gz)
	Report        json.RawMessage             `json:"report"`
}

const formatID = "certen-g1fixture/1"

func main() {
	var (
		endpoint = flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
		account  = flag.String("account", "", "the transaction's principal")
		tx       = flag.String("tx", "", "transaction hash, hex")
		book     = flag.String("keybook", "", "the key book the intent declares")
		page     = flag.String("keypage", "", "the key page the intent declares")
		capPath  = flag.String("capture", "", "the validators' stored capture of the intent (JSON, optionally gzip); empty: capture now (inside the node's retention)")
		govproof = flag.String("govproof", "govproof", "the governance proof CLI (the validators' /app/govproof)")
		txhash   = flag.String("txhash", "", "the txhash CLI (the validators' /app/txhash), for G2")
		incPath  = flag.String("incarnation-evidence", "pkg/proof/testdata/incarnation/kermit.json", "incarnation evidence JSON")
		pin      = flag.String("pin", "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0", "pinned incarnation, hex32")
		archive  = flag.String("archive", "pkg/proof/v2/testdata/archive.json.gz", "major records already walked (gzip JSON); extended from the network")
		out      = flag.String("out", "", "directory to write <name>.json.gz and <name>.capture.json.gz into")
		name     = flag.String("name", "", "fixture name")
		shared   = flag.Bool("shared-archive", false, "write the major records once to <out>/archive.json.gz instead of into every fixture")
	)
	flag.Parse()
	if *account == "" || *tx == "" || *name == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "g1fixture: -account, -tx, -name and -out are required")
		os.Exit(2)
	}
	if err := run(*endpoint, *account, *tx, *book, *page, *capPath, *govproof, *txhash, *incPath, *pin, *archive, *out, *name, *shared); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func logf(f string, a ...any) { fmt.Printf(f+"\n", a...) }

func run(endpoint, account, tx, book, page, capPath, govproofPath, txhashPath, incPath, pinHex, archivePath, out, name string, shared bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	q := proof.NewHTTPQuerier(endpoint)

	raw, err := os.ReadFile(incPath)
	if err != nil {
		return err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		return fmt.Errorf("incarnation evidence: %w", err)
	}
	incRep, err := inc.Verify()
	if err != nil {
		return fmt.Errorf("incarnation evidence does not verify: %w", err)
	}
	var pinned [32]byte
	if b, err := hex.DecodeString(pinHex); err != nil || len(b) != 32 {
		return errors.New("-pin must be 32 bytes of hex")
	} else {
		copy(pinned[:], b)
	}

	// 1. The L1-L4 chained proof, as the validators' discovery builds it.
	router, err := proof.LoadNetworkRouter(ctx, endpoint)
	if err != nil {
		return err
	}
	partition, err := router.Partition(account)
	if err != nil {
		return err
	}
	gen, err := proof.NewLiteClientProofGenerator(endpoint, 10*time.Minute)
	if err != nil {
		return err
	}
	chained, err := gen.GenerateChainedProof(ctx, account, tx, partition)
	if err != nil {
		return fmt.Errorf("L1-L4 chained proof: %w", err)
	}
	if err := chained_proof.NewProofVerifier(false).Verify(ctx, chained); err != nil {
		return fmt.Errorf("the chained proof does not verify offline: %w", err)
	}
	logf("L1-L4 chained proof built and verified: %d leg(s) %v", len(chained.Legs()), chained.SignerPartitions())
	complete := proof.ChainedProofToCompleteProof(chained)

	// 2. The key page, exactly as the intent certificate resolves it, then G0, G1, G2 through the production CLI generator.
	resolver, err := proof.NewChainKeyPageResolver(endpoint, logf)
	if err != nil {
		return err
	}
	keyPage, err := resolver.ResolveSigningKeyPage(ctx, account, tx, book, page)
	if err != nil {
		return fmt.Errorf("the signing key page: %w", err)
	}
	logf("the transaction's signatures resolve to key page %s (declared %q)", keyPage, page)
	work, err := os.MkdirTemp("", "g1fixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	gg, err := proof.NewCLIGovernanceProofGenerator(govproofPath, endpoint, work, 10*time.Minute)
	if err != nil {
		return err
	}
	if txhashPath != "" {
		gg.SetTxHashPath(txhashPath)
	}
	req := &proof.GovernanceRequest{AccountURL: account, TransactionHash: tx, KeyPage: keyPage, Chain: "main"}
	w0, err := gg.GenerateG0(ctx, req)
	if err != nil || w0 == nil || w0.G0 == nil || !w0.G0.G0ProofComplete {
		return fmt.Errorf("G0: %v", err)
	}
	if err := proof.BindG0ToChainedProof(w0.G0, complete); err != nil {
		return fmt.Errorf("G0 does not bind to the chained proof: %w", err)
	}
	w1, err := gg.GenerateG1(ctx, req)
	if err != nil || w1 == nil || w1.G1 == nil {
		return fmt.Errorf("G1: %v", err)
	}
	if !w1.G1.G1ProofComplete || !w1.G1.ThresholdSatisfied {
		return fmt.Errorf("G1 incomplete: complete=%v thresholdSatisfied=%v uniqueKeys=%d", w1.G1.G1ProofComplete, w1.G1.ThresholdSatisfied, w1.G1.UniqueValidKeys)
	}
	w2, err := gg.GenerateG2(ctx, req)
	if err != nil || w2 == nil || w2.G2 == nil || !w2.G2.G2ProofComplete {
		return fmt.Errorf("G2: %v", err)
	}
	if w1.Authorization == nil || w1.VoteEvidence == nil || w2.Authorization == nil {
		return errors.New("G1/G2 carry no vote record or no evidence for it")
	}
	if err := proof.VerifyVoteEvidence(ctx, w0.G0, w1.VoteEvidence, w1.Authorization); err != nil {
		return fmt.Errorf("the G1 vote record does not evaluate again from its evidence: %w", err)
	}
	d1, err := proof.GovernanceDecisionRecord(w0.G0, w1.Authorization)
	if err != nil {
		return err
	}
	d2, err := proof.GovernanceDecisionRecord(w0.G0, w2.Authorization)
	if err != nil {
		return err
	}
	if !bytes.Equal(d1, d2) {
		return errors.New("G1 and G2 recorded different decisions")
	}
	commit := proof.GovernanceCommitment(d1)
	logf("G0-G2 built, G0 bound to the chained proof, decision %x re-derived from G1 and G2", commit[:8])

	// 3. The evidence 2.1 document, from the validators' capture of the same transaction.
	var cp *proofv2shadow.Capture
	if capPath != "" {
		rawCap, err := readMaybeGz(capPath)
		if err != nil {
			return err
		}
		if cp, err = proofv2shadow.DecodeCapture(rawCap); err != nil {
			return fmt.Errorf("the stored capture: %w", err)
		}
	} else {
		probe := &proofv2.Builder{C: c, Q: q}
		col, err := proofv2shadow.NewCollector(ctx, endpoint, c, probe, logf, book, page)
		if err != nil {
			return err
		}
		if cp, err = col.Collect(ctx, account, tx); cp == nil || err != nil {
			return fmt.Errorf("capture: %v", err)
		}
	}
	logf("capture: principal %s on %s, block %d, %d pages on %d partitions", cp.Principal, cp.Partition, cp.Block, len(cp.Pages), len(cp.Partitions))
	ar, err := readArchive(archivePath)
	if err != nil {
		return err
	}
	b, err := proofv2.NewBuilderFromArchive(c, q, inc, pinned, ar)
	if err != nil {
		return err
	}
	if err := b.Refresh(ctx); err != nil {
		return err
	}
	asm, err := cp.Assembly(ctx, proofv2.NetLog{Net: c}, proofv2.NetChains{Net: c})
	if err != nil {
		return fmt.Errorf("assembly: %w", err)
	}
	var ev *proofv2.Evidence
	var rep *proofv2.Report
	for {
		ev, rep, err = b.Build21(ctx, 0, account, tx, strings.ToLower(partition), asm)
		if !errors.Is(err, proofv2.ErrNotYetCertified) && !(err != nil && strings.Contains(err.Error(), "quorum not met: 0 of")) {
			break
		}
		logf("waiting for the Directory to certify the block ...")
		time.Sleep(15 * time.Second)
		if err := b.Refresh(ctx); err != nil {
			return err
		}
	}
	if err != nil {
		return fmt.Errorf("evidence 2.1: %w", err)
	}
	// verified again from genesis, exactly as an offline verifier does
	if _, err := proofv2.Verify21FromGenesis(ev, b.Archive(), incRep.Inputs, incRep.Incarnation); err != nil {
		return fmt.Errorf("the built evidence 2.1 does not verify from genesis: %w", err)
	}
	logf("evidence 2.1 verified: certified DN %d (%s); %s anchor block %d; %d pages proven; mode %q; %d unproven; %d disclosures",
		rep.CertifiedBlock, rep.SetVerdict, rep.Partition, rep.AnchorBlock, len(rep.Proven), rep.AuthorizationMode, len(rep.Unproven), len(rep.Disclosures))
	for _, p := range rep.Proven {
		logf("  proven %s  %s block %d roles %v declared %v", p.URL, p.Partition, p.Block, p.Roles, p.Declared)
	}
	for _, u := range rep.Unproven {
		logf("  UNPROVEN: %s", u.Error())
	}
	for _, d := range rep.Disclosures {
		logf("  disclosure: %v", d)
	}

	f := &Fixture{Format: formatID, Name: name, Account: account, TxHash: tx, KeyBook: book, KeyPage: keyPage,
		BuiltAt: time.Now().UTC().Format(time.RFC3339), ChainedProof: chained}
	for _, e := range []struct {
		dst *json.RawMessage
		v   any
	}{{&f.G0, w0.G0}, {&f.G1, w1.G1}, {&f.G2, w2.G2}, {&f.Authorization, w1.Authorization}, {&f.VoteEvidence, w1.VoteEvidence}, {&f.ProofV2, ev}, {&f.Report, rep}} {
		if *e.dst, err = json.Marshal(e.v); err != nil {
			return err
		}
	}
	arJSON, err := proofv2.MarshalArchive(b.Archive())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if shared {
		if err := writeGzRaw(filepath.Join(out, "archive.json.gz"), arJSON); err != nil {
			return err
		}
	} else {
		f.Archive = arJSON
	}
	if err := writeGz(filepath.Join(out, name+".json.gz"), f); err != nil {
		return err
	}
	if err := writeGz(filepath.Join(out, name+".capture.json.gz"), cp); err != nil {
		return err
	}
	if len(rep.Unproven) > 0 {
		return fmt.Errorf("the fixture is written, but the report is not a verified S3: %d unproven (first: %s)", len(rep.Unproven), rep.Unproven[0].Error())
	}
	return nil
}

func readMaybeGz(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		z, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(z)
	}
	return b, nil
}

func readArchive(path string) (*proofv2.Archive, error) {
	j, err := readMaybeGz(path)
	if err != nil {
		return nil, err
	}
	return proofv2.UnmarshalArchive(j)
}

func writeGz(path string, v any) error {
	j, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeGzRaw(path, j)
}

func writeGzRaw(path string, j []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	z, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	z.Header.ModTime = time.Time{} // byte-stable: no time in the gzip header
	if _, err := z.Write(j); err != nil {
		return err
	}
	return z.Close()
}
