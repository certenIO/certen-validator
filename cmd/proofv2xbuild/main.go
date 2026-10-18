// Command proofv2xbuild captures a live transaction with the cross-partition collector (history, signature chains, transaction), assembles
// evidence 2.1 from the capture and verifies it offline with Verify21FromGenesis (RB9 Phase C1b-2). It reads only. The transaction's
// block must still be inside the node's retention when the capture starts (about 945 s on Kermit).
//
//	proofv2xbuild -account acc://x.acme/data -tx <hex> -keybook acc://x.acme/book -keypage acc://x.acme/book/1 \
//	    -incarnation-evidence pkg/proof/testdata/incarnation/kermit.json -archive pkg/proof/v2/testdata/archive.json.gz -out dir
package main

import (
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

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	account := flag.String("account", "", "the transaction's principal")
	tx := flag.String("tx", "", "transaction hash, hex")
	book := flag.String("keybook", "", "the key book the intent declares")
	page := flag.String("keypage", "", "the key page the intent declares")
	incPath := flag.String("incarnation-evidence", "pkg/proof/testdata/incarnation/kermit.json", "incarnation evidence JSON")
	pin := flag.String("pin", "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0", "pinned incarnation, hex32")
	archivePath := flag.String("archive", "pkg/proof/v2/testdata/archive.json.gz", "major records already walked (gzip JSON); extended from the network")
	out := flag.String("out", "", "directory to write capture.json.gz, evidence21.json.gz and archive.json.gz into")
	flag.Parse()
	if err := run(*endpoint, *account, *tx, *book, *page, *incPath, *pin, *archivePath, *out); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(endpoint, account, tx, book, page, incPath, pinHex, archivePath, out string) error {
	if account == "" || tx == "" {
		return errors.New("-account and -tx are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
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
	var pinned [32]byte
	if b, err := hex.DecodeString(pinHex); err != nil || len(b) != 32 {
		return errors.New("-pin must be 32 bytes of hex")
	} else {
		copy(pinned[:], b)
	}

	// Capture first: the pages are only servable while their block is inside the node's retention.
	t0 := time.Now()
	probe := &proofv2.Builder{C: c, Q: q}
	col, err := proofv2shadow.NewCollector(ctx, endpoint, c, probe, func(f string, a ...any) { fmt.Printf(f+"\n", a...) }, book, page)
	if err != nil {
		return err
	}
	cp, err := col.Collect(ctx, account, tx)
	if cp == nil {
		return fmt.Errorf("capture: %w", err)
	}
	fmt.Printf("captured %d pages on %d partitions at block %d (%s)\n", len(cp.Pages), len(cp.Partitions), cp.Block, time.Since(t0).Round(time.Millisecond))
	for _, n := range cp.Notes {
		fmt.Println("  note:", n)
	}
	if err != nil {
		return fmt.Errorf("capture stopped with a named state: %w", err)
	}

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
	fmt.Printf("spine: %d majors\n", len(b.Archive().Majors))

	asm, err := cp.Assembly(ctx, proofv2.NetLog{Net: c}, proofv2.NetChains{Net: c})
	if err != nil {
		return err
	}
	var ev *proofv2.Evidence
	var rep *proofv2.Report
	for {
		ev, rep, err = b.Build21(ctx, 0, account, tx, "bvn1", asm)
		// A minor-root record served before its validator signatures arrived is not a refusal: retry (RB9-C1b-2-B1).
		if !errors.Is(err, proofv2.ErrNotYetCertified) && !(err != nil && strings.Contains(err.Error(), "quorum not met: 0 of")) {
			break
		}
		fmt.Println("waiting for the Directory to certify the block ...")
		time.Sleep(15 * time.Second)
		if err := b.Refresh(ctx); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	fmt.Printf("evidence 2.1 verified: certified DN %d, set checked at DN %d (%s); %s anchor block %d; %d pages proven\n",
		rep.CertifiedBlock, rep.CheckBlock, rep.SetVerdict, rep.Partition, rep.AnchorBlock, len(rep.Proven))
	fmt.Printf("  authorization mode %q, routing height %d, %d arrivals derived, %d unproven, %d disclosures\n",
		rep.AuthorizationMode, rep.RoutingHeight, len(rep.Arrivals), len(rep.Unproven), len(rep.Disclosures))
	for _, u := range rep.Unproven {
		fmt.Println("  UNPROVEN:", u.Error())
	}
	for _, p := range rep.Proven {
		fmt.Printf("  proven %s  %s block %d roles %v declared %v\n", p.URL, p.Partition, p.Block, p.Roles, p.Declared)
	}
	if out != "" {
		if err := os.MkdirAll(out, 0o755); err != nil {
			return err
		}
		if err := writeGz(filepath.Join(out, "capture.json.gz"), cp); err != nil {
			return err
		}
		if err := writeGz(filepath.Join(out, "evidence21.json.gz"), ev); err != nil {
			return err
		}
		aj, err := proofv2.MarshalArchive(b.Archive())
		if err != nil {
			return err
		}
		if err := writeGzRaw(filepath.Join(out, "archive.json.gz"), aj); err != nil {
			return err
		}
	}
	return nil
}

func readArchive(path string) (*proofv2.Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	j, err := io.ReadAll(z)
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
	z := gzip.NewWriter(f)
	if _, err := z.Write(j); err != nil {
		return err
	}
	return z.Close()
}
