// Command proofv2build builds proof v2 Accumulate evidence for live transactions and verifies it offline (RB6 Phase A).
//
//	proofv2build -incarnation-evidence kermit.json -pin <hex32> -corpus corpus.txt [-out dir]
//
// Each corpus line is "<account> <tx hex> [bvn]". With -out, the archive and each evidence are written as JSON so the
// offline verifier and its tests can use them.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	incPath := flag.String("incarnation-evidence", "", "incarnation evidence JSON (cmd/incarnation -out)")
	pin := flag.String("pin", "", "pinned incarnation, hex32")
	corpus := flag.String("corpus", "", "targets, one per line: <account> <tx hex> [bvn]")
	bvn := flag.String("bvn", "bvn1", "default BVN")
	out := flag.String("out", "", "directory to write archive.json.gz and <tx>.json into")
	flag.Parse()
	if err := run(*endpoint, *incPath, *pin, *corpus, *bvn, *out); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(endpoint, incPath, pinHex, corpus, bvn, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

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
		return fmt.Errorf("-pin must be 32 bytes of hex")
	} else {
		copy(pinned[:], b)
	}

	t0 := time.Now()
	b, err := proofv2.NewBuilder(ctx, jsonrpc.NewClient(endpoint), proof.NewHTTPQuerier(endpoint), inc, pinned)
	if err != nil {
		return err
	}
	fmt.Printf("spine: %d majors from the pinned genesis (%s)\n", len(b.Archive().Majors), time.Since(t0).Round(time.Millisecond))
	if out != "" {
		if err := writeArchive(filepath.Join(out, "archive.json.gz"), b.Archive()); err != nil {
			return err
		}
	}

	f, err := os.Open(corpus)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n, failed := 0, 0
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 || len(fs[1]) != 64 {
			continue
		}
		n++
		account, tx, leg := fs[0], fs[1], bvn
		if len(fs) > 2 {
			leg = fs[2]
		}
		t1 := time.Now()
		ev, err := b.Build(ctx, account, tx, leg)
		if err != nil {
			failed++
			fmt.Printf("FAIL %s: %v\n", tx[:12], err)
			continue
		}
		rep, err := proofv2.Verify(ev, b.Archive(), inc, pinned)
		if err != nil {
			failed++
			fmt.Printf("FAIL %s verify: %v\n", tx[:12], err)
			continue
		}
		fmt.Printf("PASS %s: certified DN %d, set checked at DN %d: %s (%d validators, threshold %d) (%s)\n",
			tx[:12], rep.CertifiedBlock, rep.CheckBlock, rep.SetVerdict, rep.Validators, rep.Threshold, time.Since(t1).Round(time.Millisecond))
		if out != "" {
			j, _ := json.MarshalIndent(ev, "", " ")
			if err := os.WriteFile(filepath.Join(out, tx+".json"), j, 0o644); err != nil {
				return err
			}
		}
	}
	fmt.Printf("%d of %d built and verified\n", n-failed, n)
	if failed > 0 {
		return fmt.Errorf("%d failed", failed)
	}
	return nil
}

func writeArchive(path string, ar *proofv2.Archive) error {
	j, err := proofv2.MarshalArchive(ar)
	if err != nil {
		return err
	}
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
