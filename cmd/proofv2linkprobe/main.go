// Command proofv2linkprobe records REAL link responses of the Directory (RB9-F5 package F5-2, V-E probes V1/V4), read-only: for a live
// evidence 2.1 fixture it asks the served query
//
//	query acc://dn.acme/anchors {queryType: chain, name: "anchor(directory)-root", entry: <previous root>, includeReceipt: {forHeight: <RootChainIndex>}}
//
// for every link the anchored form of the fixture needs, and for the genesis entry and chosen major-block closes linked into the fixture's
// certified anchor, and writes the receipts with the question each answers. The recorded file is committed with a pinned manifest; the
// tests replay it (no network).
//
//	proofv2linkprobe -fixture <dir with evidence21.json.gz and archive.json.gz> -inc <incarnation json> -out <links.json> [-majors 2,250]
package main

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// Link is one recorded answer.
type Link struct {
	Label   string `json:"label"`
	Prev    string `json:"prev"`
	Height  uint64 `json:"height"`
	Receipt string `json:"receipt,omitempty"`
	// NotAnchored is the served refusal text when the previous root is not yet anchored at or below Height (probe V4).
	NotAnchored string `json:"notAnchored,omitempty"`
}

// File is the recorded file.
type File struct {
	Endpoint   string `json:"endpoint"`
	RecordedAt string `json:"recordedAt"`
	Fixture    string `json:"fixture"`
	Links      []Link `json:"links"`
}

type recorder struct {
	src   proofv2.LinkSource
	label string
	out   *File
}

func (r *recorder) Link(ctx context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	l, err := r.src.Link(ctx, prev, height)
	rec := Link{Label: r.label, Prev: hex.EncodeToString(prev[:]), Height: height}
	if err != nil {
		rec.NotAnchored = err.Error()
	} else {
		b, merr := l.MarshalBinary()
		if merr != nil {
			return nil, merr
		}
		rec.Receipt = hex.EncodeToString(b)
	}
	r.out.Links = append(r.out.Links, rec)
	return l, err
}

func gunzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(z)
}

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	fixture := flag.String("fixture", "", "directory holding evidence21.json.gz and archive.json.gz")
	incPath := flag.String("inc", "", "incarnation evidence json")
	out := flag.String("out", "", "file to write")
	majors := flag.String("majors", "2,250", "major blocks whose closing root is linked into the certified anchor")
	g1 := flag.String("g1", "", "comma-separated pkg/consensus live suites (manifest.json directories): record the links of all their fixtures instead of -fixture")
	flag.Parse()
	var err error
	if *g1 != "" {
		err = runG1(*endpoint, *g1, *incPath, *out)
	} else {
		err = run(*endpoint, *fixture, *incPath, *out, *majors)
	}
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(endpoint, fixture, incPath, outPath, majors string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	raw, err := gunzip(filepath.Join(fixture, "evidence21.json.gz"))
	if err != nil {
		return err
	}
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		return err
	}
	arRaw, err := gunzip(filepath.Join(fixture, "archive.json.gz"))
	if err != nil {
		return err
	}
	ar, err := proofv2.UnmarshalArchive(arRaw)
	if err != nil {
		return err
	}
	incRaw, err := os.ReadFile(incPath)
	if err != nil {
		return err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(incRaw, inc); err != nil {
		return err
	}
	ir, err := inc.Verify()
	if err != nil {
		return err
	}
	file := &File{Endpoint: endpoint, RecordedAt: time.Now().UTC().Format(time.RFC3339), Fixture: filepath.ToSlash(fixture)}
	live := proofv2.NewClientLinks(jsonrpc.NewClient(endpoint))
	rec := &recorder{src: live, label: "fixture", out: file}
	anchored, err := proofv2.AnchorEvidence(ctx, ev, ar, ir.Inputs, rec)
	if err != nil {
		return fmt.Errorf("anchoring the fixture: %w", err)
	}
	fmt.Printf("fixture: %d certify runs -> %d kept, %d hops -> %d kept, %d links\n", len(ev.Certify), len(anchored.Certify), len(ev.Check.Hops), len(anchored.Check.Hops), len(anchored.Links))

	// The certified anchor's height, for the extra entries.
	height, err := certifiedHeight(ev)
	if err != nil {
		return err
	}
	extra := func(label string, prev [32]byte) error {
		r := &recorder{src: live, label: label, out: file}
		_, err := r.Link(ctx, prev, height)
		return err
	}
	if err := extra("genesis", ir.Inputs.GenesisRootChainAnchor); err != nil {
		return fmt.Errorf("genesis entry: %w", err)
	}
	for _, s := range strings.Split(majors, ",") {
		m, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || m < 1 || m > len(ar.Majors) {
			return fmt.Errorf("major %q", s)
		}
		root, err := proofv2.MajorRootChainAnchor(ar, uint64(m))
		if err != nil {
			return err
		}
		if err := extra(fmt.Sprintf("major-%d", m), root); err != nil {
			return fmt.Errorf("major %d: %w", m, err)
		}
	}
	b, err := json.MarshalIndent(file, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	fmt.Printf("recorded %d answers -> %s\n", len(file.Links), outPath)
	return os.WriteFile(outPath, append(b, '\n'), 0o644)
}

func certifiedHeight(ev *proofv2.Evidence) (uint64, error) {
	if len(ev.Certify) == 0 {
		return 0, fmt.Errorf("the fixture certifies nothing")
	}
	idx, _, err := proofv2.RunAnchor(ev.Certify[len(ev.Certify)-1])
	return idx, err
}

// runG1 records the links the anchored form of every fixture of the given pkg/consensus live suites needs (the 19 live intents of
// RB9-E: testdata/g1_live and testdata/g1_live_fixedprover), once per distinct question.
func runG1(endpoint, dirs, incPath, outPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	incRaw, err := os.ReadFile(incPath)
	if err != nil {
		return err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(incRaw, inc); err != nil {
		return err
	}
	ir, err := inc.Verify()
	if err != nil {
		return err
	}
	file := &File{Endpoint: endpoint, RecordedAt: time.Now().UTC().Format(time.RFC3339), Fixture: dirs}
	live := proofv2.NewClientLinks(jsonrpc.NewClient(endpoint))
	asked := map[string]bool{}
	for _, dir := range strings.Split(dirs, ",") {
		mraw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			return err
		}
		var m struct {
			Archive string `json:"archive"`
			Cases   []struct {
				Name string `json:"name"`
				File string `json:"file"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(mraw, &m); err != nil {
			return err
		}
		shared, err := gunzip(filepath.Join(dir, m.Archive))
		if err != nil {
			return err
		}
		for _, c := range m.Cases {
			raw, err := gunzip(filepath.Join(dir, c.File))
			if err != nil {
				return err
			}
			var f struct {
				ProofV2 json.RawMessage `json:"proof_v2"`
				Archive json.RawMessage `json:"archive"`
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				return err
			}
			if len(f.Archive) == 0 {
				f.Archive = shared
			}
			ev := new(proofv2.Evidence)
			if err := json.Unmarshal(f.ProofV2, ev); err != nil {
				return err
			}
			ar, err := proofv2.UnmarshalArchive(f.Archive)
			if err != nil {
				return err
			}
			before := len(file.Links)
			rec := &recorder{src: live, label: filepath.Base(dir) + "/" + c.Name, out: file}
			seen := &dedupe{inner: rec, asked: asked}
			anchored, err := proofv2.AnchorEvidence(ctx, ev, ar, ir.Inputs, seen)
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			fmt.Printf("%s: %d certify runs -> %d, %d hops -> %d, %d links (%d new answers)\n", c.Name, len(ev.Certify), len(anchored.Certify), len(ev.Check.Hops), len(anchored.Check.Hops), len(anchored.Links), len(file.Links)-before)
		}
	}
	b, err := json.MarshalIndent(file, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	fmt.Printf("recorded %d answers -> %s\n", len(file.Links), outPath)
	return os.WriteFile(outPath, append(b, '\n'), 0o644)
}

// dedupe asks the live endpoint once per distinct question and replays the recorded answer after.
type dedupe struct {
	inner *recorder
	asked map[string]bool
}

func (d *dedupe) Link(ctx context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	k := hex.EncodeToString(prev[:]) + ":" + strconv.FormatUint(height, 10)
	if d.asked[k] {
		for _, l := range d.inner.out.Links {
			if l.Prev == hex.EncodeToString(prev[:]) && l.Height == height {
				if l.Receipt == "" {
					return nil, fmt.Errorf("%w: %s", proofv2.ErrLinkNotAnchored, l.NotAnchored)
				}
				raw, _ := hex.DecodeString(l.Receipt)
				r := new(merkle.Receipt)
				return r, r.UnmarshalBinary(raw)
			}
		}
	}
	d.asked[k] = true
	return d.inner.Link(ctx, prev, height)
}
