// Copyright 2026 Certen Protocol

// Command vectorgen records the finality_adiri3 vector set (V2_SPEC_S7 5.8, annex R11-adiri) and re-derives the Adiri pins
// inputs from public data.
//
//	go run ./pkg/finality/adiri/vectorgen -mode fetch   -cache <dir>
//	go run ./pkg/finality/adiri/vectorgen -mode vectors -cache <dir> -out pkg/finality/adiri/testdata/finality_adiri3
//	go run ./pkg/finality/adiri/vectorgen -mode adiri5  -out pkg/finality/adiri/testdata/finality_adiri5   (set5.go: hand-built, offline)
//
// fetch reads the public data (tn_genesis, every sealed epoch record, the genesis link headers) from a public Adiri endpoint.
// vectors builds the LIVE vectors with the Prover against the same endpoint, derives the ADVERSARIAL vectors by mutating the
// real bytes, and generates the SYNTHETIC vectors with test keys that live only in the gitignored keys/ directory next to this
// file (the vectors contain public material only). Every expected verdict is a literal written in this package, not computed
// by the verifier under test.
//
// Vector format (finality_adiri3/1): vectors.json holds {format, vectors[]}; each vector is {name, group live|adversarial|synthetic,
// note, leg{chain,number,hash,header_hex?}, pins "embedded" | the adiri pins section, evidence (a file under evidence/) or base +
// edits, expect}. Edits are {offset, delete, insert(hex)} against the BASE vector's evidence bytes, applied from the highest
// offset to the lowest. expect is the canonical text {"code":...,"fields":{...}} (sorted keys, unsigned integers as decimal
// strings, byte arrays as lowercase hex); a verdict has code "finalized". MANIFEST.json lists the sha256 of every file;
// MANIFEST.json.sha256 is the sha256 of MANIFEST.json. A vector whose pins is an object is verified against that section
// (the live vectors use the embedded pins section).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	mode := flag.String("mode", "", "fetch | vectors | adiri5")
	rpc := flag.String("rpc", "https://rpc.telcoin.network", "public Adiri endpoint")
	cache := flag.String("cache", "", "directory of fetched public data")
	out := flag.String("out", "", "vector output directory")
	keys := flag.String("keys", "pkg/finality/adiri/vectorgen/keys", "adiri5: the gitignored directory of the synthetic test-key seed")
	base := flag.String("base", "pkg/finality/adiri/testdata/finality_adiri3", "adiri5: the set whose syn-rotation evidence the pins vectors re-use")
	flag.Parse()
	var err error
	switch *mode {
	case "fetch":
		err = fetchLive(*rpc, *cache, nil)
	case "vectors":
		err = writeVectors(*rpc, *cache, *out)
	case "adiri5":
		err = writeAdiri5(*out, *keys, *base)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vectorgen:", err)
		os.Exit(1)
	}
}

func writeVectors(rpc, cache, out string) error {
	if cache == "" || out == "" {
		return fmt.Errorf("-cache and -out are required")
	}
	facts := loadFacts(cache)
	evidence, live := recordLive(rpc, cache, out, facts)
	all := append([]vec(nil), live...)
	var base vec
	for _, v := range live {
		if v.Name == "live-513643-epoch651" {
			base = v
		}
	}
	all = append(all, adversarial(base, evidence[base.Name], facts)...)
	sev, svs := synthetic("pkg/finality/adiri/vectorgen/keys")
	for k, v := range sev {
		evidence[k] = v
	}
	all = append(all, svs...)
	ev2, vs2 := set2Vectors()
	for k, v := range ev2 {
		evidence[k] = v
	}
	all = append(all, vs2...)
	return writeSet(out, "finality_adiri3/1", "finality_adiri3/manifest/1", evidence, all)
}

// writeSet writes a vector set: evidence files, vectors.json, MANIFEST.json and MANIFEST.json.sha256.
func writeSet(out, format, manifestFormat string, evidence map[string][]byte, all []vec) error {
	if err := os.MkdirAll(filepath.Join(out, "evidence"), 0o755); err != nil {
		return err
	}
	files := map[string]string{}
	names := make([]string, 0, len(evidence))
	for k := range evidence {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		p := filepath.Join("evidence", k+".bin")
		if err := os.WriteFile(filepath.Join(out, p), evidence[k], 0o644); err != nil {
			return err
		}
		files[filepath.ToSlash(p)] = sha(evidence[k])
	}
	vj, err := json.MarshalIndent(map[string]any{"format": format, "vectors": all}, "", " ")
	if err != nil {
		return err
	}
	vj = append(vj, '\n')
	if err := os.WriteFile(filepath.Join(out, "vectors.json"), vj, 0o644); err != nil {
		return err
	}
	files["vectors.json"] = sha(vj)
	mj, _ := json.MarshalIndent(map[string]any{"format": manifestFormat, "files": files}, "", " ")
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json"), mj, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(mj)
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors, %d evidence files; MANIFEST sha256 %x\n", len(all), len(evidence), sum)
	return nil
}
