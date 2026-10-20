// Copyright 2026 Certen Protocol

// Command vectorgen records the finality_adiri1 vector set and re-derives the Adiri pins from public data.
//
//	go run ./pkg/finality/adiri/vectorgen -mode fetch -cache <dir>
//	go run ./pkg/finality/adiri/vectorgen -mode pins  -cache <dir>
//	go run ./pkg/finality/adiri/vectorgen -mode vectors -cache <dir> -out pkg/finality/adiri/testdata/finality_adiri1
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "", "fetch | pins | vectors")
	rpc := flag.String("rpc", "https://rpc.telcoin.network", "public Adiri endpoint")
	cache := flag.String("cache", "", "directory of fetched public data")
	out := flag.String("out", "", "vector output directory")
	flag.Parse()
	var err error
	switch *mode {
	case "fetch":
		err = fetchLive(*rpc, *cache, nil)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vectorgen:", err)
		os.Exit(1)
	}
	_ = out
}
