// Copyright 2026 Certen Protocol

// Command finalityethl1record captures the live Sepolia data of the published vector set finality_ethl1_v1 once (record)
// and derives the vectors, pins and expected verdicts from the captured bytes offline (build). Tests never touch the network.
//
//	finalityethl1record record -out pkg/finality/ethl1/testdata/finality_ethl1_v1/raw
//	finalityethl1record build  -raw pkg/finality/ethl1/testdata/finality_ethl1_v1/raw -out pkg/finality/ethl1/testdata/finality_ethl1_v1
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: finalityethl1record record|build [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	out := fs.String("out", "", "output directory")
	raw := fs.String("raw", "", "raw capture directory (build, record2: the v1 capture)")
	raw2 := fs.String("raw2", "", "second raw capture directory written by record2 (build2)")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "record":
		err = record(*out)
	case "build":
		err = build(*raw, *out)
	case "record2":
		err = record2(*raw, *out)
	case "build2":
		err = build2(*raw, *raw2, *out)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", ethrpc.RedactError(err))
		os.Exit(1)
	}
}
