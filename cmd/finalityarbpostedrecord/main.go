// Copyright 2026 Certen Protocol

// Command finalityarbpostedrecord records one LIVE arb-sepolia l1_posted evidence container from a capture store (record) and
// derives the published vector set finality_arb_posted1 from the recorded bytes offline (build).
//
//	finalityarbpostedrecord record -store <capture dir> -out <raw dir> [-batch N]     network: L1/L2 RPC and Lodestar
//	finalityarbpostedrecord build  -raw <raw dir> -out pkg/finality/arbposted/testdata/finality_arb_posted1   offline, deterministic
//
// Every adversarial vector is a byte mutation of the recorded evidence (or a pins / leg-header variant) and states its expected
// verdict as a canonical literal written in build.go; build refuses to write a case whose verdict differs from its literal.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: finalityarbpostedrecord record|build [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	store := fs.String("store", "", "capture store directory (record)")
	raw := fs.String("raw", "", "raw directory (build input, record output with -out)")
	out := fs.String("out", "", "output directory")
	batch := fs.Uint64("batch", 0, "batch sequence number to record (0: first with a proof)")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "record":
		err = record(*store, *out, *batch)
	case "build":
		err = build(*raw, *out)
	case "build2":
		err = build2(*raw, *out)
	case "measure":
		err = measure(*raw)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
