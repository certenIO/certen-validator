// Copyright 2026 Certen Protocol

// Command finalitybasefinalrecord is the recorder of the finality_base_final1 vector set and a live exercise of the
// base-sepolia/finalized/v1 builder:
//
//	finalitybasefinalrecord measure                       eth_getCode hashes of the contracts the pins name
//	finalitybasefinalrecord capture -dir D -game 0x..     capture the proofs of one game near the L1 head
//	finalitybasefinalrecord pins -out FILE                merge the D1 base_sepolia keys into the embedded pins file
//	finalitybasefinalrecord record ...                    (see record.go) capture legs, headers and LC material
//	finalitybasefinalrecord build ...                     (see build.go) derive the vector set from the recorded bytes
//
// Provider text goes through pkg/ethrpc redaction before it is printed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: finalitybasefinalrecord measure|capture|pins|record|build [flags]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "measure":
		err = measure(ctx)
	case "capture":
		fs := flag.NewFlagSet("capture", flag.ExitOnError)
		dir := fs.String("dir", "", "capture directory")
		game := fs.String("game", "", "game proxy address")
		back := fs.Uint64("back", 12, "capture this many blocks behind the proof provider head")
		_ = fs.Parse(os.Args[2:])
		err = captureCmd(ctx, *dir, *game, *back)
	case "pins":
		fs := flag.NewFlagSet("pins", flag.ExitOnError)
		out := fs.String("out", "", "pins file to write")
		_ = fs.Parse(os.Args[2:])
		err = pinsCmd(ctx, *out)
	case "record":
		fs := flag.NewFlagSet("record", flag.ExitOnError)
		dir := fs.String("dir", "", "capture directory")
		raw := fs.String("raw", "", "LC raw directory (finalityethl1record record output)")
		out := fs.String("out", "", "raw legs directory")
		_ = fs.Parse(os.Args[2:])
		err = recordCmd(ctx, *dir, *raw, *out)
	case "judge":
		fs := flag.NewFlagSet("judge", flag.ExitOnError)
		dir := fs.String("dir", "", "capture directory")
		legs := fs.String("legs", "", "raw legs directory")
		_ = fs.Parse(os.Args[2:])
		err = judgeCmd(ctx, *dir, *legs)
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		dir := fs.String("dir", "", "capture directory")
		raw := fs.String("raw", "", "LC raw directory")
		legs := fs.String("legs", "", "raw legs directory")
		out := fs.String("out", "", "output set directory")
		_ = fs.Parse(os.Args[2:])
		err = buildCmd(ctx, *dir, *raw, *legs, *out)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
