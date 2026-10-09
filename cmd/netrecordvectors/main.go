// Command netrecordvectors writes Go-produced binary vectors for the two records a network update writes,
// protocol.NetworkDefinition and protocol.NetworkGlobals: each case is the record as Go marshals it (hex) and as Go
// renders it to JSON. The TypeScript verifier (certen-sdk packages/verify) decodes the bytes and must reproduce the JSON,
// because it applies a proven write to either account the way pkg/proof/v2 applyProvenUpdate does.
//
//	go run ./cmd/netrecordvectors -out ../certen-sdk/packages/verify/test/fixtures/netrecords.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type vector struct {
	Name string          `json:"name"`
	Kind string          `json:"kind"` // "definition" or "globals"
	Hex  string          `json:"hex"`
	JSON json.RawMessage `json:"json"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	out := flag.String("out", "", "file to write the network record vectors to")
	sigs := flag.String("sigs", "", "file to write the key signature vectors to")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}

	key := func(b byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = b + byte(i)
		}
		return k
	}
	hash := func(b byte) [32]byte {
		var h [32]byte
		for i := range h {
			h[i] = b ^ byte(i*7)
		}
		return h
	}

	defs := map[string]*protocol.NetworkDefinition{
		"definition-minimal": {NetworkName: "DevNet", Version: 1},
		"definition-genesis-shape": {
			NetworkName: "Kermit", Version: 1,
			Partitions: []*protocol.PartitionInfo{{ID: "Directory", Type: protocol.PartitionTypeDirectory}, {ID: "BVN1", Type: protocol.PartitionTypeBlockValidator}, {ID: "BVN2", Type: protocol.PartitionTypeBlockValidator}},
			Validators: []*protocol.ValidatorInfo{
				{PublicKey: key(1), PublicKeyHash: hash(1), Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: true}, {ID: "BVN1", Active: true}}},
				{PublicKey: key(40), PublicKeyHash: hash(40), Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: true}, {ID: "BVN2", Active: false}}},
			},
		},
		"definition-update-v2": {
			NetworkName: "Kermit", Version: 2,
			Partitions: []*protocol.PartitionInfo{{ID: "Directory", Type: protocol.PartitionTypeDirectory}, {ID: "BVN1", Type: protocol.PartitionTypeBlockValidator}, {ID: "BVN3", Type: protocol.PartitionTypeBlockSummary}, {ID: "Boot", Type: protocol.PartitionTypeBootstrap}},
			Validators: []*protocol.ValidatorInfo{
				{PublicKey: key(1), PublicKeyHash: hash(1), Operator: protocol.AccountUrl("op1"), Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: true}, {ID: "BVN1", Active: true}}},
				{PublicKey: key(90), PublicKeyHash: hash(90), Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: false}}},
				{PublicKey: key(120), PublicKeyHash: hash(120), Operator: protocol.AccountUrl("op3", "book", "1"), Partitions: []*protocol.ValidatorPartitionInfo{{ID: "BVN1", Active: true}}},
			},
		},
	}
	globals := map[string]*protocol.NetworkGlobals{
		"globals-empty": {},
		"globals-genesis-shape": {
			OperatorAcceptThreshold:  protocol.Rational{Numerator: 2, Denominator: 3},
			ValidatorAcceptThreshold: protocol.Rational{Numerator: 2, Denominator: 3},
			MajorBlockSchedule:       "0 */12 * * *",
			FeeSchedule:              &protocol.FeeSchedule{CreateIdentitySliding: []protocol.Fee{500000}, CreateSubIdentity: 10000},
			Limits:                   &protocol.NetworkLimits{DataEntryParts: 100, AccountAuthorities: 20, BookPages: 20, PageEntries: 100, IdentityAccounts: 1000},
		},
		"globals-every-field": {
			OperatorAcceptThreshold:  protocol.Rational{Numerator: 3, Denominator: 4},
			ValidatorAcceptThreshold: protocol.Rational{Numerator: 5, Denominator: 7},
			MajorBlockSchedule:       "0 0 * * *",
			AnchorEmptyBlocks:        true,
			FeeSchedule:              &protocol.FeeSchedule{CreateIdentitySliding: []protocol.Fee{500000, 250000, 125000}, CreateSubIdentity: 10000, BareIdentityDiscount: 2500},
			Limits:                   &protocol.NetworkLimits{DataEntryParts: 100, AccountAuthorities: 20, BookPages: 20, PageEntries: 100, IdentityAccounts: 1000, PendingMajorBlocks: 30, EventsPerBlock: 1 << 40},
			BlockInterval:            1500 * time.Millisecond,
		},
	}

	var vs []vector
	for _, n := range []string{"definition-minimal", "definition-genesis-shape", "definition-update-v2"} {
		d := defs[n]
		vs = append(vs, vector{n, "definition", hex.EncodeToString(must(d.MarshalBinary())), must(json.Marshal(d))})
	}
	for _, n := range []string{"globals-empty", "globals-genesis-shape", "globals-every-field"} {
		g := globals[n]
		vs = append(vs, vector{n, "globals", hex.EncodeToString(must(g.MarshalBinary())), must(json.Marshal(g))})
	}
	b := must(json.MarshalIndent(map[string]any{"generator": "certen-validator cmd/netrecordvectors", "vectors": vs}, "", " "))
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(vs), *out)
	if *sigs != "" {
		if err := writeSignatureVectors(*sigs); err != nil {
			panic(err)
		}
		fmt.Printf("wrote signature vectors to %s\n", *sigs)
	}
}
