// Copyright 2026 Certen Protocol

// Package testvalset is the validator set tests sign for: the set registered on the live V8.1 anchors
// (root a85a6911...74e8 on sepolia, base-sepolia and arbitrum-sepolia, read 2026-09-28). The node takes
// its set from configuration and refuses to start without one (RB3-F21), so a test states it too.
//
// Imported only by tests; nothing here is in a shipped binary.
package testvalset

import "os"

// Settings are the variables and values that configure the registered set.
var Settings = map[string]string{
	"CERTEN_VALIDATOR_SET_ADDRESSES": "0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D,0x5555afA8Ff8048BddAAC1554AFd790c9bf7ec6E0," +
		"0x6ACaa68417F5ad5d4a02D9d3d72E291efFcDf30A,0x16aB06F3634218a8f1F3B01dCdd32DDFbdc8a69D," +
		"0xf150Ff923E29F797b4598b89bD7D02002D00Db3a,0x70A6A81bb5E3B63B1929301239DE1F5c63Ec4F3a," +
		"0xee2EfA29989Fe6E53572087680c661EC29e045Fe",
	"CERTEN_VALIDATOR_SET_POWERS":        "100,100,100,100,100,100,100",
	"CERTEN_VALIDATOR_SET_THRESHOLD_NUM": "2",
	"CERTEN_VALIDATOR_SET_THRESHOLD_DEN": "3",
}

// Configure sets the registered set in the process environment where a variable is not already set.
// Called from a package's TestMain.
func Configure() {
	for k, v := range Settings {
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

// Environ is Settings as KEY=VALUE entries, for a child process's environment.
func Environ() []string {
	out := make([]string, 0, len(Settings))
	for k, v := range Settings {
		out = append(out, k+"="+v)
	}
	return out
}
