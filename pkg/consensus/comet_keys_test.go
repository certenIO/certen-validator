// Copyright 2026 Certen Protocol

package consensus

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
)

// RB3-F95 phase 1: a validator's CometBFT keys are read from its volume and never deleted, overwritten
// or derived from its name; a lost key comes back only from its secret seed, identical.

const testChain = "certen-testnet"

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// liveHome lays out a home exactly as production has it today: files written by CometBFT's own
// writers, holding the public-formula keys.
func liveHome(t *testing.T, validatorID string) (string, cometKeyPaths) {
	t.Helper()
	home := t.TempDir()
	p := cometPaths(home)
	for _, d := range []string{filepath.Dir(p.privvalKey), filepath.Dir(p.privvalState)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	k := formulaKey(testChain, validatorID)
	pv := privval.NewFilePV(k, p.privvalKey, p.privvalState)
	pv.Save()
	if err := (&p2p.NodeKey{PrivKey: k}).SaveAs(p.nodeKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.genesis, []byte(`{"chain_id":"certen-testnet"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, p
}

func snapshot(t *testing.T, p cometKeyPaths) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range []string{p.privvalKey, p.privvalState, p.nodeKey, p.genesis} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[f] = b
	}
	return out
}

func sameFiles(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	for f, b := range before {
		if !bytes.Equal(b, after[f]) {
			t.Errorf("%s changed", filepath.Base(f))
		}
	}
}

func seedHex(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

// Production today: the node keeps its keys exactly as they are (deploying this changes nothing on the
// chain), and says the consensus and node keys are still the public formula's.
func TestTheLiveKeysAreKeptExactlyAsTheyAre(t *testing.T) {
	home, p := liveHome(t, "validator-1")
	before := snapshot(t, p)
	for i := 0; i < 3; i++ {
		rep, err := ensureCometKeys(home, "validator-1", testChain, env(nil), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.PrivvalIsFormula || !rep.NodeKeyIsFormula || rep.PrivvalFromSeed || rep.StateCreated {
			t.Fatalf("report %+v", rep)
		}
	}
	sameFiles(t, before, snapshot(t, p))
	// CometBFT's own loader (which exits the process on a bad file) still accepts them.
	privval.LoadFilePV(p.privvalKey, p.privvalState)
}

func TestNoKeyIsEverInvented(t *testing.T) {
	home, p := liveHome(t, "validator-2")
	if err := os.Remove(p.privvalKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCometKeys(home, "validator-2", testChain, env(nil), nil); err == nil ||
		!strings.Contains(err.Error(), envPrivvalSeed) {
		t.Fatalf("a missing consensus key with no seed: %v", err)
	}
	if _, err := os.Stat(p.privvalKey); err == nil {
		t.Fatal("a consensus key was written with no seed to write it from")
	}

	home, p = liveHome(t, "validator-2")
	if err := os.Remove(p.nodeKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCometKeys(home, "validator-2", testChain, env(nil), nil); err == nil ||
		!strings.Contains(err.Error(), envNodeKeySeed) {
		t.Fatalf("a missing node key with no seed: %v", err)
	}
}

// With a seed, deleting a key file cannot take the validator off the network: it comes back identical.
func TestASeededKeyComesBackIdenticalAfterItsFileIsDeleted(t *testing.T) {
	home := t.TempDir()
	p := cometPaths(home)
	if err := os.MkdirAll(filepath.Dir(p.genesis), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.genesis, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env(map[string]string{envPrivvalSeed: seedHex(0x11), envNodeKeySeed: "0x" + seedHex(0x22)})
	first, err := ensureCometKeys(home, "validator-3", testChain, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.PrivvalFromSeed || !first.NodeKeyFromSeed || !first.StateCreated || first.PrivvalIsFormula {
		t.Fatalf("first boot report %+v", first)
	}
	before := snapshot(t, p)
	privval.LoadFilePV(p.privvalKey, p.privvalState) // CometBFT accepts what was written

	for _, f := range []string{p.privvalKey, p.nodeKey} {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	again, err := ensureCometKeys(home, "validator-3", testChain, e, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !again.PrivvalPubKey.Equals(first.PrivvalPubKey) || again.NodeID != first.NodeID {
		t.Fatal("a re-created key is not the key the seed backed before")
	}
	sameFiles(t, before, snapshot(t, p))
	if first.PrivvalPubKey.Equals(keyFromSeed(bytes.Repeat([]byte{0x22}, 32), labelPrivval).PubKey()) {
		t.Fatal("the consensus key and the node key share a derivation")
	}
}

// A file that is not the key its seed backs is refused, and left as it is.
func TestAKeyThatDisagreesWithItsSeedIsRefusedAndLeftAlone(t *testing.T) {
	home, p := liveHome(t, "validator-4")
	before := snapshot(t, p)
	for _, e := range []map[string]string{{envPrivvalSeed: seedHex(0x33)}, {envNodeKeySeed: seedHex(0x44)}} {
		if _, err := ensureCometKeys(home, "validator-4", testChain, env(e), nil); err == nil {
			t.Fatalf("a key that is not its seed's was accepted (%v)", e)
		}
	}
	sameFiles(t, before, snapshot(t, p))
}

// The signing state is never deleted or rewritten; missing, it is created at height 0.
func TestTheSigningStateIsNeverTouched(t *testing.T) {
	home, p := liveHome(t, "validator-5")
	signed := []byte("{\n  \"height\": \"12345\",\n  \"round\": 0,\n  \"step\": 3\n}")
	if err := os.WriteFile(p.privvalState, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCometKeys(home, "validator-5", testChain, env(nil), nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p.privvalState); !bytes.Equal(got, signed) {
		t.Fatalf("the signing state was rewritten: %s", got)
	}
	if err := os.Remove(p.privvalState); err != nil {
		t.Fatal(err)
	}
	rep, err := ensureCometKeys(home, "validator-5", testChain, env(nil), nil)
	if err != nil || !rep.StateCreated {
		t.Fatalf("(%+v, %v)", rep, err)
	}
	privval.LoadFilePV(p.privvalKey, p.privvalState)
}

func TestNoGenesisIsEverGenerated(t *testing.T) {
	home, p := liveHome(t, "validator-6")
	if err := os.Remove(p.genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCometKeys(home, "validator-6", testChain, env(nil), nil); err == nil {
		t.Fatal("started with no genesis")
	}
	if _, err := os.Stat(p.genesis); err == nil {
		t.Fatal("a genesis was written")
	}
}

func TestAMalformedSeedIsRefusedWithoutPrintingIt(t *testing.T) {
	home, _ := liveHome(t, "validator-7")
	bad := "zz" + seedHex(0x55)[2:]
	_, err := ensureCometKeys(home, "validator-7", testChain, env(map[string]string{envPrivvalSeed: bad}), nil)
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("malformed seed: %v", err)
	}
}

// Nothing in the package deletes a key, a signing state or a genesis, or derives a key from a name.
func TestNothingDeletesOrDerivesCometKeys(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, bad := range []string{"os.Remove(privValKeyFile)", "os.Remove(privValStateFile)", "os.Remove(nodeKeyFile)",
			"generateDeterministicNodeKey", "writeDeterministicGenesisIfNeeded", "privValidator.Save()",
			// RB3-F114: a ledger that cannot be recovered is not started fresh under a chain with history.
			"State recovery failed (will start fresh)"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s still contains %s", f, bad)
			}
		}
		if f != "comet_keys.go" && strings.Contains(src, "certen-validator-key-") {
			t.Errorf("%s derives a key from the public formula", f)
		}
	}
}

// RB3-F95 phase 2: the rotation tool's key for a seed is the key a node started with that seed runs - so the
// key the chain is told about is the key the validator signs with.
func TestTheToolsSeedKeyIsTheNodesSeedKey(t *testing.T) {
	home := t.TempDir()
	p := cometPaths(home)
	if err := os.MkdirAll(filepath.Dir(p.genesis), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.genesis, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := bytes.Repeat([]byte{0x3c}, 32)
	rep, err := ensureCometKeys(home, "validator-3", testChain,
		env(map[string]string{envPrivvalSeed: hex.EncodeToString(s), envNodeKeySeed: seedHex(0x3d)}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.PrivvalPubKey.Equals(CometPrivvalKeyFromSeed(s).PubKey()) {
		t.Fatal("the tool derives a different consensus key from the seed than the node runs")
	}
	if string(rep.NodeID) != string(p2p.PubKeyToID(CometNodeKeyFromSeed(bytes.Repeat([]byte{0x3d}, 32)).PubKey())) {
		t.Fatal("the tool derives a different node id from the seed than the node runs")
	}
}

// A seed is exactly 32 bytes. HMAC zero-pads a short key, so a 31-byte prefix of a seed ending in 0 backed the very
// same key (RB5-F24: it made "another" rotation key equal the first one in 1 run of 256). keyFromSeed refuses it.
func TestASeedIsExactly32Bytes(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed[:31] {
		seed[i] = byte(i + 1)
	}
	for _, n := range []int{0, 31, 33, 64} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("a %d-byte seed backed a key", n)
				}
			}()
			s := make([]byte, n)
			copy(s, seed)
			keyFromSeed(s, labelPrivval)
		}()
	}
	if keyFromSeed(seed, labelPrivval).Equals(keyFromSeed(seed, labelNodeKey)) {
		t.Fatal("the consensus and node keys of one seed coincide")
	}
}
