package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	keyA = "88eb4560b4147983e3d72bc6ddb04812d84be905d97f400f5c378b1fc0e252d53d9e2069891d56e2696fe43f2cd153df10bebf7f0fd4da4497f6d24f3cf9a82ff27ef2a8b731c609b732202334a4115b034dd18193d860c75837e46729c90a05"
	keyB = "b6034ecded6be69758a7bfe10dd6f38eba8068433821419762cdad9d1b9d423a02f6fe69f49d720315565700437302ca0edb2af84b1b2ae1114a9f131bcf6fa8ebe00bfa02834ac598ea9aa285a79c07d626e2b89f2784fce679d6e8b25e9ea5"
)

func writeKeys(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pubkeys.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The running keys come from the operator's file, never from a list compiled into the tool: after a
// rotation a compiled-in list names retired keys and the identity check would pass or fail against
// the wrong set.
func TestLoadRunningPubkeys_ReadsTheSuppliedFile(t *testing.T) {
	p := writeKeys(t, `{"validators":[{"validator_id":"validator-1","bls_public_key":"0x`+keyA+`"},`+
		`{"validator_id":"validator-2","bls_public_key":"`+strings.ToUpper(keyB)+`"}]}`)
	got, err := loadRunningPubkeys(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["validator-1"] != keyA || got["validator-2"] != keyB {
		t.Fatalf("got %v", got)
	}
}

func TestLoadRunningPubkeys_RefusesBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"empty list":     `{"validators":[]}`,
		"missing id":     `{"validators":[{"bls_public_key":"` + keyA + `"}]}`,
		"missing key":    `{"validators":[{"validator_id":"validator-1"}]}`,
		"not hex":        `{"validators":[{"validator_id":"validator-1","bls_public_key":"zz"}]}`,
		"not a G2 point": `{"validators":[{"validator_id":"validator-1","bls_public_key":"` + strings.Repeat("11", 96) + `"}]}`,
		"duplicate id": `{"validators":[{"validator_id":"validator-1","bls_public_key":"` + keyA + `"},` +
			`{"validator_id":"validator-1","bls_public_key":"` + keyB + `"}]}`,
		"duplicate key": `{"validators":[{"validator_id":"validator-1","bls_public_key":"` + keyA + `"},` +
			`{"validator_id":"validator-2","bls_public_key":"` + keyA + `"}]}`,
		"private key present": `{"validators":[{"validator_id":"validator-1","bls_public_key":"` + keyA +
			`","bls_private_key":"01"}]}`,
	} {
		if _, err := loadRunningPubkeys(writeKeys(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := loadRunningPubkeys(""); err == nil {
		t.Error("no file: accepted — the identity check must never run against an implicit key list")
	}
}

// After a rotation the registry holds the new keys: the new list resolves every node, the retired
// list resolves none.
func TestResolveIdentities_RotatedRegistry(t *testing.T) {
	registry := map[string]string{"0xaaa": keyB, "0xbbb": keyA}
	claimed, fails := resolveIdentities(map[string]string{"validator-1": keyA, "validator-2": keyB}, registry)
	if len(fails) != 0 || claimed["0xbbb"] != "validator-1" || claimed["0xaaa"] != "validator-2" {
		t.Fatalf("claimed %v fails %v", claimed, fails)
	}
	_, fails = resolveIdentities(map[string]string{"validator-1": strings.Repeat("ab", 96)}, registry)
	if len(fails) != 1 || !strings.Contains(fails[0], "NOT in the anchor registry") {
		t.Fatalf("retired key: fails %v", fails)
	}
	_, fails = resolveIdentities(map[string]string{"validator-1": keyA}, map[string]string{"0x1": keyA, "0x2": keyA})
	if len(fails) != 1 || !strings.Contains(fails[0], "2 addresses") {
		t.Fatalf("ambiguous: fails %v", fails)
	}
}
