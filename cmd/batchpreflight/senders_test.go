package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB3-F64: each validator's sending key is checked against the identity its BLS key resolves to; the key
// itself is never shown.
func TestSendingKeysAreCheckedAgainstTheRegistry(t *testing.T) {
	dir := t.TempDir()
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hex1 := common.Bytes2Hex(crypto.FromECDSA(k1))
	p1 := write("v1.env", "FOO=bar\r\nETH_PRIVATE_KEY=0x"+hex1+"\r\n")
	p2 := write("v2.env", "ETH_PRIVATE_KEY=\""+common.Bytes2Hex(crypto.FromECDSA(k2))+"\"\n")
	senders, err := loadSenderAddresses("validator-1=" + p1 + ",validator-2=" + p2)
	if err != nil {
		t.Fatal(err)
	}
	a1, a2 := crypto.PubkeyToAddress(k1.PublicKey), crypto.PubkeyToAddress(k2.PublicKey)
	if senders["validator-1"] != a1 || senders["validator-2"] != a2 {
		t.Fatalf("derived %v", senders)
	}

	claimed := map[string]string{strings.ToLower(a1.Hex()): "validator-1", strings.ToLower(a2.Hex()): "validator-2"}
	if m := senderMismatches(claimed, senders); len(m) != 0 {
		t.Fatalf("own keys reported: %v", m)
	}
	// validator-2 sending with validator-1's key: the F64 incident.
	shared := map[string]common.Address{"validator-1": a1, "validator-2": a1}
	if m := senderMismatches(claimed, shared); len(m) < 2 {
		t.Fatalf("a shared key was not reported: %v", m)
	}
	if m := senderMismatches(claimed, map[string]common.Address{"validator-1": a1}); len(m) != 1 {
		t.Fatalf("an unchecked validator was not reported: %v", m)
	}

	bad := write("bad.env", "ETH_PRIVATE_KEY=zz"+hex1[2:]+"\n")
	if _, err := loadSenderAddresses("validator-1=" + bad); err == nil || strings.Contains(err.Error(), hex1[2:]) {
		t.Fatalf("malformed key: %v", err)
	}
	if _, err := loadSenderAddresses(""); err == nil {
		t.Fatal("no -sender-envs accepted")
	}
}
