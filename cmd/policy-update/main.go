// Command policy-update creates, signs and submits entitlement PolicyUpdate
// transactions — the only supported way to change the entitlement rule on a
// running chain.
//
// Why this exists: the rule decides whether ValidatorBlocks are accepted, and
// acceptance feeds the app hash. Editing an environment variable to change it
// bricked the fleet on 2026-07-27, because replayed history was judged by a
// rule that had not committed it. A PolicyUpdate takes effect at a HEIGHT, so
// every node switches together and replay stays deterministic.
//
//	policy-update keygen
//	    Generate an admin keypair. The public half goes in
//	    CERTEN_ENTITLEMENT_ADMIN_KEYS at genesis; the private half signs updates.
//
//	policy-update propose --mode enforce --activation-height N --version V \
//	    --entitlement-keys entitlement-v1:<hex> --admin-key-id A --admin-secret <hex|@file>
//	    Build and sign an update. Prints the transaction JSON.
//
//	policy-update sign --tx tx.json --admin-key-id B --admin-secret <hex|@file>
//	    Add another admin's signature to an existing transaction (m-of-n).
//
//	policy-update submit --tx tx.json --rpc http://host:26657
//	    Broadcast it to a validator.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen()
	case "propose":
		err = propose(os.Args[2:])
	case "sign":
		err = signExisting(os.Args[2:])
	case "submit":
		err = submit(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `policy-update — change the entitlement rule at an activation height

  keygen    generate an admin keypair
  propose   build and sign an update
  sign      add another admin signature (m-of-n)
  submit    broadcast to a validator

Run any subcommand with --help for its flags.
`)
}

func keygen() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// The seed, not the expanded private key: it is what ed25519.NewKeyFromSeed
	// takes and half the length to mishandle.
	fmt.Printf("public  (for CERTEN_ENTITLEMENT_ADMIN_KEYS): %s\n", hex.EncodeToString(pub))
	fmt.Printf("secret  (KEEP OFF THE VALIDATORS):           %s\n", hex.EncodeToString(priv.Seed()))
	fmt.Fprintln(os.Stderr, "\nThe secret never belongs on a validator. A validator only needs the "+
		"public half, sealed at genesis; signing happens wherever the operator keeps the secret.")
	return nil
}

// loadSecret accepts a hex seed or @path, so a key need not appear in shell
// history or the process table.
func loadSecret(v string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(v)
	if strings.HasPrefix(raw, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(raw, "@"))
		if err != nil {
			return nil, fmt.Errorf("read secret file: %w", err)
		}
		raw = strings.TrimSpace(string(b))
	}
	seed, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("secret must be hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("secret must be %d hex-encoded bytes (got %d)", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func parseKeyList(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, hexKey, ok := strings.Cut(entry, ":")
		if !ok || id == "" || hexKey == "" {
			return nil, fmt.Errorf("entry %q is not <keyID>:<hexPubKey>", entry)
		}
		b, err := hex.DecodeString(hexKey)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("entry %q: key must be %d hex bytes", id, ed25519.PublicKeySize)
		}
		out[id] = hexKey
	}
	return out, nil
}

func propose(args []string) error {
	fs := flag.NewFlagSet("propose", flag.ExitOnError)
	mode := fs.String("mode", "", "off | observe | enforce")
	activation := fs.Int64("activation-height", 0, "height at which the rule takes effect")
	version := fs.Uint64("version", 0, "must exceed the highest committed policy version")
	entKeys := fs.String("entitlement-keys", "", "<keyID>:<hexPubKey>[,...] — epoch signing keys the gate will trust")
	keyID := fs.String("admin-key-id", "", "this signer's admin key id")
	secret := fs.String("admin-secret", "", "hex seed, or @path")
	out := fs.String("out", "", "write the transaction here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode == "" || *activation == 0 || *version == 0 || *keyID == "" || *secret == "" {
		fs.Usage()
		return fmt.Errorf("--mode, --activation-height, --version, --admin-key-id and --admin-secret are required")
	}

	keys, err := parseKeyList(*entKeys)
	if err != nil {
		return err
	}
	priv, err := loadSecret(*secret)
	if err != nil {
		return err
	}

	tx := &consensus.PolicyUpdateTx{
		Kind:             consensus.PolicyUpdateKind,
		Mode:             *mode,
		Keys:             keys,
		ActivationHeight: *activation,
		Version:          *version,
	}
	tx.Signatures = []consensus.PolicySignature{{
		KeyID:     *keyID,
		Signature: hex.EncodeToString(ed25519.Sign(priv, tx.SigningBytes())),
	}}

	fmt.Fprintf(os.Stderr,
		"Activation must be at least %d blocks ahead of the block that carries this "+
			"update, or validators will refuse it.\n", consensus.MinActivationDelay)
	return writeTx(tx, *out)
}

func signExisting(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	path := fs.String("tx", "", "transaction file to add a signature to")
	keyID := fs.String("admin-key-id", "", "this signer's admin key id")
	secret := fs.String("admin-secret", "", "hex seed, or @path")
	out := fs.String("out", "", "write here (default: overwrite --tx)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		fs.Usage()
		return fmt.Errorf("--tx, --admin-key-id and --admin-secret are required")
	}

	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var tx consensus.PolicyUpdateTx
	if err := json.Unmarshal(b, &tx); err != nil {
		return fmt.Errorf("parse transaction: %w", err)
	}
	priv, err := loadSecret(*secret)
	if err != nil {
		return err
	}

	// Signing the digest of the CURRENT fields means any tampering between
	// signers invalidates the earlier signatures too.
	for _, s := range tx.Signatures {
		if s.KeyID == *keyID {
			return fmt.Errorf("key id %q has already signed this update", *keyID)
		}
	}
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{
		KeyID:     *keyID,
		Signature: hex.EncodeToString(ed25519.Sign(priv, tx.SigningBytes())),
	})

	dest := *out
	if dest == "" {
		dest = *path
	}
	fmt.Fprintf(os.Stderr, "signatures on this update: %d\n", len(tx.Signatures))
	return writeTx(&tx, dest)
}

func writeTx(tx *consensus.PolicyUpdateTx, path string) error {
	b, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func submit(args []string) error {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	path := fs.String("tx", "", "transaction file")
	rpc := fs.String("rpc", "http://127.0.0.1:26657", "CometBFT RPC endpoint of any validator")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		fs.Usage()
		return fmt.Errorf("--tx is required")
	}

	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	// Compact: the bytes submitted are the bytes every validator hashes, so
	// incidental whitespace should not vary between operators.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return fmt.Errorf("transaction is not valid JSON: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_sync",
		"params": map[string]any{"tx": base64.StdEncoding.EncodeToString(compact.Bytes())},
	})
	if err != nil {
		return err
	}

	resp, err := http.Post(strings.TrimRight(*rpc, "/"), "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	fmt.Println(string(out))
	if bytes.Contains(out, []byte(`"code":5`)) {
		return fmt.Errorf("the chain rejected this update; the log above says why")
	}
	fmt.Fprintln(os.Stderr, "\nAccepted into the mempool. It is SCHEDULED, not active: the rule "+
		"changes at the activation height, on every node at once.")
	return nil
}
