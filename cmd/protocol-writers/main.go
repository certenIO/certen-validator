// Copyright 2026 Certen Protocol

// protocol-writers gives each writer to certen-protocol.acme its own key (RB4-F51).
//
// Every writer - the bridge and the seven validators' write-backs - used to sign with one key on
// certen-protocol.acme/book/1, the book's highest-priority page: one leak was authority over the whole
// identity, nothing showed which service wrote what, and the key could not be revoked without stopping
// every writer at once. The writers move to book/2, one key each, and book/2 is denied UpdateKeyPage and
// UpdateAccountAuth, so a writer key can write but cannot change who may; book/1 keeps that authority.
//
// Private keys are read from, or generated into, env files and never printed; only public keys are.
//
//	protocol-writers keygen      -env-file F -var V                  generate a key into F as V (refuses if V is set)
//	protocol-writers pubkey      -env-file F -var V                  print the public key of V in F
//	protocol-writers buy-credits -env-file F -var V -to URL -credits N   buy N credits for URL from V's lite token account
//	protocol-writers create-page -env-file F -var V -book URL -keys H,H...  create the next page of URL holding the keys
//	protocol-writers restrict    -env-file F -var V -page URL        deny URL UpdateKeyPage and UpdateAccountAuth
//	protocol-writers add-key     -env-file F -var V -page URL -key H  add a key to URL
//	protocol-writers remove-key  -env-file F -var V -page URL -key H  remove a key from URL
//	protocol-writers show        -url URL                            print a key page's keys, version, credits and denials
//
// Every signing command signs with the highest-priority page (book/1) of the target's book, or with V's
// lite identity for buy-credits, and waits until the network has executed the transaction.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: protocol-writers keygen|pubkey|buy-credits|create-page|restrict|add-key|remove-key|show [flags]")
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	apiURL := fs.String("api", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 API")
	envFile := fs.String("env-file", "", "env file holding the key")
	envVar := fs.String("var", "", "variable holding the key (64-byte hex ed25519)")
	to := fs.String("to", "", "credit recipient")
	credits := fs.Uint64("credits", 0, "whole credits to buy")
	book := fs.String("book", "", "key book")
	keys := fs.String("keys", "", "comma-separated public keys (hex)")
	page := fs.String("page", "", "key page")
	key := fs.String("key", "", "public key (hex)")
	target := fs.String("url", "", "key page to show")
	_ = fs.Parse(os.Args[2:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(*apiURL)

	switch cmd {
	case "keygen":
		require(*envFile, "-env-file", *envVar, "-var")
		pub, err := keygen(*envFile, *envVar)
		check(err)
		fmt.Printf("%s %x\n", *envVar, pub)
	case "pubkey":
		sk := loadKey(*envFile, *envVar)
		fmt.Printf("%x\n", sk.Public())
	case "buy-credits":
		require(*to, "-to")
		if *credits == 0 {
			fail("-credits is required")
		}
		check(buyCredits(ctx, c, loadKey(*envFile, *envVar), parse(*to), *credits))
	case "create-page":
		require(*book, "-book", *keys, "-keys")
		body := &protocol.CreateKeyPage{}
		for _, h := range strings.Split(*keys, ",") {
			body.Keys = append(body.Keys, &protocol.KeySpecParams{KeyHash: keyHash(h)})
		}
		b := parse(*book)
		check(send(ctx, c, loadKey(*envFile, *envVar), b, b.JoinPath("1"), body))
	case "restrict":
		require(*page, "-page")
		p := parse(*page)
		check(send(ctx, c, loadKey(*envFile, *envVar), p, topPage(p), &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
			&protocol.UpdateAllowedKeyPageOperation{Deny: []protocol.TransactionType{
				protocol.TransactionTypeUpdateKeyPage, protocol.TransactionTypeUpdateAccountAuth}},
		}}))
	case "add-key", "remove-key":
		require(*page, "-page", *key, "-key")
		p := parse(*page)
		var op protocol.KeyPageOperation = &protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyHash(*key)}}
		if cmd == "remove-key" {
			op = &protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyHash(*key)}}
		}
		check(send(ctx, c, loadKey(*envFile, *envVar), p, topPage(p), &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{op}}))
	case "show":
		require(*target, "-url")
		kp, err := loadPage(ctx, c, parse(*target))
		check(err)
		fmt.Printf("%v version=%d credits=%s threshold=%d denied=%v\n", kp.Url, kp.Version,
			protocol.FormatAmount(kp.CreditBalance, protocol.CreditPrecisionPower), kp.AcceptThreshold, kp.TransactionBlacklist.Unpack())
		for _, e := range kp.Keys {
			fmt.Printf("  key %x\n", e.PublicKeyHash)
		}
	default:
		fail("unknown command " + cmd)
	}
}

// keygen writes a new key into envFile as envVar and returns its public key. A file that already sets
// envVar is refused: a key in use is replaced deliberately, never by a second run of this.
func keygen(envFile, envVar string) (ed25519.PublicKey, error) {
	if v, err := readEnv(envFile, envVar); err == nil && v != "" {
		return nil, fmt.Errorf("%s already sets %s", envFile, envVar)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(envFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		if b, err := os.ReadFile(envFile); err == nil && b[len(b)-1] != '\n' {
			if _, err := f.WriteString("\n"); err != nil {
				return nil, err
			}
		}
	}
	if _, err := fmt.Fprintf(f, "%s=%x\n", envVar, []byte(sk)); err != nil {
		return nil, err
	}
	return pub, f.Sync()
}

func buyCredits(ctx context.Context, c *jsonrpc.Client, sk ed25519.PrivateKey, to *url.URL, credits uint64) error {
	ns, err := c.NetworkStatus(ctx, api.NetworkStatusOptions{Partition: protocol.Directory})
	if err != nil {
		return fmt.Errorf("network status: %w", err)
	}
	oracle := ns.Oracle.Price
	if oracle == 0 {
		return fmt.Errorf("the network reports no ACME oracle price")
	}
	// credits(units) = acme * CreditUnitsPerFiatUnit * oracle / (AcmeOraclePrecision * AcmePrecision)
	amount := new(big.Int).SetUint64(credits * protocol.CreditPrecision)
	amount.Mul(amount, big.NewInt(int64(protocol.AcmeOraclePrecision*protocol.AcmePrecision)))
	amount.Div(amount, new(big.Int).SetUint64(protocol.CreditUnitsPerFiatUnit*oracle))
	lid := protocol.LiteAuthorityForKey(sk.Public().(ed25519.PublicKey), protocol.SignatureTypeED25519)
	lta := lid.JoinPath(protocol.ACME)
	before, _ := creditBalance(ctx, c, to)
	fmt.Printf("buying %d credits for %v with %s ACME from %v (oracle %d)\n", credits, to,
		protocol.FormatBigAmount(amount, protocol.AcmePrecisionPower), lta, oracle)
	if err := send(ctx, c, sk, lta, lid, &protocol.AddCredits{Recipient: to, Amount: *amount, Oracle: oracle}); err != nil {
		return err
	}
	// The credits arrive in a synthetic deposit after the purchase executes.
	for ctx.Err() == nil {
		if after, err := creditBalance(ctx, c, to); err == nil && after > before {
			fmt.Printf("%v credits: %s -> %s\n", to, protocol.FormatAmount(before, protocol.CreditPrecisionPower),
				protocol.FormatAmount(after, protocol.CreditPrecisionPower))
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("the purchase executed but %v's credits did not arrive: %w", to, ctx.Err())
}

// send signs body for principal as signer and waits until the network has executed it.
func send(ctx context.Context, c *jsonrpc.Client, sk ed25519.PrivateKey, principal, signer *url.URL, body protocol.TransactionBody) error {
	version := uint64(1)
	if _, _, isPage := protocol.ParseKeyPageUrl(signer); isPage {
		kp, err := loadPage(ctx, c, signer)
		if err != nil {
			return err
		}
		if _, _, ok := kp.EntryByKeyHash(sha256sum(sk.Public().(ed25519.PublicKey))); !ok {
			return fmt.Errorf("the key %x is not on %v", sk.Public(), signer)
		}
		version = kp.Version
	}
	tx := &protocol.Transaction{Header: protocol.TransactionHeader{Principal: principal}, Body: body}
	sig := &protocol.ED25519Signature{
		PublicKey:     sk.Public().(ed25519.PublicKey),
		Signer:        signer,
		SignerVersion: version,
		Timestamp:     uint64(time.Now().UnixMicro()),
	}
	init, err := sig.Initiator()
	if err != nil {
		return fmt.Errorf("initiator: %w", err)
	}
	copy(tx.Header.Initiator[:], init.MerkleHash())
	protocol.SignED25519(sig, sk, nil, tx.GetHash())
	sig.TransactionHash = *(*[32]byte)(tx.GetHash())
	env := &messaging.Envelope{Transaction: []*protocol.Transaction{tx}, Signatures: []protocol.Signature{sig}}
	subs, err := c.Submit(ctx, env, api.SubmitOptions{})
	if err != nil {
		return fmt.Errorf("submit %v: %w", body.Type(), err)
	}
	for _, s := range subs {
		if !s.Success {
			return fmt.Errorf("submit %v: %s", body.Type(), s.Message)
		}
	}
	txid := tx.ID()
	fmt.Printf("%v on %v signed by %v: %v\n", body.Type(), principal, signer, txid)
	for ctx.Err() == nil {
		r, err := api.Querier2{Querier: c}.QueryTransaction(ctx, txid, nil)
		if err == nil && r.Status == errors.Delivered {
			fmt.Printf("  executed\n")
			return nil
		}
		if err == nil && r.Error != nil {
			return fmt.Errorf("%v %v failed: %v", body.Type(), txid, r.Error)
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%v %v: not executed: %w", body.Type(), txid, ctx.Err())
}

func loadPage(ctx context.Context, c *jsonrpc.Client, u *url.URL) (*protocol.KeyPage, error) {
	kp := new(protocol.KeyPage)
	if _, err := (api.Querier2{Querier: c}).QueryAccountAs(ctx, u, nil, &kp); err != nil {
		return nil, fmt.Errorf("query %v: %w", u, err)
	}
	return kp, nil
}

func creditBalance(ctx context.Context, c *jsonrpc.Client, u *url.URL) (uint64, error) {
	r, err := api.Querier2{Querier: c}.QueryAccount(ctx, u, nil)
	if err != nil {
		return 0, err
	}
	ca, ok := r.Account.(protocol.AccountWithCredits)
	if !ok {
		return 0, fmt.Errorf("%v holds no credits", u)
	}
	return ca.GetCreditBalance(), nil
}

// topPage is the highest-priority page of p's book, the only page allowed to restrict or re-key p.
func topPage(p *url.URL) *url.URL {
	b, _, ok := protocol.ParseKeyPageUrl(p)
	if !ok {
		fail(fmt.Sprintf("%v is not a key page", p))
	}
	return b.JoinPath("1")
}

func loadKey(envFile, envVar string) ed25519.PrivateKey {
	require(envFile, "-env-file", envVar, "-var")
	v, err := readEnv(envFile, envVar)
	check(err)
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		fail(fmt.Sprintf("%s in %s is not a %d-byte hex ed25519 private key", envVar, envFile, ed25519.PrivateKeySize))
	}
	return ed25519.PrivateKey(b)
}

// readEnv returns the last value envFile gives envVar, as docker compose's env_file reads it.
func readEnv(envFile, envVar string) (string, error) {
	f, err := os.Open(envFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var v string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, val, ok := strings.Cut(line, "="); ok && strings.TrimSpace(strings.TrimPrefix(k, "export ")) == envVar {
			v = strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	return v, sc.Err()
}

func keyHash(h string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != ed25519.PublicKeySize {
		fail(fmt.Sprintf("%q is not a %d-byte hex public key", h, ed25519.PublicKeySize))
	}
	return sha256sum(b)
}

func sha256sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func parse(s string) *url.URL {
	u, err := url.Parse(s)
	check(err)
	return u
}

func require(pairs ...string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i] == "" {
			fail(pairs[i+1] + " is required")
		}
	}
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "protocol-writers:", msg)
	os.Exit(1)
}
