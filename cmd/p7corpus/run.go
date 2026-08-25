package main

// Running one corpus case: build the transaction, build the signatures, ask
// accumulate-core what it thinks of each, then submit and record what the
// network did.
//
// The order matters. The verdict is computed BEFORE submission, from the bytes
// themselves, so a network refusal cannot be mistaken for a cryptographic one
// and a network acceptance cannot stand in for a verdict we did not compute.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// protocolModule records which build of the protocol package produced the
// verdicts, because the verdicts are only as good as their reference.
const protocolModule = "gitlab.com/accumulatenetwork/accumulate v1.4.2"

// nonce hands out strictly increasing timestamps. Accumulate refuses a
// signature whose timestamp is not greater than the key's last used value, so
// two signatures made in the same millisecond by one key would collide.
var lastNonce uint64

func nonce() uint64 {
	n := uint64(time.Now().UnixMicro())
	if n <= lastNonce {
		n = lastNonce + 1
	}
	lastNonce = n
	return n
}

// buildSignature produces one signature exactly as accumulate-core would.
func buildSignature(seeds map[string]string, p signaturePlan, version, ts uint64,
	txn *protocol.Transaction, initiator bool) (protocol.Signature, error) {

	priv, err := keyFor(seeds, p.Seed)
	if err != nil {
		return nil, err
	}

	b := new(signing.Builder).
		SetUrl(mustURL(p.SignerPage)).
		SetPrivateKey(priv).
		SetVersion(version).
		SetTimestamp(ts)
	if p.Type != protocol.SignatureTypeUnknown {
		b.SetType(p.Type)
	}

	// Delegators are stated outermost-first. The builder wraps in the order it
	// is given, so the LAST one added ends up outermost - the list is walked
	// backwards. Getting this backwards produces a well-formed signature that
	// never verifies, which is precisely the failure mode
	// PHASE7_DELEGATION_PLAN section 1.3 warns about.
	for i := len(p.Delegators) - 1; i >= 0; i-- {
		b.AddDelegator(mustURL(p.Delegators[i]))
	}

	var sig protocol.Signature
	if initiator {
		sig, err = b.Initiate(txn)
	} else {
		sig, err = b.Sign(txn.GetHash())
	}
	if err != nil {
		return nil, err
	}

	if p.Merkle {
		if err := resignOverMerkleDigest(sig, priv, txn.GetHash()); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

// resignOverMerkleDigest re-signs the inner ed25519 over the Initiator() merkle
// digest instead of the metadata digest.
//
// Both are accepted (protocol/signature_utils.go:26-41). The builder only ever
// produces the metadata form, so the merkle form has to be asked for - and it
// is asked for through protocol.SignED25519, the same function the builder
// calls, rather than by assembling the digest by hand.
func resignOverMerkleDigest(sig protocol.Signature, priv ed25519.PrivateKey, txHash []byte) error {
	us, ok := sig.(protocol.UserSignature)
	if !ok {
		return fmt.Errorf("%v cannot produce an initiator hash", sig.Type())
	}
	h, err := us.Initiator()
	if err != nil {
		return fmt.Errorf("initiator: %w", err)
	}
	ks, _, err := innerKeySig(sig)
	if err != nil {
		return err
	}
	ed, ok := ks.(*protocol.ED25519Signature)
	if !ok {
		return fmt.Errorf("the merkle form is only built for ed25519, not %v", ks.Type())
	}
	protocol.SignED25519(ed, priv, h.MerkleHash(), txHash)
	return nil
}

// keyIsDirectOnOuterPage asks the chain whether the signing key is ALSO a plain
// entry on the outermost delegator page.
//
// Where it is, the case does not discriminate: an implementation that ignores
// delegation entirely, and only looks the key hash up on the page it is asked
// about, passes it anyway. That is worth knowing per case rather than assumed,
// because provision.py built the depth chains by creating every book with the
// same key - so C, E, G and H all have this property and D and F do not.
func keyIsDirectOnOuterPage(ctx context.Context, c *client, sp signaturePlan,
	ks protocol.KeySignature) (*bool, error) {

	if len(sp.Delegators) == 0 {
		return nil, nil
	}
	acct, err := account(ctx, c, mustURL(sp.Delegators[0]))
	if err != nil {
		return nil, err
	}
	kp, ok := acct.(*protocol.KeyPage)
	if !ok {
		return nil, fmt.Errorf("%s is not a key page", sp.Delegators[0])
	}
	want := hex.EncodeToString(ks.GetPublicKeyHash())
	direct := false
	for _, k := range kp.Keys {
		if hex.EncodeToString(k.PublicKeyHash) == want {
			direct = true
			break
		}
	}
	return &direct, nil
}

// traceOf renders a built signature into the corpus record, verdict included.
func traceOf(p casePlan, sp signaturePlan, sig protocol.Signature, txHash [32]byte,
	partition string) (trace, error) {

	verdict, form, digest, err := classify(sig, txHash)
	if err != nil {
		return trace{}, err
	}
	ks, path, err := innerKeySig(sig)
	if err != nil {
		return trace{}, err
	}

	delegators := make([]string, 0, len(path))
	for _, u := range path {
		delegators = append(delegators, u.String())
	}

	t := trace{
		Case:            p.Case,
		Shape:           p.Shape,
		Label:           fmt.Sprintf("%s/%s@%s", p.Case, sp.Seed, shortURL(sp.SignerPage)),
		Why:             p.Why,
		Expect:          p.Expect,
		RefusalKind:     p.RefusalKind,
		Principal:       p.Principal,
		TransactionHash: hex.EncodeToString(txHash[:]),
		Type:            sig.Type().String(),
		KeyType:         ks.Type().String(),
		Delegators:      delegators,
		PublicKey:       hex.EncodeToString(ks.GetPublicKey()),
		Signature:       hex.EncodeToString(ks.GetSignature()),
		Signer:          ks.GetSigner().String(),
		SignerVersion:   ks.GetSignerVersion(),
		Timestamp:       ks.GetTimestamp(),
		SignerPartition: partition,
		CoreVerdict:     verdict,
		DigestForm:      form,
	}
	if digest != nil {
		t.Digest = hex.EncodeToString(digest)
	}
	return t, nil
}

func shortURL(s string) string {
	if len(s) > 6 && s[:6] == "acc://" {
		return s[6:]
	}
	return s
}

// runCase builds, verdicts and submits one case.
func runCase(ctx context.Context, c *client, r *router, seeds map[string]string, p casePlan) ([]trace, error) {
	dataAccount := p.Principal + "/data"
	if err := ensureDataAccount(ctx, c, seeds, p, dataAccount); err != nil {
		return nil, err
	}

	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(dataAccount)
	txn.Body = &protocol.WriteData{
		Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{
			[]byte("certen phase 7 corpus " + p.Case),
			fmt.Append(nil, nonce()),
		}},
	}

	// The transaction hash is NOT read before the signatures are built.
	// Transaction.GetHash() memoizes and Initiate() sets Header.Initiator, so
	// reading the hash first caches one computed with a ZERO initiator; every
	// signature then covers that stale hash and the network refuses the whole
	// envelope with "transaction ... is not signed". The signatures are built
	// first and the hash is read once afterwards, when it is final.
	sigs := make([]protocol.Signature, 0, len(p.Signatures))
	for i, sp := range p.Signatures {
		if err := ensureKeyRegistered(ctx, c, seeds, p, sp); err != nil {
			return nil, err
		}
		version, err := pageVersion(ctx, c, sp.SignerPage)
		if err != nil {
			return nil, err
		}
		sig, err := buildSignature(seeds, sp, version, nonce(), txn, i == 0)
		if err != nil {
			return nil, fmt.Errorf("build %s: %w", sp.Seed, err)
		}
		sigs = append(sigs, sig)
	}

	var txHash [32]byte
	copy(txHash[:], txn.GetHash())

	traces := make([]trace, 0, len(p.Signatures))
	for i, sp := range p.Signatures {
		part, err := r.route(sp.SignerPage)
		if err != nil {
			return nil, err
		}
		t, err := traceOf(p, sp, sigs[i], txHash, part)
		if err != nil {
			return nil, err
		}
		ks, _, err := innerKeySig(sigs[i])
		if err != nil {
			return nil, err
		}
		if t.KeyIsDirectOnOuterPage, err = keyIsDirectOnOuterPage(ctx, c, sp, ks); err != nil {
			return nil, err
		}
		traces = append(traces, t)
		fmt.Printf("  %-24s core=%-5t form=%-16s signer=%s (%s)\n",
			t.Label, t.CoreVerdict, t.DigestForm, shortURL(t.Signer), part)
	}

	if p.SkipSubmit {
		return traces, nil
	}

	env := new(messaging.Envelope)
	env.Transaction = []*protocol.Transaction{txn}
	env.Signatures = sigs

	_, err := submit(ctx, c, env)
	for i := range traces {
		traces[i].Submitted = err == nil
		if err != nil {
			traces[i].SubmitError = err.Error()
		}
	}
	if err != nil {
		fmt.Printf("  submit refused: %v\n", err)
		return traces, nil
	}

	txid := txn.ID()
	status, execErr := awaitDelivered(ctx, c, txid, 90*time.Second)
	for i := range traces {
		traces[i].TxID = txid.String()
		traces[i].ExecStatus = status
		traces[i].ExecError = execErr
	}
	fmt.Printf("  submitted %s -> %s %s\n", txid.String(), status, execErr)
	return traces, nil
}

// ensureDataAccount creates the data account a case writes to, if it is not
// already there.
//
// It is created with the case's BOOTSTRAP signatures - keys that satisfy the
// ADI's authority directly - and never with the case's own signatures. A
// refusal case's signatures are supposed not to execute, so using them here
// would mean the case could never get as far as producing its specimen.
func ensureDataAccount(ctx context.Context, c *client, seeds map[string]string,
	p casePlan, dataAccount string) error {

	acct, err := account(ctx, c, mustURL(dataAccount))
	if err != nil {
		return err
	}
	if acct != nil {
		return nil
	}
	if len(p.Bootstrap) == 0 {
		return fmt.Errorf("%s does not exist and case %s has no bootstrap signer to create it",
			dataAccount, p.Case)
	}

	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(p.Principal)
	txn.Body = &protocol.CreateDataAccount{Url: mustURL(dataAccount)}

	sigs := make([]protocol.Signature, 0, len(p.Bootstrap))
	for i, sp := range p.Bootstrap {
		version, err := pageVersion(ctx, c, sp.SignerPage)
		if err != nil {
			return err
		}
		sig, err := buildSignature(seeds, sp, version, nonce(), txn, i == 0)
		if err != nil {
			return err
		}
		sigs = append(sigs, sig)
	}

	env := new(messaging.Envelope)
	env.Transaction = []*protocol.Transaction{txn}
	env.Signatures = sigs
	if _, err := submit(ctx, c, env); err != nil {
		return fmt.Errorf("create %s: %w", dataAccount, err)
	}
	status, execErr := awaitDelivered(ctx, c, txn.ID(), 120*time.Second)
	fmt.Printf("  created %s -> %s %s\n", dataAccount, status, execErr)

	acct, err = account(ctx, c, mustURL(dataAccount))
	if err != nil {
		return err
	}
	if acct == nil {
		// The submission being accepted says nothing about execution; this is
		// the check that distinguishes them.
		return fmt.Errorf("%s still does not exist after submission (status %s %s)",
			dataAccount, status, execErr)
	}
	return nil
}

// ensureKeyRegistered puts a non-ed25519 signature's key hash on its page.
//
// Without this, case K would prove nothing. A BTC signature from a key the page
// does not carry is refused for NOT BEING ON THE PAGE, which is a membership
// reason - and the whole point of case K is that an unsupported TYPE must be
// refused with its own reason rather than one that reads as a threshold
// shortfall. The key has to be a legitimate member so that its type is the only
// thing wrong with it.
func ensureKeyRegistered(ctx context.Context, c *client, seeds map[string]string,
	p casePlan, sp signaturePlan) error {

	if sp.Type == protocol.SignatureTypeUnknown || sp.Type == protocol.SignatureTypeED25519 {
		return nil
	}
	priv, err := keyFor(seeds, sp.Seed)
	if err != nil {
		return err
	}

	// Derive the public key the way the signature will carry it, then hash it
	// the way the signature type hashes it - both through protocol, so the page
	// entry and the signature cannot disagree.
	probe, err := protocol.NewSignature(sp.Type)
	if err != nil {
		return err
	}
	if err := signing.PrivateKey(priv).SetPublicKey(probe); err != nil {
		return err
	}
	ks, ok := probe.(protocol.KeySignature)
	if !ok {
		return fmt.Errorf("%v is not a key signature", sp.Type)
	}
	hash := ks.GetPublicKeyHash()

	acct, err := account(ctx, c, mustURL(sp.SignerPage))
	if err != nil {
		return err
	}
	kp, ok := acct.(*protocol.KeyPage)
	if !ok || acct == nil {
		return fmt.Errorf("%s is not a key page", sp.SignerPage)
	}
	for _, k := range kp.Keys {
		if hex.EncodeToString(k.PublicKeyHash) == hex.EncodeToString(hash) {
			return nil
		}
	}

	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(sp.SignerPage)
	txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
		&protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: hash}},
	}}

	sigs := make([]protocol.Signature, 0, len(p.Bootstrap))
	for i, bs := range p.Bootstrap {
		version, err := pageVersion(ctx, c, bs.SignerPage)
		if err != nil {
			return err
		}
		sig, err := buildSignature(seeds, bs, version, nonce(), txn, i == 0)
		if err != nil {
			return err
		}
		sigs = append(sigs, sig)
	}
	env := new(messaging.Envelope)
	env.Transaction = []*protocol.Transaction{txn}
	env.Signatures = sigs
	if _, err := submit(ctx, c, env); err != nil {
		return fmt.Errorf("register %v key on %s: %w", sp.Type, sp.SignerPage, err)
	}
	status, execErr := awaitDelivered(ctx, c, txn.ID(), 120*time.Second)
	fmt.Printf("  registered %v key %s on %s -> %s %s\n",
		sp.Type, hex.EncodeToString(hash)[:16], shortURL(sp.SignerPage), status, execErr)

	acct, err = account(ctx, c, mustURL(sp.SignerPage))
	if err != nil {
		return err
	}
	if kp, ok := acct.(*protocol.KeyPage); ok {
		for _, k := range kp.Keys {
			if hex.EncodeToString(k.PublicKeyHash) == hex.EncodeToString(hash) {
				return nil
			}
		}
	}
	return fmt.Errorf("%v key is still not on %s after submission (status %s %s)",
		sp.Type, sp.SignerPage, status, execErr)
}

// marker
