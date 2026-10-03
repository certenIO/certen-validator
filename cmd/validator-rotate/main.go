// Command validator-rotate rotates a validator's CometBFT consensus key on the running chain (RB3-F95).
//
// The validator set is consensus state. Replacing a key file changes nothing the chain recognises; the chain
// must agree to the new key, by a transaction the sealed admin quorum signs. This tool builds, signs,
// preflights and submits that transaction. The runbook is RUNBOOK_F95_CONSENSUS_KEY_ROTATION.md.
//
//	validator-rotate keygen --kind consensus|node --out <seed-file>
//	    A fresh 32-byte secret seed, written to a NEW file (0600; an existing file is never overwritten).
//	    Prints the public key / node id. The seed never leaves the file: it becomes the validator's
//	    COMET_PRIVVAL_SEED (or COMET_NODE_KEY_SEED) and an offline backup.
//
//	validator-rotate propose --chain-id C --version V --old <pubkey> --new-seed @<seed-file> \
//	    --admin-key-id A --admin-secret @<file> --out tx.json
//	    The rotation, the new key's proof of possession and the first admin signature.
//
//	validator-rotate sign --tx tx.json --admin-key-id B --admin-secret @<file>
//	    Another admin's signature (the sealed threshold decides how many).
//
//	validator-rotate preflight --tx tx.json --rpc http://v1:26657,http://v2:26657,...
//	    Every validator's RPC: all run the rotation rules, all on the tx's chain, the old key is in the set,
//	    the new key is not, and no earlier rotation is still waiting for its new key to sign. GO or NO-GO.
//
//	validator-rotate submit --tx tx.json --rpc http://v1:26657
//	    Commit it. Prints the height, and the height from which the slot belongs to the new key.
//
//	validator-rotate status --rpc http://v1:26657
//	    The chain's rotation log: accepted rotations and whether each new key has signed yet.
//
//	validator-rotate tick --rpc http://v1:26657 [--count N]
//	    Make the chain produce N blocks. Empty blocks are disabled, so on an idle chain a rotation takes
//	    effect (two blocks after it) and is adopted (a later block carrying the new key's signature) only
//	    when blocks are made; a tick is a transaction that changes nothing else.
//
//	validator-rotate history-check --rpc http://v1:26657
//	    Read every committed block and report any transaction of the kinds rules v8 adds. Rules v8
//	    continues v7 state only because there are none; this proves it for the chain at hand.
//
//	validator-rotate history-check --rules 12 --rpc http://v1:26657
//	    Read every committed block and its result codes and judge them as a v12 node does before it starts:
//	    no transaction of a kind v10-v12 added decided the older way, no block with two accepted validator
//	    rotations. Run against the live chain before deploying v12; every node repeats it when it starts.
//
//	validator-rotate admin-rotate keygen|status|request|possess|sign|preflight|submit
//	    Rotate CERTEN's admin set with the admin quorum in force (rules v12; adminrotate.go).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// rotationRulesVersion is the execution-rules version that recognises a rotation. Every validator must
// report it before a rotation is submitted: a node on older rules would judge the block differently.
const rotationRulesVersion = 8

// formulaIDs is how many validator-N formula keys are checked against: the fleet is validator-1..7, with
// headroom so a future validator-8.. cannot be handed a derivable key either.
const formulaIDs = 64

// maxHeightLag is how far behind the highest node a validator may be at preflight.
const maxHeightLag = 2

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "propose":
		err = propose(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "preflight":
		err = preflight(os.Args[2:], http.DefaultClient)
	case "submit":
		err = submit(os.Args[2:], http.DefaultClient)
	case "status":
		err = status(os.Args[2:], http.DefaultClient)
	case "tick":
		err = tick(os.Args[2:], http.DefaultClient)
	case "history-check":
		err = historyCheck(os.Args[2:], http.DefaultClient)
	case "bls-possession":
		err = blsPossession(os.Args[2:])
	case "bls-registry-propose":
		err = blsRegistryPropose(os.Args[2:])
	case "bls-registry-sign":
		err = blsRegistrySign(os.Args[2:])
	case "bls-registry-preflight":
		err = blsRegistryPreflight(os.Args[2:], http.DefaultClient)
	case "bls-registry-submit":
		err = blsRegistrySubmit(os.Args[2:], http.DefaultClient)
	case "admin-reseal":
		err = adminReseal(os.Args[2:], http.DefaultClient)
	case "admin-rotate":
		err = adminRotate(os.Args[2:], http.DefaultClient)
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
	fmt.Fprint(os.Stderr, `validator-rotate - rotate a validator's CometBFT consensus key on the running chain

  keygen     a fresh secret seed in a new file; prints the public key or node id
  propose    build the rotation, its proof of possession and the first admin signature
  sign       add another admin signature
  preflight  check every validator is ready for this rotation (GO / NO-GO)
  submit     commit the rotation
  status     the chain's rotation log
  tick       make the chain produce blocks (empty blocks are disabled)
  history-check  prove no committed transaction is of a kind rules v8 adds (--rules 12: judge history as v12 does)

  bls-possession          on a validator: its BLS registry entry and the key's proof of possession
  bls-registry-propose    assemble the BLS registry (RB5 D3), verify every possession, first admin signature
  bls-registry-sign       add another admin signature
  bls-registry-preflight  every node runs the same rules, v10 or later, and every anchor commits the registry's CERTEN set root
  bls-registry-submit     commit the registry: from the next block every ValidatorBlock carries an intent certificate

  admin-reseal            every node runs rules v11, then commit the one admin re-seal they define (certen-testnet)

  admin-rotate keygen     a fresh admin key: secret to a new file, public key printed
  admin-rotate status     the admin set in force, its id, the next sequence, every change recorded
  admin-rotate request    the unsigned rotation to a new admin set (rules v12)
  admin-rotate possess    a new key's proof of possession
  admin-rotate sign       a current admin's approval, offline
  admin-rotate preflight  every node on rules v12 reports the same admin set, and the chain's rule accepts the rotation
  admin-rotate submit     preflight, then commit it (--dry-run: preflight only)

Run any subcommand with --help for its flags. The runbook is RUNBOOK_F95_CONSENSUS_KEY_ROTATION.md.
`)
}

// writeNewSecret writes a secret to a file that must not exist yet, readable by its owner only.
func writeNewSecret(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s (an existing file is never overwritten): %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	kind := fs.String("kind", "consensus", "consensus (COMET_PRIVVAL_SEED) or node (COMET_NODE_KEY_SEED)")
	out := fs.String("out", "", "new file for the seed (required; never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required: the seed is written to a file, never printed")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	switch *kind {
	case "consensus":
		key := consensus.CometPrivvalKeyFromSeed(seed)
		if err := writeNewSecret(*out, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
			return err
		}
		pub := key.PubKey().Bytes()
		fmt.Printf("consensus public key (hex):    %s\n", hex.EncodeToString(pub))
		fmt.Printf("consensus public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("validator address:             %s\n", key.PubKey().Address())
		fmt.Fprintf(os.Stderr, "\nThe seed is in %s. It becomes this validator's COMET_PRIVVAL_SEED and must be backed up "+
			"OFFLINE before the rotation is submitted: after the rotation the chain accepts no other key for this slot.\n", *out)
	case "node":
		key := consensus.CometNodeKeyFromSeed(seed)
		if err := writeNewSecret(*out, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
			return err
		}
		fmt.Printf("node id: %s\n", key.PubKey().Address())
		fmt.Fprintf(os.Stderr, "\nThe seed is in %s. It becomes this validator's COMET_NODE_KEY_SEED; every other "+
			"validator's COMETBFT_P2P_PERSISTENT_PEERS must name the new node id.\n", *out)
	default:
		return fmt.Errorf("--kind must be consensus or node")
	}
	return nil
}

// loadSeed reads a 32-byte hex seed, from @path or inline.
func loadSeed(v string) ([]byte, error) {
	raw := strings.TrimSpace(v)
	if strings.HasPrefix(raw, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(raw, "@"))
		if err != nil {
			return nil, fmt.Errorf("read secret file: %w", err)
		}
		raw = strings.TrimSpace(string(b))
	}
	seed, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil || len(seed) != 32 {
		return nil, errors.New("a secret is 32 bytes of hex (the value is not printed)")
	}
	return seed, nil
}

// loadAdmin reads an admin secret: the ed25519 seed policy-update keygen printed.
func loadAdmin(v string) (ed25519.PrivateKey, error) {
	seed, err := loadSeed(v)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// parsePubKey accepts a consensus public key as hex or as the base64 CometBFT prints.
func parsePubKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if b, err := hex.DecodeString(strings.TrimPrefix(v, "0x")); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	return nil, fmt.Errorf("%q is not an ed25519 public key (hex or base64)", v)
}

func buildRotation(chainID string, version uint64, oldPub []byte, newSeed []byte) (*consensus.ValidatorRotationTx, error) {
	newKey := consensus.CometPrivvalKeyFromSeed(newSeed)
	newPub := newKey.PubKey().Bytes()
	if bytes.Equal(newPub, oldPub) {
		return nil, errors.New("the new key is the old key")
	}
	if id, ok := consensus.IsFormulaKey(chainID, newPub, formulaIDs); ok {
		return nil, fmt.Errorf("the new key is %s's public-formula key - anyone can derive it", id)
	}
	tx := &consensus.ValidatorRotationTx{
		Kind: consensus.ValidatorRotationKind, ChainID: chainID, Version: version,
		OldPubKey: hex.EncodeToString(oldPub), NewPubKey: hex.EncodeToString(newPub),
	}
	tx.Possession = hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(newKey), tx.PossessionBytes()))
	if err := tx.CheckShape(); err != nil {
		return nil, err
	}
	return tx, nil
}

func addSignature(tx *consensus.ValidatorRotationTx, keyID string, admin ed25519.PrivateKey) error {
	for _, s := range tx.Signatures {
		if s.KeyID == keyID {
			return fmt.Errorf("admin %q has already signed this rotation", keyID)
		}
	}
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{
		KeyID: keyID, Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes())),
	})
	return nil
}

func propose(args []string) error {
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	chainID := fs.String("chain-id", "", "the CometBFT chain id (genesis chain_id)")
	version := fs.Uint64("version", 0, "the next rotation version (status shows the current one)")
	oldKey := fs.String("old", "", "the consensus public key leaving the set (hex or base64)")
	newSeed := fs.String("new-seed", "", "@<seed-file> from keygen --kind consensus")
	keyID := fs.String("admin-key-id", "", "this admin's key id")
	secret := fs.String("admin-secret", "", "@<file> holding this admin's secret")
	out := fs.String("out", "", "write the transaction here (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainID == "" || *version == 0 || *oldKey == "" || *newSeed == "" || *keyID == "" || *secret == "" || *out == "" {
		return errors.New("--chain-id, --version, --old, --new-seed, --admin-key-id, --admin-secret and --out are required")
	}
	oldPub, err := parsePubKey(*oldKey)
	if err != nil {
		return err
	}
	seed, err := loadSeed(*newSeed)
	if err != nil {
		return err
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	tx, err := buildRotation(*chainID, *version, oldPub, seed)
	if err != nil {
		return err
	}
	if err := addSignature(tx, *keyID, admin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "rotation v%d on %s: %s -> %s (new validator address %s)\n", tx.Version, tx.ChainID,
		tx.OldPubKey, tx.NewPubKey, cmted25519.PubKey(mustHex(tx.NewPubKey)).Address())
	return writeTx(tx, *out, false)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the rotation to sign")
	keyID := fs.String("admin-key-id", "", "this admin's key id")
	secret := fs.String("admin-secret", "", "@<file> holding this admin's secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readTx(*path)
	if err != nil {
		return err
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	if err := addSignature(tx, *keyID, admin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "admin signatures on this rotation: %d\n", len(tx.Signatures))
	return writeTx(tx, *path, true)
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func readTx(path string) (*consensus.ValidatorRotationTx, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeValidatorRotation(b)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.ValidatorRotationKind)
	}
	if err := tx.CheckShape(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return tx, nil
}

func writeTx(tx *consensus.ValidatorRotationTx, path string, replace bool) error {
	b, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if replace {
		return os.WriteFile(path, b, 0o600)
	}
	return writeNewSecret(path, b)
}

// ---- RPC -----------------------------------------------------------------------------------------------

type rpcDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func rpcCall(c rpcDoer, base, method string, params map[string]any, out any) error {
	return rpcCallParams(c, base, method, params, out)
}

// rpcCallParams is rpcCall with params of any JSON shape: CometBFT takes an object, Ethereum JSON-RPC a list.
func rpcCallParams(c rpcDoer, base, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", base, method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s %s: unreadable reply: %w", base, method, err)
	}
	if env.Error != nil {
		return fmt.Errorf("%s %s: %s %s", base, method, env.Error.Message, env.Error.Data)
	}
	return json.Unmarshal(env.Result, out)
}

type nodeView struct {
	rpc        string
	chainID    string
	height     int64
	appVersion uint64
	set        map[string]int64 // hex pubkey -> power
	rotations  *ledger.ValidatorRotationLog
}

func readNode(c rpcDoer, base string) (*nodeView, error) {
	v := &nodeView{rpc: base, set: map[string]int64{}}
	var info struct {
		Response struct {
			AppVersion string `json:"app_version"`
		} `json:"response"`
	}
	if err := rpcCall(c, base, "abci_info", map[string]any{}, &info); err != nil {
		return nil, err
	}
	fmt.Sscanf(info.Response.AppVersion, "%d", &v.appVersion)
	var st struct {
		NodeInfo struct {
			Network string `json:"network"`
		} `json:"node_info"`
		SyncInfo struct {
			LatestBlockHeight string `json:"latest_block_height"`
		} `json:"sync_info"`
	}
	if err := rpcCall(c, base, "status", map[string]any{}, &st); err != nil {
		return nil, err
	}
	v.chainID = st.NodeInfo.Network
	fmt.Sscanf(st.SyncInfo.LatestBlockHeight, "%d", &v.height)
	var vals struct {
		Validators []struct {
			PubKey struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"pub_key"`
			VotingPower string `json:"voting_power"`
		} `json:"validators"`
	}
	if err := rpcCall(c, base, "validators", map[string]any{"per_page": "100"}, &vals); err != nil {
		return nil, err
	}
	for _, val := range vals.Validators {
		pub, err := base64.StdEncoding.DecodeString(val.PubKey.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: undecodable validator key", base)
		}
		var p int64
		fmt.Sscanf(val.VotingPower, "%d", &p)
		v.set[hex.EncodeToString(pub)] = p
	}
	var q struct {
		Response struct {
			Code  uint32 `json:"code"`
			Log   string `json:"log"`
			Value string `json:"value"`
		} `json:"response"`
	}
	if err := rpcCall(c, base, "abci_query", map[string]any{"path": "/certen/validator_rotations"}, &q); err != nil {
		return nil, err
	}
	if q.Response.Code != 0 {
		return nil, fmt.Errorf("%s: the rotation log is not available (%s) - is this node on rules v%d?", base, q.Response.Log, rotationRulesVersion)
	}
	raw, err := base64.StdEncoding.DecodeString(q.Response.Value)
	if err != nil {
		return nil, err
	}
	v.rotations = &ledger.ValidatorRotationLog{}
	if err := json.Unmarshal(raw, v.rotations); err != nil {
		return nil, fmt.Errorf("%s: unreadable rotation log: %w", base, err)
	}
	return v, nil
}

// preflightChecks judges a rotation against every validator's view. It returns the reasons it must not be
// submitted; none means GO.
// fleetRulesProblems is why a fleet is not ready for a transaction kind that rules v<min> introduced: every node must
// run rules v<min> or later, and all the same version - nodes on different rules judge the same block differently
// (from v11, for instance, admin signatures are judged by the admin set in force, which a re-seal changes).
func fleetRulesProblems(views []*nodeView, min uint64, what string) []string {
	var problems []string
	for _, v := range views {
		if v.appVersion < min {
			problems = append(problems, fmt.Sprintf("%s runs execution rules v%d; the %s needs v%d or later", v.rpc, v.appVersion, what, min))
		}
		if v.appVersion != views[0].appVersion {
			problems = append(problems, fmt.Sprintf("%s runs execution rules v%d and %s v%d: the whole fleet must run the same rules",
				v.rpc, v.appVersion, views[0].rpc, views[0].appVersion))
		}
	}
	return problems
}

func preflightChecks(tx *consensus.ValidatorRotationTx, views []*nodeView) []string {
	var nogo []string
	if len(views) == 0 {
		return []string{"no validator RPC endpoint given"}
	}
	oldKey, newKey := strings.ToLower(tx.OldPubKey), strings.ToLower(tx.NewPubKey)
	if id, ok := consensus.IsFormulaKey(tx.ChainID, mustHex(newKey), formulaIDs); ok {
		nogo = append(nogo, fmt.Sprintf("the new key is %s's public-formula key", id))
	}
	nogo = append(nogo, fleetRulesProblems(views, rotationRulesVersion, "rotation")...)
	for _, v := range views {
		if v.chainID != tx.ChainID {
			nogo = append(nogo, fmt.Sprintf("%s is on chain %q, the rotation is for %q", v.rpc, v.chainID, tx.ChainID))
		}
		if _, ok := v.set[oldKey]; !ok {
			nogo = append(nogo, fmt.Sprintf("%s: the old key is not in the validator set", v.rpc))
		}
		if _, ok := v.set[newKey]; ok {
			nogo = append(nogo, fmt.Sprintf("%s: the new key already holds a slot", v.rpc))
		}
		// The chain accepts only the next version, and while the latest rotation's new key has not signed,
		// only a re-rotation of that same slot.
		var latest *ledger.ValidatorRotationRecord
		for i := range v.rotations.Rotations {
			if r := &v.rotations.Rotations[i]; latest == nil || r.Version > latest.Version {
				latest = r
			}
		}
		want := uint64(1)
		if latest != nil {
			want = latest.Version + 1
			if latest.AdoptedHeight == 0 && !strings.EqualFold(latest.NewPubKey, oldKey) {
				nogo = append(nogo, fmt.Sprintf("%s: rotation v%d (height %d) is not adopted - its new key has not signed yet",
					v.rpc, latest.Version, latest.Height))
			}
		}
		if tx.Version != want {
			nogo = append(nogo, fmt.Sprintf("%s: the next rotation version is %d, this is %d", v.rpc, want, tx.Version))
		}
	}
	// The set as the first node reports it: after this rotation, the validators still able to sign must hold
	// more than two thirds of the power, with the rotated one counted out until it runs its new key.
	var total, remaining int64
	for k, p := range views[0].set {
		total += p
		if k != oldKey {
			remaining += p
		}
	}
	if total > 0 && remaining*3 <= total*2 {
		nogo = append(nogo, fmt.Sprintf("with this validator out, %d of %d power remains - not more than two thirds", remaining, total))
	}
	// Every validator must be keeping up: the rotation takes one slot out until its new key runs, so the
	// others must all be live to keep the margin the chain has.
	var top int64
	for _, v := range views {
		if v.height > top {
			top = v.height
		}
	}
	for _, v := range views {
		if top-v.height > maxHeightLag {
			nogo = append(nogo, fmt.Sprintf("%s is at height %d, %d behind: every validator must be caught up", v.rpc, v.height, top-v.height))
		}
	}
	if len(views) < len(views[0].set) {
		nogo = append(nogo, fmt.Sprintf("only %d of %d validators were checked: preflight every validator", len(views), len(views[0].set)))
	}
	return nogo
}

func splitRPCs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func preflight(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	path := fs.String("tx", "", "the signed rotation")
	rpcs := fs.String("rpc", "", "EVERY validator's CometBFT RPC, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tx, err := readTx(*path)
	if err != nil {
		return err
	}
	var views []*nodeView
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		fmt.Printf("%s: chain %s height %d rules v%d validators %d rotations %d\n", base, v.chainID, v.height, v.appVersion, len(v.set), len(v.rotations.Rotations))
		views = append(views, v)
	}
	if nogo := preflightChecks(tx, views); len(nogo) > 0 {
		for _, r := range nogo {
			fmt.Println("  NO-GO:", r)
		}
		return errors.New("NO-GO")
	}
	fmt.Printf("GO: rotation v%d, %d admin signature(s) attached (the chain verifies them against its sealed quorum)\n", tx.Version, len(tx.Signatures))
	return nil
}

func submit(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	path := fs.String("tx", "", "the signed, preflighted rotation")
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *rpc == "" {
		return errors.New("--tx and --rpc are required")
	}
	h, err := broadcastCommit(c, *rpc, *path)
	if err != nil {
		return err
	}
	fmt.Printf("ACCEPTED at height %d. From height %d the slot belongs to the new key: switch that validator to it now "+
		"(runbook step 5); until it signs, no further rotation is accepted.\n", h, h+2)
	return nil
}

// broadcastCommit commits the transaction in the file at path through one validator's RPC and returns its height.
// Any non-zero code is a refusal - reported as one, never as success.
func broadcastCommit(c rpcDoer, rpc, path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return 0, fmt.Errorf("the transaction is not JSON: %w", err)
	}
	var res struct {
		CheckTx struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"check_tx"`
		TxResult struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"tx_result"`
		Height string `json:"height"`
	}
	if err := rpcCall(c, rpc, "broadcast_tx_commit", map[string]any{"tx": base64.StdEncoding.EncodeToString(compact.Bytes())}, &res); err != nil {
		return 0, err
	}
	if res.CheckTx.Code != 0 {
		return 0, fmt.Errorf("REFUSED by the mempool (code %d): %s", res.CheckTx.Code, res.CheckTx.Log)
	}
	if res.TxResult.Code != 0 {
		return 0, fmt.Errorf("REFUSED by the chain at height %s (code %d): %s", res.Height, res.TxResult.Code, res.TxResult.Log)
	}
	h, err := strconv.ParseInt(res.Height, 10, 64)
	if err != nil || h <= 0 {
		return 0, fmt.Errorf("the chain accepted the transaction at an unreadable height %q", res.Height)
	}
	return h, nil
}

func status(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := readNode(c, *rpc)
	if err != nil {
		return err
	}
	fmt.Printf("chain %s height %d rules v%d, %d validators\n", v.chainID, v.height, v.appVersion, len(v.set))
	for _, k := range consensus.ValidatorSetSummary(v.set) {
		fmt.Println("  ", k)
	}
	if len(v.rotations.Rotations) == 0 {
		fmt.Println("no rotations; the next version is 1")
		return nil
	}
	for _, r := range v.rotations.Rotations {
		state := fmt.Sprintf("adopted at %d", r.AdoptedHeight)
		if r.AdoptedHeight == 0 {
			state = "NOT ADOPTED - its new key has not signed yet"
		}
		fmt.Printf("  v%d at height %d: %s... -> %s... power %d, %s\n", r.Version, r.Height, r.OldPubKey[:12], r.NewPubKey[:12], r.Power, state)
	}
	return nil
}

func tick(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("tick", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	count := fs.Int("count", 1, "how many blocks to make (1..20)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rpc == "" || *count < 1 || *count > 20 {
		return errors.New("--rpc is required and --count is 1..20")
	}
	for i := 0; i < *count; i++ {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		b, err := json.Marshal(consensus.ChainTickTx{Kind: consensus.ChainTickKind, Nonce: hex.EncodeToString(nonce)})
		if err != nil {
			return err
		}
		var res struct {
			CheckTx struct {
				Code uint32 `json:"code"`
				Log  string `json:"log"`
			} `json:"check_tx"`
			TxResult struct {
				Code uint32 `json:"code"`
				Log  string `json:"log"`
			} `json:"tx_result"`
			Height string `json:"height"`
		}
		if err := rpcCall(c, *rpc, "broadcast_tx_commit", map[string]any{"tx": base64.StdEncoding.EncodeToString(b)}, &res); err != nil {
			return err
		}
		if res.CheckTx.Code != 0 || res.TxResult.Code != 0 {
			return fmt.Errorf("tick refused (check %d, deliver %d): %s%s - is every node on rules v%d?",
				res.CheckTx.Code, res.TxResult.Code, res.CheckTx.Log, res.TxResult.Log, rotationRulesVersion)
		}
		fmt.Printf("block %s\n", res.Height)
	}
	return nil
}

// v8Kinds are the transaction kinds rules v8 adds; pre-v8 history must contain none.
var v8Kinds = map[string]bool{consensus.ValidatorRotationKind: true, consensus.ChainTickKind: true}

// kindOf is a transaction's declared kind, "" when it declares none.
func kindOf(tx []byte) string {
	var probe struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(tx, &probe) != nil {
		return ""
	}
	return probe.Kind
}

func historyCheck(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("history-check", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC (it must hold every block from 1)")
	rules := fs.Int("rules", 8, "the rules whose continuation to check: 8 (the kinds v8 adds) or 12 (history as v12 judges it)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rpc == "" {
		return errors.New("--rpc is required")
	}
	switch *rules {
	case 8:
	case 12:
		return historyCheckV12(*rpc, c)
	default:
		return fmt.Errorf("--rules is 8 or 12")
	}
	var st struct {
		SyncInfo struct {
			LatestBlockHeight   string `json:"latest_block_height"`
			EarliestBlockHeight string `json:"earliest_block_height"`
		} `json:"sync_info"`
	}
	if err := rpcCall(c, *rpc, "status", map[string]any{}, &st); err != nil {
		return err
	}
	var chainStatus struct {
		NodeInfo struct {
			Network string `json:"network"`
		} `json:"node_info"`
	}
	if err := rpcCall(c, *rpc, "status", map[string]any{}, &chainStatus); err != nil {
		return err
	}
	chainID := chainStatus.NodeInfo.Network
	var latest, earliest int64
	fmt.Sscanf(st.SyncInfo.LatestBlockHeight, "%d", &latest)
	fmt.Sscanf(st.SyncInfo.EarliestBlockHeight, "%d", &earliest)
	if earliest != 1 {
		return fmt.Errorf("this node's history starts at block %d, not 1: the check needs every block", earliest)
	}
	kinds := map[string]int{}
	var txs, blocksWithTxs int
	var found []string
	for h := int64(1); h <= latest; h++ {
		var blk struct {
			Block struct {
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		}
		if err := rpcCall(c, *rpc, "block", map[string]any{"height": fmt.Sprintf("%d", h)}, &blk); err != nil {
			return err
		}
		if len(blk.Block.Data.Txs) > 0 {
			blocksWithTxs++
		}
		for _, enc := range blk.Block.Data.Txs {
			raw, err := base64.StdEncoding.DecodeString(enc)
			if err != nil {
				return fmt.Errorf("block %d: undecodable transaction", h)
			}
			txs++
			k := kindOf(raw)
			kinds[k]++
			if v8Kinds[k] {
				found = append(found, fmt.Sprintf("block %d: %s", h, k))
			}
			// Rules v8 accepts a policy update committed before it only if it is one of the allowlisted
			// ones (RB3-F117); any other would be judged differently on replay.
			if k == consensus.PolicyUpdateKind {
				pu, ok := consensus.DecodePolicyUpdate(raw)
				if !ok || pu.ChainID != "" || !consensus.IsCommittedLegacyPolicyUpdate(chainID, pu) {
					found = append(found, fmt.Sprintf("block %d: a policy update rules v8 does not recognise as committed before it", h))
				}
			}
		}
	}
	fmt.Printf("blocks 1..%d read: %d with transactions, %d transactions\n", latest, blocksWithTxs, txs)
	for k, n := range kinds {
		if k == "" {
			k = "(no kind: ValidatorBlock)"
		}
		fmt.Printf("  %-40s %d\n", k, n)
	}
	if len(found) > 0 {
		for _, f := range found {
			fmt.Println("  FOUND:", f)
		}
		return errors.New("the chain holds transactions rules v8 would judge differently: v8 must NOT continue this state")
	}
	fmt.Println("no transaction of a kind rules v8 adds, and every policy update is one v8 recognises: v8 continues this chain's history exactly")
	return nil
}
