package main

// The admin rotation subcommands (rules v12, pkg/consensus/admin_rotate.go): the admin quorum in force replaces the
// admin set - replacing, adding or removing keys and changing the threshold. Nothing here creates or changes a key
// unless the owner runs keygen; every secret is read from a file and never printed.
//
//	validator-rotate admin-rotate keygen --out <seed-file>
//	    A fresh admin key: its secret seed written to a NEW file (0600, never overwritten), its public key printed.
//
//	validator-rotate admin-rotate status --rpc http://v1:26657
//	    The admin set in force, its id, the sequence the next rotation carries, and every change recorded.
//
//	validator-rotate admin-rotate request --rpc http://v1:26657 --new-set new-set.json --out req.json
//	validator-rotate admin-rotate request --chain-id C --sequence N --current-set-id <id> --new-set new-set.json --out req.json
//	    The unsigned request: the chain, the sequence and the set in force (read from a node, or given), and the new
//	    set from new-set.json: {"admin_keys": {"<id>": "<hex ed25519 public key>", ...}, "threshold": T}.
//
//	validator-rotate admin-rotate possess --tx req.json --key-id ID --secret @<seed-file>
//	    One new key's proof of possession (run by that key's holder). Every new key - a kept one too - signs one.
//
//	validator-rotate admin-rotate sign --tx req.json --admin-key-id ID --admin-secret @<seed-file>
//	    One current admin's approval, OFFLINE. Shows what is being approved first.
//
//	validator-rotate admin-rotate preflight --tx req.json --rpc http://v1:26657,http://v2:26657,...
//	validator-rotate admin-rotate submit    --tx req.json --rpc http://v1:26657,... [--dry-run]
//	    Every validator: rules v12 or later and all the same, one chain, caught up, all reporting the same admin set;
//	    the request judged by the chain's own rule against that set - the sequence, the set in force, the threshold
//	    of distinct current admins, every possession. GO, submit commits it through the first RPC (unless --dry-run)
//	    and confirms the node recorded it.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// adminRotateRulesVersion is the execution-rules version that recognises an admin rotation.
const adminRotateRulesVersion = 12

func adminRotate(args []string, c rpcDoer) error {
	if len(args) == 0 {
		return errors.New("admin-rotate needs a subcommand: keygen, status, request, possess, sign, preflight, submit")
	}
	switch args[0] {
	case "keygen":
		return adminRotateKeygen(args[1:])
	case "status":
		return adminRotateStatus(args[1:], c)
	case "request":
		return adminRotateRequest(args[1:], c)
	case "possess":
		return adminRotatePossess(args[1:])
	case "sign":
		return adminRotateSign(args[1:])
	case "preflight":
		return adminRotateSubmit(append([]string{"--dry-run"}, args[1:]...), c, "preflight")
	case "submit":
		return adminRotateSubmit(args[1:], c, "submit")
	default:
		return fmt.Errorf("unknown admin-rotate subcommand %q", args[0])
	}
}

func adminRotateKeygen(args []string) error {
	fs := flag.NewFlagSet("admin-rotate keygen", flag.ContinueOnError)
	out := fs.String("out", "", "new file for the admin key's secret seed (required; never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required: the secret is written to a file, never printed")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := writeNewSecret(*out, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
		return err
	}
	fmt.Printf("admin public key (hex): %s\n", hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)))
	fmt.Fprintf(os.Stderr, "\nThe secret is in %s. Back it up OFFLINE before it goes into any admin set: the chain refuses a key "+
		"without its proof of possession, and a key that leaves the set can never come back.\n", *out)
	return nil
}

// readAdminSetView reads a node's admin record (/certen/admin_set).
func readAdminSetView(c rpcDoer, base string) (*consensus.AdminSetView, error) {
	var q struct {
		Response struct {
			Code  uint32 `json:"code"`
			Log   string `json:"log"`
			Value string `json:"value"`
		} `json:"response"`
	}
	if err := rpcCall(c, base, "abci_query", map[string]any{"path": "/certen/admin_set"}, &q); err != nil {
		return nil, err
	}
	if q.Response.Code != 0 {
		return nil, fmt.Errorf("%s: the admin set is not available (%s) - is this node on rules v%d?", base, q.Response.Log,
			adminRotateRulesVersion)
	}
	raw, err := base64.StdEncoding.DecodeString(q.Response.Value)
	if err != nil {
		return nil, err
	}
	var v consensus.AdminSetView
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%s: unreadable admin set: %w", base, err)
	}
	return &v, nil
}

func printAdminSet(keys map[string]string, threshold int) {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Printf("    %-20s %s\n", id, keys[id])
	}
	fmt.Printf("    threshold %d of %d\n", threshold, len(keys))
}

func adminRotateStatus(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("admin-rotate status", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rpc == "" {
		return errors.New("--rpc is required")
	}
	n, err := readNode(c, *rpc)
	if err != nil {
		return err
	}
	v, err := readAdminSetView(c, *rpc)
	if err != nil {
		return err
	}
	fmt.Printf("chain %s, committed height %d, rules v%d\n", n.chainID, v.Height, n.appVersion)
	fmt.Printf("admin set in force (set id %s):\n", v.InForceSetID)
	printAdminSet(v.InForceKeys, v.InForceThreshold)
	fmt.Printf("the next admin rotation carries sequence %d\n", v.NextSequence)
	if len(v.Changes) == 0 {
		fmt.Println("no admin-set change recorded: the set in force is the one sealed at genesis")
	}
	for i, ch := range v.Changes {
		kind := "admin rotation, sequence " + fmt.Sprint(ch.Sequence)
		if ch.Kind == "" {
			kind = "admin re-seal (rules v11)"
		}
		fmt.Printf("  change %d at height %d: %s, %d keys, threshold %d (%s)\n", i+1, ch.Height, kind, len(ch.Keys), ch.Threshold, ch.ID)
	}
	return nil
}

// newSetFile is the new admin set as an owner writes it.
type newSetFile struct {
	AdminKeys map[string]string `json:"admin_keys"`
	Threshold int               `json:"threshold"`
}

func adminRotateRequest(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("admin-rotate request", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "a validator's CometBFT RPC to read the chain, sequence and set in force from")
	chainID := fs.String("chain-id", "", "the CometBFT chain id (when not read with --rpc)")
	sequence := fs.Uint64("sequence", 0, "the next admin-rotation sequence (when not read with --rpc; status shows it)")
	current := fs.String("current-set-id", "", "the id of the admin set in force (when not read with --rpc; status shows it)")
	newSet := fs.String("new-set", "", `the new set: {"admin_keys": {"<id>": "<hex ed25519 public key>"}, "threshold": T}`)
	noTolerance := fs.Bool("accept-no-loss-tolerance", false, "allow a threshold equal to the number of keys (losing any one key then locks the admin set)")
	out := fs.String("out", "", "write the request here (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newSet == "" || *out == "" {
		return errors.New("--new-set and --out are required")
	}
	if *rpc != "" {
		if *chainID != "" || *sequence != 0 || *current != "" {
			return errors.New("give --rpc, or --chain-id, --sequence and --current-set-id - not both")
		}
		n, err := readNode(c, *rpc)
		if err != nil {
			return err
		}
		v, err := readAdminSetView(c, *rpc)
		if err != nil {
			return err
		}
		*chainID, *sequence, *current = n.chainID, v.NextSequence, v.InForceSetID
	}
	if *chainID == "" || *sequence == 0 || *current == "" {
		return errors.New("--chain-id, --sequence and --current-set-id are required without --rpc")
	}
	raw, err := os.ReadFile(*newSet)
	if err != nil {
		return err
	}
	var ns newSetFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ns); err != nil {
		return fmt.Errorf("the new set %s: %w", *newSet, err)
	}
	if err := consensus.CheckAdminSetShape(ns.AdminKeys, ns.Threshold); err != nil {
		return fmt.Errorf("the chain would refuse this set: %w", err)
	}
	if ns.Threshold == len(ns.AdminKeys) && len(ns.AdminKeys) > 1 && !*noTolerance {
		return fmt.Errorf("threshold %d of %d keys: losing any ONE key would lock the admin set for good - how "+
			"certen-testnet lost its admins. Lower the threshold, add a key, or pass --accept-no-loss-tolerance", ns.Threshold, len(ns.AdminKeys))
	}
	tx := &consensus.AdminRotateTx{Kind: consensus.AdminRotateKind, ChainID: *chainID, Sequence: *sequence,
		CurrentSetID: strings.ToLower(*current), NewAdminKeys: ns.AdminKeys, NewThreshold: ns.Threshold}
	fmt.Fprintf(os.Stderr, "admin rotation request: chain %s, sequence %d, made against set %s\nnew set (id %s):\n",
		tx.ChainID, tx.Sequence, tx.CurrentSetID, tx.NewSetID())
	printAdminSet(tx.NewAdminKeys, tx.NewThreshold)
	fmt.Fprintln(os.Stderr, "next: every new key's holder runs `admin-rotate possess`, the current admins `admin-rotate sign`")
	return writeAdminRotate(tx, *out, false)
}

func adminRotatePossess(args []string) error {
	fs := flag.NewFlagSet("admin-rotate possess", flag.ContinueOnError)
	path := fs.String("tx", "", "the request")
	keyID := fs.String("key-id", "", "the new key's id in the request")
	secret := fs.String("secret", "", "@<file> holding the new key's secret seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --key-id and --secret are required")
	}
	tx, err := readAdminRotate(*path)
	if err != nil {
		return err
	}
	pub, ok := tx.NewAdminKeys[*keyID]
	if !ok {
		return fmt.Errorf("%q is not a key of the new set", *keyID)
	}
	key, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != pub {
		return fmt.Errorf("the secret is not %q's key: the request names %s", *keyID, pub)
	}
	for _, p := range tx.Possession {
		if p.KeyID == *keyID {
			return fmt.Errorf("%q has already proved possession", *keyID)
		}
	}
	tx.Possession = append(tx.Possession, consensus.PolicySignature{KeyID: *keyID,
		Signature: hex.EncodeToString(ed25519.Sign(key, tx.PossessionBytes()))})
	fmt.Fprintf(os.Stderr, "possession proved for %s (%d of %d new keys)\n", *keyID, len(tx.Possession), len(tx.NewAdminKeys))
	return writeAdminRotate(tx, *path, true)
}

func adminRotateSign(args []string) error {
	fs := flag.NewFlagSet("admin-rotate sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the request")
	keyID := fs.String("admin-key-id", "", "your admin key id in the set in force")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readAdminRotate(*path)
	if err != nil {
		return err
	}
	for _, s := range tx.Signatures {
		if s.KeyID == *keyID {
			return fmt.Errorf("admin %q has already signed this rotation", *keyID)
		}
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approving, as %s (public key %s):\n  chain %s, sequence %d, replacing admin set %s with set %s:\n",
		*keyID, hex.EncodeToString(admin.Public().(ed25519.PublicKey)), tx.ChainID, tx.Sequence, tx.CurrentSetID, tx.NewSetID())
	printAdminSet(tx.NewAdminKeys, tx.NewThreshold)
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{KeyID: *keyID,
		Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes()))})
	fmt.Fprintf(os.Stderr, "admin signatures on this rotation: %d (the chain counts distinct keys of the set in force)\n", len(tx.Signatures))
	return writeAdminRotate(tx, *path, true)
}

// adminRotateNode is one validator's view for the preflight.
type adminRotateNode struct {
	*nodeView
	admin *consensus.AdminSetView
}

// adminRotatePreflight lists why the request must not be submitted to this fleet; none means GO.
func adminRotatePreflight(tx *consensus.AdminRotateTx, nodes []adminRotateNode) []string {
	if len(nodes) == 0 {
		return []string{"no validator RPC endpoint given"}
	}
	var views []*nodeView
	for _, n := range nodes {
		views = append(views, n.nodeView)
	}
	problems := fleetRulesProblems(views, adminRotateRulesVersion, "admin rotation")
	var top int64
	for _, n := range nodes {
		if n.height > top {
			top = n.height
		}
	}
	first := nodes[0]
	for _, n := range nodes {
		if n.chainID != tx.ChainID {
			problems = append(problems, fmt.Sprintf("%s is on chain %q, the rotation is for %q", n.rpc, n.chainID, tx.ChainID))
		}
		if top-n.height > maxHeightLag {
			problems = append(problems, fmt.Sprintf("%s is at height %d, %d behind: every validator must be caught up", n.rpc, n.height, top-n.height))
		}
		if n.admin.InForceSetID != first.admin.InForceSetID || n.admin.NextSequence != first.admin.NextSequence ||
			len(n.admin.Changes) != len(first.admin.Changes) {
			problems = append(problems, fmt.Sprintf("%s reports admin set %s and next sequence %d, %s reports %s and %d: the fleet "+
				"disagrees about its admins", n.rpc, n.admin.InForceSetID, n.admin.NextSequence, first.rpc,
				first.admin.InForceSetID, first.admin.NextSequence))
		}
	}
	if len(nodes) < len(first.set) {
		problems = append(problems, fmt.Sprintf("only %d of %d validators were checked: preflight every validator", len(nodes), len(first.set)))
	}
	// The chain's own rule, against the set every node reports, for the next block.
	if err := consensus.VerifyAdminRotate(tx, first.chainID, first.admin.Policy(), first.admin.Height+1); err != nil {
		problems = append(problems, "the chain would refuse it: "+err.Error())
	}
	return problems
}

func adminRotateSubmit(args []string, c rpcDoer, name string) error {
	fs := flag.NewFlagSet("admin-rotate "+name, flag.ContinueOnError)
	path := fs.String("tx", "", "the signed request")
	rpcs := fs.String("rpc", "", "EVERY validator's CometBFT RPC, comma-separated")
	dryRun := fs.Bool("dry-run", false, "check every validator is ready, commit nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || strings.TrimSpace(*rpcs) == "" {
		return errors.New("--tx and --rpc (every validator) are required")
	}
	tx, err := readAdminRotate(*path)
	if err != nil {
		return err
	}
	var nodes []adminRotateNode
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		a, err := readAdminSetView(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		fmt.Printf("%s: chain %s height %d rules v%d, admin set %s…, next sequence %d\n", base, v.chainID, v.height,
			v.appVersion, a.InForceSetID[:16], a.NextSequence)
		nodes = append(nodes, adminRotateNode{nodeView: v, admin: a})
	}
	if problems := adminRotatePreflight(tx, nodes); len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("  NO-GO:", p)
		}
		return fmt.Errorf("NO-GO (%d problem(s))", len(problems))
	}
	fmt.Printf("GO: every validator runs rules v%d on %s and reports admin set %s; sequence %d, signed by the threshold of "+
		"distinct admins in force, every new key proving possession\n", nodes[0].appVersion, tx.ChainID, tx.CurrentSetID, tx.Sequence)
	if tx.NewThreshold == len(tx.NewAdminKeys) && len(tx.NewAdminKeys) > 1 {
		fmt.Printf("WARNING: threshold %d of %d - losing any one of the new keys locks the admin set\n", tx.NewThreshold, len(tx.NewAdminKeys))
	}
	if *dryRun {
		fmt.Printf("dry run: would commit admin rotation %s…\n", tx.RotationID()[:32])
		return nil
	}
	h, err := broadcastCommit(c, nodes[0].rpc, *path)
	if err != nil {
		return err
	}
	after, err := readAdminSetView(c, nodes[0].rpc)
	if err != nil {
		return fmt.Errorf("committed at height %d, but the admin set could not be read back: %w", h, err)
	}
	recorded := false
	for _, ch := range after.Changes {
		if ch.Height == h && ch.ID == tx.RotationID() {
			recorded = true
		}
	}
	if !recorded {
		return fmt.Errorf("committed at height %d, but %s does not record the rotation at that height", h, nodes[0].rpc)
	}
	fmt.Printf("ACCEPTED at height %d (%s…). From height %d the admin set is %s:\n", h, tx.RotationID()[:32], h+1, tx.NewSetID())
	printAdminSet(tx.NewAdminKeys, tx.NewThreshold)
	return nil
}

func readAdminRotate(path string) (*consensus.AdminRotateTx, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeAdminRotate(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.AdminRotateKind)
	}
	if tx.ChainID == "" || tx.Sequence == 0 {
		return nil, fmt.Errorf("%s is not a well-formed %s request", path, consensus.AdminRotateKind)
	}
	return tx, nil
}

func writeAdminRotate(tx *consensus.AdminRotateTx, path string, replace bool) error {
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

// historyCheckV12 reads every committed block of the chain and its result codes and judges them as a v12 node judges
// its history before it starts (consensus.CommittedBlockViolations). Against a v11 fleet - before the upgrade - no
// admin rotation can be recorded, so the committed policy is not needed; against a v12 node it is read, and an
// accepted admin rotation must be in its record.
func historyCheckV12(rpc string, c rpcDoer) error {
	n, err := readNode(c, rpc)
	if err != nil {
		return err
	}
	var st struct {
		SyncInfo struct {
			LatestBlockHeight   string `json:"latest_block_height"`
			EarliestBlockHeight string `json:"earliest_block_height"`
		} `json:"sync_info"`
	}
	if err := rpcCall(c, rpc, "status", map[string]any{}, &st); err != nil {
		return err
	}
	var latest, earliest int64
	fmt.Sscanf(st.SyncInfo.LatestBlockHeight, "%d", &latest)
	fmt.Sscanf(st.SyncInfo.EarliestBlockHeight, "%d", &earliest)
	if earliest != 1 {
		return fmt.Errorf("this node's history starts at block %d, not 1: the check needs every block", earliest)
	}
	var policy *ledger.EntitlementPolicyState
	if n.appVersion >= adminRotateRulesVersion {
		v, err := readAdminSetView(c, rpc)
		if err != nil {
			return err
		}
		policy = v.Policy()
	}
	kinds := map[string]int{}
	var found []string
	txCount := 0
	for h := int64(1); h <= latest; h++ {
		var blk struct {
			Block struct {
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		}
		if err := rpcCall(c, rpc, "block", map[string]any{"height": fmt.Sprintf("%d", h)}, &blk); err != nil {
			return err
		}
		var res struct {
			TxsResults []struct {
				Code uint32 `json:"code"`
			} `json:"txs_results"`
		}
		if err := rpcCall(c, rpc, "block_results", map[string]any{"height": fmt.Sprintf("%d", h)}, &res); err != nil {
			return err
		}
		txs := make([][]byte, len(blk.Block.Data.Txs))
		for i, enc := range blk.Block.Data.Txs {
			raw, err := base64.StdEncoding.DecodeString(enc)
			if err != nil {
				return fmt.Errorf("block %d: undecodable transaction", h)
			}
			txs[i] = raw
			kinds[kindOf(raw)]++
		}
		codes := make([]uint32, len(res.TxsResults))
		for i, r := range res.TxsResults {
			codes[i] = r.Code
		}
		v, err := consensus.CommittedBlockViolations(h, txs, codes, policy)
		if err != nil {
			return err
		}
		found = append(found, v...)
		txCount += len(txs)
	}
	fmt.Printf("chain %s, rules v%d: blocks 1..%d read with their results, %d transactions\n", n.chainID, n.appVersion, latest, txCount)
	ks := make([]string, 0, len(kinds))
	for k := range kinds {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		name := k
		if name == "" {
			name = "(no kind: ValidatorBlock)"
		}
		fmt.Printf("  %-40s %d\n", name, kinds[k])
	}
	if len(found) > 0 {
		for _, f := range found {
			fmt.Println("  FOUND:", f)
		}
		return errors.New("the chain holds history rules v12 decide differently: v12 must NOT continue this state")
	}
	fmt.Println("no transaction rules v12 decide differently: v12 continues this chain's history exactly")
	return nil
}
