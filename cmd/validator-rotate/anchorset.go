package main

// The anchor-set subcommands (rules v14, pkg/consensus/anchor_set.go, RB4-F35): CERTEN's V8 anchor on every settlement
// chain becomes consensus state through an admin-quorum transaction. The first one committed is the v14 activation: from
// the next height every ValidatorBlock's chain targets must name these anchors, and a ceiling touching an unpriced chain
// is refused. Every secret is read from a file and never printed.
//
//	validator-rotate anchor-set status --rpc http://v1:26657
//	    The anchor set in force (or that none is: v14 not yet activated), every version recorded, the next version.
//
//	validator-rotate anchor-set propose --chain-id C --version V \
//	    --anchor 11155111=0x..,84532=0x..,421614=0x.. --admin-key-id A --admin-secret @<file> --out set.json
//	    Assembles the set, checks its shape (every settlement chain once, non-zero addresses) and adds the first admin
//	    signature. --rpc instead of --chain-id/--version reads both from a node.
//
//	validator-rotate anchor-set sign --tx set.json --admin-key-id B --admin-secret @<file>
//	    Another admin's approval, OFFLINE. Shows what is being approved first.
//
//	validator-rotate anchor-set preflight --tx set.json --rpc http://v1:26657,... \
//	    --eth-rpc 11155111=<url>,84532=<url>,421614=<url>
//	validator-rotate anchor-set submit    --tx set.json --rpc http://v1:26657,... --eth-rpc ... [--dry-run]
//	    Every validator: rules v14 and all the same, one chain, caught up, the same admin set and the same anchor-set log;
//	    the chain's own rule (VerifyAnchorSet) accepts the set for the next block; and on every chain the anchor is a
//	    contract on that chain (eth_chainId matches, eth_getCode is not empty). GO, submit commits it through the first RPC
//	    (unless --dry-run) and confirms the node recorded it at the commit height.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// anchorSetRulesVersion is the execution-rules version that recognises an anchor set.
const anchorSetRulesVersion = 14

func anchorSet(args []string, c rpcDoer) error {
	if len(args) == 0 {
		return errors.New("anchor-set needs a subcommand: status, propose, sign, preflight, submit")
	}
	switch args[0] {
	case "status":
		return anchorSetStatus(args[1:], c)
	case "propose":
		return anchorSetPropose(args[1:], c)
	case "sign":
		return anchorSetSign(args[1:])
	case "preflight":
		return anchorSetSubmit(append([]string{"--dry-run"}, args[1:]...), c, "preflight")
	case "submit":
		return anchorSetSubmit(args[1:], c, "submit")
	default:
		return fmt.Errorf("unknown anchor-set subcommand %q", args[0])
	}
}

// readAnchorSetLog reads a node's committed anchor set log (/certen/anchor_set).
func readAnchorSetLog(c rpcDoer, base string) (*ledger.AnchorSetLog, error) {
	var q struct {
		Response struct {
			Code  uint32 `json:"code"`
			Log   string `json:"log"`
			Value string `json:"value"`
		} `json:"response"`
	}
	if err := rpcCall(c, base, "abci_query", map[string]any{"path": "/certen/anchor_set"}, &q); err != nil {
		return nil, err
	}
	if q.Response.Code == 2 && strings.HasPrefix(q.Response.Log, "unknown query path") {
		return nil, fmt.Errorf("%s: %w (%s) - is this node on rules v%d?", base, errQueryNotServed, q.Response.Log, anchorSetRulesVersion)
	}
	if q.Response.Code != 0 {
		return nil, fmt.Errorf("%s: the anchor set log is not available (%s)", base, q.Response.Log)
	}
	raw, err := base64.StdEncoding.DecodeString(q.Response.Value)
	if err != nil {
		return nil, err
	}
	var l ledger.AnchorSetLog
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: unreadable anchor set log: %w", base, err)
	}
	return &l, nil
}

func nextAnchorSetVersion(l *ledger.AnchorSetLog) uint64 {
	if l == nil || len(l.Versions) == 0 {
		return 1
	}
	return l.Versions[len(l.Versions)-1].Version + 1
}

func printAnchors(anchors []ledger.AnchorSetEntry) {
	for _, a := range anchors {
		name := strconv.FormatInt(a.ChainID, 10)
		if ch, ok := supportedchains.Lookup(a.ChainID); ok {
			name = ch.Name + " (" + name + ")"
		}
		fmt.Printf("    %-32s %s\n", name, a.Anchor)
	}
}

func anchorSetStatus(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("anchor-set status", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rpc == "" {
		return errors.New("--rpc is required")
	}
	v, err := readNode(c, *rpc)
	if err != nil {
		return err
	}
	l, err := readAnchorSetLog(c, *rpc)
	if err != nil {
		return err
	}
	fmt.Printf("chain %s height %d rules v%d\n", v.chainID, v.height, v.appVersion)
	inForce := consensus.AnchorSetAt(l, v.height+1)
	if inForce == nil {
		fmt.Println("NO anchor set is in force: rules v14 are not yet activated on this chain, and no v14 proposer admits any intent")
	} else {
		fmt.Printf("anchor set v%d in force (accepted at height %d, %s…):\n", inForce.Version, inForce.Height, inForce.ID[:27])
		printAnchors(inForce.Anchors)
	}
	for _, r := range l.Versions {
		fmt.Printf("  v%d at height %d: %s\n", r.Version, r.Height, r.ID)
	}
	fmt.Printf("the next anchor set carries version %d\n", nextAnchorSetVersion(l))
	return nil
}

// parseAnchors reads --anchor: chainId=0xaddress pairs, comma-separated.
func parseAnchors(s string) ([]ledger.AnchorSetEntry, error) {
	var out []ledger.AnchorSetEntry
	for _, part := range splitRPCs(s) {
		id, addr, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("--anchor entry %q is not <chainId>=<0x address>", part)
		}
		chainID, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("--anchor entry %q: %q is not a chain id", part, id)
		}
		addr = strings.TrimSpace(addr)
		if !common.IsHexAddress(addr) || !strings.HasPrefix(addr, "0x") {
			return nil, fmt.Errorf("--anchor entry %q: %q is not a 0x address", part, addr)
		}
		out = append(out, ledger.AnchorSetEntry{ChainID: chainID, Anchor: common.HexToAddress(addr).Hex()})
	}
	return out, nil
}

func signAnchorSet(tx *consensus.AnchorSetTx, keyID string, admin ed25519.PrivateKey) error {
	for _, s := range tx.Signatures {
		if s.KeyID == keyID {
			return fmt.Errorf("admin %s has already signed this anchor set", keyID)
		}
	}
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{KeyID: keyID,
		Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes()))})
	return nil
}

func describeAnchorSet(tx *consensus.AnchorSetTx) {
	fmt.Fprintf(os.Stderr, "anchor set v%d on chain %s:\n", tx.Version, tx.ChainID)
	for _, a := range tx.Anchors {
		name := strconv.FormatInt(a.ChainID, 10)
		if ch, ok := supportedchains.Lookup(a.ChainID); ok {
			name = ch.Name + " (" + name + ")"
		}
		fmt.Fprintf(os.Stderr, "    %-32s %s\n", name, a.Anchor)
	}
	if left := omittedChains(tx); len(left) > 0 {
		fmt.Fprintf(os.Stderr, "    NOT committed by this set (a block targeting one is refused, ANCHOR_NOT_COMMITTED, until a later version names it): %s\n",
			strings.Join(left, ", "))
	}
}

// omittedChains names the catalogued chains tx commits no anchor for. A set need not name every catalogued chain - the
// catalogue grows, and a chain joins through a later anchor-set version - but an operator must see what a set leaves out
// before anyone signs it.
func omittedChains(tx *consensus.AnchorSetTx) []string {
	named := map[int64]bool{}
	for _, a := range tx.Anchors {
		named[a.ChainID] = true
	}
	var out []string
	for _, c := range supportedchains.All {
		if !named[c.ID] {
			out = append(out, fmt.Sprintf("%s (%d)", c.Name, c.ID))
		}
	}
	return out
}

func anchorSetPropose(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("anchor-set propose", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "a validator's CometBFT RPC, to read the chain id and the next version from")
	chainID := fs.String("chain-id", "", "the CERTEN chain id (offline, instead of --rpc)")
	version := fs.Uint64("version", 0, "the next anchor-set version (offline, instead of --rpc; 1 for the first)")
	anchors := fs.String("anchor", "", "every settlement chain's V8 anchor: <chainId>=<0x address>, comma-separated")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	out := fs.String("out", "", "anchor-set transaction to write (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *anchors == "" || *keyID == "" || *secret == "" || *out == "" {
		return errors.New("--anchor, --admin-key-id, --admin-secret and --out are required")
	}
	if (*rpc == "") == (*chainID == "" || *version == 0) {
		return errors.New("give either --rpc, or --chain-id and --version")
	}
	if *rpc != "" {
		v, err := readNode(c, *rpc)
		if err != nil {
			return err
		}
		l, err := readAnchorSetLog(c, *rpc)
		if err != nil {
			return err
		}
		*chainID, *version = v.chainID, nextAnchorSetVersion(l)
	}
	entries, err := parseAnchors(*anchors)
	if err != nil {
		return err
	}
	tx := &consensus.AnchorSetTx{Kind: consensus.AnchorSetKind, ChainID: *chainID, Version: *version, Anchors: entries}
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the anchor set would be refused: %w", err)
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	describeAnchorSet(tx)
	if err := signAnchorSet(tx, *keyID, admin); err != nil {
		return err
	}
	return writeAnchorSet(tx, *out, false)
}

func anchorSetSign(args []string) error {
	fs := flag.NewFlagSet("anchor-set sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the anchor-set transaction")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readAnchorSet(*path)
	if err != nil {
		return err
	}
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the anchor set would be refused: %w", err)
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	describeAnchorSet(tx)
	if err := signAnchorSet(tx, *keyID, admin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "admin signatures on this anchor set: %d (the chain counts distinct keys of the set in force)\n", len(tx.Signatures))
	return writeAnchorSet(tx, *path, true)
}

// anchorSetNode is one validator's view for the preflight.
type anchorSetNode struct {
	*nodeView
	admin   *consensus.AdminSetView
	anchors *ledger.AnchorSetLog
}

// anchorSetPreflight lists why the anchor set must not be submitted to this fleet; none means GO.
func anchorSetPreflight(tx *consensus.AnchorSetTx, nodes []anchorSetNode) []string {
	if len(nodes) == 0 {
		return []string{"no validator RPC endpoint given"}
	}
	var views []*nodeView
	for _, n := range nodes {
		views = append(views, n.nodeView)
	}
	problems := fleetRulesProblems(views, anchorSetRulesVersion, "anchor set")
	var top int64
	for _, n := range nodes {
		if n.height > top {
			top = n.height
		}
	}
	first := nodes[0]
	for _, n := range nodes {
		if n.chainID != tx.ChainID {
			problems = append(problems, fmt.Sprintf("%s is on chain %q, the anchor set is for %q", n.rpc, n.chainID, tx.ChainID))
		}
		if top-n.height > maxHeightLag {
			problems = append(problems, fmt.Sprintf("%s is at height %d, %d behind: every validator must be caught up", n.rpc, n.height, top-n.height))
		}
		if n.admin.InForceSetID != first.admin.InForceSetID {
			problems = append(problems, fmt.Sprintf("%s reports admin set %s, %s reports %s: the fleet disagrees about its admins",
				n.rpc, n.admin.InForceSetID, first.rpc, first.admin.InForceSetID))
		}
		if nextAnchorSetVersion(n.anchors) != nextAnchorSetVersion(first.anchors) {
			problems = append(problems, fmt.Sprintf("%s's next anchor-set version is %d, %s's is %d: the fleet disagrees about its anchor sets",
				n.rpc, nextAnchorSetVersion(n.anchors), first.rpc, nextAnchorSetVersion(first.anchors)))
		}
	}
	if len(nodes) < len(first.set) {
		problems = append(problems, fmt.Sprintf("only %d of %d validators were checked: preflight every validator", len(nodes), len(first.set)))
	}
	// The chain's own rule, against the admin set and the anchor-set log every node reports, for the next block.
	if _, err := consensus.VerifyAnchorSet(tx, first.chainID, first.admin.Policy(), first.anchors, first.height+1); err != nil {
		problems = append(problems, "the chain would refuse it: "+err.Error())
	}
	return problems
}

// anchorOnChainProblems checks every anchor against its chain: the endpoint serves that chain, and the address holds
// code there. An address with no code on its chain is never an anchor.
func anchorOnChainProblems(c rpcDoer, tx *consensus.AnchorSetTx, ethRPCs map[int64]string) []string {
	var problems []string
	for _, a := range tx.Anchors {
		url, ok := ethRPCs[a.ChainID]
		if !ok {
			problems = append(problems, fmt.Sprintf("chain %d: no --eth-rpc endpoint given, so its anchor %s is unchecked", a.ChainID, a.Anchor))
			continue
		}
		var idHex string
		if err := rpcCallParams(c, url, "eth_chainId", []any{}, &idHex); err != nil {
			problems = append(problems, fmt.Sprintf("chain %d: %v", a.ChainID, err))
			continue
		}
		id, ok := new(big.Int).SetString(strings.TrimPrefix(idHex, "0x"), 16)
		if !ok || !id.IsInt64() || id.Int64() != a.ChainID {
			problems = append(problems, fmt.Sprintf("chain %d: %s serves chain %s, not %d", a.ChainID, url, idHex, a.ChainID))
			continue
		}
		var code string
		if err := rpcCallParams(c, url, "eth_getCode", []any{a.Anchor, "latest"}, &code); err != nil {
			problems = append(problems, fmt.Sprintf("chain %d: %v", a.ChainID, err))
			continue
		}
		if strings.TrimPrefix(code, "0x") == "" {
			problems = append(problems, fmt.Sprintf("chain %d: %s holds no code: it is not a contract on that chain", a.ChainID, a.Anchor))
		}
	}
	return problems
}

// parseEthRPCs reads --eth-rpc: chainId=url pairs, comma-separated.
func parseEthRPCs(s string) (map[int64]string, error) {
	out := map[int64]string{}
	for _, part := range splitRPCs(s) {
		id, url, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("--eth-rpc entry %q is not <chainId>=<url>", part)
		}
		chainID, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("--eth-rpc entry %q: %q is not a chain id", part, id)
		}
		out[chainID] = strings.TrimSpace(url)
	}
	return out, nil
}

func anchorSetSubmit(args []string, c rpcDoer, name string) error {
	fs := flag.NewFlagSet("anchor-set "+name, flag.ContinueOnError)
	path := fs.String("tx", "", "the signed anchor-set transaction")
	rpcs := fs.String("rpc", "", "EVERY validator's CometBFT RPC, comma-separated")
	ethRPC := fs.String("eth-rpc", "", "a JSON-RPC endpoint of every settlement chain: <chainId>=<url>, comma-separated")
	dryRun := fs.Bool("dry-run", false, "check every validator and every anchor, commit nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || strings.TrimSpace(*rpcs) == "" || strings.TrimSpace(*ethRPC) == "" {
		return errors.New("--tx, --rpc (every validator) and --eth-rpc (every settlement chain) are required")
	}
	tx, err := readAnchorSet(*path)
	if err != nil {
		return err
	}
	eth, err := parseEthRPCs(*ethRPC)
	if err != nil {
		return err
	}
	var nodes []anchorSetNode
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		a, err := readAdminSetView(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		l, err := readAnchorSetLog(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		fmt.Printf("%s: chain %s height %d rules v%d, admin set %s…, anchor sets recorded %d\n", base, v.chainID, v.height,
			v.appVersion, a.InForceSetID[:16], len(l.Versions))
		nodes = append(nodes, anchorSetNode{nodeView: v, admin: a, anchors: l})
	}
	problems := anchorSetPreflight(tx, nodes)
	problems = append(problems, anchorOnChainProblems(c, tx, eth)...)
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("  NO-GO:", p)
		}
		return fmt.Errorf("NO-GO (%d problem(s))", len(problems))
	}
	fmt.Printf("GO: every validator runs rules v%d on %s and reports the same admin set and anchor sets; version %d, signed by "+
		"the threshold of distinct admins in force; every anchor is a contract on its chain\n", nodes[0].appVersion, tx.ChainID, tx.Version)
	if *dryRun {
		fmt.Printf("dry run: would commit anchor set %s…\n", tx.AnchorSetID()[:27])
		return nil
	}
	h, err := broadcastCommit(c, nodes[0].rpc, *path)
	if err != nil {
		return err
	}
	after, err := readAnchorSetLog(c, nodes[0].rpc)
	if err != nil {
		return fmt.Errorf("committed at height %d, but the anchor set log could not be read back: %w", h, err)
	}
	var rec *ledger.AnchorSetRecord
	for i := range after.Versions {
		if r := &after.Versions[i]; r.Height == h && r.ID == tx.AnchorSetID() {
			rec = r
		}
	}
	if rec == nil {
		return fmt.Errorf("committed at height %d, but %s does not record the anchor set at that height", h, nodes[0].rpc)
	}
	fmt.Printf("ACCEPTED at height %d (%s…). From height %d every ValidatorBlock's chain targets must name:\n", h,
		tx.AnchorSetID()[:27], h+1)
	printAnchors(rec.Anchors)
	return nil
}

func readAnchorSet(path string) (*consensus.AnchorSetTx, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeAnchorSet(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.AnchorSetKind)
	}
	if tx.ChainID == "" || tx.Version == 0 {
		return nil, fmt.Errorf("%s is not a well-formed %s transaction", path, consensus.AnchorSetKind)
	}
	return tx, nil
}

func writeAnchorSet(tx *consensus.AnchorSetTx, path string, replace bool) error {
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
