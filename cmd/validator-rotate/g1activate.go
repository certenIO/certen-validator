package main

// The g1-activate subcommands (rules v15, pkg/consensus/g1_activation.go, RB9-C2): proof v2 evidence 2.1 - every page of
// the governing set at its own partition and block, proven vote records, govRoot v4 - becomes mandatory through ONE
// admin-quorum transaction. The activation is a single height H, a committed fact: blocks at heights above H must carry
// evidence 2.1 (a 2.0 certificate is refused), blocks at or below it are decided exactly as rules v14 decide them (a 2.1
// certificate is refused, ErrIntentProofV21NotInForce). The chain accepts one activation, once, and it cannot be undone.
// Every secret is read from a file and never printed.
//
//	validator-rotate g1-activate status --rpc http://v1:26657[,http://v2:26657,...]
//	    The activation in force (or that none is: rules v15 not yet activated), per node: its rules version and what it
//	    records, and whether the nodes agree.
//
//	validator-rotate g1-activate propose --chain-id C --admin-key-id A --admin-secret @<file> --out activate.json
//	    The activation transaction for the chain (version 1), with the first admin signature. --rpc instead of --chain-id
//	    reads the chain id from a node and refuses when the chain already recorded an activation. Without the admin flags
//	    it writes the unsigned payload.
//
//	validator-rotate g1-activate sign --tx activate.json --admin-key-id B --admin-secret @<file>
//	    Another admin's approval, OFFLINE. Shows what is being approved first.
//
//	validator-rotate g1-activate preflight --tx activate.json --rpc http://v1:26657,...
//	validator-rotate g1-activate submit    --tx activate.json --rpc http://v1:26657,... [--dry-run]
//	    Every validator: rules v15 and all the same, one chain, caught up, the same admin set, NO activation recorded on any
//	    node and every node agreeing on that; the chain's own rule (VerifyG1Activation) accepts the transaction for the next
//	    block, i.e. the threshold of distinct keys of the admin set in force signed it. GO, submit commits it through the
//	    first RPC (unless --dry-run) and confirms the node recorded it at the commit height.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// g1ActivateRulesVersion is the execution-rules version that recognises a cross-partition activation.
const g1ActivateRulesVersion = 15

func g1Activate(args []string, c rpcDoer) error {
	if len(args) == 0 {
		return errors.New("g1-activate needs a subcommand: status, propose, sign, preflight, submit")
	}
	switch args[0] {
	case "status":
		return g1ActivateStatus(os.Stdout, args[1:], c)
	case "propose":
		return g1ActivatePropose(args[1:], c)
	case "sign":
		return g1ActivateSign(args[1:])
	case "preflight":
		return g1ActivateSubmit(os.Stdout, append([]string{"--dry-run"}, args[1:]...), c, "preflight")
	case "submit":
		return g1ActivateSubmit(os.Stdout, args[1:], c, "submit")
	default:
		return fmt.Errorf("unknown g1-activate subcommand %q", args[0])
	}
}

// readG1ActivationLog reads a node's committed cross-partition activation log (/certen/g1_activation).
func readG1ActivationLog(c rpcDoer, base string) (*ledger.G1ActivationLog, error) {
	var q struct {
		Response struct {
			Code  uint32 `json:"code"`
			Log   string `json:"log"`
			Value string `json:"value"`
		} `json:"response"`
	}
	if err := rpcCall(c, base, "abci_query", map[string]any{"path": "/certen/g1_activation"}, &q); err != nil {
		return nil, err
	}
	if q.Response.Code == 2 && strings.HasPrefix(q.Response.Log, "unknown query path") {
		return nil, fmt.Errorf("%s: %w (%s) - is this node on rules v%d?", base, errQueryNotServed, q.Response.Log, g1ActivateRulesVersion)
	}
	if q.Response.Code != 0 {
		return nil, fmt.Errorf("%s: the cross-partition activation log is not available (%s)", base, q.Response.Log)
	}
	raw, err := base64.StdEncoding.DecodeString(q.Response.Value)
	if err != nil {
		return nil, err
	}
	var l ledger.G1ActivationLog
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: unreadable cross-partition activation log: %w", base, err)
	}
	return &l, nil
}

// g1ActivationLine is how a log reads in one line: none, or the height and id of the activation.
func g1ActivationLine(l *ledger.G1ActivationLog) string {
	if l == nil || len(l.Activations) == 0 {
		return "none"
	}
	a := l.Activations[0]
	return fmt.Sprintf("activated at height %d (%s)", a.Height, a.ID)
}

func g1ActivateStatus(w io.Writer, args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("g1-activate status", flag.ContinueOnError)
	rpcs := fs.String("rpc", "", "a validator's CometBFT RPC, or every validator's, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*rpcs) == "" {
		return errors.New("--rpc is required")
	}
	var first *ledger.G1ActivationLog
	agree, served := true, 0
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		if err != nil {
			return err
		}
		l, err := readG1ActivationLog(c, base)
		if errors.Is(err, errQueryNotServed) {
			fmt.Fprintf(w, "%s: chain %s height %d rules v%d: this node does not serve the activation log - rules v%d are not deployed on it\n",
				base, v.chainID, v.height, v.appVersion, g1ActivateRulesVersion)
			agree = false
			continue
		}
		if err != nil {
			return err
		}
		served++
		fmt.Fprintf(w, "%s: chain %s height %d rules v%d, cross-partition activation: %s\n", base, v.chainID, v.height, v.appVersion,
			g1ActivationLine(l))
		if first == nil {
			first = l
		} else if g1ActivationLine(l) != g1ActivationLine(first) {
			agree = false
		}
		if v.appVersion < g1ActivateRulesVersion {
			agree = false
		}
	}
	if served == 0 {
		fmt.Fprintf(w, "NO node serves the activation log: rules v%d are not yet deployed\n", g1ActivateRulesVersion)
		return nil
	}
	if !agree {
		fmt.Fprintf(w, "THE NODES DISAGREE (or some do not run rules v%d): they do not all report the same activation\n", g1ActivateRulesVersion)
	}
	if len(first.Activations) == 0 {
		fmt.Fprintln(w, "rules v15 not yet activated: blocks are decided as rules v14 decide them, a certificate carrying evidence 2.1 "+
			"is refused (ErrIntentProofV21NotInForce), and every certificate carries evidence 2.0")
		return nil
	}
	a := first.Activations[0]
	fmt.Fprintf(w, "cross-partition activation accepted at height %d (%s): evidence 2.1 is required from height %d; a certificate "+
		"carrying evidence 2.0 is refused there (ErrIntentProofV21Missing)\n", a.Height, a.ID, a.Height+1)
	return nil
}

func signG1Activation(tx *consensus.G1ActivationTx, keyID string, admin ed25519.PrivateKey) error {
	for _, s := range tx.Signatures {
		if s.KeyID == keyID {
			return fmt.Errorf("admin %s has already signed this activation", keyID)
		}
	}
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{KeyID: keyID,
		Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes()))})
	return nil
}

func describeG1Activation(tx *consensus.G1ActivationTx) {
	fmt.Fprintf(os.Stderr, "cross-partition activation (version %d) on chain %s:\n", tx.Version, tx.ChainID)
	fmt.Fprintf(os.Stderr, "    from the block AFTER the one that accepts this, every ValidatorBlock must carry proof v2 evidence 2.1 "+
		"(govRoot v4); a 2.0 certificate is refused there.\n")
	fmt.Fprintf(os.Stderr, "    blocks up to and including the accepting block are decided as rules v14 decide them.\n")
	fmt.Fprintf(os.Stderr, "    ONE-WAY: the chain accepts this once and it cannot be replayed, moved or undone.\n")
}

func g1ActivatePropose(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("g1-activate propose", flag.ContinueOnError)
	rpc := fs.String("rpc", "", "a validator's CometBFT RPC, to read the chain id from")
	chainID := fs.String("chain-id", "", "the CERTEN chain id (offline, instead of --rpc)")
	keyID := fs.String("admin-key-id", "", "your admin key id (with --admin-secret; both omitted writes the unsigned payload)")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	out := fs.String("out", "", "activation transaction to write (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	if (*keyID == "") != (*secret == "") {
		return errors.New("--admin-key-id and --admin-secret go together")
	}
	if (*rpc == "") == (*chainID == "") {
		return errors.New("give either --rpc, or --chain-id")
	}
	if *rpc != "" {
		v, err := readNode(c, *rpc)
		if err != nil {
			return err
		}
		l, err := readG1ActivationLog(c, *rpc)
		if err != nil {
			return err
		}
		if len(l.Activations) > 0 {
			return fmt.Errorf("%s already records the cross-partition activation (%s): the chain activates once", *rpc, g1ActivationLine(l))
		}
		*chainID = v.chainID
	}
	tx := &consensus.G1ActivationTx{Kind: consensus.G1ActivationKind, ChainID: *chainID, Version: 1}
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the activation would be refused: %w", err)
	}
	describeG1Activation(tx)
	if *keyID != "" {
		admin, err := loadAdmin(*secret)
		if err != nil {
			return err
		}
		if err := signG1Activation(tx, *keyID, admin); err != nil {
			return err
		}
	}
	return writeG1Activation(tx, *out, false)
}

func g1ActivateSign(args []string) error {
	fs := flag.NewFlagSet("g1-activate sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the activation transaction")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readG1Activation(*path)
	if err != nil {
		return err
	}
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the activation would be refused: %w", err)
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	describeG1Activation(tx)
	if err := signG1Activation(tx, *keyID, admin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "admin signatures on this activation: %d (the chain counts distinct keys of the set in force)\n", len(tx.Signatures))
	return writeG1Activation(tx, *path, true)
}

// g1ActivateNode is one validator's view for the preflight.
type g1ActivateNode struct {
	*nodeView
	admin       *consensus.AdminSetView
	activations *ledger.G1ActivationLog
	// spine and registry are the node's committed Accumulate spine and BLS registry logs: whether the chain requires the v3 intent
	// certificate (consensus.ProofV3Required) is derived from them exactly as the chain derives it.
	spine    *ledger.AccumulateSpineLog
	registry *ledger.BLSRegistryLog
}

// g1ActivatePreflight lists why the activation must not be submitted to this fleet; none means GO.
func g1ActivatePreflight(tx *consensus.G1ActivationTx, nodes []g1ActivateNode) []string {
	if len(nodes) == 0 {
		return []string{"no validator RPC endpoint given"}
	}
	var views []*nodeView
	for _, n := range nodes {
		views = append(views, n.nodeView)
	}
	problems := fleetRulesProblems(views, g1ActivateRulesVersion, "cross-partition activation")
	var top int64
	for _, n := range nodes {
		if n.height > top {
			top = n.height
		}
	}
	first := nodes[0]
	for _, n := range nodes {
		if n.chainID != tx.ChainID {
			problems = append(problems, fmt.Sprintf("%s is on chain %q, the activation is for %q", n.rpc, n.chainID, tx.ChainID))
		}
		if top-n.height > maxHeightLag {
			problems = append(problems, fmt.Sprintf("%s is at height %d, %d behind: every validator must be caught up", n.rpc, n.height, top-n.height))
		}
		if n.admin.InForceSetID != first.admin.InForceSetID {
			problems = append(problems, fmt.Sprintf("%s reports admin set %s, %s reports %s: the fleet disagrees about its admins",
				n.rpc, n.admin.InForceSetID, first.rpc, first.admin.InForceSetID))
		}
		// Evidence 2.1 is judged where the v3 intent certificate is. On a chain that does not require it yet (no verified Accumulate spine
		// of the registry's incarnation) an activation would record a height at which nothing is judged and would take effect only once
		// a spine appears, at a time no one chose (F8): it is signed and submitted after the spine exists.
		if !consensus.ProofV3Required(n.spine, consensus.RegistryAt(n.registry, n.height+1)) {
			problems = append(problems, fmt.Sprintf("%s does not require proof v3 (no verified Accumulate spine of the registry's incarnation in force "+
				"for the next block): evidence 2.1 is judged only where the v3 intent certificate is required, so the activation would take effect "+
				"at a time no one chose; activate after the spine exists", n.rpc))
		}
		if len(n.activations.Activations) > 0 {
			problems = append(problems, fmt.Sprintf("%s already records the cross-partition activation (%s): the chain activates once",
				n.rpc, g1ActivationLine(n.activations)))
		}
		if g1ActivationLine(n.activations) != g1ActivationLine(first.activations) {
			problems = append(problems, fmt.Sprintf("%s reports activation %s, %s reports %s: the fleet disagrees about the activation",
				n.rpc, g1ActivationLine(n.activations), first.rpc, g1ActivationLine(first.activations)))
		}
	}
	if len(nodes) < len(first.set) {
		problems = append(problems, fmt.Sprintf("only %d of %d validators were checked: preflight every validator", len(nodes), len(first.set)))
	}
	// The chain's own rule, against the admin set and the activation log the first node reports, for the next block.
	if _, err := consensus.VerifyG1Activation(tx, first.chainID, first.admin.Policy(), first.activations, first.height+1); err != nil {
		problems = append(problems, "the chain would refuse it: "+err.Error())
	}
	return problems
}

func g1ActivateSubmit(w io.Writer, args []string, c rpcDoer, name string) error {
	fs := flag.NewFlagSet("g1-activate "+name, flag.ContinueOnError)
	path := fs.String("tx", "", "the signed activation transaction")
	rpcs := fs.String("rpc", "", "EVERY validator's CometBFT RPC, comma-separated")
	dryRun := fs.Bool("dry-run", false, "check every validator, commit nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || strings.TrimSpace(*rpcs) == "" {
		return errors.New("--tx and --rpc (every validator) are required")
	}
	tx, err := readG1Activation(*path)
	if err != nil {
		return err
	}
	var nodes []g1ActivateNode
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		a, err := readAdminSetView(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		l, err := readG1ActivationLog(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		sp, err := readAccumulateSpineLog(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		rg, err := readBLSRegistryLog(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		fmt.Fprintf(w, "%s: chain %s height %d rules v%d, admin set %s…, cross-partition activation: %s, proof v3 required: %t\n", base, v.chainID, v.height,
			v.appVersion, a.InForceSetID[:16], g1ActivationLine(l), consensus.ProofV3Required(sp, consensus.RegistryAt(rg, v.height+1)))
		nodes = append(nodes, g1ActivateNode{nodeView: v, admin: a, activations: l, spine: sp, registry: rg})
	}
	problems := g1ActivatePreflight(tx, nodes)
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(w, "  NO-GO:", p)
		}
		return fmt.Errorf("NO-GO (%d problem(s))", len(problems))
	}
	fmt.Fprintf(w, "GO: every validator runs rules v%d on %s, requires proof v3 and reports the same admin set and no activation; signed by the "+
		"threshold of distinct admins in force\n", nodes[0].appVersion, tx.ChainID)
	if *dryRun {
		fmt.Fprintf(w, "dry run: would commit the cross-partition activation %s…\n", tx.ActivationID()[:32])
		return nil
	}
	h, err := broadcastCommit(c, nodes[0].rpc, *path)
	if err != nil {
		return err
	}
	after, err := readG1ActivationLog(c, nodes[0].rpc)
	if err != nil {
		return fmt.Errorf("committed at height %d, but the activation log could not be read back: %w", h, err)
	}
	var rec *ledger.G1ActivationRecord
	for i := range after.Activations {
		if r := &after.Activations[i]; r.Height == h && r.ID == tx.ActivationID() {
			rec = r
		}
	}
	if rec == nil {
		return fmt.Errorf("committed at height %d, but %s does not record the activation at that height", h, nodes[0].rpc)
	}
	fmt.Fprintf(w, "ACCEPTED at height %d (%s…). Evidence 2.1 is required from height %d: every ValidatorBlock above %d must carry it, "+
		"and a certificate carrying evidence 2.0 is refused there.\n", h, tx.ActivationID()[:32], h+1, h)
	return nil
}

func readG1Activation(path string) (*consensus.G1ActivationTx, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeG1Activation(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.G1ActivationKind)
	}
	if tx.ChainID == "" || tx.Version == 0 {
		return nil, fmt.Errorf("%s is not a well-formed %s transaction", path, consensus.G1ActivationKind)
	}
	return tx, nil
}

func writeG1Activation(tx *consensus.G1ActivationTx, path string, replace bool) error {
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
