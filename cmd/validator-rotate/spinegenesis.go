package main

// The spine genesis subcommands (rules v13, pkg/consensus/accumulate_spine.go): the Accumulate validator-set spine
// starts - or, after the registry moved to a new Accumulate incarnation, restarts - from a genesis the admin quorum in
// force signs. Accepting it switches the chain to v3 intent certificates, so when it happens is the admins' decision.
//
//	validator-rotate spine-genesis propose --chain-id C --evidence kermit.json [--incarnation 0x..] \
//	    --admin-key-id A --admin-secret @<file> --out genesis.json
//	    Builds the genesis from incarnation evidence (cmd/incarnation; proof.IncarnationEvidence), verifying it offline
//	    first - and that it recomputes --incarnation, when given - then adds the first admin signature.
//
//	validator-rotate spine-genesis sign --tx genesis.json --admin-key-id B --admin-secret @<file>
//
//	validator-rotate spine-genesis preflight --tx genesis.json --rpc http://v1:26657,...
//	    Every validator runs rules v13 on the genesis's chain, caught up, all reporting the same admin set, BLS registry
//	    and spine; the admin quorum in force for the next block signed it; the registry in force attests under the
//	    incarnation the genesis recomputes; and the spine is not already that incarnation's. GO / NO-GO.
//
//	validator-rotate spine-genesis submit --tx genesis.json --rpc http://v1:26657,...
//	    The preflight, then commit, then confirm the node it was committed through records the genesis.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
)

func spineGenesis(args []string, c rpcDoer) error {
	if len(args) == 0 {
		return errors.New("spine-genesis needs a subcommand: propose, sign, preflight, submit")
	}
	switch args[0] {
	case "propose":
		return spineGenesisPropose(args[1:])
	case "sign":
		return spineGenesisSign(args[1:])
	case "preflight":
		return spineGenesisSubmit(append([]string{"--dry-run"}, args[1:]...), c, "preflight")
	case "submit":
		return spineGenesisSubmit(args[1:], c, "submit")
	default:
		return fmt.Errorf("unknown spine-genesis subcommand %q", args[0])
	}
}

func spineGenesisPropose(args []string) error {
	fs := flag.NewFlagSet("spine-genesis propose", flag.ContinueOnError)
	chainID := fs.String("chain-id", "", "the CERTEN chain id")
	evidence := fs.String("evidence", "", "the incarnation evidence JSON (cmd/incarnation)")
	incarnation := fs.String("incarnation", "", "optional: the incarnation the evidence must recompute, 0x-hex32")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	out := fs.String("out", "", "genesis transaction to write (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainID == "" || *evidence == "" || *keyID == "" || *secret == "" || *out == "" {
		return errors.New("--chain-id, --evidence, --admin-key-id, --admin-secret and --out are required")
	}
	raw, err := os.ReadFile(*evidence)
	if err != nil {
		return err
	}
	var ev proof.IncarnationEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("%s is not incarnation evidence: %w", *evidence, err)
	}
	// The evidence is verified offline before anyone signs: the genesis facts recompute an incarnation proven from the
	// network's genesis block, not facts a file merely states.
	rep, err := ev.Verify()
	if err != nil {
		return fmt.Errorf("the incarnation evidence does not verify: %w", err)
	}
	got := "0x" + hex.EncodeToString(rep.Incarnation[:])
	if *incarnation != "" && !strings.EqualFold(strings.TrimSpace(*incarnation), got) {
		return fmt.Errorf("the evidence recomputes incarnation %s, not %s", got, *incarnation)
	}
	tx := consensus.NewAccumulateSpineGenesis(*chainID, rep.Inputs)
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the genesis would be refused: %w", err)
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	signSpineGenesis(tx, *keyID, admin)
	fmt.Fprintf(os.Stderr, "spine genesis of incarnation %s (%s, genesis %s) for chain %s, id %s…\n", got, rep.NetworkName,
		rep.GenesisTime, *chainID, tx.GenesisID()[:40])
	return writeSpineGenesis(tx, *out, false)
}

func spineGenesisSign(args []string) error {
	fs := flag.NewFlagSet("spine-genesis sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the genesis transaction")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readSpineGenesis(*path)
	if err != nil {
		return err
	}
	for _, s := range tx.Signatures {
		if s.KeyID == *keyID {
			return fmt.Errorf("admin %s has already signed this genesis", *keyID)
		}
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	signSpineGenesis(tx, *keyID, admin)
	return writeSpineGenesis(tx, *path, true)
}

// spineGenesisNode is one validator's view for the preflight.
type spineGenesisNode struct {
	*nodeView
	admin    *consensus.AdminSetView
	registry *ledger.BLSRegistryLog
	spine    *ledger.AccumulateSpineLog
}

// spineGenesisPreflight lists why the genesis must not be submitted to this fleet; none means GO.
func spineGenesisPreflight(tx *consensus.AccumulateSpineGenesisTx, nodes []spineGenesisNode) []string {
	if len(nodes) == 0 {
		return []string{"no validator RPC endpoint given"}
	}
	var views []*nodeView
	for _, n := range nodes {
		views = append(views, n.nodeView)
	}
	problems := fleetRulesProblems(views, spineRulesVersion, "spine genesis")
	if err := tx.CheckShape(); err != nil {
		problems = append(problems, "the genesis: "+err.Error())
	}
	var top int64
	for _, n := range nodes {
		top = max(top, n.height)
	}
	first := nodes[0]
	for _, n := range nodes {
		if n.chainID != tx.ChainID {
			problems = append(problems, fmt.Sprintf("%s is on chain %q, the genesis is for %q", n.rpc, n.chainID, tx.ChainID))
		}
		if top-n.height > maxHeightLag {
			problems = append(problems, fmt.Sprintf("%s is at height %d, %d behind: every validator must be caught up", n.rpc, n.height, top-n.height))
		}
		if n.admin.InForceSetID != first.admin.InForceSetID {
			problems = append(problems, fmt.Sprintf("%s reports admin set %s, %s reports %s: the fleet disagrees about its admins",
				n.rpc, n.admin.InForceSetID, first.rpc, first.admin.InForceSetID))
		}
		if len(n.registry.Versions) != len(first.registry.Versions) || len(n.spine.Checkpoints) != len(first.spine.Checkpoints) ||
			(n.spine.Genesis == nil) != (first.spine.Genesis == nil) {
			problems = append(problems, fmt.Sprintf("%s and %s report different BLS registries or spines", n.rpc, first.rpc))
		}
	}
	if len(nodes) < len(first.set) {
		problems = append(problems, fmt.Sprintf("only %d of %d validators were checked: preflight every validator", len(nodes), len(first.set)))
	}
	next := first.admin.Height + 1
	// The chain's own rules, against what every node reports, for the next block.
	if err := consensus.VerifyAccumulateSpineGenesisQuorum(tx, first.admin.Policy(), next); err != nil {
		problems = append(problems, "the chain would refuse it: "+err.Error())
	}
	in, err := tx.Inputs()
	if err != nil {
		return append(problems, "the genesis: "+err.Error())
	}
	inc, err := proof.ComputeIncarnation(in)
	if err != nil {
		return append(problems, "the genesis does not describe an incarnation: "+err.Error())
	}
	incHex := "0x" + hex.EncodeToString(inc[:])
	reg := consensus.RegistryAt(first.registry, next)
	switch {
	case reg == nil:
		problems = append(problems, "no BLS registry is in force: the spine starts under the registry's incarnation, so the registry comes first")
	case !strings.EqualFold(reg.AccumulateIncarnation, incHex):
		problems = append(problems, fmt.Sprintf("the genesis is incarnation %s, the BLS registry in force (version %d) attests under %s",
			incHex, reg.Version, reg.AccumulateIncarnation))
	case first.spine.Genesis != nil && first.spine.Genesis.Incarnation == incHex:
		problems = append(problems, fmt.Sprintf("the spine of incarnation %s was started at height %d: it is replaced only when "+
			"the registry moves to another incarnation", incHex, first.spine.Genesis.Height))
	}
	return problems
}

func spineGenesisSubmit(args []string, c rpcDoer, name string) error {
	fs := flag.NewFlagSet("spine-genesis "+name, flag.ContinueOnError)
	path := fs.String("tx", "", "the signed genesis")
	rpcs := fs.String("rpc", "", "EVERY validator's CometBFT RPC, comma-separated")
	dryRun := fs.Bool("dry-run", false, "check every validator is ready, commit nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || strings.TrimSpace(*rpcs) == "" {
		return errors.New("--tx and --rpc (every validator) are required")
	}
	tx, err := readSpineGenesis(*path)
	if err != nil {
		return err
	}
	var nodes []spineGenesisNode
	for _, base := range splitRPCs(*rpcs) {
		n, err := readSpineGenesisNode(c, base)
		if err != nil {
			return fmt.Errorf("NO-GO: %w", err)
		}
		fmt.Printf("%s: chain %s height %d rules v%d, admin set %s…, %d registry version(s), spine verified through major block %d\n",
			base, n.chainID, n.height, n.appVersion, n.admin.InForceSetID[:16], len(n.registry.Versions), len(n.spine.Checkpoints))
		nodes = append(nodes, *n)
	}
	if problems := spineGenesisPreflight(tx, nodes); len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("  NO-GO:", p)
		}
		return fmt.Errorf("NO-GO (%d problem(s))", len(problems))
	}
	fmt.Printf("GO: every validator runs rules v%d on %s; the genesis is the registry's incarnation, signed by the threshold of "+
		"distinct admins in force\n", nodes[0].appVersion, tx.ChainID)
	if *dryRun {
		fmt.Printf("dry run: would commit spine genesis %s…\n", tx.GenesisID()[:40])
		return nil
	}
	h, err := broadcastCommit(c, nodes[0].rpc, *path)
	if err != nil {
		return err
	}
	// The node it was committed through has applied the block when broadcast_tx_commit returns (the others may still
	// be applying it, so they are not asked here; spine-genesis preflight against the fleet shows each one's spine).
	l, err := readAccumulateSpineLog(c, nodes[0].rpc)
	if err != nil {
		return fmt.Errorf("committed at height %d, but the spine could not be read back: %w", h, err)
	}
	if l.Genesis == nil || l.Genesis.Height != h || l.Genesis.SetHash == "" {
		return fmt.Errorf("committed at height %d, but %s does not record the genesis at that height", h, nodes[0].rpc)
	}
	fmt.Printf("ACCEPTED at height %d (%s…): the spine starts from this genesis; extensions carry its major blocks from 1.\n",
		h, tx.GenesisID()[:40])
	return nil
}

func readSpineGenesisNode(c rpcDoer, base string) (*spineGenesisNode, error) {
	v, err := readNode(c, base)
	if err != nil {
		return nil, err
	}
	a, err := readAdminSetView(c, base)
	if err != nil {
		return nil, err
	}
	r, err := readBLSRegistryLog(c, base)
	if err != nil {
		return nil, err
	}
	s, err := readAccumulateSpineLog(c, base)
	if err != nil {
		return nil, err
	}
	return &spineGenesisNode{nodeView: v, admin: a, registry: r, spine: s}, nil
}

func signSpineGenesis(tx *consensus.AccumulateSpineGenesisTx, keyID string, admin ed25519.PrivateKey) {
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{KeyID: keyID,
		Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes()))})
}

func readSpineGenesis(path string) (*consensus.AccumulateSpineGenesisTx, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeAccumulateSpineGenesis(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.AccumulateSpineGenesisKind)
	}
	if tx.ChainID == "" {
		return nil, fmt.Errorf("%s is not a well-formed %s transaction", path, consensus.AccumulateSpineGenesisKind)
	}
	return tx, nil
}

func writeSpineGenesis(tx *consensus.AccumulateSpineGenesisTx, path string, replace bool) error {
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
