package main

// The BLS registry subcommands (RB5 D3): CERTEN's BLS registry becomes consensus state through an admin-quorum
// transaction, and from the block after it every ValidatorBlock must carry an intent certificate the chain verifies
// against it.
//
//	validator-rotate bls-possession --chain-id C --validator-id ID --evm-address 0x.. --power N --bls-key <key file> --out m.json
//	    Run ON the validator, against its own BLS key file (BLS_KEY_PATH). Writes its member entry: id, address, BLS
//	    public key, power, and the key's proof of possession over that membership. The key itself is never printed.
//
//	validator-rotate bls-registry-propose --chain-id C --version V --threshold 2/3 --incarnation 0x.. \
//	    --members m1.json,m2.json,... --admin-key-id A --admin-secret @<file> --out reg.json
//	    Assembles the registry, verifies every member's possession, and adds the first admin signature.
//
//	validator-rotate bls-registry-sign --tx reg.json --admin-key-id B --admin-secret @<file>
//
//	validator-rotate bls-registry-preflight --tx reg.json --rpc http://v1:26657,... --eth-rpc <url> --anchor 0x..[,0x..]
//	    Every CERTEN node runs rules v10 on the registry's chain, and the CERTEN set root the registry records is
//	    each anchor's currentValidatorSetRoot - certificates under it bind to the quorum the anchors commit. GO / NO-GO.
//
//	validator-rotate bls-registry-submit --tx reg.json --rpc http://v1:26657

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ledger"
)

func blsPossession(args []string) error {
	fs := flag.NewFlagSet("bls-possession", flag.ContinueOnError)
	chainID := fs.String("chain-id", "", "the CERTEN chain id")
	id := fs.String("validator-id", "", "this validator's id, as its ValidatorBlocks name it")
	addr := fs.String("evm-address", "", "this validator's registered EVM address on the anchors")
	power := fs.Uint64("power", 0, "its voting power, as the anchors register it")
	keyPath := fs.String("bls-key", "", "this validator's BLS key file (BLS_KEY_PATH)")
	out := fs.String("out", "", "member entry to write (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainID == "" || *id == "" || *addr == "" || *power == 0 || *keyPath == "" || *out == "" {
		return errors.New("--chain-id, --validator-id, --evm-address, --power, --bls-key and --out are required")
	}
	km := bls.NewKeyManager(*keyPath)
	if err := km.LoadKey(); err != nil {
		return fmt.Errorf("the BLS key: %w", err)
	}
	m := ledger.BLSRegistryMember{ValidatorID: *id, EVMAddress: strings.ToLower(*addr), BLSPubKey: km.PrivateKey().PublicKey().Hex(), Power: *power}
	e := consensus.BLSRegistryEntry{BLSRegistryMember: m, Possession: consensus.SignPossession(km.PrivateKey(), *chainID, m)}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewSecret(*out, append(b, '\n')); err != nil {
		return err
	}
	fmt.Printf("member %s: BLS public key %s…, possession written to %s\n", *id, m.BLSPubKey[:16], *out)
	return nil
}

func blsRegistryPropose(args []string) error {
	fs := flag.NewFlagSet("bls-registry-propose", flag.ContinueOnError)
	chainID := fs.String("chain-id", "", "the CERTEN chain id")
	version := fs.Uint64("version", 0, "the next registry version (1 for the first)")
	threshold := fs.String("threshold", "", "the quorum threshold as num/den, the anchors' (2/3)")
	incarnation := fs.String("incarnation", "", "the Accumulate incarnation (cmd/incarnation), 0x-hex32")
	members := fs.String("members", "", "comma-separated member entry files (bls-possession)")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	out := fs.String("out", "", "registry transaction to write (a new file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainID == "" || *version == 0 || *threshold == "" || *incarnation == "" || *members == "" || *keyID == "" ||
		*secret == "" || *out == "" {
		return errors.New("--chain-id, --version, --threshold, --incarnation, --members, --admin-key-id, --admin-secret and --out are required")
	}
	num, den, err := parseThreshold(*threshold)
	if err != nil {
		return err
	}
	tx := &consensus.BLSRegistryTx{Kind: consensus.BLSRegistryKind, ChainID: *chainID, Version: *version,
		ThresholdNumerator: num, ThresholdDenominator: den, AccumulateIncarnation: strings.ToLower(*incarnation)}
	for _, path := range strings.Split(*members, ",") {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return err
		}
		var e consensus.BLSRegistryEntry
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return fmt.Errorf("member entry %s: %w", path, err)
		}
		tx.Members = append(tx.Members, e)
	}
	// Every key's possession, uniqueness and the rest - the chain's own stateless check, before anyone signs.
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the registry would be refused: %w", err)
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	signRegistry(tx, *keyID, admin)
	return writeRegistry(tx, *out, false)
}

func blsRegistrySign(args []string) error {
	fs := flag.NewFlagSet("bls-registry-sign", flag.ContinueOnError)
	path := fs.String("tx", "", "the registry transaction")
	keyID := fs.String("admin-key-id", "", "your admin key id")
	secret := fs.String("admin-secret", "", "@<file> holding your admin secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *keyID == "" || *secret == "" {
		return errors.New("--tx, --admin-key-id and --admin-secret are required")
	}
	tx, err := readRegistry(*path)
	if err != nil {
		return err
	}
	for _, s := range tx.Signatures {
		if s.KeyID == *keyID {
			return fmt.Errorf("admin %s has already signed this registry", *keyID)
		}
	}
	admin, err := loadAdmin(*secret)
	if err != nil {
		return err
	}
	signRegistry(tx, *keyID, admin)
	return writeRegistry(tx, *path, true)
}

func blsRegistryPreflight(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("bls-registry-preflight", flag.ContinueOnError)
	path := fs.String("tx", "", "the signed registry transaction")
	rpcs := fs.String("rpc", "", "every validator's CometBFT RPC, comma-separated")
	ethRPC := fs.String("eth-rpc", "", "a JSON-RPC endpoint of an anchor chain")
	anchors := fs.String("anchor", "", "the V8.2 anchor address(es) on that chain, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *rpcs == "" || *ethRPC == "" || *anchors == "" {
		return errors.New("--tx, --rpc, --eth-rpc and --anchor are required")
	}
	tx, err := readRegistry(*path)
	if err != nil {
		return err
	}
	var problems []string
	if err := tx.CheckShape(); err != nil {
		problems = append(problems, "the registry: "+err.Error())
	}
	members := make([]ledger.BLSRegistryMember, 0, len(tx.Members))
	for _, e := range tx.Members {
		members = append(members, e.BLSRegistryMember)
	}
	root, err := consensus.RegistryCertenSetRoot(members, tx.ThresholdNumerator, tx.ThresholdDenominator)
	if err != nil {
		return err
	}
	fmt.Printf("registry v%d: %d members, threshold %d/%d, CERTEN set root 0x%x\n", tx.Version, len(tx.Members),
		tx.ThresholdNumerator, tx.ThresholdDenominator, root)
	var views []*nodeView
	for _, base := range splitRPCs(*rpcs) {
		v, err := readNode(c, base)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: %v", base, err))
		case v.chainID != tx.ChainID:
			problems = append(problems, fmt.Sprintf("%s runs chain %q, the registry is for %q", base, v.chainID, tx.ChainID))
		default:
			views = append(views, v)
		}
	}
	if len(views) > 0 {
		problems = append(problems, fleetRulesProblems(views, 10, "registry")...)
	}
	selector := ethcrypto.Keccak256([]byte("currentValidatorSetRoot()"))[:4]
	for _, a := range splitRPCs(*anchors) {
		var out string
		if err := ethCall(c, *ethRPC, a, selector, &out); err != nil {
			problems = append(problems, fmt.Sprintf("anchor %s: %v", a, err))
			continue
		}
		got := strings.TrimPrefix(strings.ToLower(out), "0x")
		if got != hex.EncodeToString(root[:]) {
			problems = append(problems, fmt.Sprintf("anchor %s commits CERTEN set root 0x%s, the registry 0x%x: "+
				"certificates under it would not bind to the quorum this anchor commits", a, got, root))
		}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("  NO-GO:", p)
		}
		return fmt.Errorf("NO-GO (%d problem(s))", len(problems))
	}
	fmt.Printf("GO: every node runs rules v%d on the registry's chain, and every anchor commits its CERTEN set root\n", views[0].appVersion)
	return nil
}

// ethCall reads a no-argument view through eth_call at the latest block.
func ethCall(c rpcDoer, base, to string, selector []byte, out *string) error {
	return rpcCallParams(c, base, "eth_call", []any{map[string]string{"to": to, "data": "0x" + hex.EncodeToString(selector)}, "latest"}, out)
}

func blsRegistrySubmit(args []string, c rpcDoer) error {
	fs := flag.NewFlagSet("bls-registry-submit", flag.ContinueOnError)
	path := fs.String("tx", "", "the signed, preflighted registry")
	rpc := fs.String("rpc", "", "one validator's CometBFT RPC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *rpc == "" {
		return errors.New("--tx and --rpc are required")
	}
	tx, err := readRegistry(*path)
	if err != nil {
		return err
	}
	if err := tx.CheckShape(); err != nil {
		return fmt.Errorf("the registry would be refused: %w", err)
	}
	h, err := broadcastCommit(c, *rpc, *path)
	if err != nil {
		return err
	}
	fmt.Printf("ACCEPTED at height %d. From height %d every ValidatorBlock must carry an intent certificate verified "+
		"against registry v%d.\n", h, h+1, tx.Version)
	return nil
}

func parseThreshold(s string) (uint64, uint64, error) {
	n, d, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, fmt.Errorf("--threshold %q is not num/den", s)
	}
	num, err1 := strconv.ParseUint(n, 10, 64)
	den, err2 := strconv.ParseUint(d, 10, 64)
	if err1 != nil || err2 != nil || den == 0 || num == 0 || num > den {
		return 0, 0, fmt.Errorf("--threshold %q is not a fraction in (0, 1]", s)
	}
	return num, den, nil
}

func signRegistry(tx *consensus.BLSRegistryTx, keyID string, admin ed25519.PrivateKey) {
	tx.Signatures = append(tx.Signatures, consensus.PolicySignature{KeyID: keyID,
		Signature: hex.EncodeToString(ed25519.Sign(admin, tx.SigningBytes()))})
}

func readRegistry(path string) (*consensus.BLSRegistryTx, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tx, ok := consensus.DecodeBLSRegistry(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not a %s transaction", path, consensus.BLSRegistryKind)
	}
	return tx, nil
}

func writeRegistry(tx *consensus.BLSRegistryTx, path string, replace bool) error {
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
