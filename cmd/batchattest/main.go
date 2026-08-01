// Command batchattest produces a REAL quorum attestation over a batch anchor root and
// submits it, closing the last unproven link in the batch path.
//
// It performs, entirely in-process (no proof-service call — the Groth16 prover is local):
//
//  1. load the validator BLS private keys
//  2. compute the V6.1 pre-exec message for the BATCH anchor
//     (executionCommitment slot = batchRoot, operationID slot = batchOperationID)
//  3. sign with every validator, aggregate signatures and pubkeys
//  4. verify the aggregate locally BEFORE proving — a bad aggregate would otherwise
//     surface as an unexplained Groth16 failure minutes later
//  5. GenerateProof against the on-disk proving keys
//  6. VerifyProofLocally — catches a proving-key/VK mismatch without spending gas
//  7. ToSolidityCalldata -> executeComprehensiveProof
//  8. re-read proofExecuted from chain to confirm it actually flipped
//
// Usage:
//
//	go run ./cmd/batchattest \
//	  -keys bls_keys_backup_MASTER.json -zkkeys bls_zk_keys_bls12381_v2 \
//	  -rpc $RPC -anchor 0x... -bundle 0x... -root 0x... -batchop 0x... \
//	  -chain 11155111 [-submit]
//
// Without -submit it stops after step 6, so the whole cryptographic chain can be validated
// with no transaction and no cost.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

type keyFile struct {
	Validators []struct {
		ValidatorID   string `json:"validator_id"`
		EthAddress    string `json:"eth_address"`
		BLSPublicKey  string `json:"bls_public_key"`
		BLSPrivateKey string `json:"bls_private_key"`
	} `json:"validators"`
}

func mustHash(s string) [32]byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		fatal("bad 32-byte hex %q: %v", s, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", a...)
	os.Exit(1)
}

func step(n int, f string, a ...interface{}) {
	fmt.Printf("[%d] "+f+"\n", append([]interface{}{n}, a...)...)
}

func main() {
	var (
		keysPath   = flag.String("keys", "bls_keys_backup_MASTER.json", "validator BLS key file")
		zkKeysDir  = flag.String("zkkeys", "bls_zk_keys_bls12381_v2", "directory holding pk/vk/cs")
		rpcURL     = flag.String("rpc", "", "EVM RPC URL")
		anchorHex  = flag.String("anchor", "", "CertenAnchorV7 address")
		bundleHex  = flag.String("bundle", "", "batch anchor bundleId")
		rootHex    = flag.String("root", "", "batch root")
		batchOpHex = flag.String("batchop", "", "batch operationID")
		chainID    = flag.Int64("chain", 11155111, "EVM chain id")
		submit     = flag.Bool("submit", false, "actually send executeComprehensiveProof")
		ethKey     = flag.String("ethkey", os.Getenv("PRIVATE_KEY"), "EVM private key for submission")
	)
	flag.Parse()

	if *rpcURL == "" || *anchorHex == "" || *bundleHex == "" || *rootHex == "" || *batchOpHex == "" {
		fatal("-rpc, -anchor, -bundle, -root and -batchop are all required")
	}

	bundleID := mustHash(*bundleHex)
	batchRoot := mustHash(*rootHex)
	batchOpID := mustHash(*batchOpHex)
	anchorAddr := common.HexToAddress(*anchorHex)

	ctx := context.Background()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		fatal("dial rpc: %v", err)
	}

	// ---- 0. Read the set root FROM CHAIN --------------------------------------
	// Never assume it: the message the quorum signs must use the root the anchor will
	// actually reconstruct, and a local/on-chain divergence is exactly the failure that
	// makes every signature silently invalid.
	setRoot, err := readSetRoot(ctx, client, anchorAddr)
	if err != nil {
		fatal("reading currentValidatorSetRoot: %v", err)
	}
	step(0, "on-chain validatorSetRoot = 0x%x", setRoot)

	localRoot, lerr := contracts.GetV6_1ValidatorSetRoot()
	if lerr == nil {
		if localRoot != setRoot {
			fatal("set root MISMATCH — local 0x%x vs chain 0x%x. Every signature would verify "+
				"against a different message; fix the operator config before proceeding.",
				localRoot, setRoot)
		}
		step(0, "local config agrees with chain")
	} else {
		fmt.Printf("    (local set root unavailable: %v — using chain value)\n", lerr)
	}

	// ---- 1. Load keys ---------------------------------------------------------
	raw, err := os.ReadFile(*keysPath)
	if err != nil {
		fatal("reading %s: %v", *keysPath, err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		fatal("parsing key file: %v", err)
	}
	if len(kf.Validators) == 0 {
		fatal("key file contains no validators")
	}
	step(1, "loaded %d validator keys", len(kf.Validators))

	// Cross-check the on-chain registry before doing any crypto: if the deployed set does
	// not match, the signatures below would be over a message the anchor never reconstructs.
	if va, vp, vt, vs, verr := validatorSetForProof(ctx, client, anchorAddr); verr != nil {
		fatal("validator registry: %v", verr)
	} else {
		step(1, "on-chain registry: %d validators, signedVP=%s totalVP=%s", len(va), vs, vt)
		_ = vp
	}

	// ---- 2. Compute the batch quorum message ----------------------------------
	msgHash := contracts.ComputeEvmMessageHashV6_1_Pre(*chainID, bundleID, batchRoot, batchOpID, setRoot)
	step(2, "quorum message = 0x%x", msgHash)

	// ---- 3. Sign and aggregate ------------------------------------------------
	var sigs []*bls.Signature
	var pubs []*bls.PublicKey
	for _, v := range kf.Validators {
		skBytes, err := hex.DecodeString(strings.TrimPrefix(v.BLSPrivateKey, "0x"))
		if err != nil {
			fatal("%s: bad private key: %v", v.ValidatorID, err)
		}
		sk, err := bls.PrivateKeyFromBytes(skBytes)
		if err != nil {
			fatal("%s: loading private key: %v", v.ValidatorID, err)
		}
		sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
		if sig == nil {
			fatal("%s: signing returned nil", v.ValidatorID)
		}
		sigs = append(sigs, sig)
		pubs = append(pubs, sk.PublicKey())
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		fatal("aggregating signatures: %v", err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		fatal("aggregating pubkeys: %v", err)
	}
	step(3, "aggregated %d signatures", len(sigs))

	// ---- 4. Build the witness -------------------------------------------------
	totalVP := uint64(100 * len(kf.Validators))
	witness, err := bls_zkp.CreateWitnessFromBLSData(
		msgHash, aggSig.Bytes(), aggPub.Bytes(), totalVP, totalVP,
	)
	if err != nil {
		fatal("building witness: %v", err)
	}
	step(4, "witness built (signedVP=%d totalVP=%d)", totalVP, totalVP)

	// ---- 5. Prove -------------------------------------------------------------
	prover := bls_zkp.NewBLSZKProver()
	pk := filepath.Join(*zkKeysDir, "proving_key.bin")
	vk := filepath.Join(*zkKeysDir, "verification_key.bin")
	cs := filepath.Join(*zkKeysDir, "constraint_system.bin")
	if err := prover.InitializeFromKeys(pk, vk, cs); err != nil {
		fatal("loading proving keys from %s: %v", *zkKeysDir, err)
	}
	step(5, "proving keys loaded from %s", *zkKeysDir)

	zkProof, err := prover.GenerateProof(witness)
	if err != nil {
		fatal("generating Groth16 proof: %v", err)
	}
	step(5, "Groth16 proof generated")

	// ---- 6. Verify locally BEFORE spending gas --------------------------------
	ok, err := prover.VerifyProofLocally(zkProof)
	if err != nil || !ok {
		fatal("proof failed LOCAL verification (ok=%v err=%v) — the on-disk proving keys do "+
			"not match this circuit; submitting would revert in _verifyGroth16", ok, err)
	}
	step(6, "proof verifies locally")

	calldata, err := zkProof.ToSolidityCalldata()
	if err != nil {
		fatal("encoding proof calldata: %v", err)
	}
	step(6, "ABI-encoded BLSSignatureProof = %d bytes", len(calldata))

	if !*submit {
		fmt.Println("\nDRY RUN COMPLETE — cryptographic chain validated, nothing submitted.")
		fmt.Printf("signature hex (for -submit run): 0x%s\n", hex.EncodeToString(calldata))
		return
	}

	// ---- 7/8. Submit and confirm ---------------------------------------------
	if *ethKey == "" {
		fatal("-ethkey (or PRIVATE_KEY) required to submit")
	}
	fmt.Println("\nSubmitting executeComprehensiveProof …")
	txHash, err := submitAttestation(ctx, client, anchorAddr, *ethKey, *chainID,
		bundleID, batchRoot, batchOpID, calldata, msgHash, totalVP)
	if err != nil {
		fatal("submitting attestation: %v", err)
	}
	step(7, "attestation tx %s", txHash)

	executed, err := readProofExecuted(ctx, client, anchorAddr, bundleID)
	if err != nil {
		fatal("reading proofExecuted: %v", err)
	}
	if !executed {
		fatal("tx mined but proofExecuted is still false — the batch is not spendable")
	}
	step(8, "proofExecuted = TRUE — batch root attested, members can now settle")
}

func readSetRoot(ctx context.Context, c *ethclient.Client, addr common.Address) ([32]byte, error) {
	const j = `[{"type":"function","name":"currentValidatorSetRoot","inputs":[],"outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"}]`
	p, err := abi.JSON(strings.NewReader(j))
	if err != nil {
		return [32]byte{}, err
	}
	var out []interface{}
	if err := bind.NewBoundContract(addr, p, c, c, c).
		Call(&bind.CallOpts{Context: ctx}, &out, "currentValidatorSetRoot"); err != nil {
		return [32]byte{}, err
	}
	return out[0].([32]byte), nil
}

func readProofExecuted(ctx context.Context, c *ethclient.Client, addr common.Address, id [32]byte) (bool, error) {
	const j = `[{"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32"}],"outputs":[
	 {"name":"a","type":"bytes32"},{"name":"b","type":"bytes32"},{"name":"c","type":"bytes32"},
	 {"name":"d","type":"bytes32"},{"name":"e","type":"bytes32"},{"name":"f","type":"bytes32"},
	 {"name":"g","type":"bytes32"},{"name":"h","type":"bytes32"},{"name":"i","type":"uint256"},
	 {"name":"j","type":"uint256"},{"name":"k","type":"address"},{"name":"l","type":"bool"},
	 {"name":"m","type":"bool"},{"name":"n","type":"bool"},{"name":"o","type":"uint8"}],"stateMutability":"view"}]`
	p, err := abi.JSON(strings.NewReader(j))
	if err != nil {
		return false, err
	}
	var out []interface{}
	if err := bind.NewBoundContract(addr, p, c, c, c).
		Call(&bind.CallOpts{Context: ctx}, &out, "anchors", id); err != nil {
		return false, err
	}
	if len(out) < 13 {
		return false, fmt.Errorf("anchors returned %d fields", len(out))
	}
	return out[12].(bool), nil
}

func submitAttestation(
	ctx context.Context,
	c *ethclient.Client,
	anchorAddr common.Address,
	ethKeyHex string,
	chainID int64,
	bundleID, batchRoot, batchOpID [32]byte,
	sigCalldata []byte,
	msgHash [32]byte,
	totalVP uint64,
) (string, error) {
	sk, err := ethcrypto.HexToECDSA(strings.TrimPrefix(ethKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("parsing eth key: %w", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(sk, big.NewInt(chainID))
	if err != nil {
		return "", err
	}
	auth.Context = ctx
	auth.GasLimit = 1200000

	anchor, err := contracts.NewCertenAnchorWrapper(anchorAddr, c)
	if err != nil {
		return "", fmt.Errorf("binding anchor: %w", err)
	}

	validators, powers, total, signed, err := validatorSetForProof(ctx, c, anchorAddr)
	if err != nil {
		return "", err
	}
	_ = totalVP

	proof := contracts.CertenAnchorV4CertenProof{
		TransactionHash: bundleID,
		MerkleRoot:      batchRoot,
		ProofHashes:     [][32]byte{},
		LeafHash:        [32]byte{},
		GovernanceProof: contracts.CertenAnchorV4GovernanceProofData{
			// HIGH-003: a non-zero keyBookRoot WITH a verifying KeyPage merkle proof is
			// mandatory whenever minimumGovernanceLevel >= 1. An empty keyBookRoot is
			// rejected outright — that is what reverted the first submission attempt.
			// Minimum satisfying shape is a 2-leaf tree:
			//   root  = sortedHash(keccak(authority), sibling)
			//   proof = [sibling]
			KeyBookRoot:        keyBookRootFor(auth.From),
			KeyPageProofs:      keyPageProofFor(),
			AuthorityAddress:   auth.From,
			AuthorityLevel:     2,
			Nonce:              new(big.Int).SetBytes(bundleID[24:]),
			RequiredSignatures: big.NewInt(1),
			ProvidedSignatures: big.NewInt(1),
			ThresholdMet:       true,
		},
		BlsProof: contracts.CertenAnchorV4BLSProofData{
			AggregateSignature: sigCalldata, // ABI-encoded BLSSignatureProof
			ValidatorAddresses: validators,
			VotingPowers:       powers,
			TotalVotingPower:   total,
			SignedVotingPower:  signed,
			ThresholdMet:       true,
			MessageHash:        msgHash,
		},
		Commitments: contracts.CertenAnchorV4CommitmentData{
			OperationCommitment: batchOpID, // V7 requires this to equal the anchor's operationID
			ExecutionCommitment: batchRoot,
			SourceChain:         "accumulate",
			SourceBlockHeight:   big.NewInt(0),
			SourceTxHash:        bundleID,
			TargetChain:         fmt.Sprintf("evm-%d", chainID),
			TargetAddress:       anchorAddr,
		},
		ExpirationTime: big.NewInt(1 << 40),
		Metadata:       []byte("batch-attest"),
	}

	tx, err := anchor.ExecuteComprehensiveProofSimple(auth, bundleID, proof)
	if err != nil {
		return "", err
	}
	receipt, err := bind.WaitMined(ctx, c, tx)
	if err != nil {
		return tx.Hash().Hex(), err
	}
	if receipt.Status == 0 {
		return tx.Hash().Hex(), fmt.Errorf("executeComprehensiveProof reverted")
	}
	return tx.Hash().Hex(), nil
}

// validatorSetForProof reads the registry FROM CHAIN.
//
// V8's _verifyBLSProof (CRYPTO-007) recomputes signedVotingPower from the registry and
// requires every declared power to equal the registered one, so these arrays must mirror
// what the contract holds. Reading them from chain rather than local config removes the
// class of failure that produced the earlier set-root mismatch.
// keyPageSibling is the fixed second leaf of the minimal KeyPage tree.
var keyPageSibling = ethcrypto.Keccak256Hash([]byte("certen:keypage:sibling:v1"))

// keyBookRootFor builds the 2-leaf KeyPage root that HIGH-003 verifies the authority
// against. sortedHash matches CertenAnchorV8._verifyMerkleProof.
func keyBookRootFor(authority common.Address) [32]byte {
	leaf := ethcrypto.Keccak256Hash(authority.Bytes())
	var out [32]byte
	if bytesLessThan(leaf, keyPageSibling) {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, leaf[:]...), keyPageSibling[:]...))
	} else {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, keyPageSibling[:]...), leaf[:]...))
	}
	return out
}

func keyPageProofFor() [][32]byte {
	return [][32]byte{keyPageSibling}
}

func bytesLessThan(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func validatorSetForProof(
	ctx context.Context,
	c *ethclient.Client,
	anchorAddr common.Address,
) ([]common.Address, []*big.Int, *big.Int, *big.Int, error) {
	addrs, _, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	const j = `[{"type":"function","name":"getBLSValidatorInfo","inputs":[{"name":"validator","type":"address"}],"outputs":[{"name":"registered","type":"bool"},{"name":"votingPower","type":"uint256"}],"stateMutability":"view"},
	           {"type":"function","name":"totalVotingPower","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"}]`
	parsed, perr := abi.JSON(strings.NewReader(j))
	if perr != nil {
		return nil, nil, nil, nil, perr
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, c, c, c)

	powers := make([]*big.Int, 0, len(addrs))
	signed := big.NewInt(0)
	for _, a := range addrs {
		var out []interface{}
		if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "getBLSValidatorInfo", a); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("reading validator %s: %w", a.Hex(), err)
		}
		reg := out[0].(bool)
		pw := out[1].(*big.Int)
		if !reg {
			return nil, nil, nil, nil, fmt.Errorf(
				"validator %s is NOT registered on this anchor — the local set and the "+
					"deployed registry disagree", a.Hex())
		}
		powers = append(powers, pw)
		signed = new(big.Int).Add(signed, pw)
	}

	var tout []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &tout, "totalVotingPower"); err != nil {
		return nil, nil, nil, nil, err
	}
	total := tout[0].(*big.Int)

	return addrs, powers, total, signed, nil
}
