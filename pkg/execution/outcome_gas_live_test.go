//go:build live

package execution

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// registryOverheadGas is recordBatchOutcome's execution gas apart from the Groth16 verification, measured by forge's gas
// report of certen-contracts test/CertenOutcomeRegistryV1.t.sol (commit 16c6d47, 2026-10-03): its maximum, 214,816, with
// a mock verifier costing 2,454 - so 212,362 for the registry, the anchor's quorum checks over seven registered signers
// and the two storage writes.
const registryOverheadGas = 214_816 - 2_454

// RB5 D4: outcomeRecordGas covers a real recordBatchOutcome on every chain, read-only. The deployed verifier's own cost of
// checking a real proof is simulated (eth_estimateGas, nothing sent), added to the registry's measured overhead and the
// transaction's intrinsic gas over its exact calldata, and the sum must leave at least a third of headroom under the limit.
func TestTheOutcomeRecordGasLimitCoversARealRecord(t *testing.T) {
	if os.Getenv("BLS_ZK_KEYS_DIR") == "" {
		t.Fatal("the live build requires BLS_ZK_KEYS_DIR")
	}
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, [32]byte{0x11}, [32]byte{0x77}, [32]byte{0x44}, [32]byte{0xaf}, [32]byte{0xca})
	var sigs []*bls.Signature
	var pubs []*bls.PublicKey
	var signers []string
	var powers []*big.Int
	for i := 0; i < 7; i++ { // every validator signs: the largest signer set, the largest calldata
		sk, pk, err := bls.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, bls_zkp.SignV6_1PreExec(sk, msg))
		pubs = append(pubs, pk)
		signers = append(signers, common.BigToAddress(big.NewInt(int64(0x1000000+i))).Hex())
		powers = append(powers, big.NewInt(100))
	}
	aggSig, _ := bls.AggregateSignatures(sigs)
	aggPub, _ := bls.AggregatePublicKeys(pubs)
	agg := &consensus.QuorumAggregate{AggregateSignatureHex: hex.EncodeToString(aggSig.Bytes()), AggregatePublicKeyHex: hex.EncodeToString(aggPub.Bytes()),
		SignedVotingPower: big.NewInt(700), TotalVotingPower: big.NewInt(700), Signers: signers, SignerPowers: powers}
	proof, _, err := (&EthereumContractManager{}).BuildQuorumBLSProofData(agg, msg)
	if err != nil {
		t.Fatal(err)
	}
	calldata, err := outcomeRegistryABI.Pack("recordBatchOutcome", [32]byte{0x11}, [32]byte{0x77}, proof)
	if err != nil {
		t.Fatal(err)
	}
	intrinsic := uint64(21_000)
	for _, b := range calldata {
		if b == 0 {
			intrinsic += 4
		} else {
			intrinsic += 16
		}
	}
	verifierABI, _ := abi.JSON(strings.NewReader(`[{"type":"function","name":"verifyBLSSignature","stateMutability":"view",
		"inputs":[{"name":"p","type":"bytes"},{"name":"m","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}]}]`))
	vdata, _ := verifierABI.Pack("verifyBLSSignature", proof.AggregateSignature, msg)
	for _, c := range []struct{ env, verifier string }{
		{"CERTEN_LIVE_SEPOLIA_RPC", "0x25ebFbC617e777Ae983a2C22E3B9649E3EB93802"},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPC", "0x25ebFbC617e777Ae983a2C22E3B9649E3EB93802"},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", "0x11f0E387d14aee3c2894af72189dfDD92d0925BE"},
	} {
		client, err := ethclient.Dial(os.Getenv(c.env))
		if err != nil {
			t.Fatal(err)
		}
		to := common.HexToAddress(c.verifier)
		// The verifier call's estimate, less its own intrinsic gas: what verifying a real proof costs inside the record.
		est, err := client.EstimateGas(context.Background(), ethereum.CallMsg{To: &to, Data: vdata})
		if err != nil {
			t.Fatalf("%s: %v", c.env, err)
		}
		vIntrinsic := uint64(21_000)
		for _, b := range vdata {
			if b == 0 {
				vIntrinsic += 4
			} else {
				vIntrinsic += 16
			}
		}
		verify := est - vIntrinsic
		total := intrinsic + registryOverheadGas + verify
		t.Logf("%s: verifier %d + registry %d + intrinsic %d (%d B calldata) = %d of the %d limit (%.0f%%)", c.env, verify,
			registryOverheadGas, intrinsic, len(calldata), total, outcomeRecordGas, 100*float64(total)/float64(outcomeRecordGas))
		if total*3/2 > outcomeRecordGas {
			t.Fatalf("%s: a real record needs about %d gas; the %d limit leaves less than a third of headroom", c.env, total, outcomeRecordGas)
		}
	}
}
