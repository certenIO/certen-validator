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

// RB5 D4 / RB5-F55, against the deployed verifiers: a 5-of-7 quorum signs an outcome message, the strict path
// (BuildQuorumBLSProofData) proves it with the production proving keys, and the BLSZKVerifierV2_1 each V8.2 anchor
// uses accepts exactly those bytes for that message - and refuses them for any other. The live build requires the
// proving keys (BLS_ZK_KEYS_DIR) and every chain's RPC; nothing is skipped.
func TestTheQuorumProofPathIsAcceptedByTheDeployedVerifiers(t *testing.T) {
	if os.Getenv("BLS_ZK_KEYS_DIR") == "" {
		t.Fatal("the live build requires BLS_ZK_KEYS_DIR (the proving keys whose verification key is deployed)")
	}
	// A quorum of 7 fresh keys at 100 each; 5 sign (500/700 >= 2/3).
	var sigs []*bls.Signature
	var pubs []*bls.PublicKey
	var signers []string
	var powers []*big.Int
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, [32]byte{0x11}, [32]byte{0x77}, [32]byte{0x44}, [32]byte{0xaf}, [32]byte{0xca})
	for i := 0; i < 5; i++ {
		sk, pk, err := bls.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, bls_zkp.SignV6_1PreExec(sk, msg))
		pubs = append(pubs, pk)
		signers = append(signers, common.BigToAddress(big.NewInt(int64(i+1))).Hex())
		powers = append(powers, big.NewInt(100))
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		t.Fatal(err)
	}
	if !aggPub.VerifyG1(aggSig, bls_zkp.HashMessageToG1V2(msg)) {
		t.Fatal("the test quorum's aggregate does not verify")
	}
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: hex.EncodeToString(aggSig.Bytes()), AggregatePublicKeyHex: hex.EncodeToString(aggPub.Bytes()),
		SignedVotingPower: big.NewInt(500), TotalVotingPower: big.NewInt(700), Signers: signers, SignerPowers: powers,
	}
	proof, _, err := (&EthereumContractManager{}).BuildQuorumBLSProofData(agg, msg)
	if err != nil {
		t.Fatalf("the strict path did not prove an honest quorum: %v", err)
	}
	if !proof.ThresholdMet || proof.MessageHash != msg {
		t.Fatalf("proof data %+v", proof)
	}

	verifierABI, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"verifyBLSSignature","stateMutability":"view",
		"inputs":[{"name":"aggregateSignatureProof","type":"bytes"},{"name":"messageHash","type":"bytes32"}],
		"outputs":[{"name":"","type":"bool"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ env, verifier string }{
		{"CERTEN_LIVE_SEPOLIA_RPC", "0x25ebFbC617e777Ae983a2C22E3B9649E3EB93802"},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPC", "0x25ebFbC617e777Ae983a2C22E3B9649E3EB93802"},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", "0x11f0E387d14aee3c2894af72189dfDD92d0925BE"},
	} {
		rpcURL := os.Getenv(c.env)
		if rpcURL == "" {
			t.Fatalf("the live build requires %s", c.env)
		}
		client, err := ethclient.Dial(rpcURL)
		if err != nil {
			t.Fatal(err)
		}
		verify := func(m [32]byte) bool {
			data, err := verifierABI.Pack("verifyBLSSignature", proof.AggregateSignature, m)
			if err != nil {
				t.Fatal(err)
			}
			to := common.HexToAddress(c.verifier)
			out, err := client.CallContract(context.Background(), ethereum.CallMsg{To: &to, Data: data}, nil)
			if err != nil {
				t.Fatalf("%s: verifyBLSSignature: %v", c.env, err)
			}
			res, err := verifierABI.Unpack("verifyBLSSignature", out)
			if err != nil {
				t.Fatal(err)
			}
			return res[0].(bool)
		}
		if !verify(msg) {
			t.Fatalf("%s: the deployed verifier %s rejects the strict path's proof of an honest quorum", c.env, c.verifier)
		}
		other := msg
		other[31] ^= 1
		if verify(other) {
			t.Fatalf("%s: the deployed verifier accepted the proof for a message the quorum never signed", c.env)
		}
	}
}

// RB5-F13, the other half: a Phase 8 result aggregate - RFC 9380 hash_to_curve (RB5-F54) - is not an aggregate the
// deployed verifiers can be given. The strict path, with the production proving keys, refuses to prove it over the
// message it signed: the circuit's hash of that message is another curve point, so no witness satisfies it.
func TestAPhase8AggregateCannotBeProvenForTheDeployedVerifiers(t *testing.T) {
	if os.Getenv("BLS_ZK_KEYS_DIR") == "" {
		t.Fatal("the live build requires BLS_ZK_KEYS_DIR (the proving keys whose verification key is deployed)")
	}
	_, folded, _ := phase8Quorum(t)
	var signers []string
	var powers []*big.Int
	for i := range folded.Attestations {
		signers = append(signers, common.BigToAddress(big.NewInt(int64(i+1))).Hex())
		powers = append(powers, big.NewInt(100))
	}
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: hex.EncodeToString(folded.AggregatedSignature), AggregatePublicKeyHex: hex.EncodeToString(folded.AggregatedPublicKey),
		SignedVotingPower: big.NewInt(int64(100 * len(signers))), TotalVotingPower: big.NewInt(700), Signers: signers, SignerPowers: powers,
	}
	if _, _, err := (&EthereumContractManager{}).BuildQuorumBLSProofData(agg, folded.MessageHash); err == nil {
		t.Fatal("the strict path proved a Phase 8 aggregate for the deployed verifiers")
	} else {
		t.Logf("refused, as it must be: %v", err)
	}
}
