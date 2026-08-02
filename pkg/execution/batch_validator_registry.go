package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Validator registry — read from the anchor, never from config alone
// =============================================================================
//
// AggregateBatchAttestations resolves both the BLS public key it verifies a partial against
// and the voting power that partial contributes. Both must come from the CHAIN, because both
// are what the chain will re-check:
//
//   - the pubkey, because a validator that supplied its own would be free to sign with a key
//     it controls while spending power registered to somebody else;
//   - the power, because SignedVotingPower is a public input to the ZK proof and the anchor
//     compares the resulting aggregate pubkey against its authorized-subset commitments.
//
// CertenAnchorV8_1 stores exactly this: `mapping(address => ValidatorInfo) public validators`
// where ValidatorInfo is (registered, votingPower, blsPublicKey, registeredAt). The addresses
// to look up come from contracts.GetV6_1ValidatorSet — safe as an INDEX because the anchor's
// currentValidatorSetRoot commits to that same roster, so a drifted config produces a setRoot
// the contract rejects rather than a quorum it silently mis-scores.

// validatorsABIJSON is the `mapping(address => ValidatorInfo) public validators` getter,
// transcribed from CertenAnchorV8_1.sol:411-416.
const validatorsABIJSON = `[{"type":"function","name":"validators","inputs":[{"name":"","type":"address"}],"outputs":[` +
	`{"name":"registered","type":"bool"},` +
	`{"name":"votingPower","type":"uint256"},` +
	`{"name":"blsPublicKey","type":"bytes"},` +
	`{"name":"registeredAt","type":"uint256"}` +
	`],"stateMutability":"view"}]`

// ReadValidatorRegistry loads the on-chain validator registry, keyed by lowercased EVM address.
//
// Every configured validator must be registered with positive power and a well-formed BLS
// public key. A partial registry is refused rather than returned: it would silently understate
// TotalVotingPower, which inflates every threshold comparison and could let a sub-quorum look
// sufficient.
func ReadValidatorRegistry(
	ctx context.Context,
	ecm *EthereumContractManager,
	anchorAddr common.Address,
) (map[string]consensus.ValidatorRegistryEntry, error) {
	if ecm == nil || ecm.client == nil {
		return nil, fmt.Errorf("no chain client for registry read")
	}

	addrs, cfgPowers, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		return nil, fmt.Errorf("validator set roster: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("validator set roster is empty")
	}

	parsed, err := abiFromJSON(validatorsABIJSON)
	if err != nil {
		return nil, err
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, ecm.client, ecm.client, ecm.client)
	opts := &bind.CallOpts{Context: ctx}

	reg := make(map[string]consensus.ValidatorRegistryEntry, len(addrs))
	for i, a := range addrs {
		var out []interface{}
		if err := bound.Call(opts, &out, "validators", a); err != nil {
			return nil, fmt.Errorf("reading validators(%s) from anchor %s: %w",
				a.Hex(), anchorAddr.Hex(), err)
		}
		if len(out) < 4 {
			return nil, fmt.Errorf("validators() returned %d fields, expected 4 — the "+
				"ValidatorInfo struct layout changed", len(out))
		}

		registered, _ := out[0].(bool)
		if !registered {
			return nil, fmt.Errorf(
				"validator %s is in this node's configured set but is NOT registered on anchor %s; "+
					"refusing to aggregate against an incomplete registry",
				a.Hex(), anchorAddr.Hex())
		}

		power, ok := out[1].(*big.Int)
		if !ok || power == nil || power.Sign() <= 0 {
			return nil, fmt.Errorf("validator %s has no on-chain voting power", a.Hex())
		}
		// A config power that disagrees with the chain means the locally computed
		// currentValidatorSetRoot is stale, and the contract would reject any signature
		// claiming it. Fail here, where the error names the cause.
		if i < len(cfgPowers) && cfgPowers[i] != nil && cfgPowers[i].Cmp(power) != 0 {
			return nil, fmt.Errorf(
				"validator %s: configured power %s but chain says %s — the local validator-set "+
					"root is stale and every quorum signature would be rejected",
				a.Hex(), cfgPowers[i], power)
		}

		pubBytes, ok := out[2].([]byte)
		if !ok || len(pubBytes) == 0 {
			return nil, fmt.Errorf("validator %s has no registered BLS public key", a.Hex())
		}
		// Parse now rather than at fold time: a malformed key registered on chain would
		// otherwise surface as "attestation does not verify" and look like a signing bug.
		if _, perr := bls.PublicKeyFromBytes(pubBytes); perr != nil {
			return nil, fmt.Errorf("validator %s has an unparseable registered BLS key (%d bytes): %w",
				a.Hex(), len(pubBytes), perr)
		}

		key := strings.ToLower(a.Hex())
		reg[key] = consensus.ValidatorRegistryEntry{
			EVMAddress:   key,
			PublicKeyHex: hex.EncodeToString(pubBytes),
			VotingPower:  new(big.Int).Set(power),
		}
	}

	return reg, nil
}

// ResolveOwnEVMAddress determines which registry entry belongs to THIS validator by matching
// the node's own BLS public key.
//
// This is the identity source of truth, and it needs no configuration at all. The alternative
// — a VALIDATOR_EVM_ADDRESS env per container — is silently wrong when an address is pasted
// into the wrong service: the misattributed partial is refused by the aggregator's registry
// pubkey check, so the quorum simply runs one signer short with nothing pointing at why.
//
// Matching on the key cannot be misconfigured, and it fails loudly in exactly the case where
// this node should NOT be attesting: its key is not in the registered set.
func ResolveOwnEVMAddress(registry map[string]consensus.ValidatorRegistryEntry) (string, error) {
	km := bls.GetValidatorBLSKey()
	if km == nil {
		return "", fmt.Errorf("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return "", fmt.Errorf("validator BLS private key not loaded")
	}
	return matchRegistryByPubkey(registry, sk.PublicKey().Hex())
}

// matchRegistryByPubkey is the pure core of ResolveOwnEVMAddress, split out so the matching
// rules can be tested without a process-wide BLS key manager.
func matchRegistryByPubkey(
	registry map[string]consensus.ValidatorRegistryEntry,
	ownPubHex string,
) (string, error) {
	mine := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ownPubHex), "0x"))
	if mine == "" {
		return "", fmt.Errorf("this validator's BLS public key is empty")
	}

	var matches []string
	for addr, e := range registry {
		if strings.ToLower(strings.TrimPrefix(e.PublicKeyHex, "0x")) == mine {
			matches = append(matches, addr)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf(
			"this validator's BLS key is not registered on the anchor; it cannot attest to "+
				"batches (registry holds %d validator(s))", len(registry))
	default:
		// Two addresses sharing one key would make voting power ambiguous — the same signature
		// could be counted twice under different addresses.
		return "", fmt.Errorf(
			"this validator's BLS key is registered under %d addresses (%s); voting power is "+
				"ambiguous and attesting would be unsafe", len(matches), strings.Join(matches, ", "))
	}
}
