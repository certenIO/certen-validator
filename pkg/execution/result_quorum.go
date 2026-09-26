package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
)

// =============================================================================
// Post-execution quorum - counted against the on-chain validator registry
// =============================================================================
//
// Phase 8 decides whether a settled result may be written back to Accumulate. It summed each
// attestation's own Weight field - for a peer, whatever its JSON said - over whatever key the
// attestation carried, with no dedupe, against a total of len(peers)+1. One responder at a peer URL
// declaring Weight 100 met the threshold alone (RB3-F41). One attestation over a different message
// aborted the whole aggregate, so a single divergent peer could deny every write-back.
//
// The pre-execution batch quorum already counts correctly (AggregateBatchAttestations): the key and
// the power come from the chain's registry, never from the attester. Phase 8 now counts the same way:
//
//   - an attestation counts only if its key is a REGISTERED key, and it counts that validator's
//     registered power - the attester's Weight is overwritten, never read;
//   - one validator counts once;
//   - it must have signed THIS result's message; one that signed another is excluded and named, and
//     cannot help or block the honest result;
//   - the total is the registry's total power, not the number of peers configured.

// ResultQuorumRegistryFn returns the validator registry the post-execution quorum for chainID is
// counted against: the same on-chain registry the pre-execution batch quorum reads.
type ResultQuorumRegistryFn func(ctx context.Context, chainID string) (map[string]consensus.ValidatorRegistryEntry, error)

// ResultQuorumRegistryFromChains reads the registry from the anchor each chain's resolver names.
func ResultQuorumRegistryFromChains(chains EVMChainResolver) ResultQuorumRegistryFn {
	return func(ctx context.Context, chainID string) (map[string]consensus.ValidatorRegistryEntry, error) {
		id, ok := new(big.Int).SetString(strings.TrimSpace(chainID), 10)
		if !ok || !id.IsInt64() {
			return nil, fmt.Errorf("chain id %q is not a decimal EVM chain id", chainID)
		}
		ecm, anchor, err := chains.ManagerForChain(id.Int64())
		if err != nil {
			return nil, fmt.Errorf("resolving chain %s: %w", chainID, err)
		}
		return ReadValidatorRegistry(ctx, ecm, anchor)
	}
}

// ExcludedResultAttestation is an attestation that did not count toward the quorum, and why.
type ExcludedResultAttestation struct {
	ValidatorID string
	Reason      string
}

// foldResultAttestations verifies each attestation against the registry and aggregates the ones that
// count. The aggregate's weights are registry power; ThresholdMet requires both the fraction of
// registered power and, when the threshold sets one, a minimum NUMBER of distinct signers.
func foldResultAttestations(
	ctx context.Context,
	strat attestation.AttestationStrategy,
	message *attestation.AttestationMessage,
	atts []*attestation.Attestation,
	registry map[string]consensus.ValidatorRegistryEntry,
	threshold *attestation.ThresholdConfig,
) (*attestation.AggregatedAttestation, []ExcludedResultAttestation, error) {
	if strat == nil || message == nil {
		return nil, nil, fmt.Errorf("result quorum needs a strategy and the attested message")
	}
	if threshold == nil || threshold.Denominator == 0 || threshold.Numerator == 0 || threshold.Numerator > threshold.Denominator {
		return nil, nil, fmt.Errorf("result quorum needs a sensible threshold")
	}
	if len(registry) == 0 {
		return nil, nil, fmt.Errorf("empty validator registry - no voting power to count against")
	}

	expected, err := strat.ComputeMessageHash(message)
	if err != nil {
		return nil, nil, fmt.Errorf("computing the attested message hash: %w", err)
	}

	total := big.NewInt(0)
	byKey := make(map[string]string, len(registry))
	for addr, entry := range registry {
		if entry.VotingPower == nil || entry.VotingPower.Sign() <= 0 {
			return nil, nil, fmt.Errorf("registered validator %s has no voting power", addr)
		}
		total.Add(total, entry.VotingPower)
		byKey[normalizeKeyHex(entry.PublicKeyHex)] = addr
	}
	if !total.IsInt64() {
		return nil, nil, fmt.Errorf("registry total voting power %s does not fit the attestation weight", total)
	}

	type counted struct {
		addr string
		att  *attestation.Attestation
	}
	var good []counted
	var excluded []ExcludedResultAttestation
	exclude := func(att *attestation.Attestation, reason string) {
		id := ""
		if att != nil {
			id = att.ValidatorID
		}
		excluded = append(excluded, ExcludedResultAttestation{ValidatorID: id, Reason: reason})
	}
	seen := make(map[string]bool, len(atts))

	for _, att := range atts {
		if att == nil {
			exclude(nil, "empty attestation")
			continue
		}
		if att.MessageHash != expected {
			exclude(att, fmt.Sprintf("signed a different result (message %x, this result %x)", att.MessageHash[:8], expected[:8]))
			continue
		}
		addr, ok := byKey[normalizeKeyHex(hex.EncodeToString(att.PublicKey))]
		if !ok {
			exclude(att, "signing key is not a registered validator key")
			continue
		}
		if seen[addr] {
			exclude(att, fmt.Sprintf("second attestation for registered validator %s", addr))
			continue
		}
		valid, verr := strat.Verify(ctx, att)
		if verr != nil {
			exclude(att, fmt.Sprintf("signature cannot be checked: %v", verr))
			continue
		}
		if !valid {
			exclude(att, "signature does not verify")
			continue
		}
		seen[addr] = true
		att.Weight = registry[addr].VotingPower.Int64()
		good = append(good, counted{addr: addr, att: att})
	}

	if len(good) == 0 {
		return nil, excluded, fmt.Errorf("no attestation from a registered validator over this result (%d excluded)", len(excluded))
	}

	// Same fold on every validator regardless of arrival order.
	sort.Slice(good, func(i, j int) bool { return good[i].addr < good[j].addr })
	accepted := make([]*attestation.Attestation, len(good))
	for i, g := range good {
		accepted[i] = g.att
	}

	agg, err := strat.Aggregate(ctx, accepted)
	if err != nil {
		return nil, excluded, fmt.Errorf("aggregate attestations: %w", err)
	}
	agg.TotalWeight = total.Int64()
	agg.ThresholdWeight = threshold.CalculateThresholdWeight(agg.TotalWeight)
	enoughSigners := threshold.MinValidators <= 0 ||
		(len(registry) >= threshold.MinValidators && len(accepted) >= threshold.MinValidators)
	agg.ThresholdMet = enoughSigners && agg.AchievedWeight >= agg.ThresholdWeight
	return agg, excluded, nil
}

// registryAttestationSet is the validator set a Phase 8 quorum is counted against, as a snapshot: the
// registry's members at their registered power. It is the same on every validator, whoever builds it.
func registryAttestationSet(
	registry map[string]consensus.ValidatorRegistryEntry,
	thresholdWeight func(int64) int64,
	blockNumber uint64,
) (*ValidatorSetSnapshot, error) {
	addrs := make([]string, 0, len(registry))
	for addr := range registry {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	snapshot := &ValidatorSetSnapshot{
		BlockNumber: blockNumber,
		CreatedAt:   time.Now().UTC(),
		Validators:  make([]ValidatorEntry, len(addrs)),
		TotalWeight: big.NewInt(0),
	}
	for i, addr := range addrs {
		entry := registry[addr]
		pub, err := hex.DecodeString(normalizeKeyHex(entry.PublicKeyHex))
		if err != nil {
			return nil, fmt.Errorf("registered key for %s: %w", addr, err)
		}
		snapshot.Validators[i] = ValidatorEntry{
			ValidatorID: addr,
			Address:     common.HexToAddress(addr),
			PublicKey:   pub,
			Weight:      new(big.Int).Set(entry.VotingPower),
			Index:       uint32(i),
		}
		snapshot.TotalWeight.Add(snapshot.TotalWeight, entry.VotingPower)
	}
	if !snapshot.TotalWeight.IsInt64() {
		return nil, fmt.Errorf("registry total voting power %s does not fit 64 bits", snapshot.TotalWeight)
	}
	snapshot.ThresholdWeight = big.NewInt(thresholdWeight(snapshot.TotalWeight.Int64()))
	snapshot.ValidatorRoot = snapshot.ComputeValidatorRoot()
	snapshot.SnapshotID = snapshot.ComputeSnapshotID()
	return snapshot, nil
}

func normalizeKeyHex(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}
