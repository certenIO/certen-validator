// V6.1 A+++ validator set bootstrap.
//
// The V6.1 anchor contract maintains a currentValidatorSetRoot that gets
// folded into the pre-execution BLS messageHash. For BFT signing to match
// what the contract verifies, the validator MUST locally compute the SAME
// setRoot the contract holds. Two ways to get it:
//
//  1. Fetch on-chain via getValidatorSetRoot() at startup. Reliable but adds
//     an RPC dependency to BFT signing and a per-chain cache.
//  2. Compute locally from operator config (this file). Same 7 addresses +
//     voting powers + threshold the deploy script registered → same root.
//     The user's deployment posture is "single shared root across all 7
//     chains" (same operator set, same powers, same threshold), so one
//     cached root serves every chain.
//
// We use option 2 with optional on-chain verification at startup (see
// VerifyAgainstChain). If env config drifts from what's actually registered
// on any chain, the validator will produce signatures that fail to verify
// — failing-loud beats silently signing junk.
package contracts

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// The validator set this node signs for: the addresses, voting powers and threshold registered on the
// anchors, whose set root every quorum message and BLS proof commits to. It is the validators' own pin -
// a registry that changed under them is refused, not followed (batch_settlement_window compares the two).
//
// It is CONFIGURED, never assumed (RB3-F21): the set used to fall back to seven addresses, power 100 and
// 2/3 compiled into the binary whenever the variables were absent - which is how production ran - so a
// rotated key or a changed set would have needed a code change, and a deployment that lost its
// configuration signed for a set nobody had chosen. Absent, the node does not start.
//
// The names are version-neutral; the CERTEN_V6_1_VALIDATOR_* names they replace are still read, and a
// node given both refuses to start unless they say the same thing.
const (
	envValidatorSetAddrs        = "CERTEN_VALIDATOR_SET_ADDRESSES"     // comma-separated 0x hex
	envValidatorSetPowers       = "CERTEN_VALIDATOR_SET_POWERS"        // comma-separated integers, one per address
	envValidatorSetThresholdNum = "CERTEN_VALIDATOR_SET_THRESHOLD_NUM" // numerator of the quorum threshold
	envValidatorSetThresholdDen = "CERTEN_VALIDATOR_SET_THRESHOLD_DEN" // denominator of the quorum threshold

	legacyValidatorSetAddrs        = "CERTEN_V6_1_VALIDATOR_ADDRESSES"
	legacyValidatorSetPowers       = "CERTEN_V6_1_VALIDATOR_POWERS"
	legacyValidatorSetThresholdNum = "CERTEN_V6_1_VALIDATOR_THRESHOLD_NUM"
	legacyValidatorSetThresholdDen = "CERTEN_V6_1_VALIDATOR_THRESHOLD_DEN"
)

// validatorSetSetting reads one setting under its name and its former name: the value either states, and
// an error when both are set and differ, or when neither is.
func validatorSetSetting(name, legacy string) (string, error) {
	v := strings.TrimSpace(os.Getenv(name))
	l := strings.TrimSpace(os.Getenv(legacy))
	if v != "" && l != "" && !strings.EqualFold(strings.Join(splitCSV(v), ","), strings.Join(splitCSV(l), ",")) {
		return "", fmt.Errorf("%s and %s are both set and disagree; set only %s", name, legacy, name)
	}
	if v == "" {
		v = l
	}
	if v == "" {
		return "", fmt.Errorf("the validator set is not configured: set %s (the registered set, as on the anchors)", name)
	}
	return v, nil
}

var (
	cachedSetRoot     [32]byte
	cachedSetRootSet  bool
	cachedSetRootErr  error
	cachedSetRootOnce sync.Once

	cachedSetRootMu sync.RWMutex
)

// GetV6_1ValidatorSetRoot returns the V6.1 currentValidatorSetRoot computed
// from operator config. The result is cached after first computation —
// validator config does not change at runtime, so re-computing on every BFT
// signing call would be wasteful.
//
// Source order: env override → defaults.
func GetV6_1ValidatorSetRoot() ([32]byte, error) {
	cachedSetRootOnce.Do(func() {
		root, err := computeV6_1ValidatorSetRoot()
		cachedSetRootMu.Lock()
		cachedSetRoot = root
		cachedSetRootSet = err == nil
		cachedSetRootErr = err
		cachedSetRootMu.Unlock()
	})
	cachedSetRootMu.RLock()
	defer cachedSetRootMu.RUnlock()
	return cachedSetRoot, cachedSetRootErr
}

// ResetV6_1ValidatorSetRootCache clears the cached root. Tests call this
// between cases that vary the env. Production callers should never need it.
func ResetV6_1ValidatorSetRootCache() {
	cachedSetRootMu.Lock()
	cachedSetRoot = [32]byte{}
	cachedSetRootSet = false
	cachedSetRootErr = nil
	cachedSetRootOnce = sync.Once{}
	cachedSetRootMu.Unlock()
}

func computeV6_1ValidatorSetRoot() ([32]byte, error) {
	addrs, err := resolveValidatorAddrs()
	if err != nil {
		return [32]byte{}, fmt.Errorf("resolve validator addrs: %w", err)
	}
	powers, err := resolveVotingPowers(len(addrs))
	if err != nil {
		return [32]byte{}, fmt.Errorf("resolve voting powers: %w", err)
	}
	num, den, err := resolveThreshold()
	if err != nil {
		return [32]byte{}, err
	}

	sortedAddrs, sortedPowers := SortValidatorsForSetRoot(addrs, powers)
	return ComputeValidatorSetRootV6_1(sortedAddrs, sortedPowers, num, den)
}

func resolveValidatorAddrs() ([]common.Address, error) {
	setting, err := validatorSetSetting(envValidatorSetAddrs, legacyValidatorSetAddrs)
	if err != nil {
		return nil, err
	}
	raw := splitCSV(setting)
	if len(raw) == 0 {
		return nil, fmt.Errorf("no validator addresses configured (set %s)", envValidatorSetAddrs)
	}
	out := make([]common.Address, len(raw))
	for i, s := range raw {
		s = strings.TrimSpace(s)
		if !common.IsHexAddress(s) {
			return nil, fmt.Errorf("validator addr %d (%q) is not a valid hex address", i, s)
		}
		out[i] = common.HexToAddress(s)
	}
	return out, nil
}

func resolveVotingPowers(want int) ([]*big.Int, error) {
	setting, err := validatorSetSetting(envValidatorSetPowers, legacyValidatorSetPowers)
	if err != nil {
		return nil, err
	}
	raw := splitCSV(setting)
	if len(raw) != want {
		return nil, fmt.Errorf("%s has %d entries but %d validators configured",
			envValidatorSetPowers, len(raw), want)
	}
	out := make([]*big.Int, want)
	for i, s := range raw {
		v, ok := new(big.Int).SetString(strings.TrimSpace(s), 10)
		if !ok || v.Sign() <= 0 {
			return nil, fmt.Errorf("voting power %d (%q) is not a positive decimal integer", i, s)
		}
		out[i] = v
	}
	return out, nil
}

// resolveThreshold is the quorum threshold committed into the validator-set root. A value that is not a
// positive integer, or a numerator above its denominator (which the anchor's setThreshold refuses), is
// refused, and so is an absent one: it used to become 2/3 silently, committing a root the operator did not
// choose.
func resolveThreshold() (num, den *big.Int, err error) {
	n, err := thresholdPart(envValidatorSetThresholdNum, legacyValidatorSetThresholdNum)
	if err != nil {
		return nil, nil, err
	}
	d, err := thresholdPart(envValidatorSetThresholdDen, legacyValidatorSetThresholdDen)
	if err != nil {
		return nil, nil, err
	}
	if n > d {
		return nil, nil, fmt.Errorf("%s=%d exceeds %s=%d", envValidatorSetThresholdNum, n, envValidatorSetThresholdDen, d)
	}
	return big.NewInt(n), big.NewInt(d), nil
}

func thresholdPart(name, legacy string) (int64, error) {
	setting, err := validatorSetSetting(name, legacy)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(setting, 10, 64)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("%s=%q is not a positive integer", name, setting)
	}
	return v, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// GetV6_1ValidatorSet returns the operator addresses and voting powers the validator-set
// root is derived from.
//
// Exported so the batch attestation path can populate BLSProofData's validator arrays from
// the SAME source the set root comes from. Deriving them independently would let the
// threshold arithmetic submitted on-chain drift from the quorum the root actually commits
// to — the contract would then be checking a threshold against numbers no one attested.
func GetV6_1ValidatorSet() ([]common.Address, []*big.Int, error) {
	addrs, err := resolveValidatorAddrs()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve validator addrs: %w", err)
	}
	powers, err := resolveVotingPowers(len(addrs))
	if err != nil {
		return nil, nil, fmt.Errorf("resolve voting powers: %w", err)
	}
	out := make([]*big.Int, 0, len(powers))
	for _, p := range powers {
		out = append(out, new(big.Int).Set(p))
	}
	return append([]common.Address(nil), addrs...), out, nil
}
