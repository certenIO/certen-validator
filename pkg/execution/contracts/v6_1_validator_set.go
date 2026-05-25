// V6.1 A+++ validator set bootstrap.
//
// The V6.1 anchor contract maintains a currentValidatorSetRoot that gets
// folded into the pre-execution BLS messageHash. For BFT signing to match
// what the contract verifies, the validator MUST locally compute the SAME
// setRoot the contract holds. Two ways to get it:
//
//   1. Fetch on-chain via getValidatorSetRoot() at startup. Reliable but adds
//      an RPC dependency to BFT signing and a per-chain cache.
//   2. Compute locally from operator config (this file). Same 7 addresses +
//      voting powers + threshold the deploy script registered → same root.
//      The user's deployment posture is "single shared root across all 7
//      chains" (same operator set, same powers, same threshold), so one
//      cached root serves every chain.
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
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// Default 7-validator operator set. Matches DeployAnchorV6.s.sol /
// DeployAnchorV6_1.s.sol fallback addresses, so the validator works
// out-of-the-box for any chain deployed with default validators.
var defaultValidatorAddrs = []string{
	"0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8",
	"0x518273099F5c4b87eEA65141931B78012dfE5c7d",
	"0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6",
	"0x6Ff54041Afef809e93ce6B570545069d2764783f",
	"0x9eaA84E3D31479eCC9130187DA9f962625e8C271",
	"0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf",
	"0x0D786D587aBe92f1031506fF3eF88c79a93A8962",
}

// Default voting power per validator (matches deploy script's
// DEFAULT_VOTING_POWER = 100).
const defaultVotingPower int64 = 100

// Default BLS threshold: 2/3 (Byzantine-fault-tolerant majority).
const defaultThresholdNum int64 = 2
const defaultThresholdDen int64 = 3

// Env var names for operator-override of the V6.1 validator set.
const (
	envValidatorSetAddrs        = "CERTEN_V6_1_VALIDATOR_ADDRESSES"   // comma-separated 0x hex
	envValidatorSetPowers       = "CERTEN_V6_1_VALIDATOR_POWERS"      // comma-separated ints
	envValidatorSetThresholdNum = "CERTEN_V6_1_VALIDATOR_THRESHOLD_NUM" // default 2
	envValidatorSetThresholdDen = "CERTEN_V6_1_VALIDATOR_THRESHOLD_DEN" // default 3
)

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
	num, den := resolveThreshold()

	sortedAddrs, sortedPowers := SortValidatorsForSetRoot(addrs, powers)
	return ComputeValidatorSetRootV6_1(sortedAddrs, sortedPowers, num, den)
}

func resolveValidatorAddrs() ([]common.Address, error) {
	override := strings.TrimSpace(os.Getenv(envValidatorSetAddrs))
	var raw []string
	if override != "" {
		raw = splitCSV(override)
	} else {
		raw = defaultValidatorAddrs
	}
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
	override := strings.TrimSpace(os.Getenv(envValidatorSetPowers))
	if override == "" {
		out := make([]*big.Int, want)
		for i := range out {
			out[i] = big.NewInt(defaultVotingPower)
		}
		return out, nil
	}
	raw := splitCSV(override)
	if len(raw) != want {
		return nil, fmt.Errorf("%s has %d entries but %d validators configured",
			envValidatorSetPowers, len(raw), want)
	}
	out := make([]*big.Int, want)
	for i, s := range raw {
		v, ok := new(big.Int).SetString(strings.TrimSpace(s), 10)
		if !ok {
			return nil, fmt.Errorf("voting power %d (%q) is not a decimal integer", i, s)
		}
		out[i] = v
	}
	return out, nil
}

func resolveThreshold() (num, den *big.Int) {
	num = big.NewInt(parseInt64Env(envValidatorSetThresholdNum, defaultThresholdNum))
	den = big.NewInt(parseInt64Env(envValidatorSetThresholdDen, defaultThresholdDen))
	return
}

func parseInt64Env(name string, fallback int64) int64 {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return fallback
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return fallback
	}
	if !v.IsInt64() {
		return fallback
	}
	return v.Int64()
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
