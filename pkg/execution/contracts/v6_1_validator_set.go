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

// Default 7-validator operator set. THESE MUST MATCH the addresses
// registered on the V6.1 anchor at deployment time — otherwise the locally-
// computed setRoot disagrees with the contract's currentValidatorSetRoot,
// the BFT-signed messageHash diverges from the one the contract recomputes,
// and TX2 (executeComprehensiveProof) reverts with
// "BLS signature verification failed".
//
// These are the rotated V6 addresses (SEPOLIA_V6_VALIDATOR_1..7 from
// certen-contracts/evm/.env) registered by deploy_v6_1_chain.sh on
// 2026-05-25. If you redeploy with a different operator set, override via
// CERTEN_V6_1_VALIDATOR_ADDRESSES env on every validator.
var defaultValidatorAddrs = []string{
	"0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D",
	"0x5555afA8Ff8048BddAAC1554AFd790c9bf7ec6E0",
	"0x6ACaa68417F5ad5d4a02D9d3d72E291efFcDf30A",
	"0x16aB06F3634218a8f1F3B01dCdd32DDFbdc8a69D",
	"0xf150Ff923E29F797b4598b89bD7D02002D00Db3a",
	"0x70A6A81bb5E3B63B1929301239DE1F5c63Ec4F3a",
	"0xee2EfA29989Fe6E53572087680c661EC29e045Fe",
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
