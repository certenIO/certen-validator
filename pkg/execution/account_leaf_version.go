// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// AccountLeafVersion is the account generation a settlement chain is on, named by the batch leaf it verifies (RB5-F57):
//
//	v3 - CertenAccountV7_2 (factory V10): certen:batchleaf:v3, no execution window in the leaf;
//	v4 - CertenAccountV7_3 (factory V11): certen:batchleaf:v4, the member's notBefore/notAfter in the leaf.
//
// A chain is on exactly ONE version. Its trees, settlement calldata, outcome derivation and backfill all use it, and
// nothing ever tries the other version: a member whose account is of the other generation is refused by name.
type AccountLeafVersion string

const (
	AccountLeafV3 AccountLeafVersion = "v3"
	AccountLeafV4 AccountLeafVersion = "v4"
)

// AccountLeafVersionsEnv configures the version per chain, as comma-separated <chainId>=<version> pairs (for example
// "84532=v4"). A pair overrides that chain's default; a chain with neither is on no version.
const AccountLeafVersionsEnv = "CERTEN_ACCOUNT_LEAF_VERSIONS"

var (
	// ErrNoAccountLeafVersion: the chain is on no account leaf version, so no leaf can be formed for it.
	ErrNoAccountLeafVersion = errors.New("no account leaf version is configured for the chain")
	// ErrUnknownAccountLeafVersion: a configured version is not one this validator implements.
	ErrUnknownAccountLeafVersion = errors.New("unknown account leaf version")
)

// defaultAccountLeafVersions is every supported settlement chain on the generation it is deployed with today: all three
// on CertenAccountV7_2 (v3). A chain moves to v4 only by configuration, after its factory V11 is deployed (RB5 §4a: Base
// Sepolia first; Sepolia and Arbitrum Sepolia in RB7 §3A).
func defaultAccountLeafVersions() map[int64]AccountLeafVersion {
	return map[int64]AccountLeafVersion{
		84532:    AccountLeafV3, // Base Sepolia
		11155111: AccountLeafV3, // Sepolia
		421614:   AccountLeafV3, // Arbitrum Sepolia
	}
}

// AccountLeafVersions is the version of every chain that has one. Immutable once built.
type AccountLeafVersions struct {
	byChain map[int64]AccountLeafVersion
}

// ParseAccountLeafVersion is the version a configuration names, refused by name when unknown.
func ParseAccountLeafVersion(s string) (AccountLeafVersion, error) {
	switch v := AccountLeafVersion(strings.ToLower(strings.TrimSpace(s))); v {
	case AccountLeafV3, AccountLeafV4:
		return v, nil
	default:
		return "", fmt.Errorf("%w: %q (this validator implements v3 and v4)", ErrUnknownAccountLeafVersion, s)
	}
}

// ParseAccountLeafVersions is the defaults with spec's pairs applied. An unparsable pair, an unknown version or a chain
// named twice is refused by name: a misconfigured chain must not start on a version nobody chose.
func ParseAccountLeafVersions(spec string) (AccountLeafVersions, error) {
	out := AccountLeafVersions{byChain: defaultAccountLeafVersions()}
	seen := map[int64]bool{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return AccountLeafVersions{}, fmt.Errorf("%s: %q is not <chainId>=<version>", AccountLeafVersionsEnv, pair)
		}
		id, err := strconv.ParseInt(strings.TrimSpace(k), 10, 64)
		if err != nil || id <= 0 {
			return AccountLeafVersions{}, fmt.Errorf("%s: %q does not name a chain id", AccountLeafVersionsEnv, pair)
		}
		if seen[id] {
			return AccountLeafVersions{}, fmt.Errorf("%s: chain %d is named twice; a chain is on exactly one version",
				AccountLeafVersionsEnv, id)
		}
		seen[id] = true
		ver, err := ParseAccountLeafVersion(v)
		if err != nil {
			return AccountLeafVersions{}, fmt.Errorf("%s: chain %d: %w", AccountLeafVersionsEnv, id, err)
		}
		out.byChain[id] = ver
	}
	return out, nil
}

// For is the chain's version, or ErrNoAccountLeafVersion.
func (v AccountLeafVersions) For(chainID int64) (AccountLeafVersion, error) {
	ver, ok := v.byChain[chainID]
	if !ok {
		return "", fmt.Errorf("%w: chain %d (set %s)", ErrNoAccountLeafVersion, chainID, AccountLeafVersionsEnv)
	}
	return ver, nil
}

// Require refuses, naming each, every chain that is on no version.
func (v AccountLeafVersions) Require(chainIDs ...int64) error {
	var missing []string
	for _, id := range chainIDs {
		if _, err := v.For(id); err != nil {
			missing = append(missing, strconv.FormatInt(id, 10))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: chain(s) %s settle through the batch path and are on none (set %s)",
			ErrNoAccountLeafVersion, strings.Join(missing, ", "), AccountLeafVersionsEnv)
	}
	return nil
}

// String lists every chain's version in chain order.
func (v AccountLeafVersions) String() string {
	ids := make([]int64, 0, len(v.byChain))
	for id := range v.byChain {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d=%s", id, v.byChain[id]))
	}
	return strings.Join(parts, ",")
}

// AccountLeafVersionsFromEnv is the configured versions (AccountLeafVersionsEnv over the defaults), required for every
// chain the batch path settles on. Startup refuses on any error.
func AccountLeafVersionsFromEnv(batchChains []int64) (AccountLeafVersions, error) {
	v, err := ParseAccountLeafVersions(os.Getenv(AccountLeafVersionsEnv))
	if err != nil {
		return AccountLeafVersions{}, err
	}
	if err := v.Require(batchChains...); err != nil {
		return AccountLeafVersions{}, err
	}
	return v, nil
}

// accountLeafVersions is the process's versions: the defaults until startup sets the configured ones, once, before any
// tree is formed.
var accountLeafVersions atomic.Pointer[AccountLeafVersions]

func init() {
	d := AccountLeafVersions{byChain: defaultAccountLeafVersions()}
	accountLeafVersions.Store(&d)
}

// SetAccountLeafVersions installs the process's versions. Startup calls it once, before the batch path runs.
func SetAccountLeafVersions(v AccountLeafVersions) {
	if v.byChain == nil {
		v = AccountLeafVersions{byChain: map[int64]AccountLeafVersion{}}
	}
	accountLeafVersions.Store(&v)
}

// AccountLeafVersionOf is the version the process holds for the chain, or ErrNoAccountLeafVersion.
func AccountLeafVersionOf(chainID int64) (AccountLeafVersion, error) {
	return accountLeafVersions.Load().For(chainID)
}

// LeafDomain is the LEAF_DOMAIN an account of this version reports.
func (v AccountLeafVersion) LeafDomain() (string, error) {
	switch v {
	case AccountLeafV3:
		return contracts.LeafDomainV7_2, nil
	case AccountLeafV4:
		return contracts.LeafDomainV7_3, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownAccountLeafVersion, v)
	}
}

// AccountContract names the account generation of this version.
func (v AccountLeafVersion) AccountContract() string {
	switch v {
	case AccountLeafV3:
		return "CertenAccountV7_2 (factory V10)"
	case AccountLeafV4:
		return "CertenAccountV7_3 (factory V11)"
	default:
		return "an unknown account generation"
	}
}
