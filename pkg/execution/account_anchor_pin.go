// Copyright 2026 Certen Protocol

package execution

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
)

// AccountAnchorAllowlistEnv adds anchors an account may be pointed at, beyond the anchor each chain is
// configured with: "chainID:0xAnchor,chainID:0xAnchor". Its use is the contract upgrade - listing the
// new anchor lets accounts migrate to it by intent. Every validator must carry the same value, or
// they disagree on such an intent and it fails to reach quorum.
const AccountAnchorAllowlistEnv = "CERTEN_ACCOUNT_ANCHOR_ALLOWLIST"

// parseAccountAnchorAllowlist reads AccountAnchorAllowlistEnv. A malformed entry is an error, not a
// skip: a validator that silently dropped an entry would refuse what its peers allow.
func parseAccountAnchorAllowlist(raw string) (map[int64][]common.Address, error) {
	out := map[int64][]common.Address{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || !common.IsHexAddress(strings.TrimSpace(parts[1])) {
			return nil, fmt.Errorf("%s entry %q is not chainID:0xAddress", AccountAnchorAllowlistEnv, entry)
		}
		chainID, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s entry %q: bad chain ID: %w", AccountAnchorAllowlistEnv, entry, err)
		}
		out[chainID] = append(out[chainID], common.HexToAddress(strings.TrimSpace(parts[1])))
	}
	return out, nil
}

// AllowedAccountAnchor reports whether an account on chainID may be pointed at anchor: the anchor this
// validator settles that chain against, or one the allowlist names for it. A malformed allowlist
// allows nothing beyond the configured anchor.
func (s *BatchStack) AllowedAccountAnchor(chainID int64, anchor common.Address) bool {
	if s == nil || anchor == (common.Address{}) {
		return false
	}
	if orch, err := s.OrchestratorFor(chainID); err == nil && orch.anchorV7 == anchor {
		return true
	}
	extra, err := parseAccountAnchorAllowlist(os.Getenv(AccountAnchorAllowlistEnv))
	if err != nil {
		return false
	}
	for _, a := range extra[chainID] {
		if a == anchor {
			return true
		}
	}
	return false
}

// orchestratorAnchorPolicy is the allowlist as one orchestrator sees it: its own chain's anchor and
// the allowlist's entries for it.
type orchestratorAnchorPolicy struct{ o *BatchOrchestrator }

func (p orchestratorAnchorPolicy) AllowedAccountAnchor(chainID int64, anchor common.Address) bool {
	if p.o == nil || anchor == (common.Address{}) {
		return false
	}
	if anchor == p.o.anchorV7 {
		return true
	}
	extra, err := parseAccountAnchorAllowlist(os.Getenv(AccountAnchorAllowlistEnv))
	if err != nil {
		return false
	}
	for _, a := range extra[chainID] {
		if a == anchor {
			return true
		}
	}
	return false
}

// checkMemberAnchorPin applies the account anchor pin to every call a member makes.
func checkMemberAnchorPin(policy consensus.AccountAnchorPolicy, p *PendingBatchIntent) error {
	for _, l := range p.Legs {
		if err := consensus.CheckAccountAnchorCall(policy, p.ChainID, p.Account, l.Target, l.Data); err != nil {
			return fmt.Errorf("member %s: %w", p.IntentID, err)
		}
	}
	return nil
}

// checkCallAnchorPin is consensus.CheckAccountAnchorCall for callers in this package.
func checkCallAnchorPin(policy consensus.AccountAnchorPolicy, chainID int64, account, target common.Address, data []byte) error {
	return consensus.CheckAccountAnchorCall(policy, chainID, account, target, data)
}

var _ consensus.AccountAnchorPolicy = (*BatchStack)(nil)
