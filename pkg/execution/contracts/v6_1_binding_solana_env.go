// Shared Solana V6.1 deployment-config resolvers. Live in the `contracts`
// package so BOTH the BFT signing path (pkg/consensus/v6_1_signing.go) and the
// submission path (pkg/execution/bft_target_chain_integration.go) resolve the
// cluster name and validator-set-root from the same source — guaranteeing the
// signed messageHash and the submitted/anchored messageHash are byte-identical.

package contracts

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

// SolanaClusterFromEnv returns the deployment cluster name the on-chain
// CertenAnchorV6_1 was initialized with (it stores this as deployment_cluster
// and derives deployment_chain_id = keccak256("certen:chain:v1:solana:" ||
// cluster)). Set via SOLANA_DEPLOYMENT_CLUSTER; defaults to "devnet".
func SolanaClusterFromEnv() string {
	c := strings.TrimSpace(os.Getenv("SOLANA_DEPLOYMENT_CLUSTER"))
	if c == "" {
		return "devnet"
	}
	return c
}

// SolanaValidatorSetRootFromEnvOrEmpty resolves the 32-byte validator_set_root
// to fold into the V6.1 messageHash. It MUST equal the contract's stored
// current_validator_set_root at verify time, otherwise execute_comprehensive_proof
// rejects with MessageHashMismatch (6057).
//
// Bring-up workflow (mirrors the Cardano override):
//   - Before any validator is registered, the contract's root is the empty-set
//     root (computed here when the env var is unset) — so a fresh deploy matches
//     with no config.
//   - After registering validators on-chain, read the exact root via the
//     program's get_validator_set_root query and pin it in SOLANA_VALIDATOR_SET_ROOT
//     (hex, 64 chars). Both off-chain sides then bind that value.
func SolanaValidatorSetRootFromEnvOrEmpty(thresholdNum, thresholdDen uint64) [32]byte {
	if root, ok := parseHex32(os.Getenv("SOLANA_VALIDATOR_SET_ROOT")); ok {
		return root
	}
	// Empty-set root — byte-identical to what the contract seeds at initialize()
	// (recompute_validator_set_root(&[], num, den)).
	return ComputeSolanaValidatorSetRootV6_1(nil, nil, thresholdNum, thresholdDen)
}

// parseHex32 parses an optionally-0x-prefixed 64-char hex string into [32]byte.
// Returns (_, false) for empty / malformed input.
func parseHex32(raw string) ([32]byte, bool) {
	clean := strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if len(clean) != 64 {
		return [32]byte{}, false
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		hi, ok1 := hexNibbleSolana(clean[2*i])
		lo, ok2 := hexNibbleSolana(clean[2*i+1])
		if !ok1 || !ok2 {
			return [32]byte{}, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibbleSolana(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// SolanaExecutionCommitmentStubV6_1 is the opaque execution-commitment Solana
// binds at create_anchor time. Unlike EVM/NEAR — where the value-moving target +
// amount are known up front — the Solana value move executes later through the
// user's abstract account, so the anchor commits a deterministic value derived
// from the Accumulate-side commitments. It is treated as OPAQUE by the V6.1
// gates: create_anchor and execute_comprehensive_proof never recompute it; they
// only require the same value to flow into bundle_id derivation and the
// messageHash. BOTH off-chain sides MUST call this so those agree.
//
//	keccak256(adiURLHash ‖ operationCommitment ‖ crossChainCommitment ‖ governanceRoot)
func SolanaExecutionCommitmentStubV6_1(
	adiURLHash, operationCommitment, crossChainCommitment, governanceRoot [32]byte,
) [32]byte {
	preimage := make([]byte, 0, 4*32)
	preimage = append(preimage, adiURLHash[:]...)
	preimage = append(preimage, operationCommitment[:]...)
	preimage = append(preimage, crossChainCommitment[:]...)
	preimage = append(preimage, governanceRoot[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// SolanaExecutionCommitmentV6_1 is the CRITICAL-001 value-bound execution commitment
// that binds the EXACT transfer (recipient + lamports) the intent authorizes,
// REPLACING the opaque stub above. The on-chain certen_account_v2 execute_direct
// handler recomputes this from the runtime (expected_recipient, lamports_value) and
// asserts equality with the anchor's stored execution_commitment (EVM CertenAccountV4
// CRITICAL-001 parity), then also asserts expected_recipient is the System-Transfer
// destination so funds cannot be redirected.
//
// Byte layout (MUST match the Rust twin exactly):
//
//	keccak256("certen:exec:solana" || recipient(32B pubkey) || lamports(u64 LE, 8B))
//
// A native SOL transfer carries no extra calldata, so data is omitted on both sides.
// BOTH off-chain sides (consensus signer + executor) MUST call this so the signed
// messageHash, the bundle_id, and the anchored commitment all agree.
func SolanaExecutionCommitmentV6_1(recipient [32]byte, lamports uint64) [32]byte {
	preimage := make([]byte, 0, 18+32+8)
	preimage = append(preimage, []byte("certen:exec:solana")...)
	preimage = append(preimage, recipient[:]...)
	amt := make([]byte, 8)
	binary.LittleEndian.PutUint64(amt, lamports)
	preimage = append(preimage, amt...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// SolanaRecipient32 decodes a Solana recipient (base58 pubkey, or 0x-hex right-
// aligned) into a 32-byte array — the form the on-chain Pubkey and
// SolanaExecutionCommitmentV6_1 expect. Mirrors execution.DeriveSolanaRecipient so
// the consensus signer and the executor derive the recipient identically. Returns
// the zero array on a decode error (a zero recipient simply can't match any real
// anchor commitment, so the cycle fails closed).
func SolanaRecipient32(addr string) [32]byte {
	var out [32]byte
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X") {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(addr, "0x"), "0X"))
		if err == nil && len(b) <= 32 {
			copy(out[32-len(b):], b)
		}
		return out
	}
	if b, err := base58.Decode(addr); err == nil && len(b) == 32 {
		copy(out[:], b)
	}
	return out
}
