// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// ContractIdentitySource composes the LegContext of one STORED leg (V2_SPEC_S8 WP-S8-5). Every read is of the shape the live store holds
// (checked by pr/rb11-prod-shape-check.sh section S8): the settlement from the stored bundle (proof_bundles.bundle_data, gzip JSON,
// component 5, via FinalityAddendaRepository.LegSettlement), the batch root from the bundle's component 1, the operation id from
// external_chain_results, the account URL from proof_artifacts, the accumulate set root and incarnation from
// intent_quorum_certificates.message_inputs, the S9 registry from intent_quorum_certificates.registry (members with a 192-character
// lowercase hex key WITHOUT 0x), S6 from the replay-guard evidence stored beside the observation, S7 from the stored addendum chain.
// A value the store does not hold stays ZERO so that the verifier names it (context_incomplete{missing}); nothing is invented or defaulted.
type ContractIdentitySource struct {
	client  *Client
	addenda *FinalityAddendaRepository
	pins    *finality.Pins
}

func NewContractIdentitySource(client *Client, addenda *FinalityAddendaRepository, pins *finality.Pins) *ContractIdentitySource {
	return &ContractIdentitySource{client: client, addenda: addenda, pins: pins}
}

type qcRegistry struct {
	Members []struct {
		Power      uint64 `json:"power"`
		BLSPubKey  string `json:"bls_pub_key"`
		EVMAddress string `json:"evm_address"`
	} `json:"members"`
	ThresholdNumerator   uint64 `json:"threshold_numerator"`
	ThresholdDenominator uint64 `json:"threshold_denominator"`
	CertenSetRoot        string `json:"certen_set_root"`
}

type qcInputs struct {
	AccumulateSetRoot string `json:"accumulate_set_root"`
	Incarnation       string `json:"incarnation"`
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("not a 32-byte hex value (%d characters)", len(s))
	}
	copy(out[:], b)
	return out, nil
}

// ADIURLOf is the ADI root of an account URL: acc://<adi>.acme from acc://<adi>.acme/<path>.
func ADIURLOf(accountURL string) string {
	u := strings.TrimSpace(accountURL)
	rest := strings.TrimPrefix(u, "acc://")
	if rest == u || rest == "" {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return "acc://" + rest
}

// Registry9Of builds the S9 registry from the stored QC registry document. The BLS key keeps its stored form; a key that is not 192
// lowercase hex characters without 0x makes Registry9.Validate fail, which the verifier names context_incomplete{registry9}.
func Registry9Of(raw json.RawMessage) (*ci.Registry9, error) {
	var d qcRegistry
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("the QC registry is not the stored document shape: %w", err)
	}
	root, err := hex32(d.CertenSetRoot)
	if err != nil {
		return nil, fmt.Errorf("registry certen_set_root: %w", err)
	}
	r := &ci.Registry9{Num: d.ThresholdNumerator, Den: d.ThresholdDenominator, CertenSetRoot: root}
	for _, m := range d.Members {
		r.Members = append(r.Members, ci.RegistryMember{Address: common.HexToAddress(m.EVMAddress), Power: m.Power, BLSKey: m.BLSPubKey})
	}
	return r, nil
}

// S6Of judges the stored replay-guard evidence of a settlement (empty = none stored): s6_proven with its link, s6_not_proven with the S6
// named state verbatim, or s6_silent{absent} when the store holds none. S6 is never inferred.
func S6Of(s *ethproof.Settlement, raw []byte) (status ci.S6Status, reason, state string, link *ci.S6Link) {
	if len(raw) == 0 || string(raw) == "null" {
		return ci.S6Silent, "absent", "", nil
	}
	ev, err := ethproof.DecodeReplayGuardEvidence(raw)
	if err != nil {
		return ci.S6NotProven, "", "s6_replay_unproven: stored evidence undecodable: " + err.Error(), nil
	}
	chk, err := ev.Verify(s)
	if err != nil {
		return ci.S6NotProven, "", err.Error(), nil
	}
	if chk.State != ethproof.ReplayProven {
		return ci.S6NotProven, "", chk.State + ": " + chk.Reason, nil
	}
	return ci.S6Proven, "", "", &ci.S6Link{Contract: chk.Contract, LeafKey: chk.Slot.Key,
		SettlementBlock: ci.BlockRef{Number: chk.SettlementBlock.Number, Hash: chk.SettlementBlock.Hash},
		ProvenAt:        ci.BlockRef{Number: chk.ProvenAt.Number, Hash: chk.ProvenAt.Hash}, CodeHash: chk.CodeHash}
}

// ComposeContractIdentity builds the LegContext of a stored proof. A proof with no settlement evidence has no leg: the finality named
// state of its absence is returned as the error (finality_included_unavailable), exactly as the S7 section composer does.
func (s *ContractIdentitySource) ComposeContractIdentity(ctx context.Context, proofID string) (ci.LegContext, error) {
	var lc ci.LegContext
	ref, err := s.addenda.LegRef(ctx, proofID)
	if err != nil {
		return lc, err
	}
	st, err := s.addenda.LegSettlement(ctx, ref)
	if err != nil {
		return lc, err
	}
	lc.Chain, lc.Settlement = ref.Chain, st.Included
	if _, lc.Receipt, err = st.Included.Verify(); err != nil {
		return lc, fmt.Errorf("the stored settlement does not verify: %w", err)
	}
	if st.Included.Tx != nil {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(st.Included.Tx.LeafValue); err != nil {
			return lc, fmt.Errorf("the stored transaction leaf does not decode: %w", err)
		}
		lc.Tx = tx
	}
	var accountURL sql.NullString
	var opID, guard []byte
	if err := s.client.DB().QueryRowContext(ctx, `SELECT pa.account_url, ecr.operation_id, ecr.artifact_json->'replay_guard'
		FROM proof_artifacts pa LEFT JOIN LATERAL (SELECT operation_id, artifact_json FROM external_chain_results WHERE proof_id = pa.proof_id ORDER BY created_at DESC LIMIT 1) ecr ON true
		WHERE pa.proof_id = $1::uuid`, proofID).Scan(&accountURL, &opID, &guard); err != nil {
		return lc, err
	}
	lc.ADIURL = ADIURLOf(accountURL.String)
	if lc.Batch.BatchRoot, err = s.batchRoot(ctx, proofID); err != nil {
		return lc, err
	}
	if len(opID) == 32 {
		copy(lc.Batch.OperationID[:], opID)
		var reg, inputs []byte
		err := s.client.DB().QueryRowContext(ctx, `SELECT registry, message_inputs FROM intent_quorum_certificates WHERE operation_id = $1`, "0x"+hex.EncodeToString(opID)).Scan(&reg, &inputs)
		if err != nil && err != sql.ErrNoRows {
			return lc, err
		}
		if err == nil {
			var in qcInputs
			if err := json.Unmarshal(inputs, &in); err != nil {
				return lc, fmt.Errorf("the QC message_inputs are not the stored shape: %w", err)
			}
			lc.Batch.AccSetRoot, _ = hex32(in.AccumulateSetRoot)
			lc.Batch.Incarnation, _ = hex32(in.Incarnation)
			if lc.Registry9, err = Registry9Of(reg); err != nil {
				return lc, err
			}
		}
	}
	lc.S6Status, lc.S6Reason, lc.S6State, lc.S6 = S6Of(st.Included, guard)
	adds, err := s.addenda.Chain(ctx, proofID)
	if err != nil {
		return lc, err
	}
	rep := finality.Verify(ref.Chain, st.Included, st.Block(), adds, s.pins)
	lc.S7 = &rep
	return lc, nil
}

// batchRoot reads proof_components.1_merkle_inclusion.merkle_root (lowercase hex, no 0x) of the proof's newest stored bundle. A proof with
// no bundle, or a bundle with no root, yields the zero root, which the verifier names context_incomplete{batch.batchRoot}.
func (s *ContractIdentitySource) batchRoot(ctx context.Context, proofID string) ([32]byte, error) {
	var data []byte
	err := s.client.DB().QueryRowContext(ctx, `SELECT bundle_data FROM proof_bundles WHERE proof_id = $1::uuid AND octet_length(bundle_data) <= $2 ORDER BY created_at DESC, bundle_id DESC LIMIT 1`, proofID, int64(maxStoredBundle)).Scan(&data)
	if err == sql.ErrNoRows {
		return [32]byte{}, nil
	}
	if err != nil {
		return [32]byte{}, err
	}
	doc, err := gunzipBounded(data)
	if err != nil {
		return [32]byte{}, bundleInvalid(proofID, err.Error())
	}
	var b struct {
		Components struct {
			Merkle struct {
				Root string `json:"merkle_root"`
			} `json:"1_merkle_inclusion"`
		} `json:"proof_components"`
	}
	if err := json.Unmarshal(doc, &b); err != nil {
		return [32]byte{}, bundleInvalid(proofID, "the bundle is not the certen_v1 shape: "+err.Error())
	}
	if b.Components.Merkle.Root == "" {
		return [32]byte{}, nil
	}
	root, err := hex32(b.Components.Merkle.Root)
	if err != nil {
		return [32]byte{}, bundleInvalid(proofID, "1_merkle_inclusion.merkle_root: "+err.Error())
	}
	return root, nil
}
