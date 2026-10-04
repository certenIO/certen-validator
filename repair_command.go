package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
)

const repairUsage = "usage: certen-validator repair anchor-blocks [--apply] [--min-depth N] | repair projections [--apply] | repair consensus-records --rpc ADDR [--apply] | repair member-proof-cycle --intent ID --chain CHAIN_ID --tx SETTLEMENT_TX [--apply] [--wait DURATION] | repair outcome-trees [--apply] [--recorded] | repair member-proof-unavailable --intent ID --chain CHAIN_ID --tx SETTLEMENT_TX --operator NAME --evidence TEXT [--apply] | repair stale-lifecycle [--apply] [--older-than DURATION] [--by NAME]"

// runRepairCommand runs `validator repair anchor-blocks`: it reads every canonical anchor's verify and
// create transactions back from their chain - locating the create transaction where the row does not name
// it (RB3-F33) - and completes or corrects what the chain contradicts: the create transaction, its block
// and the verify block on the anchor row, both transactions' senders (RB3-F127), the layer-5 rows, and the
// Certen anchor proofs this validator signed (see execution.RepairAnchorBlocks). Without --apply it only
// reports. Run it on every validator: each revises the proofs it signed.
//
// `validator repair projections` moves the settlement transaction out of the anchor columns of
// proof_artifacts, anchor_references and validator_attestations, deciding each proof from chain facts (see
// execution.RepairProofProjections, RB3-F135). Run it once, on any validator, after anchor-blocks.
//
// `validator repair consensus-records --rpc ADDR` restates the consensus entries written before RB3-F138 from
// the commit that committed their height, read from the CometBFT node at ADDR (this validator's own, e.g.
// tcp://127.0.0.1:26657), and withdraws the unverified signature validity of their batch rows. Run it once.
//
// Exit status: 0 when nothing was refused, 2 when something was refused or could not be read, 1 on error.
func runRepairCommand(args []string) int {
	// Served by the running validator, not by this process (member_repair_command.go).
	if len(args) > 0 && args[0] == "member-proof-cycle" {
		return runMemberRepairCommand(args[1:])
	}
	// RB6 state 3: declare an executed member's proof unavailable, with evidence (proof_unavailable_command.go).
	if len(args) > 0 && args[0] == "member-proof-unavailable" {
		return runProofUnavailableCommand(args[1:])
	}
	// RB6-F12: resolve intents left authorized with nothing executed (stale_lifecycle_command.go).
	if len(args) > 0 && args[0] == "stale-lifecycle" {
		return runStaleLifecycleCommand(args[1:])
	}
	// Into this validator's own kept-tree store (outcome_repair_command.go).
	if len(args) > 0 && args[0] == "outcome-trees" {
		apply, recorded := false, false
		for _, a := range args[1:] {
			switch {
			case a == "--apply" && !apply:
				apply = true
			case a == "--recorded" && !recorded:
				recorded = true
			default:
				log.Print(repairUsage)
				return 1
			}
		}
		return runOutcomeTreeRepair(apply, recorded)
	}
	if len(args) == 0 || (args[0] != "anchor-blocks" && args[0] != "projections" && args[0] != "consensus-records") {
		log.Print(repairUsage)
		return 1
	}
	what := args[0]
	apply, minDepth, rpcAddr := false, 0, ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--apply":
			apply = true
		case "--rpc":
			if what != "consensus-records" || i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				log.Print(repairUsage)
				return 1
			}
			rpcAddr = strings.TrimSpace(args[i+1])
			i++
		case "--min-depth":
			if what != "anchor-blocks" {
				log.Print(repairUsage)
				return 1
			}
			if i+1 >= len(args) {
				log.Print(repairUsage)
				return 1
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				log.Printf("--min-depth must be a positive integer: %q", args[i+1])
				return 1
			}
			minDepth = n
			i++
		default:
			log.Print(repairUsage)
			return 1
		}
	}

	if what == "consensus-records" && rpcAddr == "" {
		log.Print("repair consensus-records needs --rpc: the CometBFT node whose block store holds the commits")
		return 1
	}

	cfg, err := config.Load()
	if err != nil {
		log.Printf("load configuration: %v", err)
		return 1
	}
	if cfg.ValidatorID == "" {
		log.Print("VALIDATOR_ID is required: the repair records who made each correction and revises only that validator's proofs")
		return 1
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		log.Printf("connect database: %v", err)
		return 1
	}
	defer client.Close()
	latest, err := schema.LatestVersion()
	if err == nil {
		err = (schema.Runner{DB: client.DB()}).Verify(context.Background(), latest)
	}
	if err != nil {
		log.Printf("the schema is older than this binary (%v); run `validator migrate up` first", err)
		return 1
	}

	if what == "projections" {
		return runProjectionRepair(client, cfg.ValidatorID, apply)
	}
	if what == "consensus-records" {
		return runConsensusRecordsRepair(client, rpcAddr, cfg.ValidatorID, apply)
	}

	signers, err := repairSigners(cfg)
	if err != nil {
		log.Printf("signing keys: %v", err)
		return 1
	}
	reader := execution.NewEthAnchorTxReader()
	defer reader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	report, err := execution.RepairAnchorBlocks(ctx, execution.AnchorRepairConfig{
		Repair:      database.NewEvidenceRepair(client),
		Proofs:      database.NewProofRepository(client),
		Reader:      reader,
		ValidatorID: cfg.ValidatorID,
		Signers:     signers,
		MinDepth:    minDepth,
		Apply:       apply,
		Logf:        log.Printf,
	})
	if report != nil {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	}
	if err != nil {
		log.Printf("anchor repair stopped: %v", err)
		return 1
	}
	mode := "dry run: nothing was changed; re-run with --apply"
	if apply {
		mode = "applied"
	}
	log.Printf("anchor repair (%s) by %s: %d anchors, %d confirmed on chain, %d actions, %d refused, %d left for their signing validator, %d not yet final",
		mode, cfg.ValidatorID, report.Anchors, report.Confirmed, len(report.Actions), len(report.Refused), len(report.LeftForOwner), len(report.NotYetFinal))
	if len(report.Refused) > 0 {
		return 2
	}
	return 0
}

// repairSigners are this validator's proof signers, by the scheme the proof records. Keys are only loaded:
// a repair never generates a key, because a new key would sign as nobody.
func repairSigners(cfg *config.Config) (map[string]func([]byte) []byte, error) {
	signers := map[string]func([]byte) []byte{}

	path := ed25519KeyPath(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the Ed25519 key at %s: %w", path, err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the Ed25519 key at %s is not a %d-byte hex key", path, ed25519.PrivateKeySize)
	}
	edKey := ed25519.PrivateKey(raw)
	signers["ed25519"] = func(proofHash []byte) []byte { return ed25519.Sign(edKey, proofHash) }

	// The BLS key the validator signs legacy-path proofs with, from its key file. Never derived and
	// never written.
	km := bls.NewKeyManager(blsKeyPath(cfg))
	if err = km.LoadKey(); err != nil {
		return nil, fmt.Errorf("BLS key at %s: %w", blsKeyPath(cfg), err)
	}
	blsKey := km.GetPrivateKey()
	signers["bls12-381"] = func(proofHash []byte) []byte {
		var message [32]byte
		copy(message[:], proofHash)
		return blsKey.SignWithDomain(message[:], bls.DomainResult).Bytes()
	}
	return signers, nil
}

// runProjectionRepair runs `validator repair projections`.
func runProjectionRepair(client *database.Client, validatorID string, apply bool) int {
	reader := execution.NewEthAnchorTxReader()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	report, err := execution.RepairProofProjections(ctx, execution.ProjectionRepairConfig{
		Repair: database.NewEvidenceRepair(client), Reader: reader, ValidatorID: validatorID, Apply: apply,
	})
	if report != nil {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	}
	if err != nil {
		log.Printf("projection repair stopped: %v", err)
		return 1
	}
	mode := "dry run: nothing was changed; re-run with --apply"
	if apply {
		mode = "applied"
	}
	log.Printf("projection repair (%s) by %s: %d proofs, %d already stated their anchor, %d settlements moved "+
		"(%d with layer 5's anchor, %d with none established), %d refused, %d changed underneath",
		mode, validatorID, report.Proofs, report.AlreadyAnchor, report.Moved, report.AnchorsStated, report.AnchorsUnknown,
		len(report.Refused), len(report.Changed))
	if len(report.Refused) > 0 || len(report.Changed) > 0 {
		return 2
	}
	return 0
}

// runConsensusRecordsRepair runs `validator repair consensus-records`.
func runConsensusRecordsRepair(client *database.Client, rpcAddr, validatorID string, apply bool) int {
	commits, err := consensus.NewBlockStoreCommitReader(rpcAddr)
	if err != nil {
		log.Printf("block store: %v", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	report, err := consensus.RepairConsensusRecords(ctx, database.NewEvidenceRepair(client), commits, validatorID, apply)
	if report != nil {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	}
	if err != nil {
		log.Printf("consensus records repair stopped: %v", err)
		return 1
	}
	mode := "dry run: nothing was changed; re-run with --apply"
	if apply {
		mode = "applied"
	}
	log.Printf("consensus records repair (%s) by %s: %d entries, %d restated from their commit, %d attestation rows withdrawn, "+
		"%d heights not in the block store, %d refused, %d changed underneath",
		mode, validatorID, report.Entries, report.Corrected, report.AttestationsWithdrawn, len(report.Unavailable), len(report.Refused), len(report.Changed))
	if len(report.Refused) > 0 || len(report.Changed) > 0 || len(report.Unavailable) > 0 {
		return 2
	}
	return 0
}
