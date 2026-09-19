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
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
)

const repairUsage = "usage: certen-validator repair anchor-blocks [--apply] [--min-depth N]"

// runRepairCommand runs `validator repair anchor-blocks`: it reads every canonical anchor's create
// transaction back from its chain and corrects the anchor block stored on the anchor row, on layer-5 rows
// and on the Certen anchor proofs this validator signed (see execution.RepairAnchorBlocks). Without --apply
// it only reports. Run it on every validator: each revises the proofs it signed.
//
// Exit status: 0 when nothing was refused, 2 when something was refused or could not be read, 1 on error.
func runRepairCommand(args []string) int {
	if len(args) == 0 || args[0] != "anchor-blocks" {
		log.Print(repairUsage)
		return 1
	}
	apply, minDepth := false, 0
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--apply":
			apply = true
		case "--min-depth":
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

	// The BLS key the validator signs legacy-path proofs with: loaded from its file, or derived from the
	// validator id exactly as startup derives it when there is no file. Never written.
	km := bls.NewKeyManager(blsKeyPath(cfg))
	if _, statErr := os.Stat(blsKeyPath(cfg)); statErr == nil {
		err = km.LoadKey()
	} else {
		err = km.GenerateFromValidatorID(cfg.ValidatorID, cfg.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("BLS key: %w", err)
	}
	blsKey := km.GetPrivateKey()
	signers["bls12-381"] = func(proofHash []byte) []byte {
		var message [32]byte
		copy(message[:], proofHash)
		return blsKey.SignWithDomain(message[:], bls.DomainResult).Bytes()
	}
	return signers, nil
}
