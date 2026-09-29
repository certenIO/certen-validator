package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/execution"
)

const memberRepairUsage = "usage: certen-validator repair member-proof-cycle --intent ID --chain CHAIN_ID --tx SETTLEMENT_TX [--apply] [--wait DURATION]"

// runMemberRepairCommand runs `validator repair member-proof-cycle` (RB4-F55 repair; DESIGN_RB4_F55_repair_000ac79a.md):
// it hands one member's re-drive to the RUNNING validator of this container - the process holding the orchestrator,
// its keys, its peers and the committed-operation index - through its data directory, waits for the answer and
// prints it. Without --apply the running validator checks every precondition, re-derives the member's round and
// reports its snapshot, and runs nothing. Run it on the validator that settled the member.
//
// Exit status: 0 when the member was reached (dry run) or repaired, 2 when the request was refused or failed, 1 on
// error (including no answer within --wait).
func runMemberRepairCommand(args []string) int {
	req := execution.MemberRepairRequest{}
	wait := 20 * time.Minute
	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return "", false
			}
			i++
			return strings.TrimSpace(args[i]), true
		}
		var ok bool
		switch args[i] {
		case "--apply":
			req.Apply, ok = true, true
		case "--intent":
			req.IntentID, ok = next()
		case "--tx":
			req.SettlementTx, ok = next()
		case "--chain":
			var v string
			if v, ok = next(); ok {
				n, err := strconv.ParseInt(v, 10, 64)
				ok = err == nil && n > 0
				req.ChainID = n
			}
		case "--wait":
			var v string
			if v, ok = next(); ok {
				d, err := time.ParseDuration(v)
				ok = err == nil && d > 0
				wait = d
			}
		}
		if !ok {
			log.Print(memberRepairUsage)
			return 1
		}
	}
	if req.IntentID == "" || req.ChainID == 0 || req.SettlementTx == "" {
		log.Print(memberRepairUsage)
		return 1
	}
	cfg, err := config.Load()
	if err != nil {
		log.Printf("load configuration: %v", err)
		return 1
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "data"
	}
	res, err := requestMemberRepair(execution.MemberRepairDir(dataDir), req, wait, 2*time.Second)
	if err != nil {
		log.Printf("member repair: %v", err)
		return 1
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	switch res.Outcome {
	case execution.MemberRepairReached, execution.MemberRepairRepaired:
		return 0
	default:
		return 2
	}
}

// requestMemberRepair writes the request where the running validator serves it and waits for its result.
func requestMemberRepair(dir string, req execution.MemberRepairRequest, wait, poll time.Duration) (*execution.MemberRepairResult, error) {
	requests := filepath.Join(dir, "requests")
	if st, err := os.Stat(requests); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s does not exist: the running validator creates it when it serves repairs - is this the container of a validator running this binary?", requests)
	}
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req.RequestedAt = time.Now().UTC()
	req.ID = fmt.Sprintf("%s-%d-%s", req.RequestedAt.Format("20060102T150405Z"), req.ChainID, hex.EncodeToString(nonce))
	blob, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(dir, "."+req.ID+".json.tmp")
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(requests, req.ID+".json")); err != nil {
		return nil, err
	}
	log.Printf("repair request %s written (intent %s member %d, settlement %s, apply %v); waiting up to %s for the running validator",
		req.ID, req.IntentID, req.ChainID, req.SettlementTx, req.Apply, wait)

	result := filepath.Join(dir, "results", req.ID+".json")
	deadline := time.Now().Add(wait)
	for {
		raw, err := os.ReadFile(result)
		if err == nil {
			var res execution.MemberRepairResult
			if err := json.Unmarshal(raw, &res); err != nil {
				return nil, fmt.Errorf("result %s cannot be read: %w", result, err)
			}
			return &res, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no answer to request %s within %s; it stays in %s and its result will be written to %s", req.ID, wait, requests, result)
		}
		time.Sleep(poll)
	}
}
