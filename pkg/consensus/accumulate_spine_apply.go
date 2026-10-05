package consensus

import (
	"errors"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// processAccumulateSpineGenesis validates and records a spine genesis carried by block height (rules v13,
// accumulate_spine.go). Like the BLS registry it is written during FinalizeBlock, so the next transaction of the same
// block - and every later block - is judged against it.
//
// It is judged against the spine committed below this height plus this execution's own acceptances in the block
// (app.blockSpine) - never against a genesis an earlier execution of the same block wrote - so executing the block
// again decides every transaction of it exactly as the first execution did, a refused one included. An acceptance an
// earlier execution already wrote is not written twice.
func (app *ValidatorApp) processAccumulateSpineGenesis(gt *AccumulateSpineGenesisTx, height int64) abcitypes.ExecTxResult {
	refuse := func(why string) abcitypes.ExecTxResult {
		app.logger.Printf("🚫 [SPINE] genesis refused at height %d: %s", height, why)
		return abcitypes.ExecTxResult{Code: codeSpineGenesisRefused, Log: "spine genesis refused: " + why}
	}
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeSpineGenesisRefused, Log: "spine genesis requires a ledger store"}
	}
	if err := gt.CheckShape(); err != nil {
		return refuse(err.Error())
	}
	if gt.ChainID != app.cometChainID {
		return refuse(fmt.Sprintf("the genesis is for chain %q, this is %q", gt.ChainID, app.cometChainID))
	}
	stored, err := app.ledgerStore.LoadAccumulateSpine()
	if err != nil {
		// Refusing here would withhold the genesis's id from this node's app hash while nodes that could read their
		// ledger include it: a fork. Stop.
		app.logger.Fatalf("❌ [SPINE] the spine log could not be read at height %d: %v", height, err)
	}
	view := spineView(stored, height, &app.blockSpine)
	id := gt.GenesisID()
	// The same genesis earlier in this block: accepted again, changing nothing.
	if view.Genesis != nil && view.Genesis.Height == height && app.blockSpine.genesisID == id {
		app.blockBundles = append(app.blockBundles, id)
		return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
	}
	// The admin quorum in force for this block authorises it (AdminSetAt): when the chain starts or moves its spine is
	// a governed decision. (The same genesis again within its block, above, was authorised by its first copy.)
	policy, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		// Judging without the admin set would decide here what nodes that can read it decide otherwise: a fork. Stop.
		app.logger.Fatalf("❌ [SPINE] the committed policy (admin quorum) could not be read at height %d: %v", height, err)
	}
	if err := VerifyAccumulateSpineGenesisQuorum(gt, policy, height); err != nil {
		return refuse(err.Error())
	}
	inc, why := app.spineRegistryIncarnation(height)
	if why != "" {
		return refuse(why)
	}
	// A spine of the registry's incarnation is never replaced: the genesis was fixed under this registry's incarnation,
	// and another for the same incarnation could only be a second account of the same facts or a false one.
	if view.Genesis != nil && view.Genesis.Incarnation == incarnationHex(inc) {
		return refuse(fmt.Sprintf("the spine genesis of incarnation %s, the registry's, was accepted at height %d; it is "+
			"replaced only when the registry moves to another incarnation", view.Genesis.Incarnation, view.Genesis.Height))
	}
	in, err := gt.Inputs()
	if err != nil {
		return refuse(err.Error())
	}
	var gen *ledger.AccumulateSpineGenesis
	var set ledger.AccumulateSpineSet
	err = refusePanic("the genesis records could not be verified", func() (err error) {
		gen, set, err = proofv2.AcceptSpineGenesis(in, inc, height)
		return err
	})
	if err != nil {
		return refuse(err.Error())
	}

	// An earlier execution of this block may already have written this genesis; any other genesis accepted at or above
	// this height is a contradiction - this block's are decided here alone - and judging on would fork. Written, the
	// genesis starts the log afresh; a spine committed below this height (a dead incarnation's) is kept as Previous.
	switch {
	case stored.Genesis == nil || stored.Genesis.Height < height:
		next := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
		if below := spineBelow(stored, height); below.Genesis != nil {
			next.Previous = below
		}
		if err := app.ledgerStore.SaveAccumulateSpine(next); err != nil {
			app.logger.Fatalf("❌ [SPINE] could not persist an accepted genesis at height %d: %v", height, err)
		}
		if next.Previous != nil {
			app.logger.Printf("🧬 [SPINE] genesis accepted at height %d: incarnation %s REPLACES the spine of incarnation %s "+
				"(verified through major block %d), genesis set %s…", height, gen.Incarnation, next.Previous.Genesis.Incarnation,
				len(next.Previous.Checkpoints), gen.SetHash[:16])
		} else {
			app.logger.Printf("🧬 [SPINE] genesis accepted at height %d: incarnation %s, genesis set %s…", height,
				gen.Incarnation, gen.SetHash[:16])
		}
	case *stored.Genesis != *gen:
		app.logger.Fatalf("❌ [SPINE] the log records a genesis accepted at height %d, but this execution of block %d accepts "+
			"another: the committed log and this block disagree", stored.Genesis.Height, height)
	}
	// The block's spine starts afresh from this genesis (spineView).
	// (No extension can have been accepted earlier in it: an extension needs the spine to be the registry's
	// incarnation, and then this genesis is refused.)
	app.blockSpine = spineAcceptances{height: height, genesisID: id, genesis: gen, sets: []ledger.AccumulateSpineSet{set}}
	app.blockBundles = append(app.blockBundles, id)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// spineRegistryIncarnation is the Accumulate incarnation of the BLS registry in force for the block at height - the
// only incarnation a spine transaction of that block is judged under - or why there is none.
func (app *ValidatorApp) spineRegistryIncarnation(height int64) ([32]byte, string) {
	registry, err := app.ledgerStore.LoadBLSRegistry()
	if err != nil {
		// Judging without the registry would decide here what nodes that can read it decide otherwise: a fork. Stop.
		app.logger.Fatalf("❌ [SPINE] the BLS registry could not be read at height %d: %v", height, err)
	}
	reg := RegistryAt(registry, height)
	if reg == nil {
		return [32]byte{}, "no BLS registry is in force, so there is no incarnation for the spine"
	}
	inc, err := registryIncarnation(reg)
	if err != nil {
		return [32]byte{}, err.Error()
	}
	return inc, ""
}

// processAccumulateSpineExtend validates and records a spine extension carried by block height (rules v13), judged
// and written with processAccumulateSpineGenesis's discipline: against the spine committed below this height plus this
// execution's acceptances, and written at most once whatever the number of executions.
func (app *ValidatorApp) processAccumulateSpineExtend(et *AccumulateSpineExtendTx, height int64) abcitypes.ExecTxResult {
	refuse := func(code uint32, why string) abcitypes.ExecTxResult {
		app.logger.Printf("🚫 [SPINE] extension refused at height %d: %s", height, why)
		return abcitypes.ExecTxResult{Code: code, Log: "spine extension refused: " + why}
	}
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeSpineExtendRefused, Log: "spine extension requires a ledger store"}
	}
	if err := et.CheckShape(); err != nil {
		return refuse(codeSpineExtendRefused, err.Error())
	}
	if et.ChainID != app.cometChainID {
		return refuse(codeSpineExtendRefused, fmt.Sprintf("the extension is for chain %q, this is %q", et.ChainID, app.cometChainID))
	}
	stored, err := app.ledgerStore.LoadAccumulateSpine()
	if err != nil {
		app.logger.Fatalf("❌ [SPINE] the spine log could not be read at height %d: %v", height, err)
	}
	view := spineView(stored, height, &app.blockSpine)
	if view.Genesis == nil {
		return refuse(codeSpineExtendRefused, "the chain has no spine genesis to extend")
	}
	id := et.ExtensionID()
	// The same extension earlier in this block: accepted again, changing nothing.
	if app.blockSpine.height == height {
		for _, done := range app.blockSpine.extensionIDs {
			if done == id {
				app.blockBundles = append(app.blockBundles, id)
				return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
			}
		}
	}
	// Only a spine of the registry's incarnation is extended: a dead incarnation's spine waits for the genesis that
	// replaces it, and verifying its records would extend history the registry no longer attests under.
	inc, why := app.spineRegistryIncarnation(height)
	if why != "" {
		return refuse(codeSpineExtendRefused, why)
	}
	if view.Genesis.Incarnation != incarnationHex(inc) {
		return refuse(codeSpineExtendRefused, fmt.Sprintf("the spine is not the registry's incarnation: the spine is "+
			"incarnation %s, the BLS registry in force attests under %s", view.Genesis.Incarnation, incarnationHex(inc)))
	}
	verified := uint64(len(view.Checkpoints))
	last := et.First + uint64(len(et.Records)) - 1
	switch {
	case et.First <= verified:
		return refuse(codeSpineExtendStale, fmt.Sprintf("major blocks %d-%d: the chain has verified through major block %d; "+
			"the next extension starts at %d", et.First, last, verified, verified+1))
	case et.First > verified+1:
		return refuse(codeSpineExtendRefused, fmt.Sprintf("major blocks %d-%d: the chain has verified through major block %d, "+
			"so the next extension starts at %d - one cannot skip major blocks", et.First, last, verified, verified+1))
	}
	records, err := et.MajorRecords()
	if err != nil {
		return refuse(codeSpineExtendRefused, err.Error())
	}
	var cps []ledger.AccumulateSpineCheckpoint
	var sets []ledger.AccumulateSpineSet
	err = refusePanic("the records could not be verified", func() (err error) {
		cps, sets, err = proofv2.ExtendSpine(view, records, height)
		return err
	})
	if err != nil {
		return refuse(codeSpineExtendRefused, err.Error())
	}

	// An earlier execution of this block may already have written these checkpoints - all of them, since one write
	// records a whole extension. Any other checkpoint at their places, or only some of them, is a contradiction: none
	// was committed below this height, and this block's are decided here alone.
	if stored.Genesis == nil || *stored.Genesis != *view.Genesis {
		app.logger.Fatalf("❌ [SPINE] this execution of block %d extends the spine of the genesis accepted at height %d, but "+
			"the log holds another genesis: the committed log and this block disagree", height, view.Genesis.Height)
	}
	present := 0
	for _, c := range cps {
		if c.Major <= uint64(len(stored.Checkpoints)) {
			if stored.Checkpoints[c.Major-1] != c {
				app.logger.Fatalf("❌ [SPINE] the log records major block %d as accepted at height %d, but this execution of "+
					"block %d accepts another checkpoint for it: the committed log and this block disagree", c.Major,
					stored.Checkpoints[c.Major-1].Height, height)
			}
			present++
		}
	}
	switch present {
	case len(cps):
	case 0:
		if uint64(len(stored.Checkpoints)) != et.First-1 {
			app.logger.Fatalf("❌ [SPINE] the log holds %d checkpoints, but this execution of block %d accepts major blocks "+
				"from %d: the committed log and this block disagree", len(stored.Checkpoints), height, et.First)
		}
		next := *stored // copy; never mutate the loaded log in place
		next.Checkpoints = append(append([]ledger.AccumulateSpineCheckpoint(nil), stored.Checkpoints...), cps...)
		next.Sets = appendNewSets(stored.Sets, sets...)
		if err := app.ledgerStore.SaveAccumulateSpine(&next); err != nil {
			app.logger.Fatalf("❌ [SPINE] could not persist an accepted extension at height %d: %v", height, err)
		}
		app.logger.Printf("🧬 [SPINE] major blocks %d-%d accepted at height %d (%d new validator set(s)); the chain has "+
			"verified through major block %d", et.First, last, height, len(sets), last)
	default:
		app.logger.Fatalf("❌ [SPINE] the log records %d of the %d checkpoints this execution of block %d accepts: the "+
			"committed log and this block disagree", present, len(cps), height)
	}
	app.blockSpine.height = height
	app.blockSpine.extensionIDs = append(app.blockSpine.extensionIDs, id)
	app.blockSpine.checkpoints = append(app.blockSpine.checkpoints, cps...)
	app.blockSpine.sets = append(app.blockSpine.sets, sets...)
	app.blockBundles = append(app.blockBundles, id)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// appendNewSets returns a copy of sets with each of add whose hash it does not already hold appended.
func appendNewSets(sets []ledger.AccumulateSpineSet, add ...ledger.AccumulateSpineSet) []ledger.AccumulateSpineSet {
	out := append([]ledger.AccumulateSpineSet(nil), sets...)
	for _, s := range add {
		held := false
		for _, o := range out {
			held = held || o.Hash == s.Hash
		}
		if !held {
			out = append(out, s)
		}
	}
	return out
}

// ErrSpineNotRegistryIncarnation is a spine that cannot judge a proof at a height: there is no spine genesis, no BLS
// registry in force, or the spine's genesis is not the incarnation the registry in force attests under.
var ErrSpineNotRegistryIncarnation = errors.New("the spine is not the registry's incarnation")

// accumulateSpineAt is the Accumulate validator-set spine a transaction of the block at height is judged against: the
// spine log as committed below height plus the spine transactions this execution of that block has accepted so far -
// the same view the spine kinds themselves are judged against (spineView). It is what the intent-certificate rule reads
// to judge a proof v2 in FinalizeBlock: every input is committed state or the block, so every node, and every
// execution of the block, sees the same spine. For a height other than the block being executed it is the committed
// spine below that height alone.
//
// It is returned only when it is the spine of the REGISTRY'S incarnation - the incarnation of the BLS registry in force
// at height, the one CERTEN's quorum attests under. A proof is a claim about that network; a spine of any other
// incarnation (the registry moved and no genesis for the new incarnation is recorded yet) describes a network the
// registry no longer attests under, and judging a proof against it would accept a proof of the wrong network. So that
// case, and no genesis or no registry at all, is ErrSpineNotRegistryIncarnation, named - never an empty or stale spine.
//
// An unreadable log or registry is an error too, never an empty spine (which would refuse every proof on this node
// only); a caller in FinalizeBlock stops on it, as the spine kinds do. The caller holds app.mu.
func (app *ValidatorApp) accumulateSpineAt(height int64) (*ledger.AccumulateSpineLog, error) {
	if app.ledgerStore == nil {
		return nil, fmt.Errorf("the validator app has no ledger store")
	}
	stored, err := app.ledgerStore.LoadAccumulateSpine()
	if err != nil {
		return nil, fmt.Errorf("the spine log could not be read: %w", err)
	}
	registry, err := app.ledgerStore.LoadBLSRegistry()
	if err != nil {
		return nil, fmt.Errorf("the BLS registry could not be read: %w", err)
	}
	view := spineView(stored, height, &app.blockSpine)
	reg := RegistryAt(registry, height)
	switch {
	case reg == nil:
		return nil, fmt.Errorf("%w: no BLS registry is in force at height %d", ErrSpineNotRegistryIncarnation, height)
	case view.Genesis == nil:
		return nil, fmt.Errorf("%w: the chain has no spine genesis at height %d", ErrSpineNotRegistryIncarnation, height)
	}
	inc, err := registryIncarnation(reg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpineNotRegistryIncarnation, err)
	}
	if view.Genesis.Incarnation != incarnationHex(inc) {
		return nil, fmt.Errorf("%w: the spine is incarnation %s, the BLS registry in force at height %d attests under %s",
			ErrSpineNotRegistryIncarnation, view.Genesis.Incarnation, height, incarnationHex(inc))
	}
	return view, nil
}
