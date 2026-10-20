// Copyright 2026 Certen Protocol

package ethl1

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// The official sync-protocol vectors (consensus-specs v1.7.0-beta.4, tests/minimal/<fork>/light_client/sync). The release carries them for the
// minimal preset only (SYNC_COMMITTEE_SIZE 32, SLOTS_PER_EPOCH 8, EPOCHS_PER_SYNC_COMMITTEE_PERIOD 8), so the harness drives the very
// walker, decoders and committee code of the production verifier with that preset (preset.go); nothing is re-implemented.
//
// A sync case is a bootstrap followed by process_update / force_update / upgrade_store steps, each with the finalized and optimistic
// header the specification's light-client store holds afterwards. This verifier is a stateless walker, by design (spec 5.2 step 3): it
// requires a 2/3 sync-aggregate on EVERY update, requires a link to carry the next committee and to be applied, never keeps a
// best_valid_update, never force-updates, and keeps no optimistic header. The harness therefore compares, step by step:
//
//   - an update the walker accepts: the new finalized header (slot, beacon root, execution root) and optimistic header must equal the
//     vector's. An update that carries no next committee is validated as a final update (same checks) and its finality is applied to the
//     harness store by the rule of apply_light_client_update (fs > store.finalized.slot);
//   - an update the walker refuses by one of the named by-design refusals below: the vector's finalized header must be UNCHANGED (the
//     specification did not apply it either); the optimistic header the specification advanced is recorded as not applicable
//     ("optimistic_untracked") and the harness follows the vector's value from there;
//   - any other refusal, any mismatch, or a finalized header that moved while the walker refused: a failure (a real disagreement);
//   - force_update: the store changes through best_valid_update, which the walker never keeps: this step and every later step of the case are
//     recorded as not applicable ("force_update", "after_force_update");
//   - upgrade_store: a store-format upgrade between forks; the walker has no persistent store format: no-op, recorded.

var minimalPreset = preset{slotsPerEpoch: 8, epochsPerPeriod: 8, committeeSize: 32}

type syncHeaderCheck struct {
	Slot          uint64 `yaml:"slot"`
	BeaconRoot    string `yaml:"beacon_root"`
	ExecutionRoot string `yaml:"execution_root"`
}

type syncChecks struct {
	Finalized  syncHeaderCheck `yaml:"finalized_header"`
	Optimistic syncHeaderCheck `yaml:"optimistic_header"`
}

type syncStepBody struct {
	Update      string     `yaml:"update"`
	CurrentSlot uint64     `yaml:"current_slot"`
	Checks      syncChecks `yaml:"checks"`
}

// byDesignRefusals are the walker refusals of updates the specification accepts without finalizing anything new.
func byDesignRefusal(f *Fault) (string, bool) {
	switch f.Code {
	case CodeParticipationInsuff:
		return "participation_below_2_3", true
	case CodeLinkInvalid:
		switch f.Fields["check"] {
		case "not_finality":
			return "no_finality_in_update", true
		case "not_sync_committee_update":
			return "link_without_next_committee", true
		case "not_applied":
			return "update_not_applied", true
		}
	}
	return "", false
}

func yamlUint(v any) (uint64, error) {
	switch x := v.(type) {
	case int:
		return uint64(x), nil
	case int64:
		return uint64(x), nil
	case uint64:
		return x, nil
	case string:
		return strconv.ParseUint(strings.TrimPrefix(x, "0x"), 16, 64)
	}
	return 0, fmt.Errorf("unsupported yaml number %T", v)
}

func forksFromConfig(t *testing.T, path string) []Fork {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	order := []struct {
		name   string
		layout Layout
	}{{"GENESIS", LayoutNone}, {"ALTAIR", LayoutNone}, {"BELLATRIX", LayoutNone}, {"CAPELLA", LayoutNone}, {"DENEB", LayoutNone},
		{"ELECTRA", LayoutElectra}, {"FULU", LayoutElectra}, {"GLOAS", LayoutGloas}}
	var forks []Fork
	for _, o := range order {
		vv, ok := cfg[o.name+"_FORK_VERSION"]
		if !ok {
			continue
		}
		ver, err := yamlUint(vv)
		if err != nil {
			t.Fatalf("%s version: %v", o.name, err)
		}
		var epoch uint64
		if ev, ok := cfg[o.name+"_FORK_EPOCH"]; ok {
			if epoch, err = yamlUint(ev); err != nil {
				t.Fatalf("%s epoch: %v", o.name, err)
			}
		}
		f := Fork{Name: strings.ToLower(o.name), Epoch: epoch, Layout: o.layout}
		binary.BigEndian.PutUint32(f.Version[:], uint32(ver))
		forks = append(forks, f)
	}
	sort.SliceStable(forks, func(i, j int) bool { return forks[i].Epoch < forks[j].Epoch })
	return forks
}

func readSnappy(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := snappyDecode(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// headerRoots returns hash_tree_root(header.beacon) and the specification's execution root of the header (get_lc_execution_root: the
// root of the ExecutionPayloadHeader for the electra shape; the execution_block_hash for the Gloas shape).
func headerRoots(h lcHeader) (beacon, exec [32]byte) {
	beacon = hashTreeRootBeaconHeader(h.Beacon)
	if h.Shape == LayoutElectra {
		return beacon, executionHeaderRoot(h.Exec)
	}
	return beacon, h.ExecHash
}

type syncOutcome struct {
	name                                          string
	steps, compared, refused, optimisticUntracked int
	forceUpdate, upgradeStore, afterForce         int
	refusals                                      map[string]int
}

// hdrRef is the part of a header the vectors check: its slot, its beacon block header root and its execution root.
type hdrRef struct {
	slot         uint64
	beacon, exec [32]byte
}

func refOf(h lcHeader) hdrRef {
	b, e := headerRoots(h)
	return hdrRef{slot: h.Beacon.Slot, beacon: b, exec: e}
}

func (t checkT) ref(c syncHeaderCheck) hdrRef {
	return hdrRef{slot: c.Slot, beacon: hex32(t.T, c.BeaconRoot), exec: hex32(t.T, c.ExecutionRoot)}
}

type checkT struct{ T *testing.T }

func runSyncCase(t *testing.T, dir, name string) syncOutcome {
	t.Helper()
	out := syncOutcome{name: name, refusals: map[string]int{}}
	pr := minimalPreset
	ct := checkT{t}
	var meta struct {
		GVR     string `yaml:"genesis_validators_root"`
		Trusted string `yaml:"trusted_block_root"`
	}
	mraw, err := os.ReadFile(filepath.Join(dir, "meta.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(mraw, &meta); err != nil {
		t.Fatal(err)
	}
	gvr, trusted := hex32(t, meta.GVR), hex32(t, meta.Trusted)

	bootRaw := readSnappy(t, filepath.Join(dir, "bootstrap.ssz_snappy"))
	pins := Pins{Network: Network{ChainID: SepoliaChainID, GenesisValidatorsRoot: gvr, Forks: forksFromConfig(t, filepath.Join(dir, "config.yaml"))},
		MinParticipants: pr.floor(), MaxLinks: 64, MaxSpineHeaders: 16384}
	w := newWalker(pins, specRules{}, pr)

	layout := LayoutElectra
	if len(bootRaw) == pr.gloasBootstrapSize() {
		layout = LayoutGloas
	}
	boot, f := w.parseBootstrap(LB{Layout: layout, SSZ: bootRaw})
	if f != nil {
		t.Fatalf("%s: bootstrap does not parse: %v", name, f)
	}
	if f := w.checkForkOfSlot(boot.Header.Beacon.Slot, boot.Shape); f != nil {
		t.Fatalf("%s: bootstrap: %v", name, f)
	}
	committeeRoot := hashTreeRootSyncCommitteeN(boot.Committee, pr.committeeSize)
	period := pr.periodOf(boot.Header.Beacon.Slot)
	w.p.Anchors = []Anchor{{Period: period, CommitteeRoot: committeeRoot, BlockRoot: &trusted, WSPEpochs: 1 << 30}}
	if f := w.anchorStore(LC{AnchorKind: 2, AnchorPeriod: period, AnchorRoot: trusted}, &boot, nil); f != nil {
		t.Fatalf("%s: bootstrap refused: %v", name, f)
	}

	fin := refOf(boot.Header)
	opt := fin
	diverged := false

	sraw, err := os.ReadFile(filepath.Join(dir, "steps.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var steps []map[string]syncStepBody
	if err := yaml.Unmarshal(sraw, &steps); err != nil {
		t.Fatal(err)
	}
	for i, step := range steps {
		out.steps++
		for kind, body := range step {
			if diverged {
				out.afterForce++
				continue
			}
			switch kind {
			case "force_update":
				out.forceUpdate++
				diverged = true
			case "upgrade_store":
				out.upgradeStore++
			case "process_update":
				raw := readSnappy(t, filepath.Join(dir, body.Update+".ssz_snappy"))
				ul := LayoutElectra
				if len(raw) == pr.gloasUpdateSize() {
					ul = LayoutGloas
				}
				u, f := w.parseUpdate(i, LB{Layout: ul, SSZ: raw})
				if f != nil {
					t.Fatalf("%s step %d: update does not parse: %v", name, i, f)
				}
				if f := w.checkForkOfSlot(u.Attested.Beacon.Slot, u.Shape); f != nil {
					t.Fatalf("%s step %d: %v", name, i, f)
				}
				// an update with a next committee is a link; one without is validated as a final update (same checks)
				isFinal := branchAllZero(u.NextBranch)
				prevFin := w.s.finSlot
				ferr := w.update(i, &u, isFinal)
				exp := body.Checks
				t.Logf("%s step %d: %s %s attested=%d finalized=%d sigslot=%d participants=%d -> %s", name, i, body.Update[len(body.Update)-2:], map[bool]string{true: "final", false: "link"}[isFinal],
					u.Attested.Beacon.Slot, u.Finalized.Beacon.Slot, u.SignatureSlot, u.Aggregate.count(), func() string {
						if ferr == nil {
							return "accepted"
						}
						return string(ferr.CanonicalJSON())
					}())
				if ferr == nil {
					if isFinal {
						// apply_light_client_update for an update that carries no next committee (the walker applies only links): the
						// finalized period may rotate the committees (next becomes current, next is then unknown), and the finalized
						// header advances when it is newer
						fs := u.Finalized.Beacon.Slot
						if w.s.next != nil && pr.periodOf(fs) == pr.periodOf(prevFin)+1 {
							w.s.cur, w.s.next = w.s.next, nil
							w.s.curPeriod++
						}
						if fs > prevFin {
							w.s.finSlot = fs
						}
					}
					if w.s.finSlot > prevFin {
						fin = refOf(u.Finalized)
					}
					if a := refOf(u.Attested); a.slot > opt.slot {
						opt = a
					}
					if fin.slot > opt.slot {
						opt = fin
					}
					if fin != ct.ref(exp.Finalized) {
						t.Errorf("%s step %d: finalized header %+v, vector %+v", name, i, fin, ct.ref(exp.Finalized))
					}
					if opt != ct.ref(exp.Optimistic) {
						t.Errorf("%s step %d: optimistic header %+v, vector %+v", name, i, opt, ct.ref(exp.Optimistic))
					}
					out.compared++
					continue
				}
				reason, ok := byDesignRefusal(ferr)
				if !ok {
					t.Errorf("%s step %d: the walker refuses an update the specification accepts, and not by design: %s", name, i, ferr.CanonicalJSON())
					continue
				}
				if fin != ct.ref(exp.Finalized) {
					t.Errorf("%s step %d: refused (%s) but the vector's finalized header moved: %+v -> %+v", name, i, reason, fin, ct.ref(exp.Finalized))
					continue
				}
				out.refused++
				out.refusals[reason]++
				if opt != ct.ref(exp.Optimistic) {
					// the specification advanced its optimistic header on an update the walker does not trust; the harness follows the vector
					out.optimisticUntracked++
					opt = ct.ref(exp.Optimistic)
				}
			default:
				t.Fatalf("%s step %d: unknown step kind %q", name, i, kind)
			}
		}
	}
	return out
}

// TestOfficialSyncVectors drives the 15 sync cases of the electra, fulu and gloas forks through the production walker under the minimal
// preset (see the file comment for exactly what is compared and what is recorded as not applicable).
func TestOfficialSyncVectors(t *testing.T) {
	root, _ := officialRoot()
	var total syncOutcome
	total.refusals = map[string]int{}
	cases := 0
	for _, fork := range []string{"electra", "fulu", "gloas"} {
		dirs, _ := filepath.Glob(filepath.Join(root, "tests", "minimal", fork, "light_client", "sync", "pyspec_tests", "*"))
		sort.Strings(dirs)
		for _, d := range dirs {
			name := fork + "/" + filepath.Base(d)
			t.Run(name, func(t *testing.T) {
				o := runSyncCase(t, d, name)
				t.Logf("%s: %d steps: %d compared and equal, %d refused by design %v (optimistic header untracked in %d), %d force_update, %d upgrade_store, %d after a force_update",
					name, o.steps, o.compared, o.refused, o.refusals, o.optimisticUntracked, o.forceUpdate, o.upgradeStore, o.afterForce)
				total.steps += o.steps
				total.compared += o.compared
				total.refused += o.refused
				total.optimisticUntracked += o.optimisticUntracked
				total.forceUpdate += o.forceUpdate
				total.upgradeStore += o.upgradeStore
				total.afterForce += o.afterForce
				for k, v := range o.refusals {
					total.refusals[k] += v
				}
			})
			cases++
		}
	}
	t.Logf("sync vectors: %d cases, %d steps: %d compared and equal, %d refused by design %v, %d force_update, %d upgrade_store, %d after a force_update, optimistic header untracked in %d refused steps",
		cases, total.steps, total.compared, total.refused, total.refusals, total.forceUpdate, total.upgradeStore, total.afterForce, total.optimisticUntracked)
	if cases != 15 {
		t.Errorf("expected 15 sync cases, found %d", cases)
	}
	if total.compared == 0 {
		t.Error("no sync step was compared")
	}
	_ = hex.EncodeToString
}
