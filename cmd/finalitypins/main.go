// Copyright 2026 Certen Protocol

// finalitypins derives and re-checks the pins ledger of V2_SPEC_S7 section 4 (the Sepolia anchors of
// pkg/finality/pins/finality-pins.json and the link bytes beside it in pkg/finality/pins-links/).
//
// Usage (one command, run from the repository root; network use is explicit and only here):
//
//	finalitypins derive-sepolia [-pins pkg/finality/pins/finality-pins.json] [-links-dir pkg/finality/pins-links]
//	      [-lodestar URL] [-lighthouse URL] [-root-period 1378] [-root-block-root 0x5f71...b20d] [-min-clients 2]
//	      [-update-constant pkg/finality/pins.go] [-dry-run]
//	finalitypins verify-sepolia [-pins FILE] [-links-dir DIR]        (offline: the same re-derivation proofverify --pins-selfcheck runs)
//
// WEEKLY REGENERATION (SO3, OD2) is exactly `finalitypins derive-sepolia -update-constant pkg/finality/pins.go` followed by
// the PR: the tool re-derives the WHOLE ledger from the root pin on every run, so the file it writes never depends on the
// previous ledger being right. For every period q from the root period to the current one it
//
//  1. fetches the best light-client updates U_root..U_(cur-1) from the Lodestar endpoint (availability only: every byte is
//     verified), and the root pin's bootstrap from Lodestar AND Lighthouse (the pinned block root must be the hash tree root of
//     the header both serve, and both must serve the same committee);
//  2. derives the committee root of q from U_(q-1) (its next_sync_committee) and verifies the step through ethl1 (the
//     predecessor committee's signatures, >= 342 participants, the next-committee branch, the ledger label of the learned
//     committee): Pins.LedgerStep, the primitive Pins.Extend and `proofverify --pins-selfcheck` use;
//  3. recomputes the committee root of q from the plain Beacon API (sync_committees?epoch plus the validator pubkeys,
//     aggregate pubkey by G1 summation, SSZ root) on every client that can serve the state and records which implementation
//     agreed in `derived_by`; ANY disagreement refuses the whole run and writes nothing; fewer than -min-clients distinct
//     implementations agreeing refuses it too (finality_ledger_incomplete);
//  4. computes wsp_epochs from the live validator set with the Gloas formula (consensus-specs gloas/weak-subjectivity.md).
//
// Nothing is written unless every period passed. The link bytes are stored as pins-links/<period>.ssz: for the root period the
// bootstrap, otherwise the update that derived the entry (26,424 B for a Gloas period).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
	"github.com/certen/independant-validator/pkg/finality/lcssz"
)

const (
	defaultLodestar   = "https://lodestar-sepolia.chainsafe.io"
	defaultLighthouse = "https://ethereum-sepolia-beacon-api.publicnode.com"
	rootPeriod        = 1378
	rootBlockRoot     = "0x5f71d7f650f9252b48749b5f062c0c234e01afd69f364ab600e2b6051494b20d"
	slotsPerPeriod    = 8192
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: finalitypins derive-sepolia|verify-sepolia [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "derive-sepolia":
		err = deriveCmd(os.Args[2:])
	case "verify-sepolia":
		err = verifyCmd(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "REFUSED:", ethrpc.RedactText(err.Error()))
		os.Exit(1)
	}
}

// ---- verify-sepolia ----

func verifyCmd(args []string) error {
	fs := flag.NewFlagSet("verify-sepolia", flag.ExitOnError)
	pinsPath := fs.String("pins", "pkg/finality/pins/finality-pins.json", "pins file")
	linksDir := fs.String("links-dir", "pkg/finality/pins-links", "directory of <period>.ssz link files")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*pinsPath)
	if err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		return err
	}
	links, err := ReadLinks(*linksDir)
	if err != nil {
		return err
	}
	if err := pins.VerifyLedger(links); err != nil {
		return err
	}
	e, _ := pins.Sepolia()
	fmt.Printf("ledger of %d anchors re-derived from the root pin: ok (pins sha256 %x)\n", len(e.Anchors), pins.SHA256())
	return nil
}

// ReadLinks reads <period>.ssz files from dir.
func ReadLinks(dir string) (map[uint64][]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[uint64][]byte{}
	for _, en := range ents {
		name := en.Name()
		if !strings.HasSuffix(name, ".ssz") {
			continue
		}
		p, err := strconv.ParseUint(strings.TrimSuffix(name, ".ssz"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("link file %q is not <period>.ssz", name)
		}
		if out[p], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ---- derive-sepolia ----

type beaconClient struct {
	base string
	impl string // Lodestar/v1.49.0 ... from /eth/v1/node/version
	http *http.Client
}

func (c *beaconClient) get(ctx context.Context, path, accept string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	return b, resp.StatusCode, err
}

func (c *beaconClient) init(ctx context.Context) error {
	b, code, err := c.get(ctx, "/eth/v1/node/version", "")
	if err != nil || code != 200 {
		return fmt.Errorf("%s: node version: http %d %v", c.base, code, err)
	}
	var v struct{ Data struct{ Version string } }
	if json.Unmarshal(b, &v) != nil || v.Data.Version == "" {
		return fmt.Errorf("%s: node version unreadable", c.base)
	}
	c.impl = v.Data.Version
	return nil
}

// kind is the client family ("Lodestar", "Lighthouse"): independence is counted per family, not per endpoint.
func (c *beaconClient) kind() string {
	if i := strings.IndexAny(c.impl, "/"); i > 0 {
		return c.impl[:i]
	}
	return c.impl
}

func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

type entry struct {
	period    uint64
	root      [32]byte
	blockRoot string
	link      []byte
	body      []byte
	derivedBy []string
}

func deriveCmd(args []string) error {
	fs := flag.NewFlagSet("derive-sepolia", flag.ExitOnError)
	pinsPath := fs.String("pins", "pkg/finality/pins/finality-pins.json", "pins file to read and rewrite (anchors only)")
	linksDir := fs.String("links-dir", "pkg/finality/pins-links", "directory the link files are written to")
	lodestar := fs.String("lodestar", defaultLodestar, "Lodestar beacon endpoint (light-client source and client 1)")
	lighthouse := fs.String("lighthouse", defaultLighthouse, "Lighthouse beacon endpoint (client 2)")
	rp := fs.Uint64("root-period", rootPeriod, "period of the root pin")
	rbr := fs.String("root-block-root", rootBlockRoot, "block root of the root pin (period-start checkpoint)")
	minClients := fs.Int("min-clients", 2, "distinct beacon-client implementations that must agree on every committee root")
	outPins := fs.String("out-pins", "", "write the pins file here instead of over -pins (vector pins: never embedded)")
	apiTimeout := fs.Duration("api-timeout", 40*time.Second, "per Beacon API state request")
	toPeriod := fs.Uint64("to-period", 0, "last period to derive (0: the current period)")
	updateConst := fs.String("update-constant", "", "rewrite the PinsSHA256 constant in this Go file")
	dry := fs.Bool("dry-run", false, "derive and check everything, write nothing")
	_ = fs.Parse(args)

	ctx := context.Background()
	hc := &http.Client{Timeout: 150 * time.Second}
	lo := &beaconClient{base: strings.TrimRight(*lodestar, "/"), http: hc}
	li := &beaconClient{base: strings.TrimRight(*lighthouse, "/"), http: hc}
	if err := lo.init(ctx); err != nil {
		return err
	}
	if err := li.init(ctx); err != nil {
		return err
	}
	clients := []*beaconClient{lo, li}
	src := ethsepolia.NewHTTPSource(lo.base)
	src.Client = hc

	raw, err := os.ReadFile(*pinsPath)
	if err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		return err
	}
	e, err := pins.Sepolia()
	if err != nil {
		return err
	}
	head, err := src.HeadSlot(ctx)
	if err != nil {
		return err
	}
	cur := head / slotsPerPeriod
	if *toPeriod != 0 {
		cur = *toPeriod
	}
	fmt.Printf("head slot %d, deriving periods %d..%d\n", head, *rp, cur)

	// the root pin: bootstrap on both clients
	var root [32]byte
	rb, _ := hex.DecodeString(strings.TrimPrefix(*rbr, "0x"))
	copy(root[:], rb)
	boot, err := src.Bootstrap(ctx, root)
	if err != nil {
		return err
	}
	rootEntry, err := checkRoot(ctx, boot, root, *rp, lo, li)
	if err != nil {
		return err
	}
	entries := []entry{rootEntry}

	var ups [][]byte
	if cur > *rp {
		if ups, err = src.Updates(ctx, *rp, int(cur-*rp)); err != nil {
			return err
		}
	}
	for i, up := range ups {
		q := *rp + uint64(i) + 1
		body, err := lcssz.NextCommittee(lcssz.LayoutOfUpdate(up), up)
		if err != nil {
			return fmt.Errorf("period %d: %v", q, err)
		}
		r, err := ethl1.HashTreeRootSyncCommittee(body)
		if err != nil {
			return err
		}
		entries = append(entries, entry{period: q, root: r, link: up, body: body, derivedBy: []string{"lc_link:" + host(lo.base)}})
	}

	// wsp from the live validator set
	wsp, nActive, total, err := computeWSP(ctx, lo)
	if err != nil {
		return err
	}
	fmt.Printf("weak-subjectivity period: %d epochs (%d active validators, %d gwei effective balance)\n", wsp, nActive, total)
	if wsp < finality.MinWspEpochs {
		return fmt.Errorf("the computed weak-subjectivity period %d is below %d epochs: the loader would refuse the ledger", wsp, finality.MinWspEpochs)
	}

	// the plain Beacon API recomputation per client
	pk := map[*beaconClient]map[uint64][]byte{}
	for _, c := range clients {
		if pk[c], err = validatorPubkeys(ctx, c); err != nil {
			fmt.Printf("%s: validator pubkeys unavailable: %v\n", c.impl, ethrpc.RedactText(err.Error()))
		}
	}
	fp, err := finalizedPeriod(ctx, lo)
	if err != nil {
		return err
	}
	var incomplete []string
	for i := 1; i < len(entries); i++ {
		en := &entries[i]
		agreed := map[string]bool{}
		for _, c := range clients {
			if pk[c] == nil {
				continue
			}
			got, why := apiCommitteeRoot(ctx, c, pk[c], en.period, fp, *apiTimeout)
			if why != "" {
				fmt.Printf("period %d: %s cannot serve the state (%s)\n", en.period, c.impl, ethrpc.RedactText(why))
				continue
			}
			if got != en.root {
				return fmt.Errorf("period %d: %s recomputes committee root %x, the verified light-client link carries %x: refusing", en.period, c.impl, got, en.root)
			}
			agreed[c.kind()] = true
			en.derivedBy = append(en.derivedBy, "beacon_api:"+c.impl)
		}
		if len(agreed) < *minClients {
			incomplete = append(incomplete, fmt.Sprintf("finality_ledger_incomplete{missing_period:%d}: %d distinct beacon-client implementation(s) agreed on the committee root, -min-clients is %d", en.period, len(agreed), *minClients))
			continue
		}
		fmt.Printf("period %d: committee root %x  agreed: %v\n", en.period, en.root, keys(agreed))
	}

	if len(incomplete) > 0 {
		return fmt.Errorf("%d of %d periods lack the cross-check, nothing written:\n  %s", len(incomplete), len(entries)-1, strings.Join(incomplete, "\n  "))
	}

	// build the candidate pins and re-verify the WHOLE ledger through ethl1 before anything is written
	anchors := make([]map[string]any, 0, len(entries))
	links := map[uint64][]byte{}
	for _, en := range entries {
		sum := sha256.Sum256(en.link)
		a := map[string]any{
			"period": en.period, "committee_root": "0x" + hex.EncodeToString(en.root[:]), "wsp_epochs": wsp,
			"link_sha256": hex.EncodeToString(sum[:]), "derived_by": append([]string(nil), en.derivedBy...),
		}
		if en.blockRoot != "" {
			a["block_root"] = en.blockRoot
		}
		anchors = append(anchors, a)
		links[en.period] = en.link
	}
	out, err := rewriteAnchors(raw, anchors)
	if err != nil {
		return err
	}
	cand, err := finality.ParsePinsOverride(out)
	if err != nil {
		return err
	}
	if err := cand.VerifyLedger(links); err != nil {
		return fmt.Errorf("the derived ledger does not re-verify: %v", err)
	}
	// and the walk of the whole chain once, from the root pin to a LIVE finality update, as a real proof would use it
	if err := endToEnd(ctx, src, e, cand, links, *rp, cur); err != nil {
		return err
	}
	sum := sha256.Sum256(out)
	fmt.Printf("ledger of %d anchors verified; new pins sha256 %x (%d bytes)\n", len(anchors), sum, len(out))
	if *dry {
		return nil
	}
	if err := os.MkdirAll(*linksDir, 0o755); err != nil {
		return err
	}
	for p, b := range links {
		if err := os.WriteFile(filepath.Join(*linksDir, fmt.Sprintf("%d.ssz", p)), b, 0o644); err != nil {
			return err
		}
	}
	dst := *pinsPath
	if *outPins != "" {
		dst = *outPins
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return err
	}
	if *updateConst != "" {
		b, err := os.ReadFile(*updateConst)
		if err != nil {
			return err
		}
		re := regexp.MustCompile(`(const PinsSHA256 = ")[0-9a-f]{64}(")`)
		if !re.Match(b) {
			return fmt.Errorf("%s has no PinsSHA256 constant", *updateConst)
		}
		b = re.ReplaceAll(b, []byte("${1}"+hex.EncodeToString(sum[:])+"${2}"))
		return os.WriteFile(*updateConst, b, 0o644)
	}
	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkRoot verifies the root pin's bootstrap against both clients: the pinned block root must be the hash tree root of the
// header each serves, and both must serve the same committee.
func checkRoot(ctx context.Context, boot []byte, root [32]byte, period uint64, lo, li *beaconClient) (entry, error) {
	l := lcssz.LayoutOfBootstrap(boot)
	body, err := lcssz.BootstrapCommittee(l, boot)
	if err != nil {
		return entry{}, err
	}
	hdrAt := 4 + lcssz.CommitteeBytes + 6*32
	if l == lcssz.Gloas {
		hdrAt = 0
	}
	if len(boot) < hdrAt+112 {
		return entry{}, fmt.Errorf("the root bootstrap is too short")
	}
	hr, err := ethl1.HashTreeRootBeaconBlockHeader(boot[hdrAt : hdrAt+112])
	if err != nil {
		return entry{}, err
	}
	if hr != root {
		return entry{}, fmt.Errorf("the bootstrap header root %x is not the pinned block root %x", hr, root)
	}
	croot, err := ethl1.HashTreeRootSyncCommittee(body)
	if err != nil {
		return entry{}, err
	}
	// Lighthouse serves the same bootstrap as Beacon API JSON whatever Accept says (RB11-C1B-F2): compare field by field.
	b, code, err := li.get(ctx, "/eth/v1/beacon/light_client/bootstrap/0x"+hex.EncodeToString(root[:]), "")
	if err != nil || code != 200 {
		return entry{}, fmt.Errorf("%s did not serve the root bootstrap: http %d %v", li.impl, code, err)
	}
	var raw struct {
		Data struct {
			Header struct {
				Beacon map[string]string `json:"beacon"`
			} `json:"header"`
			CurrentSyncCommittee struct {
				Pubkeys         []string `json:"pubkeys"`
				AggregatePubkey string   `json:"aggregate_pubkey"`
			} `json:"current_sync_committee"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return entry{}, fmt.Errorf("%s root bootstrap does not parse", li.impl)
	}
	var hb []byte
	slot, _ := strconv.ParseUint(raw.Data.Header.Beacon["slot"], 10, 64)
	prop, _ := strconv.ParseUint(raw.Data.Header.Beacon["proposer_index"], 10, 64)
	hb = binary.LittleEndian.AppendUint64(hb, slot)
	hb = binary.LittleEndian.AppendUint64(hb, prop)
	for _, k := range []string{"parent_root", "state_root", "body_root"} {
		x, _ := hex.DecodeString(strings.TrimPrefix(raw.Data.Header.Beacon[k], "0x"))
		hb = append(hb, x...)
	}
	if !bytes.Equal(hb, boot[hdrAt:hdrAt+112]) {
		return entry{}, fmt.Errorf("%s serves a different root header than %s", li.impl, lo.impl)
	}
	var cb []byte
	for _, p := range raw.Data.CurrentSyncCommittee.Pubkeys {
		x, _ := hex.DecodeString(strings.TrimPrefix(p, "0x"))
		cb = append(cb, x...)
	}
	x, _ := hex.DecodeString(strings.TrimPrefix(raw.Data.CurrentSyncCommittee.AggregatePubkey, "0x"))
	cb = append(cb, x...)
	if !bytes.Equal(cb, body) {
		return entry{}, fmt.Errorf("%s serves a different root committee than %s", li.impl, lo.impl)
	}
	return entry{period: period, root: croot, blockRoot: "0x" + hex.EncodeToString(root[:]), link: boot, body: body,
		derivedBy: []string{"bootstrap:" + lo.impl + "@" + host(lo.base), "bootstrap:" + li.impl + "@" + host(li.base)}}, nil
}

// ---- plain Beacon API recomputation ----

func validatorPubkeys(ctx context.Context, c *beaconClient) (map[uint64][]byte, error) {
	b, code, err := c.get(ctx, "/eth/v1/beacon/states/finalized/validators", "")
	if err != nil || code != 200 {
		return nil, fmt.Errorf("validators: http %d %v", code, err)
	}
	var v struct {
		Data []struct {
			Index     string `json:"index"`
			Validator struct {
				Pubkey string `json:"pubkey"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	out := make(map[uint64][]byte, len(v.Data))
	for _, d := range v.Data {
		i, err := strconv.ParseUint(d.Index, 10, 64)
		if err != nil {
			return nil, err
		}
		pk, err := hex.DecodeString(strings.TrimPrefix(d.Validator.Pubkey, "0x"))
		if err != nil || len(pk) != 48 {
			return nil, fmt.Errorf("validator %d has a malformed pubkey", i)
		}
		out[i] = pk
	}
	return out, nil
}

func finalizedPeriod(ctx context.Context, c *beaconClient) (uint64, error) {
	b, code, err := c.get(ctx, "/eth/v1/beacon/states/finalized/finality_checkpoints", "")
	if err != nil || code != 200 {
		return 0, fmt.Errorf("finality_checkpoints: http %d %v", code, err)
	}
	var v struct {
		Data struct{ Finalized struct{ Epoch string } }
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, err
	}
	ep, err := strconv.ParseUint(v.Data.Finalized.Epoch, 10, 64)
	return ep / 256, err
}

// apiCommitteeRoot recomputes hash_tree_root(SyncCommittee) of period q from the Beacon API alone. It returns a non-empty
// reason when the client cannot serve a state that carries the committee (an unavailability, never a disagreement).
func apiCommitteeRoot(ctx context.Context, c *beaconClient, pk map[uint64][]byte, q, finalizedPeriod uint64, timeout time.Duration) ([32]byte, string) {
	var states []string
	if q == finalizedPeriod || q == finalizedPeriod+1 {
		states = append(states, "finalized")
	}
	states = append(states, strconv.FormatUint(q*slotsPerPeriod, 10))
	var why string
	for _, st := range states {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		b, code, err := c.get(cctx, "/eth/v1/beacon/states/"+st+"/sync_committees?epoch="+strconv.FormatUint(q*256, 10), "")
		cancel()
		if err != nil || code != 200 {
			why = fmt.Sprintf("state %s: http %d %v", st, code, err)
			continue
		}
		var v struct{ Data struct{ Validators []string } }
		if err := json.Unmarshal(b, &v); err != nil || len(v.Data.Validators) != 512 {
			why = fmt.Sprintf("state %s: committee does not parse", st)
			continue
		}
		var agg bls12381.G1Jac
		var body []byte
		for _, s := range v.Data.Validators {
			i, _ := strconv.ParseUint(s, 10, 64)
			key, ok := pk[i]
			if !ok {
				why = fmt.Sprintf("validator %d is not in the registry served", i)
				body = nil
				break
			}
			var a bls12381.G1Affine
			if _, err := a.SetBytes(key); err != nil {
				why = fmt.Sprintf("validator %d has an invalid pubkey", i)
				body = nil
				break
			}
			agg.AddMixed(&a)
			body = append(body, key...)
		}
		if body == nil {
			continue
		}
		var out bls12381.G1Affine
		out.FromJacobian(&agg)
		ab := out.Bytes()
		body = append(body, ab[:]...)
		r, err := ethl1.HashTreeRootSyncCommittee(body)
		if err != nil {
			why = err.Error()
			continue
		}
		return r, ""
	}
	return [32]byte{}, why
}

// computeWSP is the Gloas weak-subjectivity period (consensus-specs gloas/weak-subjectivity.md): with t the total effective
// balance of the active validators, the balance churn limit max(128e9, t/32768) (CHURN_LIMIT_QUOTIENT_GLOAS 32768,
// MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA 128e9), the activation/exit churn min(256e9, churn) and the consolidation churn the rest,
// delta = 2*exit/3 + activation/3 + consolidation and WSP = 256 + 10*t/(200*delta).
func computeWSP(ctx context.Context, c *beaconClient) (wsp uint64, active int, total uint64, err error) {
	b, code, err := c.get(ctx, "/eth/v1/beacon/states/finalized/validators?status=active_ongoing", "")
	if err != nil || code != 200 {
		return 0, 0, 0, fmt.Errorf("active validators: http %d %v", code, err)
	}
	var v struct {
		Data []struct {
			Validator struct {
				EffectiveBalance string `json:"effective_balance"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, 0, 0, err
	}
	for _, d := range v.Data {
		eb, err := strconv.ParseUint(d.Validator.EffectiveBalance, 10, 64)
		if err != nil {
			return 0, 0, 0, err
		}
		total += eb
	}
	const minChurn, maxActExit, quotient = uint64(128_000_000_000), uint64(256_000_000_000), uint64(32768)
	churn := total / quotient
	if churn < minChurn {
		churn = minChurn
	}
	actExit := churn
	if actExit > maxActExit {
		actExit = maxActExit
	}
	consolidation := churn - actExit
	delta := 2*actExit/3 + actExit/3 + consolidation
	if delta == 0 {
		return 0, 0, 0, fmt.Errorf("zero churn")
	}
	return 256 + 10*total/(200*delta), len(v.Data), total, nil
}

// endToEnd verifies a LIVE finality update against the candidate ledger exactly as a proof built now would be: the anchor is
// the latest entry, the links are the updates from there to the update's signature period.
func endToEnd(ctx context.Context, src *ethsepolia.HTTPSource, e *finality.EthSepoliaPins, cand *finality.Pins, links map[uint64][]byte, rp, cur uint64) error {
	ce, err := cand.Sepolia()
	if err != nil {
		return err
	}
	fu, err := src.FinalityUpdate(ctx)
	if err != nil {
		return err
	}
	l := lcssz.LayoutOfFinalityUpdate(fu)
	_, _, sig, err := lcssz.FinalityUpdateSlots(l, fu)
	if err != nil {
		return err
	}
	a, err := ce.AnchorFor(sig / slotsPerPeriod)
	if err != nil {
		return err
	}
	body, err := lcssz.NextCommittee(lcssz.LayoutOfUpdate(links[a.Period]), links[a.Period])
	if a.BlockRoot != "" {
		body, err = lcssz.BootstrapCommittee(lcssz.LayoutOfBootstrap(links[a.Period]), links[a.Period])
	}
	if err != nil {
		return err
	}
	lc := ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: a.Period, AnchorBody: ethl1.LB{Layout: ethl1.LayoutNone, SSZ: body},
		FinalUpdate: ethl1.LB{Layout: finality.L1Layout(l), SSZ: fu}}
	r, _ := hex.DecodeString(strings.TrimPrefix(a.CommitteeRoot, "0x"))
	copy(lc.AnchorRoot[:], r)
	if n := int(sig/slotsPerPeriod - a.Period); n > 0 {
		ups, err := src.Updates(ctx, a.Period, n)
		if err != nil {
			return err
		}
		for _, u := range ups {
			lc.Links = append(lc.Links, ethl1.LB{Layout: finality.L1Layout(lcssz.LayoutOfUpdate(u)), SSZ: u})
		}
	}
	h, err := ethl1.VerifyFinalizedHead(ce.L1Pins(ce.Anchors), lc)
	if err != nil {
		return fmt.Errorf("a live finality update does not verify against the candidate ledger: %v", err)
	}
	fmt.Printf("live finality update: slot %d, %d participants, %d periods crossed from anchor %d: ok\n", h.Slot, h.Participants, h.PeriodsCrossed, a.Period)
	return nil
}

// rewriteAnchors replaces eth_sepolia.anchors in a pins file and re-renders it the way the file is committed: sorted keys,
// two-space indent, LF, trailing newline, numbers untouched.
func rewriteAnchors(raw []byte, anchors []map[string]any) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	es, ok := m["eth_sepolia"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no eth_sepolia section")
	}
	list := make([]any, len(anchors))
	for i, a := range anchors {
		list[i] = a
	}
	es["anchors"] = list
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
