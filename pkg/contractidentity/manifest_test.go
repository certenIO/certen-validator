// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func embeddedOK(t *testing.T) *Manifest {
	t.Helper()
	m, err := Embedded()
	if err != nil {
		t.Fatalf("embedded manifest: %v (cause: %v)", err, errors.Unwrap(err))
	}
	return m
}

// primaryDoc parses the embedded manifest into a generic document (numbers kept exact) for fixture building.
func primaryDoc(t *testing.T) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(EmbeddedManifestBytes()))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadFixture(t *testing.T, doc map[string]any) *Manifest {
	t.Helper()
	raw := marshal(t, doc)
	m, err := LoadManifest(raw, ManifestHash(raw))
	if err != nil {
		t.Fatalf("fixture manifest: %v", err)
	}
	return m
}

// The pin constant, the embedded file and its sibling .sha256 file agree; `node lift.mjs --sync-manifest <path>` refreshes all three.
func TestManifestSync(t *testing.T) {
	raw := EmbeddedManifestBytes()
	sum := sha256.Sum256(raw)
	if bytes.Contains(raw, []byte("\r")) {
		t.Fatal("the embedded manifest contains CR bytes (it is hashed with CRLF normalised, and committed with LF)")
	}
	if ManifestSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("pin constant ManifestSHA256 = %s, the embedded file hashes to %x", ManifestSHA256, sum)
	}
	fields := strings.Fields(EmbeddedManifestSHA256File())
	if len(fields) != 2 || fields[0] != ManifestSHA256 || fields[1] != "identity-manifest.json" {
		t.Fatalf("sibling .sha256 file %q does not carry the pin %s for identity-manifest.json", EmbeddedManifestSHA256File(), ManifestSHA256)
	}
	if h := ManifestHash(raw); hex.EncodeToString(h[:]) != ManifestSHA256 {
		t.Fatalf("ManifestHash = %x", h)
	}
	// the CRLF-normalised hash of a CRLF copy equals the pin: the definition of the manifest hash
	crlf := bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n"))
	if h := ManifestHash(crlf); hex.EncodeToString(h[:]) != ManifestSHA256 {
		t.Fatalf("a CRLF copy hashes to %x", h)
	}
}

func TestEmbeddedManifestLoads(t *testing.T) {
	m := embeddedOK(t)
	if m.Source != ManifestSourceEmbedded || hex.EncodeToString(m.SHA256[:]) != ManifestSHA256 || m.Schema() != ManifestSchema {
		t.Fatalf("source %q sha %x", m.Source, m.SHA256)
	}
	if !Check("manifest_source", m.Source) {
		t.Fatalf("manifest_source %q is outside the vocabulary", m.Source)
	}
	if len(m.Chains()) != 4 || len(m.BuildKeys()) != 7 || len(m.AuthSlots()) != 25 {
		t.Fatalf("chains %d builds %d authSlots %d", len(m.Chains()), len(m.BuildKeys()), len(m.AuthSlots()))
	}
	// idempotent: the second call is the same manifest
	if again, _ := Embedded(); again != m {
		t.Fatal("Embedded is not memoised")
	}
}

// VS8-001: the embedded manifest bytes altered by one byte are manifest_corrupt, at every position class; the hash is the pin.
func TestVS8_001_AlteredBytesAreCorrupt(t *testing.T) {
	raw := EmbeddedManifestBytes()
	var want [32]byte
	b, _ := hex.DecodeString(ManifestSHA256)
	copy(want[:], b)
	if _, err := LoadManifest(raw, want); err != nil {
		t.Fatalf("pristine bytes refused: %v", err)
	}
	for _, pos := range []int{0, 1, len(raw) / 2, len(raw) - 2, len(raw) - 1} {
		alt := append([]byte(nil), raw...)
		alt[pos] ^= 0x01
		_, err := LoadManifest(alt, want)
		wantState(t, err, ManifestCorrupt())
	}
	_, err := LoadManifest(append(append([]byte(nil), raw...), ' '), want)
	wantState(t, err, ManifestCorrupt())
	_, err = LoadManifest(nil, want)
	wantState(t, err, ManifestCorrupt())
	// a wrong pin with pristine bytes is corrupt too
	other := want
	other[0] ^= 1
	_, err = LoadManifest(raw, other)
	wantState(t, err, ManifestCorrupt())
}

func TestManifestCorruptDocuments(t *testing.T) {
	doc := primaryDoc(t)
	bad := map[string]func(map[string]any){
		"unsupported schema":      func(d map[string]any) { d["schema"] = "certen:identity-manifest:v1.0" },
		"missing schema":          func(d map[string]any) { delete(d, "schema") },
		"missing builds":          func(d map[string]any) { delete(d, "builds") },
		"missing chains":          func(d map[string]any) { delete(d, "chains") },
		"builds is not an object": func(d map[string]any) { d["builds"] = []any{} },
		"policy owner key not a number": func(d map[string]any) {
			d["policy"].(map[string]any)["owner"].(map[string]any)["x"] = []any{}
		},
		"duplicate deployment (chainId, role)": func(d map[string]any) {
			dep := d["deployments"].([]any)
			d["deployments"] = append(dep, dep[0])
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			d := primaryDoc(t)
			mutate(d)
			raw := marshal(t, d)
			_, err := LoadManifest(raw, ManifestHash(raw))
			wantState(t, err, ManifestCorrupt())
		})
	}
	_ = doc
	// a duplicate object key inside the document is corrupt (encoding/json would keep the last value silently)
	raw := EmbeddedManifestBytes()
	dup := bytes.Replace(raw, []byte(`"schema"`), []byte(`"schema": "certen:identity-manifest:v1.1", "schema"`), 1)
	if bytes.Equal(dup, raw) {
		t.Fatal("fixture construction")
	}
	_, err := LoadManifest(dup, ManifestHash(dup))
	wantState(t, err, ManifestCorrupt())
	// not JSON at all
	_, err = LoadManifest([]byte("not json"), ManifestHash([]byte("not json")))
	wantState(t, err, ManifestCorrupt())
}

// VS8-002: a settlement chain absent from chains[] is manifest_unknown{chain}.
func TestVS8_002_ChainLookup(t *testing.T) {
	m := embeddedOK(t)
	for _, c := range []uint64{11155111, 84532, 421614, 2017} {
		ce, err := m.Chain(c)
		if err != nil || ce.ChainID != c || ce.Name == "" || !strings.HasPrefix(ce.SnapshotBlockHash, "0x") {
			t.Fatalf("chain %d: %+v %v", c, ce, err)
		}
	}
	for _, c := range []uint64{0, 1, 17000, 421613, 1 << 40} {
		_, err := m.Chain(c)
		wantState(t, err, ManifestUnknown(c))
	}
}

func extensionDoc(policy, eip, builds, deployments, accounts any, top map[string]any) []byte {
	d := map[string]any{"schema": ManifestSchema}
	if policy != nil {
		d["policy"] = policy
	}
	if eip != nil {
		d["eip2935"] = eip
	}
	if builds != nil {
		d["builds"] = builds
	}
	if deployments != nil {
		d["deployments"] = deployments
	}
	if accounts != nil {
		d["accounts"] = accounts
	}
	for k, v := range top {
		d[k] = v
	}
	b, _ := json.Marshal(d)
	return b
}

// VS8-003: an extension that redefines a primary key is manifest_shadow{table,key}, one vector per class.
func TestVS8_003_ExtensionMayNotShadow(t *testing.T) {
	m := embeddedOK(t)
	doc := primaryDoc(t)
	oneEIP := func() any {
		return map[string]any{"84532": doc["eip2935"].(map[string]any)["84532"]}
	}
	cases := []struct {
		name       string
		ext        []byte
		table, key string
	}{
		{"policy.blsThreshold", extensionDoc(map[string]any{"blsThreshold": map[string]any{"numerator": 1, "denominator": 2}}, nil, nil, nil, nil, nil), "policy", "blsThreshold"},
		{"policy.pubkeyBindingEnforced", extensionDoc(map[string]any{"pubkeyBindingEnforced": false}, nil, nil, nil, nil, nil), "policy", "pubkeyBindingEnforced"},
		{"policy.blsZKVerificationEnabled", extensionDoc(map[string]any{"blsZKVerificationEnabled": false}, nil, nil, nil, nil, nil), "policy", "blsZKVerificationEnabled"},
		{"policy.verifierThreshold", extensionDoc(map[string]any{"verifierThreshold": map[string]any{"numerator": 1, "denominator": 2}}, nil, nil, nil, nil, nil), "policy", "verifierThreshold"},
		{"policy.minimumGovernanceLevel", extensionDoc(map[string]any{"minimumGovernanceLevel": map[string]any{"min": 0}}, nil, nil, nil, nil, nil), "policy", "minimumGovernanceLevel"},
		{"policy.governanceVerifier", extensionDoc(map[string]any{"governanceVerifier": "0x0000000000000000000000000000000000000001"}, nil, nil, nil, nil, nil), "policy", "governanceVerifier"},
		{"policy.rules row", extensionDoc(map[string]any{"rules": []any{map[string]any{"id": "MINGOV", "authRows": []string{"A20"}, "predicate": ">= 0", "at": "pre, post", "verdict": "x"}}}, nil, nil, nil, nil, nil), "policy.rules", "MINGOV"},
		{"policy.txScan chain", extensionDoc(map[string]any{"txScan": map[string]any{"421614": map[string]any{"coveredTypes": []int{0}}}}, nil, nil, nil, nil, nil), "policy.txScan", "421614"},
		{"eip2935 row", extensionDoc(nil, oneEIP(), nil, nil, nil, nil), "eip2935", "84532"},
		{"selectors key", extensionDoc(nil, nil, nil, nil, nil, map[string]any{"selectors": map[string]any{"CertenAnchorV8_2/executeComprehensiveProof": map[string]any{"selector": "0x00000000"}}}), "selectors", "CertenAnchorV8_2/executeComprehensiveProof"},
		{"topics entry", extensionDoc(nil, nil, nil, nil, nil, map[string]any{"topics": map[string]any{"ProofExecuted": map[string]any{}}}), "topics", "ProofExecuted"},
		{"builds key", extensionDoc(nil, nil, map[string]any{"CertenAnchorV8_2/r5": doc["builds"].(map[string]any)["CertenAnchorV8_2/r5"]}, nil, nil, nil), "builds", "CertenAnchorV8_2/r5"},
		{"deployments (chainId,role)", extensionDoc(nil, nil, nil, []any{doc["deployments"].([]any)[0]}, nil, nil), "deployments", "11155111,anchor"},
		{"accounts (chainId,address)", extensionDoc(nil, nil, nil, nil, []any{doc["accounts"].([]any)[0]}, nil), "accounts", "11155111,0x2ec2d261a4770e42dbe43826489d299d596bc5f7"},
		{"a table an extension may not carry: authSlots", extensionDoc(nil, nil, nil, nil, nil, map[string]any{"authSlots": []any{}}), "authSlots", "*"},
		{"a chains row of an existing chain", extensionDoc(nil, nil, nil, nil, nil, map[string]any{"chains": []any{map[string]any{"chainId": 11155111}}}), "chains", "11155111"},
		{"a table an extension may not carry: slotChecks", extensionDoc(nil, nil, nil, nil, nil, map[string]any{"slotChecks": []any{}}), "slotChecks", "*"},
		{"unknown policy key", extensionDoc(map[string]any{"somethingNew": 1}, nil, nil, nil, nil, nil), "policy", "somethingNew"},
		{"owner row not after the last", extensionDoc(map[string]any{"owner": map[string]any{"11155111": []any{map[string]any{"role": "anchor", "address": "0x0000000000000000000000000000000000000001", "validFromBlock": 11832572, "validToBlock": nil}}}}, nil, nil, nil, nil, nil), "policy.owner", "11155111,anchor"},
		{"owner row before the last", extensionDoc(map[string]any{"owner": map[string]any{"11155111": []any{map[string]any{"role": "verifier", "address": "0x0000000000000000000000000000000000000001", "validFromBlock": 100, "validToBlock": nil}}}}, nil, nil, nil, nil, nil), "policy.owner", "11155111,verifier"},
		{"setRootHistory row not after the last", extensionDoc(map[string]any{"setRootHistory": []any{map[string]any{"chainId": 84532, "root": "0x01", "validFromBlock": 47597158, "validToBlock": nil}}}, nil, nil, nil, nil, nil), "policy.setRootHistory", "84532"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.WithExtension(tc.ext)
			wantState(t, err, ManifestShadow(tc.table, tc.key))
		})
	}
	// an extension that repeats a key inside itself shadows itself
	dup := []byte(`{"schema":"certen:identity-manifest:v1.1","eip2935":{"1":{},"1":{}}}`)
	if _, err := m.WithExtension(dup); err == nil {
		t.Fatal("duplicate key inside the extension accepted")
	} else if st, ok := AsState(err); !ok || st.Code != CodeManifestShadow {
		t.Fatalf("duplicate key: %v", err)
	}
	// schema mismatch and non-JSON are corrupt
	_, err := m.WithExtension([]byte(`{"schema":"other"}`))
	wantState(t, err, ManifestCorrupt())
	_, err = m.WithExtension([]byte(`nope`))
	wantState(t, err, ManifestCorrupt())
	// the extension never changes the manifest it is applied to
	if m.Source != ManifestSourceEmbedded || len(m.Chains()) != 4 {
		t.Fatal("the base manifest was mutated")
	}
}

// VS8-004: appended rows are accepted with manifest_source extension:<sha256>; the earlier owner is retired from the new row's block.
func TestVS8_004_ExtensionAppendsRows(t *testing.T) {
	m := embeddedOK(t)
	doc := primaryDoc(t)
	owners := m.OwnerRows(11155111, "anchor")
	if len(owners) != 1 {
		t.Fatalf("owner rows %v", owners)
	}
	newOwner := "0x00000000000000000000000000000000000000aa"
	rootRows := m.SetRootRows(84532)
	if len(rootRows) != 1 {
		t.Fatalf("set root rows %v", rootRows)
	}
	ext := extensionDoc(
		map[string]any{
			"owner":          map[string]any{"11155111": []any{map[string]any{"role": "anchor", "address": newOwner, "validFromBlock": 12000000, "validToBlock": nil, "evidence": map[string]any{"basis": "test"}}}},
			"setRootHistory": []any{map[string]any{"chainId": 84532, "root": "0x" + strings.Repeat("ab", 32), "validFromBlock": 50000000, "validToBlock": nil, "thresholdNumerator": 2, "thresholdDenominator": 3}},
		}, nil,
		map[string]any{"CertenAnchorV8_3/r5": doc["builds"].(map[string]any)["CertenAnchorV8_2/r5"]},
		nil,
		[]any{map[string]any{"chainId": 84532, "address": "0xAbC0000000000000000000000000000000000001", "adiURL": "acc://x.acme"}}, nil)
	merged, err := m.WithExtension(ext)
	if err != nil {
		t.Fatalf("extension refused: %v", err)
	}
	sum := sha256.Sum256(ext)
	if merged.Source != "extension:"+hex.EncodeToString(sum[:]) || !Check("manifest_source", merged.Source) {
		t.Fatalf("source %q", merged.Source)
	}
	if merged.SHA256 != m.SHA256 || merged.ExtensionSHA256 != sum {
		t.Fatal("merged hashes")
	}
	if _, ok := merged.Build("CertenAnchorV8_3/r5"); !ok {
		t.Error("appended build missing")
	}
	if _, ok := merged.Build("CertenAnchorV8_2/r5"); !ok {
		t.Error("existing build lost")
	}
	if len(merged.Deployments(84532)) != len(m.Deployments(84532)) {
		t.Error("appended deployment missing")
	}
	if _, ok := merged.Account(84532, "0xabc0000000000000000000000000000000000001"); !ok {
		t.Error("appended account missing (address compare is case-insensitive)")
	}
	// history: the earlier owner covers blocks before 12000000, the new one from 12000000; never both
	before := merged.OwnerCovering(11155111, "anchor", 11999999)
	after := merged.OwnerCovering(11155111, "anchor", 12000000)
	if len(before) != 1 || before[0].Address != owners[0].Address || len(after) != 1 || after[0].Address != newOwner {
		t.Fatalf("owner history before %v after %v", before, after)
	}
	if got := merged.OwnerCovering(11155111, "anchor", owners[0].ValidFromBlock-1); len(got) != 0 {
		t.Fatalf("an owner covers a block before it existed: %v", got)
	}
	// the set-root history gains a row and the earlier one is retired at the new row's block
	if len(merged.SetRootRows(84532)) != 2 {
		t.Fatalf("set root rows %v", merged.SetRootRows(84532))
	}
	if _, ok := merged.SetRootRowFor(84532, 49999999, rootRows[0].Root); !ok {
		t.Error("the earlier set-root row must cover the block before the new one")
	}
	if _, ok := merged.SetRootRowFor(84532, 50000000, rootRows[0].Root); ok {
		t.Error("the earlier set-root row must not cover the block the new one starts at")
	}
	if _, ok := merged.SetRootRowFor(84532, 50000000, "0x"+strings.Repeat("AB", 32)); !ok {
		t.Error("the new set-root row (case-insensitive root) must cover its block")
	}
	// evidence of the appended owner row is preserved verbatim in the merged document
	if !bytes.Contains(merged.Section("policy"), []byte(`"basis":"test"`)) {
		t.Error("the appended owner row lost its fields")
	}
	// other tables are untouched
	if string(merged.Section("selectors")) != string(m.Section("selectors")) {
		t.Error("selectors changed")
	}
	// the same extension applied to a manifest that already merged it now shadows
	if _, err := merged.WithExtension(ext); err == nil {
		t.Error("re-applying an extension must be a shadow")
	}
}

func TestManifestAccessorsOnTheEmbeddedManifest(t *testing.T) {
	m := embeddedOK(t)
	// deployments: five roles on each chain, the anchor addresses of the live set
	for _, c := range []uint64{11155111, 84532, 421614, 2017} {
		roles := map[string]bool{}
		for _, d := range m.Deployments(c) {
			roles[d.Role] = true
			if !strings.HasPrefix(d.Address, "0x") || len(d.Address) != 42 {
				t.Errorf("deployment %+v", d)
			}
			if !Check("role", d.Role) {
				t.Errorf("role %q outside the vocabulary", d.Role)
			}
			if _, ok := m.Build(d.Build); !ok {
				t.Errorf("deployment %s/%s names the missing build %s", d.Chain, d.Role, d.Build)
			}
		}
		if len(roles) != 5 {
			t.Errorf("chain %d has roles %v", c, roles)
		}
	}
	a, ok := m.Deployment(11155111, RoleAnchor)
	if !ok || !strings.EqualFold(a.Address, "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c") || a.Build != "CertenAnchorV8_2/r5" {
		t.Fatalf("sepolia anchor %+v", a)
	}
	if d, ok := m.DeploymentAt(11155111, strings.ToLower(a.Address)); !ok || d.Role != RoleAnchor {
		t.Error("DeploymentAt")
	}
	if _, ok := m.Deployment(11155111, "nope"); ok {
		t.Error("unknown role found")
	}
	// builds: pinned hashes and immutables
	b, ok := m.Build("CertenAnchorV8_2/r5")
	if !ok || b.Runtime.Bytes != 24337 || !strings.HasPrefix(b.Runtime.MaskedKeccak, "0x5cdb02a0") || len(b.Immutables) != 1 || b.Immutables[0].Name != "DEPLOYMENT_CHAIN_ID" || len(b.Immutables[0].References) != 9 || b.Key() != "CertenAnchorV8_2/r5" {
		t.Fatalf("anchor build %+v", b)
	}
	for _, k := range []string{"CertenAnchorV8_2/r5", "BLSZKVerifierV2_1/r5"} {
		if st := m.AuthWritersStatus(k); st != "pass" {
			t.Errorf("%s authWriters status %q", k, st)
		}
	}
	if st := m.AuthWritersStatus("CertenAccountV7_3/r5"); st != "" {
		t.Errorf("a build without a writer record has status %q", st)
	}
	if ca, ok := m.CreationArtifact("CertenAccountV7_3/r5"); !ok || ca.Bytes != 15757 {
		t.Errorf("creation artifact %+v", ca)
	}
	// accounts
	acc, ok := m.Account(11155111, "0x2EC2D261A4770E42DBE43826489D299D596BC5F7")
	if !ok || acc.ADIURL != "acc://rb7-sep-10052031.acme" || acc.Create2.Salt == "" || len(m.Accounts(11155111)) == 0 {
		t.Fatalf("account %+v", acc)
	}
	// policy
	p := m.Policy()
	if p.BLSThreshold != (Threshold{2, 3}) || p.VerifierThreshold != (Threshold{2, 3}) || !p.PubkeyBindingEnforced || !p.BLSZKVerificationEnabled ||
		p.MinimumGovernanceLevel != 1 || p.GovernanceVerifier != "0x0000000000000000000000000000000000000000" {
		t.Fatalf("policy %+v", p)
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		ids[r.ID] = true
		if !Check("rule_id", r.ID) {
			t.Errorf("rule id %q outside the vocabulary", r.ID)
		}
	}
	for _, id := range generatedVocab["rule_id"] {
		if id == "VERIFIER-ID" && !ids[id] {
			continue // judged through steps 12 / 19a, not a policy row
		}
		if !ids[id] {
			t.Errorf("policy.rules lacks the rule %s of the vocabulary", id)
		}
	}
	if r, ok := m.Rule("MINGOV"); !ok || len(r.AuthRows) != 1 || r.AuthRows[0] != "A20" {
		t.Errorf("MINGOV %+v", r)
	}
	// owners: one anchor and one verifier row per chain, the pinned EOA, open-ended
	for _, c := range []uint64{11155111, 84532, 421614, 2017} {
		for _, role := range []string{"anchor", "verifier"} {
			rows := m.OwnerRows(c, role)
			if len(rows) != 1 || !strings.EqualFold(rows[0].Address, "0x91C798AA0Ad11d2670029b3B0572d154bd42c059") || rows[0].ValidToBlock != nil {
				t.Errorf("owner rows %d/%s: %+v", c, role, rows)
				continue
			}
			if got := m.OwnerCovering(c, role, rows[0].ValidFromBlock); len(got) != 1 {
				t.Errorf("owner not covering its own first block: %v", got)
			}
			if got := m.OwnerCovering(c, role, rows[0].ValidFromBlock+10_000_000); len(got) != 1 {
				t.Errorf("open-ended owner row does not cover a later block: %v", got)
			}
		}
	}
	// set-root history rows carry keys digest, count and list on every chain
	for _, c := range []uint64{11155111, 84532, 421614, 2017} {
		rows := m.SetRootRows(c)
		if len(rows) != 1 || rows[0].KeysDigest == nil || rows[0].PKCCount == nil || rows[0].PKCList == nil || *rows[0].PKCCount != 29 || len(*rows[0].PKCList) != 29 {
			t.Errorf("set root rows %d: %+v", c, rows)
			continue
		}
		if _, ok := m.SetRootRowFor(c, rows[0].ValidFromBlock+1000, rows[0].Root); !ok {
			t.Errorf("chain %d: the row does not cover its range", c)
		}
		if _, ok := m.SetRootRowFor(c, rows[0].ValidFromBlock+1000, "0x"+strings.Repeat("00", 32)); ok {
			t.Errorf("chain %d: a different root found a row", c)
		}
		if _, ok := m.SetRootRowFor(c, rows[0].ValidFromBlock-1, rows[0].Root); ok {
			t.Errorf("chain %d: the row covers a block before it", c)
		}
	}
	if rows := m.SetRootRows(11155111); *rows[0].KeysDigest != "0x121bef0246b0b588d62106045f145c6bd4e2f5ffd2ad5dac4faa3efa75bb5173" {
		t.Errorf("keysDigest %s", *rows[0].KeysDigest)
	}
	// txScan: the shape of this manifest (no spec-shape evidence table yet)
	ts, ok := m.TxScan(421614)
	if !ok || len(ts.CoveredTypes) == 0 || len(ts.SystemTypes) == 0 || ts.Evidence != nil {
		t.Errorf("txScan %+v", ts)
	}
	if _, ok := m.TxScan(1); ok {
		t.Error("txScan for an unknown chain")
	}
	// eip2935
	if e, ok := m.EIP2935(84532); !ok || e.Window != 8191 || !strings.EqualFold(e.Address, "0x0000F90827F1C53a10cb7A02335B175320002935") {
		t.Errorf("eip2935 %+v", e)
	}
	if e, ok := m.EIP2935(421614); !ok || e.Window != 393168 {
		t.Errorf("eip2935 arbitrum %+v", e)
	}
	// selectors and topics
	if s, ok := m.Selector("CertenAnchorV8_2/executeComprehensiveProof"); !ok || s.Selector != "0x4ca9d0c8" || !s.Pinned {
		t.Errorf("selector %+v", s)
	}
	v73 := m.AccountSelectors("V7_3")
	if len(v73) != 2 || v73[0].Selector+","+v73[1].Selector != "0x329fe012,0x606f2c8d" && v73[0].Selector+","+v73[1].Selector != "0x606f2c8d,0x329fe012" {
		t.Errorf("V7_3 selectors %+v", v73)
	}
	if v72 := m.AccountSelectors("V7_2"); len(v72) != 2 || v72[0].Pinned {
		t.Errorf("V7_2 selectors %+v", v72)
	}
	if len(m.Selectors()) != 9 {
		t.Errorf("selectors %d", len(m.Selectors()))
	}
	if tp, ok := m.Topic("LeafConsumed"); !ok || tp.Topic0 != "0xf65d46899882fe56bab13370dcd464db22e179625c161992c07d962286f7ea73" {
		t.Errorf("topic %+v", tp)
	}
	if tp, ok := m.Topic("ProofExecuted"); !ok || tp.Topic0 != "0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d" {
		t.Errorf("topic %+v", tp)
	}
	ev := m.AccountEventTopics()
	if len(ev) != 3 || ev["GovernanceOperationExecuted"].Topic0 != "0x74b66e509fa5263d4932860a2e1f6d187381ae68dee216710283b8677703ff12" ||
		ev["GovernanceBatchExecuted"].Topic0 != "0xcbcdc100c8089d25ab823b5044f746670e86a90b18c729bc7d27b7ce78733c56" {
		t.Errorf("account events %+v", ev)
	}
	// the AUTH slot set
	ids25 := []string{}
	for _, s := range m.AuthSlots() {
		ids25 = append(ids25, s.ID)
	}
	if strings.Join(ids25, ",") != "A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,V01,V02,V03,C01" {
		t.Errorf("auth slot ids %v", ids25)
	}
	if s, ok := m.AuthSlot("A20"); !ok || !s.Slot.IsNo || s.Slot.Num != 30 || s.Offset == nil || *s.Offset != 21 || s.Field != "minimumGovernanceLevel" {
		t.Errorf("A20 %+v", s)
	}
	if c01, ok := m.AuthSlot("C01"); !ok || c01.Slot.Text != "account" || c01.Slot.IsNo || c01.Offset != nil || c01.Label != nil {
		t.Errorf("C01 %+v", c01)
	}
	if _, ok := m.GenerationFor("account", "0x00"); ok {
		t.Error("generation found for a hash that is in no row")
	}
	if m.Section("no-such-table") != nil || m.Section("maskRule") == nil {
		t.Error("Section")
	}
}

// The accessors of tables that the pinned manifest does not carry yet are implemented against the spec shape and tested on a fixture.
func TestSpecShapeTablesOnAFixture(t *testing.T) {
	doc := primaryDoc(t)
	doc["generations"] = []any{
		map[string]any{"role": "account", "generation": "V7_2", "pinned": false, "kind": "catalogued", "maskedKeccak": "0x" + strings.Repeat("aa", 32), "runtimeBytes": 14000, "references": []any{map[string]any{"start": 1, "length": 32}}, "source": "evm/src/account/CertenAccountV7_2.sol"},
		map[string]any{"role": "account", "generation": "V6", "pinned": false, "kind": "observed", "maskedKeccak": "0x" + strings.Repeat("bb", 32), "runtimeBytes": 9000, "references": []any{}, "source": "on-chain"},
	}
	pol := doc["policy"].(map[string]any)
	scan := pol["txScan"].(map[string]any)["11155111"].(map[string]any)
	scan["evidence"] = map[string]any{"0x00": map[string]any{"source": "osaka/fork.py:896", "observation": map[string]any{"block": 11979068, "txHash": "0xd4", "from": "0x01", "nonceBefore": 2500, "nonceAfter": 2501}}}
	m := loadFixture(t, doc)
	if !m.HasGenerations() || len(m.Generations()) != 2 {
		t.Fatalf("generations %v", m.Generations())
	}
	g, ok := m.GenerationFor("account", "0x"+strings.Repeat("aa", 32))
	if !ok || g.Generation != "V7_2" || g.Pinned || g.Kind != GenCatalogued || g.RuntimeBytes != 14000 || len(g.References) != 1 {
		t.Fatalf("generation %+v", g)
	}
	if g, _ := m.GenerationFor("account", "0x"+strings.Repeat("BB", 32)); g.Kind != GenObserved || !Check("generation_kind", g.Kind) {
		t.Fatalf("observed generation %+v", g)
	}
	ts, _ := m.TxScan(11155111)
	ev, ok := ts.Evidence["0x00"]
	if !ok || ev.Source != "osaka/fork.py:896" || !bytes.Contains(ev.Observation, []byte(`"nonceAfter":2501`)) {
		t.Fatalf("txScan evidence %+v", ts.Evidence)
	}
	// a setRootHistory row that carries none of keysDigest / pkcCount / pkcList reports them as absent, not as empty
	rows := doc["policy"].(map[string]any)["setRootHistory"].([]any)
	row := rows[0].(map[string]any)
	delete(row, "keysDigest")
	delete(row, "pkcCount")
	delete(row, "pkcList")
	m = loadFixture(t, doc)
	r := m.SetRootRows(11155111)[0]
	if r.KeysDigest != nil || r.PKCCount != nil || r.PKCList != nil {
		t.Fatalf("absent fields decoded as present: %+v", r)
	}
	row["pkcList"] = []any{}
	m = loadFixture(t, doc)
	if r := m.SetRootRows(11155111)[0]; r.PKCList == nil || len(*r.PKCList) != 0 {
		t.Fatalf("an empty pkcList must be present and empty: %+v", r.PKCList)
	}
}

func TestLoadOverrideSource(t *testing.T) {
	raw := EmbeddedManifestBytes()
	m, err := LoadOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if m.Source != "override:"+hex.EncodeToString(sum[:]) || !Check("manifest_source", m.Source) {
		t.Fatalf("source %q", m.Source)
	}
	if _, err := LoadOverride([]byte("{}")); err == nil {
		t.Fatal("an empty document was accepted as an override")
	}
}

// The embedded manifest (MANIFEST-1.2 aef3b65) carries the generations table: 16 rows, 10 observed and 6 catalogued, none pinned, the pair
// (role, generation) repeated (CertenAccountV7 twice, several `unidentified`) and the pair (role, maskedKeccak) unique [r3.2:E-e2].
func TestEmbeddedGenerationsTable(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasGenerations() || len(m.Generations()) != 16 {
		t.Fatalf("generations: %d rows", len(m.Generations()))
	}
	kinds := map[string]int{}
	byRoleGen := map[string]int{}
	seen := map[string]bool{}
	for _, g := range m.Generations() {
		kinds[g.Kind]++
		byRoleGen[g.Role+"/"+g.Generation]++
		k := g.Role + "," + strings.ToLower(g.MaskedKeccak)
		if seen[k] {
			t.Errorf("(role, maskedKeccak) %s repeats", k)
		}
		seen[k] = true
		if g.Pinned || !Check("generation_kind", g.Kind) || !Check("role", g.Role) && g.Role != "factory" || len(g.MaskedKeccak) != 66 {
			t.Errorf("generation row %+v", g)
		}
		if back, ok := m.GenerationFor(g.Role, "0x"+strings.ToUpper(g.MaskedKeccak[2:])); ok == (g.MaskedKeccak == "") || (ok && back.Generation != g.Generation) {
			t.Errorf("lookup of %s,%s: %+v %v", g.Role, g.MaskedKeccak, back, ok)
		}
		if _, ok := m.GenerationFor("no-such-role", g.MaskedKeccak); ok {
			t.Errorf("%s found under an unknown role", g.MaskedKeccak)
		}
	}
	if kinds[GenObserved] != 10 || kinds[GenCatalogued] != 6 {
		t.Errorf("kinds %v", kinds)
	}
	if byRoleGen["account/CertenAccountV7"] != 2 || byRoleGen["account/unidentified"] != 2 || byRoleGen["factory/unidentified"] != 5 {
		t.Errorf("repeated (role, generation) pairs: %v", byRoleGen)
	}
}
