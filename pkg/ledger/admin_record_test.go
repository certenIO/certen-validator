package ledger

import (
	"bytes"
	"encoding/json"
	"testing"
)

// v11CommittedPolicy is an entitlement policy exactly as the rules v11 binary serialised it (captured from that
// binary's types at origin/main 96522ff): certen-testnet's genesis seal, its re-seal at height 2788, and a scheduled
// update. Rules v12 extends AdminReseal; it must read this back to the same record and write it out to the same bytes,
// or a v12 node would hold - and persist - committed state a v11 node does not.
const v11CommittedPolicy = `{"mode":"enforce","keys":{"entitlement-v1":"aa11"},"sealedAtHeight":0,"version":3,` +
	`"adminKeys":{"ops-1":"2074b00450f5dbfd9d084423b5232e3732ef5db108f8b6fb5d4c96b73d5effd6",` +
	`"ops-2":"4572d81eeb0b2f72347f987a1a2ba75f4d5b475da14bbda9e0b585d1d50bc2f8"},"adminThreshold":2,` +
	`"adminReseals":[{"height":2788,"id":"4455af81676ff371d0f5871861f53e3ebd160cc6138373d8131629c3d3de2612",` +
	`"keys":{"admin-a":"92d403978891216dac310c053c18d048d783d0311e8558e68b26f7fc101e004a",` +
	`"admin-b":"df2b05997cf690ef04279cc71be4f51e1ea1328d06eebf33902763c8c8586696",` +
	`"admin-c":"dc7c9f6202c3285abe476b4160026ae31ef988354818d74adc61d41db5f5f029"},"threshold":2}],` +
	`"schedule":[{"mode":"observe","keys":{"entitlement-v1":"aa11"},"activationUnix":1790000000,"version":2,"proposedAtHeight":3}]}`

// Pre-v12 committed state round-trips through the v12 types to identical bytes, through the store as well as through
// JSON, and the re-seal record reads back with no kind and no sequence.
func TestPreV12AdminRecordsRoundTripToIdenticalBytes(t *testing.T) {
	var st EntitlementPolicyState
	if err := json.Unmarshal([]byte(v11CommittedPolicy), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.AdminReseals) != 1 || st.AdminReseals[0].Kind != "" || st.AdminReseals[0].Sequence != 0 {
		t.Fatalf("the v11 re-seal record reads back as %+v", st.AdminReseals)
	}
	b, err := json.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte(v11CommittedPolicy)) {
		t.Fatalf("pre-v12 state does not round-trip:\n got  %s\n want %s", b, v11CommittedPolicy)
	}

	kv := mapKV{}
	kv[string(keyEntitlementPolicy)] = []byte(v11CommittedPolicy)
	s := NewLedgerStore(kv)
	loaded, err := s.LoadEntitlementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEntitlementPolicy(loaded); err != nil {
		t.Fatal(err)
	}
	if got := kv[string(keyEntitlementPolicy)]; !bytes.Equal(got, []byte(v11CommittedPolicy)) {
		t.Fatalf("the store rewrote pre-v12 state:\n got  %s\n want %s", got, v11CommittedPolicy)
	}

	// A v12 record carries its kind and sequence; the v11 one beside it is unchanged.
	st.AdminReseals = append(st.AdminReseals, AdminReseal{Height: 3000, ID: "admin-rotation:00", Keys: map[string]string{"k": "00"},
		Threshold: 1, Kind: "certen.admin.rotate/v1", Sequence: 2})
	b, err = json.Marshal(&st)
	if err != nil {
		t.Fatal(err)
	}
	want := `"threshold":2},{"height":3000,"id":"admin-rotation:00","keys":{"k":"00"},"threshold":1,` +
		`"kind":"certen.admin.rotate/v1","sequence":2}]`
	if !bytes.Contains(b, []byte(want)) {
		t.Fatalf("a v12 record serialises as %s", b)
	}
}
