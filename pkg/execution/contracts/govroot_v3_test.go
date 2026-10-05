package contracts

import (
	"encoding/hex"
	"strings"
	"testing"
)

func fill32(b byte) (o [32]byte) {
	for i := range o {
		o[i] = b
	}
	return
}

// govRoot v3 is its own domain over the same ten slots: never a v2 (or v1) value, and the pinned vector, recomputed
// independently in Python (pycryptodome keccak) on 2026-10-05, fixes the layout.
func TestGovRootV3_DomainAndVector(t *testing.T) {
	in := fullGovInputs()
	v3, err := ComputeAccumulateGovRootV3(in)
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := ComputeAccumulateGovRootV2(in)
	if v3 == v2 || v3 == ComputeAccumulateGovRoot(in) {
		t.Fatal("govRoot v3 equals an earlier version over the same slots")
	}
	const want = "5bad3659b119abbf9207480ace6151817eeac50836d6ea1a7f59d5a8fe124fde"
	if got := hex.EncodeToString(v3[:]); got != want {
		t.Fatalf("govRoot v3 vector: got %s want %s", got, want)
	}
}

// Each slot's tag and payload layout (fixed-width fields, uint64 big-endian), pinned against the same Python
// recomputation: a reordered field, a different width or a reused tag changes these.
func TestGovRootV3_SlotVectors(t *testing.T) {
	g1 := GovRootV3G1(fill32(14), fill32(15))
	for name, c := range map[string]struct {
		got  [32]byte
		want string
	}{
		"L1": {GovRootV3L1(fill32(1), fill32(2), 3), "eabce42df409fcf82d56edf56344422f75c19bbd8613efdf2a98083f7cef317e"},
		"L2": {GovRootV3L2(fill32(4), 5), "41831ea7f130a4898a7e2b4a165a739fc326b70f9fb36557822482bf4f506ed1"},
		"L3": {GovRootV3L3(fill32(6), 7), "30cb3147c36f01830bc02be9c536a00dd7a696f6506bd331025233042481370b"},
		"L4": {GovRootV3L4(fill32(8), fill32(9), 10), "cb553fcec3c6d5e2beb6f1365b6be10be979b57b3215721246ffcb8db43cd882"},
		"G0": {GovRootV3G0(fill32(11), fill32(12), fill32(13)), "d6ddecf4f6b7c655162687b8cef6298a1d4e25ff40171afda5979a7760ed2e75"},
		"G1": {g1, "c8b774e424148496b33dab887456579f1cdd6faf42f82a9b46216ca4f16b614d"},
		"G2": {GovRootV3G2(fill32(16), g1), "97fd49d155f3a2e6b36fdc17ec57639a564344ebd20bb801781527bfe805068a"},
	} {
		if got := hex.EncodeToString(c.got[:]); got != c.want {
			t.Errorf("%s slot: got %s want %s", name, got, c.want)
		}
	}
	// The v3 G slots are not the v2 ones: the same canonical hash under v2 and v3 tags differs.
	if GovRootV3SlotHash("certen:g0:v2", nil) == GovRootV3SlotHash(GovRootV3TagG0, nil) {
		t.Fatal("the tag is not bound")
	}
}

// Every slot is required, and the refusal names the same first missing slot every time.
func TestGovRootV3_EverySlotRequiredDeterministically(t *testing.T) {
	names := []string{"L1", "L2", "L3", "L4", "G0", "G1", "G2", "key page", "key book", "operation id"}
	for i, name := range names {
		in := fullGovInputs()
		*[]*[32]byte{&in.L1AccountHash, &in.L2BPTRoot, &in.L3BlockHash, &in.L4ConsensusProofH, &in.G0CanonicalHash,
			&in.G1CanonicalHash, &in.G2CanonicalHash, &in.KeypageURLHash, &in.KeybookURLHash, &in.OperationID}[i] = [32]byte{}
		for run := 0; run < 20; run++ {
			_, err := ComputeAccumulateGovRootV3(in)
			if err == nil || !strings.Contains(err.Error(), "govRoot v3: the "+name+" slot") {
				t.Fatalf("missing %s: %v", name, err)
			}
		}
	}
	for run := 0; run < 50; run++ {
		if _, err := ComputeAccumulateGovRootV3(AccumulateGovRootInputs{}); err == nil || !strings.Contains(err.Error(), "the L1 slot") {
			t.Fatalf("all missing: %v", err)
		}
	}
}
