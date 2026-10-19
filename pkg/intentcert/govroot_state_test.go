package intentcert

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F5 package F5-3 (V-E A3): k > 0 is reachable. The real verifier of evidence 2.1 reports a set that changed in the minor run as
// verified once every write to the network and the globals accounts is accounted, and govRoot v4 commits it; the real verifier of
// evidence 2.0 still reports a changed set as asserted, and govRoot v3 still refuses it.

func verifyPortableFile(t *testing.T, path string, gz bool) *proofv2.Report {
	t.Helper()
	var raw []byte
	var err error
	if gz {
		raw = gunzipFile(t, path)
	} else if raw, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	p := new(proofv2.Portable)
	if err := json.Unmarshal(raw, p); err != nil {
		t.Fatal(err)
	}
	rep, err := proofv2.VerifyPortable(p)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return rep
}

func TestGovRootV4AcceptsAccountedSetChange(t *testing.T) {
	rep := verifyPortableFile(t, "../proof/v2/testdata/certify1/accounted-set-change-verified.json", false)
	if rep.SetVerdict != proof.VerdictVerified || rep.Validators != 4 {
		t.Fatalf("the accounted set change is %s with %d validators, want verified with 4", rep.SetVerdict, rep.Validators)
	}
	// The cross-partition fixture's inputs with the set check this verifier reached: the root is committed, not refused.
	in := v4Inputs(newX21())
	in.Report.SetVerdict, in.Report.Validators, in.Report.Threshold = rep.SetVerdict, rep.Validators, rep.Threshold
	in.Report.AccumulateSetRoot, in.Report.Incarnation = rep.AccumulateSetRoot, rep.Incarnation
	root, _, err := GovRootV4(in)
	if err != nil || root == [32]byte{} {
		t.Fatalf("govRoot v4 over a verified, accounted set change: %x, %v", root, err)
	}
}

func TestGovRootV3StillRefusesAssertedSet(t *testing.T) {
	// The real 2.0 verifier on the repository's own network-update vector (one network update in major 2): the set changed, the history is
	// not accounted in 2.0, so the verdict is asserted.
	rep := verifyPortableFile(t, "../proof/v2/testdata/conformance/network-update.json.gz", true)
	if rep.SetVerdict != proof.VerdictValidatorSetAsserted {
		t.Fatalf("the 2.0 verifier reports a changed set as %s, want validator_set_asserted", rep.SetVerdict)
	}
	repK, evK := verifiedKermit(t)
	in := goldenV3Inputs(repK, evK)
	r := *in.Report
	r.SetVerdict = rep.SetVerdict
	in.Report = &r
	if _, _, err := GovRootV3(in); err == nil || !strings.Contains(err.Error(), "validator_set_asserted, not verified") {
		t.Fatalf("govRoot v3 over an asserted set: %v", err)
	}
}
