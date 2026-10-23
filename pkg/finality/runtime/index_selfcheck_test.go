// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

type fakeSelfChecker struct {
	res baseposted.SelfCheckResult
	err error
}

func (f fakeSelfChecker) SelfCheckReport(context.Context, int) (baseposted.SelfCheckResult, error) {
	return f.res, f.err
}

// The on-demand self-check says one named thing and exits with a code that tells an operator which: ok, a mismatch, off, incomplete, failed.
func TestRTIndexSelfCheckOnDemandNamesItsResult(t *testing.T) {
	on := Config{BaseIndex: true}
	for _, c := range []struct {
		name string
		cfg  Config
		ix   IndexSelfChecker
		code int
		want string
	}{
		{"ok", on, fakeSelfChecker{res: baseposted.SelfCheckResult{Generation: 1, Entries: 4, Digests: 4}}, IndexSelfCheckOK, "finality-index-selfcheck: ok generation=1"},
		{"a mismatch counted", on, fakeSelfChecker{res: baseposted.SelfCheckResult{Generation: 1, Entries: 4, Mismatches: 1}}, IndexSelfCheckMismatch, "MISMATCH"},
		{"a mismatch named", on, fakeSelfChecker{res: baseposted.SelfCheckResult{Generation: 1}, err: finality.IndexInconsistent(84532, "bi", finality.IndexSelfCheckMismatch, "item", "idx/g1/bi/c/1/2/ab")}, IndexSelfCheckMismatch, "self_check_mismatch"},
		{"checks skipped", on, fakeSelfChecker{res: baseposted.SelfCheckResult{Generation: 1, Entries: 1, Skipped: 2}}, IndexSelfCheckIncomplete, "INCOMPLETE generation=1 around_l1_block=0 entries=1 digests=0 skipped=2"},
		{"the store failed", on, fakeSelfChecker{err: errors.New("store down")}, IndexSelfCheckFailed, "FAILED"},
		{"index off", Config{}, fakeSelfChecker{}, IndexSelfCheckNotRunning, "switched off"},
		{"no indexer", on, nil, IndexSelfCheckNotRunning, "switched off"},
		{"a bad setting", Config{IndexDisabled: finality.IndexDisabledState(84532, EnvBaseIndex, finality.IndexSettingSwitchInvalid, "")}, fakeSelfChecker{}, IndexSelfCheckNotRunning, "finality_index_disabled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			code := RunIndexSelfCheck(context.Background(), &out, c.cfg, c.ix, 16)
			if code != c.code || !strings.Contains(out.String(), c.want) {
				t.Fatalf("code %d (want %d), output %q (want it to contain %q)", code, c.code, out.String(), c.want)
			}
		})
	}
}
