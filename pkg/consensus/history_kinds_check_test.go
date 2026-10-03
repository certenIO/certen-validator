package consensus

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// The claim behind continuing older state - "no committed history contains a transaction of the new kind decided the
// old way" - is checked over the WHOLE chain, not only the blocks the committed-operation index has not yet read: a
// block an older binary committed and indexed can hold one. Before rules v12 a node whose index already covered the
// chain checked nothing at all (every case below marked "false" started). A code the kind's version never returns is
// history it does not reproduce too.
func TestCommittedRegistryAndReSealCodesAreChecked(t *testing.T) {
	f := newRegistryFixture(t)
	registry := rotJSON(t, f.registry(1, "ops-1", "ops-2"))
	reseal := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":"certen-testnet"}`, AdminResealKind))
	for name, c := range map[string]struct {
		tx   []byte
		code uint32
		ok   bool
	}{
		"a registry refused by v10":                         {registry, codeBLSRegistryRefused, true},
		"a registry v9 judged as a ValidatorBlock (code 2)": {registry, 2, false},
		"a registry decided with a ValidatorBlock's code 1": {registry, 1, false},
		"a re-seal refused by v11":                          {reseal, codeAdminResealRefused, true},
		"a re-seal v10 judged as a ValidatorBlock (code 2)": {reseal, 2, false},
		"a re-seal decided with a ValidatorBlock's code 4":  {reseal, 4, false},
		"a ValidatorBlock-shaped non-kind tx with any code": {[]byte(`{"validator_id":"v"}`), 2, true},
	} {
		app := historyApp(t, 1)
		// The older binary that committed block 1 indexed it.
		if err := app.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
			t.Fatal(err)
		}
		err := app.IndexCommittedHistory(&fakeHistory{base: 1, blocks: map[int64][][]byte{1: {c.tx}},
			times: map[int64]time.Time{1: beforeV9}, codes: map[int64][]uint32{1: {c.code}}})
		if c.ok != (err == nil) || (!c.ok && !errors.Is(err, ErrCommittedHistoryUnderCurrentRules)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
