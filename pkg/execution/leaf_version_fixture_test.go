package execution

import "testing"

// withAccountLeafVersions puts the process on spec (CERTEN_ACCOUNT_LEAF_VERSIONS syntax, over the defaults) for the test
// (RB5-F57), and restores the versions it was on afterwards.
func withAccountLeafVersions(t *testing.T, spec string) {
	t.Helper()
	v, err := ParseAccountLeafVersions(spec)
	if err != nil {
		t.Fatal(err)
	}
	prev := accountLeafVersions.Load()
	SetAccountLeafVersions(v)
	t.Cleanup(func() { accountLeafVersions.Store(prev) })
}
