package consensus

import (
	"os"
	"path/filepath"
	"testing"
)

// readRepoFile reads a source file from this package's directory. Tests run with the package
// directory as their working directory, so the name alone is enough.
func readRepoFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(".", name))
}

func readRepoFileMust(t *testing.T, name string) string {
	t.Helper()
	b, err := readRepoFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
