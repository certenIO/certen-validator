package proof

import (
	"encoding/json"
	"os"
	"testing"
)

type testVector struct {
	Description         string          `json:"description"`
	Blob0               json.RawMessage `json:"blob0"`
	Blob1               json.RawMessage `json:"blob1"`
	Blob2               json.RawMessage `json:"blob2"`
	Blob3               json.RawMessage `json:"blob3"`
	ExpectedOperationID string          `json:"expected_operation_id"`
}

func TestComputeCanonical4BlobHash_GoldenVectors(t *testing.T) {
	// Load golden test vectors shared with TypeScript
	vectorPath := "../../../certen-contracts/test/vectors/operation_id_test_vectors.json"
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("Golden test vectors not found at %s: %v", vectorPath, err)
	}

	var vectors []testVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			_, hexHash, err := ComputeCanonical4BlobHash(v.Blob0, v.Blob1, v.Blob2, v.Blob3)
			if err != nil {
				t.Fatalf("ComputeCanonical4BlobHash error: %v", err)
			}
			got := "0x" + hexHash
			if got != v.ExpectedOperationID {
				t.Errorf("OperationID mismatch\n  got:  %s\n  want: %s", got, v.ExpectedOperationID)
			}
		})
	}
}

func TestComputeCanonical4BlobHash_UnsortedKeysMatchSorted(t *testing.T) {
	// Same semantic data, different key order — MUST produce same hash
	sorted := []byte(`{"kind":"CERTEN_INTENT","version":"1.0"}`)
	unsorted := []byte(`{"version":"1.0","kind":"CERTEN_INTENT"}`)

	blob1 := []byte(`{"legs":[]}`)
	blob2 := []byte(`{"auth":{}}`)
	blob3 := []byte(`{"nonce":"x"}`)

	_, hashSorted, _ := ComputeCanonical4BlobHash(sorted, blob1, blob2, blob3)
	_, hashUnsorted, _ := ComputeCanonical4BlobHash(unsorted, blob1, blob2, blob3)

	if hashSorted != hashUnsorted {
		t.Errorf("Key ordering changed hash!\n  sorted:   %s\n  unsorted: %s", hashSorted, hashUnsorted)
	}
}

func TestComputeCanonical4BlobHash_LengthPrefixPreventsAmbiguity(t *testing.T) {
	// Two blob tuples that would collide WITHOUT length prefixes:
	// Tuple A: blob0={"a":"bc"}, blob1={"d":"e"}
	// Tuple B: blob0={"a":"b"},  blob1={"cd":"e"} (different split point)
	// With length prefixes these MUST differ.
	_, hashA, _ := ComputeCanonical4BlobHash(
		[]byte(`{"a":"bc"}`),
		[]byte(`{"d":"e"}`),
		[]byte(`{}`),
		[]byte(`{}`),
	)
	_, hashB, _ := ComputeCanonical4BlobHash(
		[]byte(`{"a":"b"}`),
		[]byte(`{"cd":"e"}`),
		[]byte(`{}`),
		[]byte(`{}`),
	)
	if hashA == hashB {
		t.Error("Length prefix failed to differentiate ambiguous blob boundary")
	}
}
