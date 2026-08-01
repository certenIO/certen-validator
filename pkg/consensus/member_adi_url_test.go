package consensus

import (
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// The bug this file exists for: EnqueueForBatch was handed CertenIntent.AccountURL, which is
// the DATA account ("acc://org.acme/data"), while CertenAccountV7 computes its leaf from the
// org ADI it was deployed with ("acc://org.acme"). keccak256 of those two strings differ, so
// the member's leaf was absent from the root the account verifies against. The batch anchor
// and its BLS attestation were paid for on chain, then settlement reverted and the intent was
// stranded with nothing recording why.
func TestMemberADIURL_PrefersOrganizationADI(t *testing.T) {
	ci := &CertenIntent{
		AccountURL:      "acc://certen-kermit-12.acme/data",
		OrganizationADI: "acc://certen-kermit-12.acme",
	}
	got, err := memberADIURL(ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "acc://certen-kermit-12.acme" {
		t.Fatalf("got %q, want the org ADI without /data", got)
	}
}

// The regression proper: the data account must never be what gets hashed.
func TestMemberADIURL_NeverReturnsTheDataAccount(t *testing.T) {
	ci := &CertenIntent{AccountURL: "acc://certen-kermit-12.acme/data"} // OrganizationADI unset
	got, err := memberADIURL(ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "acc://certen-kermit-12.acme" {
		t.Fatalf("got %q — the /data suffix must be trimmed", got)
	}
}

// This is the property that actually matters on chain: the hash the validator folds into the
// leaf must equal the hash the account contract computes from its immutable adiURL. Asserting
// on the keccak values rather than the strings is what makes this a real check.
func TestMemberADIURL_HashMatchesTheDeployedAccount(t *testing.T) {
	// Exactly the string CertenAccountFactoryV9 was called with for the live Sepolia account
	// 0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B.
	const deployedADI = "acc://certen-kermit-12.acme"
	accountHash := ethcrypto.Keccak256Hash([]byte(deployedADI))

	ci := &CertenIntent{
		AccountURL:      "acc://certen-kermit-12.acme/data",
		OrganizationADI: "acc://certen-kermit-12.acme",
	}
	resolved, err := memberADIURL(ci)
	if err != nil {
		t.Fatal(err)
	}
	if ethcrypto.Keccak256Hash([]byte(resolved)) != accountHash {
		t.Fatal("validator-side adiURLHash does not match the account's — the leaf would be unspendable")
	}

	// And prove the old behaviour genuinely was broken, so this test cannot pass vacuously.
	if ethcrypto.Keccak256Hash([]byte(ci.AccountURL)) == accountHash {
		t.Fatal("AccountURL hashes the same as the ADI; this test proves nothing")
	}
}

// Every rejection path. A wrong leaf cannot settle at all, whereas refusing to batch merely
// falls back to the per-intent path — so refusing is always the better failure.
func TestMemberADIURL_Rejections(t *testing.T) {
	cases := []struct {
		name string
		ci   *CertenIntent
	}{
		{"nil intent", nil},
		{"both empty", &CertenIntent{}},
		{"not an acc:// url", &CertenIntent{OrganizationADI: "https://example.com"}},
		{"org adi still a data account", &CertenIntent{OrganizationADI: "acc://org.acme/data"}},
		{"trailing slash", &CertenIntent{OrganizationADI: "acc://org.acme/"}},
		{"whitespace only", &CertenIntent{OrganizationADI: "   "}},
		{"accountUrl is bare /data", &CertenIntent{AccountURL: "/data"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := memberADIURL(c.ci); err == nil {
				t.Fatalf("must be refused, got %q", got)
			}
		})
	}
}

// Whitespace around an otherwise valid ADI must be trimmed, not rejected and not hashed in.
func TestMemberADIURL_TrimsWhitespace(t *testing.T) {
	ci := &CertenIntent{OrganizationADI: "  acc://org.acme  "}
	got, err := memberADIURL(ci)
	if err != nil {
		t.Fatal(err)
	}
	if got != "acc://org.acme" {
		t.Fatalf("got %q", got)
	}
}
