package contracts

import (
	"encoding/hex"
	"os"
	"testing"
)

// TestValidatorSetRoot_MatchesDeployedAnchorV7 pins the Go-computed validator-set root
// against what CertenAnchorV7._recomputeValidatorSetRoot() produces on chain for the same
// registry.
//
// # WHY THIS TEST EXISTS
//
// The set root is folded into the BLS pre-exec message. If the validator computes a
// different root than the anchor stores, every signature it produces verifies against a
// different message and executeComprehensiveProof reverts — with no diagnostic pointing at
// the cause. That failure was observed for real: the seven addresses in evm/.env are not the
// seven registered on the live V6.1 anchor, whose root is 0xa85a6911..., while this set
// derives 0x9fcf4ecc....
//
// The expected value below is what the deployed CertenAnchorV7 reports after registering the
// evm/.env set at power 100 each with a 2/3 threshold. Any drift in either the Go encoding
// or the operator config fails here rather than on chain.
func TestValidatorSetRoot_MatchesDeployedAnchorV7(t *testing.T) {
	const (
		addrs = "0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8," +
			"0x518273099F5c4b87eEA65141931B78012dfE5c7d," +
			"0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6," +
			"0x6Ff54041Afef809e93ce6B570545069d2764783f," +
			"0x9eaA84E3D31479eCC9130187DA9f962625e8C271," +
			"0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf," +
			"0x0D786D587aBe92f1031506fF3eF88c79a93A8962"
		powers = "100,100,100,100,100,100,100"

		// Reported by CertenAnchorV7.currentValidatorSetRoot() after bring-up.
		wantRoot = "9fcf4eccb59042be79ad46677d98eef3dde7b0646847d4cee35563c0302afc7c"
	)

	t.Setenv(envValidatorSetAddrs, addrs)
	t.Setenv(envValidatorSetPowers, powers)
	t.Setenv(envValidatorSetThresholdNum, "2")
	t.Setenv(envValidatorSetThresholdDen, "3")

	got, err := computeV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatalf("computing validator set root: %v", err)
	}

	if hex.EncodeToString(got[:]) != wantRoot {
		t.Fatalf(
			"validator-set root mismatch — the validator would sign against a message the "+
				"anchor does not reconstruct, and every attestation would revert\n got: %s\nwant: %s",
			hex.EncodeToString(got[:]), wantRoot)
	}
}

// The root must depend on the set: dropping a member has to change it, or an attacker could
// present a smaller quorum under a signature made for a larger one.
func TestValidatorSetRoot_DependsOnMembership(t *testing.T) {
	base := "0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8,0x518273099F5c4b87eEA65141931B78012dfE5c7d"

	t.Setenv(envValidatorSetAddrs, base)
	t.Setenv(envValidatorSetPowers, "100,100")
	t.Setenv(envValidatorSetThresholdNum, "2")
	t.Setenv(envValidatorSetThresholdDen, "3")
	two, err := computeV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(envValidatorSetAddrs, base+",0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6")
	os.Setenv(envValidatorSetPowers, "100,100,100")
	three, err := computeV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatal(err)
	}

	if two == three {
		t.Fatal("adding a validator must change the set root")
	}
}

// Threshold is inside the root (CRYPTO-006): changing it must invalidate old signatures.
func TestValidatorSetRoot_DependsOnThreshold(t *testing.T) {
	const addrs = "0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8,0x518273099F5c4b87eEA65141931B78012dfE5c7d"

	t.Setenv(envValidatorSetAddrs, addrs)
	t.Setenv(envValidatorSetPowers, "100,100")
	t.Setenv(envValidatorSetThresholdNum, "2")
	t.Setenv(envValidatorSetThresholdDen, "3")
	twoThirds, err := computeV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(envValidatorSetThresholdNum, "1")
	os.Setenv(envValidatorSetThresholdDen, "2")
	half, err := computeV6_1ValidatorSetRoot()
	if err != nil {
		t.Fatal(err)
	}

	if twoThirds == half {
		t.Fatal("changing the threshold must change the set root")
	}
}
