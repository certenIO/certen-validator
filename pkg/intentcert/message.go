package intentcert

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// IntentDomain is the per-intent message's domain tag, as a left-aligned bytes32. No anchor, batch, outcome or
// registry message uses it.
const IntentDomain = "certen:bls:v2:intent"

// MessageInputs are everything the per-intent message binds (RB5 D3). Each is required and non-zero.
type MessageInputs struct {
	// CertenChainID is the CERTEN (CometBFT) chain the ValidatorBlock is committed on. Bound so a signature on
	// one CERTEN chain is nothing on another that shares its validator set.
	CertenChainID string
	OperationID   [32]byte
	// GovRootV2 is govRoot v2 over the proof's L1-L4 and canonical G0-G2 (GovRootV2).
	GovRootV2 [32]byte
	// AccumulateSetRoot is the Directory-leg validator set root the proof's L4 was verified against, under
	// Incarnation (pkg/accumulateset).
	AccumulateSetRoot [32]byte
	Incarnation       [32]byte
	// GovernanceCommitment is keccak("certen:govdecision:v1" ‖ governance decision record) (proof.GovernanceCommitment).
	GovernanceCommitment [32]byte
	// CertenSetRoot is the anchor's currentValidatorSetRoot for the registry in force.
	CertenSetRoot [32]byte
}

// Message is
//
//	keccak256(abi.encode(
//	    bytes32("certen:bls:v2:intent"),
//	    keccak256(bytes(certenChainID)),
//	    operationID, govRootV2, accumulateSetRoot, incarnation, governanceCommitment, certenSetRoot))
//
// abi.encode of eight static bytes32 is their concatenation.
func Message(in MessageInputs) ([32]byte, error) {
	if in.CertenChainID == "" {
		return [32]byte{}, fmt.Errorf("intent message: no CERTEN chain id")
	}
	for _, f := range []struct {
		name string
		v    [32]byte
	}{{"operation id", in.OperationID}, {"govRoot v2", in.GovRootV2}, {"Accumulate set root", in.AccumulateSetRoot},
		{"incarnation", in.Incarnation}, {"governance commitment", in.GovernanceCommitment}, {"CERTEN set root", in.CertenSetRoot}} {
		if f.v == ([32]byte{}) {
			return [32]byte{}, fmt.Errorf("intent message: the %s is zero", f.name)
		}
	}
	var domain [32]byte
	copy(domain[:], IntentDomain)
	chain := crypto.Keccak256Hash([]byte(in.CertenChainID))
	buf := make([]byte, 0, 8*32)
	for _, w := range [][32]byte{domain, chain, in.OperationID, in.GovRootV2, in.AccumulateSetRoot, in.Incarnation,
		in.GovernanceCommitment, in.CertenSetRoot} {
		buf = append(buf, w[:]...)
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out, nil
}

// IntentDomainV3 is the domain of the per-intent message from proof v3's activation on (docs/proof/GOVROOT_V3.md).
// A distinct domain, so a v2 message and a v3 message can never be taken for each other, whatever their fields hold.
const IntentDomainV3 = "certen:bls:v3:intent"

// MessageInputsV3 are what the v3 per-intent message binds: as v2, with govRoot v3 and the Accumulate set root the
// validator-set spine derived (proven equal to the network account at a certified block), not the one a proof's L4
// leg carries.
type MessageInputsV3 struct {
	CertenChainID        string
	OperationID          [32]byte
	GovRootV3            [32]byte
	AccumulateSetRoot    [32]byte
	Incarnation          [32]byte
	GovernanceCommitment [32]byte
	CertenSetRoot        [32]byte
}

// MessageV3 is Message's layout under IntentDomainV3:
//
//	keccak256(abi.encode(bytes32("certen:bls:v3:intent"), keccak256(bytes(certenChainID)),
//	    operationID, govRootV3, accumulateSetRoot, incarnation, governanceCommitment, certenSetRoot))
func MessageV3(in MessageInputsV3) ([32]byte, error) {
	if in.CertenChainID == "" {
		return [32]byte{}, fmt.Errorf("intent message v3: no CERTEN chain id")
	}
	for _, f := range []struct {
		name string
		v    [32]byte
	}{{"operation id", in.OperationID}, {"govRoot v3", in.GovRootV3}, {"Accumulate set root", in.AccumulateSetRoot},
		{"incarnation", in.Incarnation}, {"governance commitment", in.GovernanceCommitment}, {"CERTEN set root", in.CertenSetRoot}} {
		if f.v == ([32]byte{}) {
			return [32]byte{}, fmt.Errorf("intent message v3: the %s is zero", f.name)
		}
	}
	var domain [32]byte
	copy(domain[:], IntentDomainV3)
	chain := crypto.Keccak256Hash([]byte(in.CertenChainID))
	buf := make([]byte, 0, 8*32)
	for _, w := range [][32]byte{domain, chain, in.OperationID, in.GovRootV3, in.AccumulateSetRoot, in.Incarnation,
		in.GovernanceCommitment, in.CertenSetRoot} {
		buf = append(buf, w[:]...)
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out, nil
}
