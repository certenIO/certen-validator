package consensus

import (
	"context"
	"errors"
	"testing"
)

type recordingKeyPageResolver struct {
	principal, txHash, book, declared string
	page                              string
	err                               error
}

func (r *recordingKeyPageResolver) ResolveSigningKeyPage(
	_ context.Context, principal, txHash, keyBook, declaredPage string,
) (string, error) {
	r.principal, r.txHash, r.book, r.declared = principal, txHash, keyBook, declaredPage
	return r.page, r.err
}

func orchidMachineSignedIntent() (*CertenIntent, *GovernanceData) {
	ci := &CertenIntent{
		IntentID:        "5a2ebba0-a722-4db6-bc6b-0f9aff4036a4",
		AccountURL:      "acc://orchid-logistics-tcl1.acme/data",
		TransactionHash: "aad58e15bd8395d6f3d7b8d5c17cc69b6a4a6190299afe0f84a5d59a696a0600",
	}
	gov := &GovernanceData{}
	gov.Authorization.RequiredKeyBook = "acc://orchid-logistics-tcl1.acme/book"
	// The intent builder's template for multi-leg intents: not a page at all.
	gov.Authorization.RequiredKeyPage = "acc://orchid-logistics-tcl1.acme/book/page"
	return ci, gov
}

// The page G1 is built against is whatever the chain says signed - page 2 for a machine-signed
// payment - not page 1, which is what the string-rule repair of "/book/page" produced.
func TestSigningKeyPageIsTheChainAnswerNotPageOne(t *testing.T) {
	ci, gov := orchidMachineSignedIntent()
	r := &recordingKeyPageResolver{page: "acc://orchid-logistics-tcl1.acme/book/2"}
	bv := &BFTValidator{}
	bv.SetKeyPageResolver(r)

	page, err := bv.resolveSigningKeyPage(context.Background(), ci, gov)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if page != "acc://orchid-logistics-tcl1.acme/book/2" {
		t.Fatalf("G1 would be built against %s; want the signing page 2", page)
	}
	if r.principal != ci.AccountURL || r.txHash != ci.TransactionHash ||
		r.book != gov.Authorization.RequiredKeyBook || r.declared != gov.Authorization.RequiredKeyPage {
		t.Fatalf("resolver was not asked about this transaction and book: %+v", r)
	}
}

// No resolver, no page: a guessed page is exactly what this replaces.
func TestSigningKeyPageWithoutResolverFails(t *testing.T) {
	ci, gov := orchidMachineSignedIntent()
	bv := &BFTValidator{}
	if page, err := bv.resolveSigningKeyPage(context.Background(), ci, gov); err == nil {
		t.Fatalf("named %q with no way to establish it; must fail", page)
	}
}

// An unresolvable page is an error returned to the caller, which fails the governance proof.
func TestSigningKeyPageResolutionFailureIsReturned(t *testing.T) {
	ci, gov := orchidMachineSignedIntent()
	bv := &BFTValidator{}
	bv.SetKeyPageResolver(&recordingKeyPageResolver{err: errors.New("no page of the book signed")})
	if page, err := bv.resolveSigningKeyPage(context.Background(), ci, gov); err == nil {
		t.Fatalf("named %q although no page of the book signed; must fail", page)
	}
}
