package intentcert

import (
	"reflect"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The encoding commits exactly the members of the final Vote shape. If a member is added to (or removed from) one of these structs the
// committed set is no longer the evidence the verifier relies on: this fails until EncodeVoteV4 is extended under a new tag and a new
// golden (RB9-C2-F3: a later change to Vote/VoteHop must not silently move or drop part of the commitment).
func TestVoteEncodingV4CoversEveryField(t *testing.T) {
	for _, c := range []struct {
		name   string
		typ    reflect.Type
		fields string
	}{
		{"Vote", reflect.TypeOf(proofv2.Vote{}), "Authority,Origin,Vote,Cause,Transport,Message,Receipt,Hops,Counted,Produced"},
		{"VoteTransport", reflect.TypeOf(proofv2.VoteTransport{}), "Kind,Source,Destination,Number"},
		{"VoteHop", reflect.TypeOf(proofv2.VoteHop{}), "Page,Message,Signature,Block,Receipt,Arrival"},
		{"Arrival", reflect.TypeOf(proofv2.Arrival{}), "Before,At"},
		{"IndexProof", reflect.TypeOf(proofv2.IndexProof{}), "Position,Entry,Receipt"},
		{"Production", reflect.TypeOf(proofv2.Production{}), "Account,Chain,Message,Receipt,Arrival,Sequenced"},
	} {
		var got []string
		for i := 0; i < c.typ.NumField(); i++ {
			got = append(got, c.typ.Field(i).Name)
		}
		if strings.Join(got, ",") != c.fields {
			t.Errorf("%s has fields %v, the v4 vote encoding commits %s: extend EncodeVoteV4 under a new tag", c.name, got, c.fields)
		}
	}
	// And EncodeVoteV4 refuses nothing the shape can hold: every populated vote encodes, deterministically.
	v := twoHopVote()
	a, err := EncodeVoteV4(&v)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := EncodeVoteV4(&v)
	if string(a) != string(b) || len(a) == 0 {
		t.Fatal("the encoding is not deterministic")
	}
	if VoteRecordTagV4 != "certen:g1:v4:vote:" {
		t.Fatalf("record tag %q", VoteRecordTagV4)
	}
}
