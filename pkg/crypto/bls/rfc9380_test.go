package bls

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// RB5-F54: the hash to G1 is RFC 9380's hash_to_curve, BLS12381G1_XMD:SHA-256_SSWU_RO_. Checked against the RFC's own
// test vectors (RFC 9380 Appendix J.9.1, DST "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_").
func TestHashToG1IsRFC9380(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_")
	for _, v := range []struct{ msg, x, y string }{
		{"",
			"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
			"08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"},
		{"abc",
			"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
			"0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"},
	} {
		p, err := hashToCurveG1([]byte(v.msg), dst)
		if err != nil {
			t.Fatal(err)
		}
		var want bls12381.G1Affine
		if _, err := want.X.SetString("0x" + v.x); err != nil {
			t.Fatal(err)
		}
		if _, err := want.Y.SetString("0x" + v.y); err != nil {
			t.Fatal(err)
		}
		if !p.Equal(&want) {
			t.Fatalf("hash_to_curve(%q) = %s, RFC 9380 says (%s, %s)", v.msg, p.String(), v.x, v.y)
		}
	}
}
