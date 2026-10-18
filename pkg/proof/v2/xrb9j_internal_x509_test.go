// Copyright 2026 Certen Protocol

package proofv2

import (
	"crypto/rsa"
	"crypto/x509"
)

func x509MarshalPKCS1(k *rsa.PrivateKey) []byte { return x509.MarshalPKCS1PrivateKey(k) }
