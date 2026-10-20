// Copyright 2026 Certen Protocol

package main

import (
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// rb8Network is a Kermit-shaped network for tests: DevNet, two routes that partition the routing space.
func rb8Network(t testing.TB) *govsig.Network {
	t.Helper()
	n, err := govsig.NewNetwork("DevNet", &protocol.RoutingTable{Routes: []protocol.Route{
		{Length: 1, Value: 0, Partition: "BVN1"},
		{Length: 1, Value: 1, Partition: "BVN2"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// rb8Verifier is a verifier that knows the network, as the G1 layer's is.
func rb8Verifier(t testing.TB) *SignatureVerifier {
	t.Helper()
	n := rb8Network(t)
	return &SignatureVerifier{network: func() (*govsig.Network, error) { return n, nil }}
}

// rb8KourouBlock is a block of the signer page's partition that is proven to be under v2-kourou.
func rb8KourouBlock(t testing.TB, signer string) int64 {
	t.Helper()
	part, err := rb8Network(t).Partition(signer)
	if err != nil {
		t.Fatal(err)
	}
	return govsig.KermitActivations()[part].Block + 1000
}

// rb8Verify verifies sd where a Kermit signature would have been recorded: after the activation of its partition.
func rb8Verify(t testing.TB, sv *SignatureVerifier, sd SignatureData, txHashHex string) (string, error) {
	t.Helper()
	return sv.VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: rb8KourouBlock(t, sd.Signer)}}, txHashHex)
}
