// Copyright 2026 Certen Protocol

// Package supportedchains is the one statement of which chains CERTEN settles on. Ethereum Sepolia, Base
// Sepolia and Arbitrum Sepolia run CERTEN's current contracts; every other chain the validator was ever
// configured for runs retired contracts, some owned by a key that has been published. Consensus, the
// strategy registry, the configuration and the evidence repairs each kept their own copy of this list
// (RB3-F26), and a copy that drifts is a chain one part accepts and another does not.
package supportedchains

import (
	"strconv"
	"strings"
)

// Chain is one supported chain.
type Chain struct {
	ID int64
	// Name is the chain's name in refusals, anchor rows and layer 5 ("base-sepolia").
	Name string
	// Network is its RPC fallback tier's name (ethrpc.EndpointsForChain).
	Network string
}

// All are the supported chains, in a fixed order.
var All = []Chain{
	{ID: 11155111, Name: "ethereum-sepolia", Network: "sepolia"},
	{ID: 84532, Name: "base-sepolia", Network: "base-sepolia"},
	{ID: 421614, Name: "arbitrum-sepolia", Network: "arbitrum-sepolia"},
}

// IDs are the supported chain IDs, in All's order.
func IDs() []int64 {
	out := make([]int64, 0, len(All))
	for _, c := range All {
		out = append(out, c.ID)
	}
	return out
}

// Lookup returns the supported chain with the given ID.
func Lookup(id int64) (Chain, bool) {
	for _, c := range All {
		if c.ID == id {
			return c, true
		}
	}
	return Chain{}, false
}

// IsSupported reports whether CERTEN settles on the chain.
func IsSupported(id int64) bool {
	_, ok := Lookup(id)
	return ok
}

// Describe renders the supported chains for messages: "ethereum-sepolia (11155111), ...".
func Describe() string {
	parts := make([]string, 0, len(All))
	for _, c := range All {
		parts = append(parts, c.Name+" ("+strconv.FormatInt(c.ID, 10)+")")
	}
	return strings.Join(parts, ", ")
}
