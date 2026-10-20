// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
)

func liveRPC() *basefinal.RPC {
	return &basefinal.RPC{
		BlockURLs: []string{"https://ethereum-sepolia-rpc.publicnode.com", "https://0xrpc.io/sep"},
		ProofURLs: []string{"https://0xrpc.io/sep", "https://api.zan.top/eth-sepolia"},
		L2URLs:    []string{"https://sepolia.base.org"},
	}
}

func addr20(s string) [20]byte {
	var a [20]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	copy(a[:], b)
	return a
}

// contracts the pins name, with the addresses the annexes derived (R11-base-sepolia Q1, R11-base-030 Q1/Q5).
var measured = []struct{ name, addr string }{
	{"portal_proxy", "0x49f53e41452C74589E85cA1677426Ba426459e85"},
	{"system_config_proxy", "0xf272670eb55e895584501d564AfEB048bEd26194"},
	{"asr_proxy", "0x2fF5cC82dBf333Ea30D8ee462178ab1707315355"},
	{"dgf_proxy", "0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1"},
	{"superchain_proxy", "0xE4401EB53AE90a5335a51fe1828d7BeCf7a63508"},
	{"portal_impl", "0xa53f56711a2f65c19c1542c98116b98fc07a9bb1"},
	{"syscfg_impl", "0xaeb75e200b9bcf9343ff1a2d2b1b3976e7339ca4"},
	{"asr_impl", "0xb1cc9f8422042eda9eb36a408002517d7c772ac7"},
	{"dgf_impl", "0x9cacf701ef24b8339cd1fdecadde7c080373fb29"},
	{"superchain_impl", "0x99fcf11772af0a9cc411af3cb4311a387dd55b15"},
	{"game_impl_0.2.0", "0xd702aaE6221f36Dfe7e8EBC4315D64344A9dB4CB"},
	{"game_impl_0.3.0", "0xB5abCf8656E3F26990ECEEEc99D22023E7eb7E3b"},
}

func measure(ctx context.Context) error {
	rpc := liveRPC()
	head, err := rpc.L1Head(ctx)
	if err != nil {
		return err
	}
	fmt.Println("L1 head", head)
	for _, m := range measured {
		code, err := rpc.Code(ctx, addr20(m.addr), head)
		if err != nil {
			fmt.Printf("%-22s %s ERROR %v\n", m.name, m.addr, err)
			continue
		}
		fmt.Printf("%-22s %s bytes=%d codeHash=0x%x\n", m.name, m.addr, len(code), crypto.Keccak256(code))
	}
	// the EIP-1967 implementation slot of each proxy must name the pinned implementation address
	for _, m := range measured[:5] {
		w, err := rpc.StorageAtLatest(ctx, addr20(m.addr), [32]byte(crypto1967()))
		if err != nil {
			fmt.Printf("%-22s impl slot ERROR %v\n", m.name, err)
			continue
		}
		fmt.Printf("%-22s impl slot -> 0x%x\n", m.name, w[12:])
	}
	return nil
}

func captureCmd(ctx context.Context, dir, game string, back uint64) error {
	if dir == "" || game == "" {
		return fmt.Errorf("-dir and -game are required")
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return err
	}
	bp, err := basefinal.ParsePins(pins)
	if err != nil {
		return err
	}
	store := basefinal.DirStore{Dir: dir}
	c, err := basefinal.CaptureGame(ctx, liveRPC(), store, bp, addr20(game), back)
	if err != nil {
		return err
	}
	fmt.Printf("captured game %s at L1 block %d hash 0x%x: %d nodes, code %d bytes\n", game, c.L1Block, c.L1Hash, len(c.Nodes), len(c.GameCode))
	return nil
}

func crypto1967() []byte {
	b, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	return b
}

var _ = os.Stderr

type bigInt = big.Int
