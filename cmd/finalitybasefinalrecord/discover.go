// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

func sel(sig string) []byte { return crypto.Keccak256([]byte(sig))[:4] }

// discoverCmd prints (index, game type, creation time, proxy, status byte of slot 0) of the DisputeGameFactory entries at the
// given indices (comma separated), or a coarse sample of the whole list when none is given.
func discoverCmd(ctx context.Context, indices string) error {
	rpc := liveRPC()
	dgf := addr20("0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1")
	b, err := rpc.CallLatest(ctx, dgf, sel("gameCount()"))
	if err != nil {
		return err
	}
	count := new(bigInt).SetBytes(b).Uint64()
	fmt.Println("gameCount", count)
	var idx []uint64
	if indices == "" {
		for i := uint64(0); i < count; i += 700 {
			idx = append(idx, i)
		}
	} else {
		for _, s := range strings.Split(indices, ",") {
			v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
			idx = append(idx, v)
		}
	}
	for _, i := range idx {
		data := append(sel("gameAtIndex(uint256)"), make([]byte, 32)...)
		binary.BigEndian.PutUint64(data[4+24:], i)
		r, err := rpc.CallLatest(ctx, dgf, data)
		if err != nil || len(r) < 96 {
			fmt.Printf("%d: error %v\n", i, err)
			continue
		}
		typ := binary.BigEndian.Uint32(r[28:32])
		ts := binary.BigEndian.Uint64(r[56:64])
		var proxy [20]byte
		copy(proxy[:], r[76:96])
		st, err := rpc.StorageAtLatest(ctx, proxy, [32]byte{})
		status := byte(255)
		if err == nil {
			status = st[15]
		}
		fmt.Printf("%d: type %d createdAt %d proxy 0x%x status %d\n", i, typ, ts, proxy, status)
	}
	return nil
}
