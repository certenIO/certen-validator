//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2).

package proof

import (
	"context"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// RB3-F109: the Accumulate module decodes the network's own status. v1.4.2 refused Kermit's executor
// version ("invalid Executor Version \"v2-kourou\""): the module was behind the network it proves.
func TestLiveTheModuleDecodesTheNetworksStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := jsonrpc.NewClient("https://kermit.accumulatenetwork.io/v3").NetworkStatus(ctx, api.NetworkStatusOptions{Partition: "Directory"})
	if err != nil {
		t.Fatalf("network status: %v", err)
	}
	if st.ExecutorVersion == 0 {
		t.Fatalf("no executor version decoded: %+v", st)
	}
	t.Logf("executor version %s, %d partitions", st.ExecutorVersion, len(st.Network.Partitions))
}
