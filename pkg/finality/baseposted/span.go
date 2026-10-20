// Copyright 2026 Certen Protocol

package baseposted

// spanParams are the chain constants a span batch is read against: the L2 genesis time (rel_timestamp is relative to it),
// the L2 block time and the L2 chain id (transactions are rebuilt for it).
type spanParams struct {
	GenesisTime uint64
	BlockTime   uint64
	ChainID     uint64
}

// decodeSpanBatch decodes a span batch payload (batch type byte already removed) into one Batch per L2 block.
// Until the Delta decoder lands this is the named state "type 1 unsupported", never a pass.
func decodeSpanBatch(payload []byte, sp spanParams) ([]Batch, error) {
	return nil, &batchFormatError{typ: 1}
}
