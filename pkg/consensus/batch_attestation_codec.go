package consensus

import (
	"encoding/json"
	"fmt"
)

// PendingAttestationCodec encodes and decodes the Phase 7-9 snapshot carried on a queued batch
// member, so the batch mempool can be persisted across restarts.
//
// It lives here because *PendingAttestation is a consensus type and pkg/execution must not
// import pkg/consensus. execution.AttestationCodec is the seam; this is the implementation the
// wiring supplies.
//
// Without it a restored member would settle but never replay its proof cycle, leaving the intent
// unattested on Accumulate — settled on chain and silent to its ADI, which is exactly the kind
// of half-recovery worth avoiding.
type PendingAttestationCodec struct{}

func (PendingAttestationCodec) Encode(v interface{}) (json.RawMessage, error) {
	att, ok := v.(*PendingAttestation)
	if !ok {
		return nil, fmt.Errorf("expected *PendingAttestation, got %T", v)
	}
	return json.Marshal(att)
}

func (PendingAttestationCodec) Decode(raw json.RawMessage) (interface{}, error) {
	var att PendingAttestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return nil, err
	}
	return &att, nil
}
