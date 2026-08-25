// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Layer4Builder constructs the two L4 legs from live v3 data.
//
// Locating the delivered anchor is O(1) and self-verifying:
//
//  1. On the DESTINATION anchor pool, the chain anchor(<source>)-root holds
//     the source's root chain anchors. Its index for a given root anchor is
//     the source's outbound sequence index. L2 and L3 already compute this
//     index, so no search is needed.
//  2. On the SOURCE anchor pool, chain anchor-sequence at that index holds
//     the anchor transaction as produced - with a nil principal.
//  3. Re-principalling that transaction to the destination pool and hashing
//     it yields the delivered transaction's hash. (Verified live: the two
//     copies differ only in the header principal.)
//  4. Querying the destination pool's `main` chain BY ENTRY with that hash
//     returns the delivered anchor and its signature set.
//
// Every derived value is checked against the anchor body before it is stored,
// so a wrong index cannot silently produce a wrong-but-well-formed leg.
type Layer4Builder struct {
	Client    *jsonrpc.Client
	Debug     bool
	Artifacts map[string][]byte // optional
}

func NewLayer4Builder(client *jsonrpc.Client, debug bool) *Layer4Builder {
	return &Layer4Builder{Client: client, Debug: debug}
}

// networkInfo is the validator set and accept threshold, read from the network
// rather than hardcoded, so a proof tracks the deployment instead of a snapshot
// of what the deployment looked like when this code was written.
type networkInfo struct {
	Validators []ValidatorKey
	Accept     Rational
	Version    uint64
}

// BuildBVNLeg proves the BVN's stateTreeAnchor was signed by a quorum of that
// BVN's own validators. The blockValidatorAnchor travels
// acc://bvn-<BVN>.acme -> acc://dn.acme/anchors.
//
// L2 already resolved the destination-side index (l2.DNIndex) by querying
// anchor(<bvn>)-root by entry = l1.BVNRootChainAnchor.
func (b *Layer4Builder) BuildBVNLeg(ctx context.Context, bvn string, l1 Layer1, l2 Layer2) (*Layer4, error) {
	if b.Client == nil {
		return nil, fmt.Errorf("layer4[bvn]: missing v3 client")
	}
	if bvn == "" {
		return nil, fmt.Errorf("layer4[bvn]: missing BVN label")
	}
	partition, sourcePool, err := bvnPartitionAndPool(bvn)
	if err != nil {
		return nil, err
	}
	return b.buildLeg(ctx, legSpec{
		Partition:       partition,
		SourcePool:      sourcePool,
		DestPool:        "acc://dn.acme/anchors",
		SequenceIndex:   l2.DNIndex,
		MinorBlockIndex: l1.BVNMinorBlockIndex,
		RootChainAnchor: l1.BVNRootChainAnchor,
		StateTreeAnchor: l2.BVNStateTreeAnchor,
		ArtifactPrefix:  "L4_bvn",
	})
}

// BuildDNLeg proves the DN's stateTreeAnchor was signed by a quorum of
// Directory validators. The directoryAnchor travels
// acc://dn.acme -> acc://bvn-<BVN>.acme/anchors.
//
// The destination-side index is the index of l2.DNRootChainAnchor on the BVN
// pool's anchor(directory)-root chain. That is a different account from the one
// L3 queried (L3 reads the DN's self-anchor chain), so it is resolved here.
func (b *Layer4Builder) BuildDNLeg(ctx context.Context, bvn string, l2 Layer2, l3 Layer3) (*Layer4, error) {
	if b.Client == nil {
		return nil, fmt.Errorf("layer4[dn]: missing v3 client")
	}
	_, destPool, err := bvnPartitionAndPool(bvn)
	if err != nil {
		return nil, err
	}

	seqIndex, err := b.anchorRootIndex(ctx, destPool, "anchor(directory)-root", l2.DNRootChainAnchor)
	if err != nil {
		return nil, fmt.Errorf("layer4[dn]: locating directory anchor on %s: %w", destPool, err)
	}

	return b.buildLeg(ctx, legSpec{
		Partition:       protocol.Directory,
		SourcePool:      "acc://dn.acme/anchors",
		DestPool:        destPool,
		SequenceIndex:   seqIndex,
		MinorBlockIndex: l2.DNMinorBlockIndex,
		RootChainAnchor: l2.DNRootChainAnchor,
		StateTreeAnchor: l3.DNStateTreeAnchor,
		ArtifactPrefix:  "L4_dn",
	})
}

type legSpec struct {
	Partition       string
	SourcePool      string
	DestPool        string
	SequenceIndex   uint64
	MinorBlockIndex uint64
	RootChainAnchor string
	StateTreeAnchor string
	ArtifactPrefix  string
}

func (b *Layer4Builder) buildLeg(ctx context.Context, spec legSpec) (*Layer4, error) {
	tag := fmt.Sprintf("layer4[%s]", spec.Partition)

	wantRoot, err := MustHex32Lower(spec.RootChainAnchor, tag+" expected rootChainAnchor")
	if err != nil {
		return nil, err
	}
	wantState, err := MustHex32Lower(spec.StateTreeAnchor, tag+" expected stateTreeAnchor")
	if err != nil {
		return nil, err
	}

	// (2) the anchor as produced, from the source pool's outbound sequence.
	srcTxn, err := b.anchorSequenceTxn(ctx, spec.SourcePool, spec.SequenceIndex, spec.ArtifactPrefix)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tag, err)
	}

	// Check the produced anchor is the one we are proving BEFORE using it to
	// derive anything, so a wrong index fails here rather than later.
	srcSource, srcMBI, srcRoot, srcState, err := partitionAnchorFields(srcTxn.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: source-side anchor: %w", tag, err)
	}
	if srcRoot != wantRoot {
		return nil, fmt.Errorf("%s: anchor-sequence[%d] rootChainAnchor=%s, expected %s (wrong anchor located)",
			tag, spec.SequenceIndex, srcRoot, wantRoot)
	}
	if srcState != wantState {
		return nil, fmt.Errorf("%s: anchor-sequence[%d] stateTreeAnchor=%s, expected %s",
			tag, spec.SequenceIndex, srcState, wantState)
	}
	if srcMBI != spec.MinorBlockIndex {
		return nil, fmt.Errorf("%s: anchor-sequence[%d] minorBlockIndex=%d, expected %d",
			tag, spec.SequenceIndex, srcMBI, spec.MinorBlockIndex)
	}
	srcPart, ok := protocol.ParsePartitionUrl(mustURL(srcSource))
	if !ok || !strings.EqualFold(srcPart, spec.Partition) {
		return nil, fmt.Errorf("%s: anchor source %s is not partition %s", tag, srcSource, spec.Partition)
	}

	// (3) derive the delivered transaction's hash.
	destURL, err := acc_url.Parse(spec.DestPool)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid destination pool %q: %w", tag, spec.DestPool, err)
	}
	delivered := srcTxn.Copy()
	delivered.Header.Principal = destURL
	deliveredHash := delivered.Hash()

	// (4) fetch the delivered anchor and its signatures.
	ce, mr, err := b.mainByEntry(ctx, spec.DestPool, deliveredHash[:], spec.ArtifactPrefix)
	if err != nil {
		return nil, fmt.Errorf("%s: delivered anchor %x on %s: %w", tag, deliveredHash[:8], spec.DestPool, err)
	}
	if mr.Sequence == nil {
		return nil, fmt.Errorf("%s: delivered anchor carries no sequence info", tag)
	}
	if mr.Status != errorsDelivered {
		return nil, fmt.Errorf("%s: delivered anchor status is %v, expected delivered", tag, mr.Status)
	}

	deliveredTM, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok {
		return nil, fmt.Errorf("%s: delivered anchor is %T, expected a transaction message", tag, mr.Message)
	}

	// Reconstruct exactly the object the validators signed. accumulate-core's
	// BlockAnchor.checkSignature rebuilds seq with a fresh TransactionMessage
	// wrapping the transaction; do the same, then confirm by verification.
	seq := &messaging.SequencedMessage{
		Message:     &messaging.TransactionMessage{Transaction: deliveredTM.Transaction},
		Source:      mr.Sequence.Source,
		Destination: mr.Sequence.Destination,
		Number:      mr.Sequence.Number,
	}
	signedHash := seq.Hash()
	seqBin, err := seq.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%s: marshaling sequenced message: %w", tag, err)
	}

	sigs, err := extractAnchorSignatures(mr, hex.EncodeToString(signedHash[:]))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tag, err)
	}

	ni, err := b.networkInfo(ctx, spec.ArtifactPrefix)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tag, err)
	}
	active := 0
	for _, v := range ni.Validators {
		if isActiveOn(v, spec.Partition) {
			active++
		}
	}
	if active == 0 {
		return nil, fmt.Errorf("%s: no validator is active on this partition", tag)
	}
	threshold, err := ni.Accept.Threshold(active)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tag, err)
	}

	leg := &Layer4{
		Partition:        spec.Partition,
		Source:           srcSource,
		Destination:      mr.Sequence.Destination.String(),
		AnchorPool:       spec.DestPool,
		AnchorIndex:      ce.Index,
		SequenceNumber:   mr.Sequence.Number,
		AnchorTxHash:     lowerHex(hex.EncodeToString(deliveredHash[:])),
		SignedHash:       lowerHex(hex.EncodeToString(signedHash[:])),
		SequencedMessage: hex.EncodeToString(seqBin),
		MinorBlockIndex:  spec.MinorBlockIndex,
		RootChainAnchor:  wantRoot,
		StateTreeAnchor:  wantState,
		Signatures:       sigs,
		ValidatorSet:     ni.Validators,
		Threshold:        threshold,
		AcceptThreshold:  ni.Accept,
		NetworkVersion:   ni.Version,
	}

	// The builder must never emit a leg the verifier would reject. Anchors
	// gather their quorum a few blocks after production, so an under-signed
	// leg here means "not ready yet", not "invalid" - it is still an error,
	// and the caller may retry or walk back.
	if err := leg.VerifyOffline(); err != nil {
		return nil, fmt.Errorf("%s: built leg does not verify: %w", tag, err)
	}
	return leg, nil
}

// errorsDelivered is the delivered status constant, kept local so this file
// does not pull in the errors package purely for one comparison.
const errorsDelivered = 201

// anchorRootIndex returns the index of entry on chain `chainName` of `account`.
// The chain query is by Entry, never Range: includeReceipt is silently ignored
// on Range queries, and an Entry query enforces uniqueness.
func (b *Layer4Builder) anchorRootIndex(ctx context.Context, account, chainName, entryHex string) (uint64, error) {
	entryHex, err := MustHex32Lower(entryHex, "anchor root entry")
	if err != nil {
		return 0, err
	}
	entry, _ := hex.DecodeString(entryHex)
	scope, err := acc_url.Parse(account)
	if err != nil {
		return 0, fmt.Errorf("invalid account %q: %w", account, err)
	}
	resp, err := b.Client.Query(ctx, scope, &v3.ChainQuery{Name: chainName, Entry: entry})
	if err != nil {
		return 0, fmt.Errorf("query %s by entry: %w", chainName, err)
	}
	ce, err := pickExactlyOneChainEntry(resp, chainName, entryHex)
	if err != nil {
		return 0, err
	}
	return ce.Index, nil
}

// anchorSequenceTxn reads the anchor transaction as produced by the source
// partition, from its outbound anchor-sequence chain.
func (b *Layer4Builder) anchorSequenceTxn(ctx context.Context, pool string, index uint64, prefix string) (*protocol.Transaction, error) {
	scope, err := acc_url.Parse(pool)
	if err != nil {
		return nil, fmt.Errorf("invalid source pool %q: %w", pool, err)
	}
	idx := index
	resp, err := b.Client.Query(ctx, scope, &v3.ChainQuery{Name: "anchor-sequence", Index: &idx})
	if err != nil {
		return nil, fmt.Errorf("query anchor-sequence[%d] on %s: %w", index, pool, err)
	}
	b.saveArtifact(fmt.Sprintf("%s_anchor_sequence_%d.json", prefix, index), resp)

	ce, ok := resp.(*v3.ChainEntryRecord[v3.Record])
	if !ok {
		return nil, fmt.Errorf("anchor-sequence[%d]: expected a chain entry, got %T", index, resp)
	}
	if ce.Index != index {
		return nil, fmt.Errorf("anchor-sequence returned index %d, requested %d", ce.Index, index)
	}
	mr, ok := ce.Value.(*v3.MessageRecord[messaging.Message])
	if !ok {
		return nil, fmt.Errorf("anchor-sequence[%d]: expected a message record, got %T", index, ce.Value)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok {
		return nil, fmt.Errorf("anchor-sequence[%d]: expected a transaction message, got %T", index, mr.Message)
	}
	if tm.Transaction == nil {
		return nil, fmt.Errorf("anchor-sequence[%d]: no transaction", index)
	}
	return tm.Transaction, nil
}

// mainByEntry fetches the delivered anchor by its transaction hash.
func (b *Layer4Builder) mainByEntry(ctx context.Context, pool string, entry []byte, prefix string) (
	*v3.ChainEntryRecord[v3.Record], *v3.MessageRecord[messaging.Message], error) {

	scope, err := acc_url.Parse(pool)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid pool %q: %w", pool, err)
	}
	resp, err := b.Client.Query(ctx, scope, &v3.ChainQuery{
		Name:           "main",
		Entry:          entry,
		IncludeReceipt: &v3.ReceiptOptions{ForAny: true},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("query main by entry: %w", err)
	}
	b.saveArtifact(fmt.Sprintf("%s_delivered_anchor.json", prefix), resp)

	ce, err := pickExactlyOneChainEntry(resp, "main", hex.EncodeToString(entry))
	if err != nil {
		return nil, nil, err
	}
	mr, ok := ce.Value.(*v3.MessageRecord[messaging.Message])
	if !ok {
		return nil, nil, fmt.Errorf("delivered anchor: expected a message record, got %T", ce.Value)
	}
	return ce, mr, nil
}

// extractAnchorSignatures pulls the validator signatures off the delivered
// anchor. Every signature must be ed25519 and must cover signedHash; a
// signature that does not is an error, not something to skip. Silently
// dropping evidence is the defect class this whole change exists to remove.
func extractAnchorSignatures(mr *v3.MessageRecord[messaging.Message], signedHashHex string) ([]AnchorSignature, error) {
	if mr.Signatures == nil || len(mr.Signatures.Records) == 0 {
		return nil, fmt.Errorf("delivered anchor carries no signature sets")
	}
	var out []AnchorSignature
	for _, set := range mr.Signatures.Records {
		if set.Signatures == nil {
			continue
		}
		for _, rec := range set.Signatures.Records {
			ba, ok := rec.Message.(*messaging.BlockAnchor)
			if !ok {
				// A signature set on an anchor may legitimately hold other
				// message kinds; they are not validator votes.
				continue
			}
			es, ok := ba.Signature.(*protocol.ED25519Signature)
			if !ok {
				return nil, fmt.Errorf("anchor signature is %T, expected ed25519", ba.Signature)
			}
			gotTx := lowerHex(hex.EncodeToString(es.TransactionHash[:]))
			if gotTx != lowerHex(signedHashHex) {
				return nil, fmt.Errorf("anchor signature covers %s, expected %s", gotTx, signedHashHex)
			}
			if es.Signer == nil {
				return nil, fmt.Errorf("anchor signature has no signer")
			}
			out = append(out, AnchorSignature{
				PublicKey:     lowerHex(hex.EncodeToString(es.PublicKey)),
				Signature:     lowerHex(hex.EncodeToString(es.Signature)),
				Signer:        es.Signer.String(),
				Timestamp:     es.Timestamp,
				SignerVersion: es.SignerVersion,
			})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("delivered anchor carries no ed25519 validator signatures")
	}
	return out, nil
}

// networkInfo reads the validator set and the network's accept threshold.
//
// This uses raw JSON-RPC rather than the typed client. The typed client
// refuses to unmarshal a network-status response whose executorVersion is
// newer than the vendored protocol package knows about (observed live:
// `invalid Executor Version "v2-jiuquan"`), which would make L4 unbuildable
// against any network ahead of this module's accumulate dependency. Reading
// only the fields L4 needs removes that coupling.
//
// Nothing read here is trusted on assertion: publicKeyHash is re-derived from
// publicKey, the threshold is recomputed, and every signature is checked
// against the set by the verifier.
func (b *Layer4Builder) networkInfo(ctx context.Context, prefix string) (*networkInfo, error) {
	if b.Client.Server == "" {
		return nil, fmt.Errorf("network-status: client has no server URL")
	}
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "network-status",
		"params": map[string]any{"partition": protocol.Directory},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Client.Server, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.Client.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("network-status: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network-status: HTTP %d", resp.StatusCode)
	}
	if b.Artifacts != nil {
		b.Artifacts[prefix+"_network_status.json"] = raw
	}

	var envelope struct {
		Error  *json.RawMessage `json:"error"`
		Result struct {
			Globals struct {
				ValidatorAcceptThreshold *struct {
					Numerator   uint64 `json:"numerator"`
					Denominator uint64 `json:"denominator"`
				} `json:"validatorAcceptThreshold"`
			} `json:"globals"`
			Network struct {
				Version    uint64 `json:"version"`
				Validators []struct {
					PublicKey     string `json:"publicKey"`
					PublicKeyHash string `json:"publicKeyHash"`
					Partitions    []struct {
						ID     string `json:"id"`
						Active bool   `json:"active"`
					} `json:"partitions"`
				} `json:"validators"`
			} `json:"network"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("network-status: decoding response: %w", err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("network-status: RPC error: %s", string(*envelope.Error))
	}
	at := envelope.Result.Globals.ValidatorAcceptThreshold
	if at == nil {
		return nil, fmt.Errorf("network-status returned no validatorAcceptThreshold")
	}
	accept := Rational{Numerator: at.Numerator, Denominator: at.Denominator}
	if _, err := accept.Threshold(1); err != nil {
		return nil, err
	}

	vals := make([]ValidatorKey, 0, len(envelope.Result.Network.Validators))
	for i, v := range envelope.Result.Network.Validators {
		pk, err := MustHex32Lower(v.PublicKey, fmt.Sprintf("network validator[%d].publicKey", i))
		if err != nil {
			return nil, err
		}
		pkh, err := MustHex32Lower(v.PublicKeyHash, fmt.Sprintf("network validator[%d].publicKeyHash", i))
		if err != nil {
			return nil, err
		}
		var activeOn []string
		for _, p := range v.Partitions {
			if p.Active {
				activeOn = append(activeOn, p.ID)
			}
		}
		vals = append(vals, ValidatorKey{PublicKey: pk, PublicKeyHash: pkh, ActiveOn: activeOn})
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("network-status returned an empty validator set")
	}
	return &networkInfo{Validators: vals, Accept: accept, Version: envelope.Result.Network.Version}, nil
}

func (b *Layer4Builder) saveArtifact(name string, v any) {
	if b.Artifacts == nil {
		return
	}
	if raw, err := json.Marshal(v); err == nil {
		b.Artifacts[name] = raw
	}
}

// bvnPartitionAndPool maps a BVN label ("bvn1") to its partition ID ("BVN1")
// and anchor pool URL.
func bvnPartitionAndPool(bvn string) (partition, pool string, err error) {
	b := strings.TrimSpace(bvn)
	if b == "" {
		return "", "", fmt.Errorf("layer4: empty BVN label")
	}
	if !strings.HasPrefix(strings.ToLower(b), "bvn") {
		return "", "", fmt.Errorf("layer4: BVN label %q must start with 'bvn'", bvn)
	}
	suffix := b[3:]
	if suffix == "" {
		return "", "", fmt.Errorf("layer4: BVN label %q has no index", bvn)
	}
	partition = "BVN" + strings.ToUpper(suffix)
	pool = fmt.Sprintf("acc://bvn-%s.acme/anchors", partition)
	return partition, pool, nil
}

func mustURL(s string) *acc_url.URL {
	u, err := acc_url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}
