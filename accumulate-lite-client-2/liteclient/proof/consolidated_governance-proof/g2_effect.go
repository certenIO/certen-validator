package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// G2 EFFECT VERIFICATION (RB5-F27).
//
// G2 claims "the actual on-chain effect matches exactly what was approved". The effect component used to compare the
// payload's computed transaction hash with its expected one - the payload check a second time - and the optional
// --expect-entry path compared a TRANSACTION hash with an ENTRY hash, two different values, so it could never pass.
//
// The effect of a transaction is what Accumulate recorded it doing. CERTEN governs WriteData transactions (an intent
// is written to its ADI's data account), whose effect is one data entry written to one account. So the effect is
// verified as:
//
//   - the governed transaction, as Accumulate holds it, is the transaction G0 proved (its hash);
//   - its body is a WriteData, and the entry hash Accumulate's own DataEntry.Hash computes from the APPROVED body is
//     the effect it specifies;
//   - Accumulate's recorded result for the transaction is a writeData result naming exactly that entry hash, written
//     to exactly the transaction's principal account, and the transaction was delivered successfully;
//   - with --expect-entry, the caller's expected entry hash is that same hash.
//
// The recorded result is what the PRINCIPAL's own partition recorded for the transaction; the outcome binding
// (g2_outcome_binding.go) separately receipt-proves the transaction's entry under EXEC_WITNESS. A transaction of another
// type has no effect this check can establish, so G2 is not claimed for it (the proof stands at G1) - never claimed
// without the check.
//
// WHERE THE RECORD IS READ (C5-D4, RB9 phase E). Accumulate executes a user transaction on its principal's partition
// only, and that partition records the result there (internal/core/execute/v2/block/transaction.go
// recordSuccessfulTransaction, with chain/write_data.go building the WriteDataResult) whichever authority's signature
// completed the approval. The v3 API's answer to a MESSAGE-ID query is not that record: pkg/api/v3/collator.go
// (queryMessage) asks every partition in network-status order (BVN1, BVN2, BVN3, Directory) and keeps the Message and
// Result of the FIRST partition that holds the message, merging only status, causes, produced and signatures. A
// partition holding an authority of the principal stores the transaction when it receives the signature request
// (msg_signature_request.go) and never executes it, so its record carries no result; when that partition sorts before
// the principal's, the collated answer says {"type":"unknown"} for a transaction the principal's partition recorded as
// a writeData. The record is therefore read as the principal's main-chain entry for the transaction - a chain query
// scoped to the principal's account, which the API routes to that account's partition alone, with no collation. It is
// the same entry-value record G0 binds the expanded message to, so the two cannot disagree about which message it is.
//
// There is no fallback. When the principal's partition does not give this transaction's entry, or gives a record that
// is not this message, the effect is not verified and the failure names what was received; the collated answer is not
// consulted, and a result of "unknown" on the principal's own record still fails by the same name as any other result
// that is not the approved writeData.

// EffectTypeRecordedWriteData names the effect verification above.
const EffectTypeRecordedWriteData = "recorded_write_data_entry"

// recordedEffect is what Accumulate holds for the governed transaction.
type recordedEffect struct {
	Transaction *protocol.Transaction
	Status      string
	StatusNo    int64
	Result      struct {
		Type       string `json:"type"`
		EntryHash  string `json:"entryHash"`
		AccountURL string `json:"accountUrl"`
	}
}

// queryRecordedEffect reads the governed transaction's message record - the transaction, its status and its result -
// from the principal's own partition: the entry G0 proved in the principal's chain, with the message record the
// partition holds for it.
func (g2 *G2Layer) queryRecordedEffect(ctx context.Context, g1Result *G1Result) (*recordedEffect, error) {
	switch {
	case g1Result.Scope == "":
		return nil, fmt.Errorf("no principal account to read the transaction record from")
	case g1Result.Chain == "":
		return nil, fmt.Errorf("no chain G0 proved the transaction in")
	case g1Result.EntryHashExec == "":
		return nil, fmt.Errorf("no chain entry G0 proved")
	case g1Result.ExpandedMessageID == "":
		return nil, fmt.Errorf("no expanded message ID to bind the record to")
	}
	fmt.Printf("[G2] [EFFECT] Reading the recorded result from the principal's own partition: %s %s-chain entry %s\n",
		g1Result.Scope, g1Result.Chain, SafeTruncate(g1Result.EntryHashExec, 16))
	resp, err := g2.g1Layer.g0Layer.client.Query(ctx, g1Result.Scope,
		g2.queryBuilder.BuildExecutionInclusionQuery(g1Result.EntryHashExec, g1Result.Chain))
	if err != nil {
		return nil, fmt.Errorf("query the principal partition's %s-chain entry %s: %w", g1Result.Chain, SafeTruncate(g1Result.EntryHashExec, 16), err)
	}
	pu := ProofUtilities{}
	record, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("the principal partition gave no %s-chain entry %s: %w", g1Result.Chain, SafeTruncate(g1Result.EntryHashExec, 16), err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return decodePrincipalChainEntry(raw, g1Result.Chain, g1Result.EntryHashExec, g1Result.ExpandedMessageID)
}

// decodePrincipalChainEntry reads the principal partition's answer for a chain entry: the entry must be the governed
// transaction's entry in the chain G0 proved, and its value must be the message G0 bound (the expanded message ID).
// Only then is the value read as the transaction's record.
func decodePrincipalChainEntry(raw []byte, chain, entry, messageID string) (*recordedEffect, error) {
	var env struct {
		RecordType string          `json:"recordType"`
		Name       string          `json:"name"`
		Entry      string          `json:"entry"`
		Value      json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("the principal partition's answer does not decode: %w", err)
	}
	trim := func(s string) string { return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x")) }
	switch {
	case env.RecordType != "chainEntry":
		return nil, fmt.Errorf("the principal partition answered a %q record, not the %s-chain entry %s", env.RecordType, chain, SafeTruncate(entry, 16))
	case !strings.EqualFold(env.Name, chain):
		return nil, fmt.Errorf("the principal partition answered an entry of its %q chain, not of the %s chain G0 proved", env.Name, chain)
	case trim(env.Entry) != trim(entry):
		return nil, fmt.Errorf("the principal partition answered chain entry %s, not the governed transaction's %s", SafeTruncate(env.Entry, 16), SafeTruncate(entry, 16))
	case len(env.Value) == 0 || string(env.Value) == "null":
		return nil, fmt.Errorf("the principal partition's %s-chain entry %s carries no message record", chain, SafeTruncate(entry, 16))
	}
	var val struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Value, &val); err != nil {
		return nil, fmt.Errorf("the principal partition's message record does not decode: %w", err)
	}
	if canonicalAccSpelling(val.ID) != canonicalAccSpelling(messageID) {
		return nil, fmt.Errorf("the principal partition's record is message %q, not the message G0 bound (%q)", val.ID, messageID)
	}
	return decodeRecordedEffect(env.Value)
}

// decodeRecordedEffect reads a message record as the v3 API returns it.
func decodeRecordedEffect(raw []byte) (*recordedEffect, error) {
	var env struct {
		Message struct {
			Transaction json.RawMessage `json:"transaction"`
		} `json:"message"`
		Status   string          `json:"status"`
		StatusNo int64           `json:"statusNo"`
		Result   json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("the transaction record does not decode: %w", err)
	}
	if len(env.Message.Transaction) == 0 {
		return nil, fmt.Errorf("the record carries no transaction")
	}
	out := &recordedEffect{Transaction: new(protocol.Transaction), Status: env.Status, StatusNo: env.StatusNo}
	if err := json.Unmarshal(env.Message.Transaction, out.Transaction); err != nil {
		return nil, fmt.Errorf("the recorded transaction does not decode: %w", err)
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("the record carries no result")
	}
	if err := json.Unmarshal(env.Result, &out.Result); err != nil {
		return nil, fmt.Errorf("the recorded result does not decode: %w", err)
	}
	return out, nil
}

// verifyRecordedEffect is the effect verification: Verified only when every check above holds. txHash is the hash G0
// proved; expectEntry is the optional caller-supplied expected entry hash.
func verifyRecordedEffect(rec *recordedEffect, txHash string, expectEntry *string) EffectVerification {
	v := EffectVerification{EffectType: EffectTypeRecordedWriteData, Details: map[string]interface{}{}}
	fail := func(format string, a ...interface{}) EffectVerification {
		v.Verified = false
		v.Details["failure"] = fmt.Sprintf(format, a...)
		fmt.Printf("[G2] [EFFECT] [FAIL] %s\n", v.Details["failure"])
		return v
	}
	if rec == nil || rec.Transaction == nil {
		return fail("no recorded transaction")
	}
	gotTx := hex.EncodeToString(rec.Transaction.GetHash())
	if !strings.EqualFold(gotTx, strings.TrimPrefix(txHash, "0x")) {
		return fail("the recorded transaction hashes to %s, not the transaction G0 proved (%s)", gotTx, txHash)
	}
	body, ok := rec.Transaction.Body.(*protocol.WriteData)
	if !ok || body == nil || body.Entry == nil {
		return fail("the transaction is a %v, whose effect this check cannot establish (only WriteData's is)", rec.Transaction.Body.Type())
	}
	approved := hex.EncodeToString(body.Entry.Hash())
	v.ExpectedValue = &approved
	recorded := strings.ToLower(strings.TrimPrefix(rec.Result.EntryHash, "0x"))
	v.ComputedValue = &recorded
	v.Details["recorded_account"] = rec.Result.AccountURL
	v.Details["status"] = fmt.Sprintf("%s/%d", rec.Status, rec.StatusNo)
	switch {
	case !isDeliveredSuccess(rec.Status, rec.StatusNo):
		return fail("the transaction was not delivered successfully (%s/%d), so it had no effect", rec.Status, rec.StatusNo)
	case !strings.EqualFold(rec.Result.Type, "writeData"):
		return fail("Accumulate recorded a %q result, not the writeData the approved body specifies", rec.Result.Type)
	case recorded != approved:
		return fail("Accumulate recorded entry %s; the approved body's entry is %s", recorded, approved)
	case rec.Transaction.Header.Principal == nil ||
		!strings.EqualFold(strings.TrimSuffix(rec.Result.AccountURL, "/"), strings.TrimSuffix(rec.Transaction.Header.Principal.String(), "/")):
		return fail("the entry was recorded on %s, not on the transaction's principal %v", rec.Result.AccountURL, rec.Transaction.Header.Principal)
	case expectEntry != nil && *expectEntry != "" && !strings.EqualFold(strings.TrimPrefix(*expectEntry, "0x"), approved):
		return fail("the expected entry %s is not the approved body's entry %s", *expectEntry, approved)
	}
	v.Verified = true
	v.Details["effect_match"] = true
	fmt.Printf("[G2] [EFFECT] [OK] Accumulate recorded entry %s on %s - exactly the approved body's entry\n",
		SafeTruncate(recorded, 16), rec.Result.AccountURL)
	return v
}
