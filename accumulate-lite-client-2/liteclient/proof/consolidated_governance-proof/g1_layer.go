// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CERTEN Governance Proof - G1 Layer (Governance Correctness)
// This file implements G1-level governance proofs as defined in CERTEN spec
// G1 proves governance correctness including KPSW-EXEC, key membership, threshold satisfaction, and timing

// =============================================================================
// G1 Proof Layer
// =============================================================================

// G1Layer implements G1 governance proofs (Governance Correctness)
type G1Layer struct {
	g0Layer               *G0Layer
	authorityBuilder      *AuthorityBuilder
	signatureVerifier     *SignatureVerifier
	client                RPCClientInterface
	artifactManager       *ArtifactManager
	queryBuilder          QueryBuilder
	cryptographicVerifier *CryptographicVerifier
	bundleIntegrityMgr    *BundleIntegrityManager
}

// NewG1Layer creates a new G1 proof layer with enhanced cryptographic capabilities
func NewG1Layer(client RPCClientInterface, artifactManager *ArtifactManager, sigbytesPath string) *G1Layer {
	g0Layer := NewG0Layer(client, artifactManager)
	authorityBuilder := NewAuthorityBuilder(client, artifactManager)

	// Authority resolution is wired in HERE rather than left optional at the
	// call site. A verifier without it counts distinct keys, which is right only
	// while every entry is a key and every signature is direct - true of all 400
	// production proofs and false the moment governance has a delegate. Making
	// the live G1 layer the place it is always attached means the delegated path
	// cannot quietly fall back to the arithmetic that cannot see it.
	signatureVerifier := NewSignatureVerifier(sigbytesPath).
		WithResolver(&AuthorityResolver{Source: newLivePageSource(client, authorityBuilder)})

	// Get enhanced cryptographic components
	cryptographicVerifier := artifactManager.GetCryptographicVerifier()
	bundleIntegrityMgr := artifactManager.GetBundleIntegrityManager()

	return &G1Layer{
		g0Layer:               g0Layer,
		authorityBuilder:      authorityBuilder,
		signatureVerifier:     signatureVerifier,
		client:                client,
		artifactManager:       artifactManager,
		queryBuilder:          QueryBuilder{},
		cryptographicVerifier: cryptographicVerifier,
		bundleIntegrityMgr:    bundleIntegrityMgr,
	}
}

// ProveG1 generates G1 proof for governance correctness
// Direct translation of Python generate_g1_proof
func (g1 *G1Layer) ProveG1(ctx context.Context, request G1Request) (*G1Result, error) {
	fmt.Printf("[G1] Starting G1 proof generation\n")
	fmt.Printf("[G1] KeyPage: %s\n", request.KeyPage)

	// Step 1: Generate G0 proof as foundation
	g0Result, err := g1.g0Layer.ProveG0(ctx, request.G0Request)
	if err != nil {
		// %w so a G0 outcome that is NOT a governance rejection - a transaction
		// that never executed, above all - stays distinguishable at the top.
		return nil, fmt.Errorf("G0 proof failed: %w", err)
	}

	fmt.Printf("[G1] G0 foundation established\n")

	// SUPERIOR CONCURRENCY: Run Steps 2 & 3 in parallel (true concurrency advantage over Python)
	startTime := time.Now()
	fmt.Printf("[G1] [CONCURRENT] Running authority snapshot and signature enumeration in parallel...\n")

	type authorityResult struct {
		snapshot *AuthoritySnapshot
		err      error
	}

	type signatureResult struct {
		count int
		err   error
	}

	// Channel for authority building result
	authChan := make(chan authorityResult, 1)
	// Channel for signature enumeration result
	sigChan := make(chan signatureResult, 1)

	// Goroutine 1: Build authority snapshot (KPSW-EXEC)
	go func() {
		fmt.Printf("[G1] [GOROUTINE-1] Starting authority snapshot building...\n")
		snapshot, err := g1.authorityBuilder.BuildAuthoritySnapshot(
			ctx,
			request.KeyPage,
			g0Result.ExecMBI,
			g0Result.ExecWitness,
		)
		authChan <- authorityResult{snapshot: snapshot, err: err}
		if err == nil {
			fmt.Printf("[G1] [GOROUTINE-1] Authority snapshot completed successfully\n")
		}
	}()

	// Goroutine 2: pre-read the KEY PAGE's P#signature chain length.
	//
	// This used to count the ADI ROOT's signature chain, because
	// extractPrincipal strips the key page path. That is a different account:
	// verified live, acc://<adi>.acme carries 3 entries while
	// acc://<adi>.acme/book/1 carries the 9 that include the ed25519
	// signatures. The count then fed "enumeration planning" that never ran.
	// It now reads the key page, and enumeration actually happens - see
	// collectViaEnumeration.
	go func() {
		fmt.Printf("[G1] [GOROUTINE-2] Reading key page P#signature chain length...\n")
		count, err := g1.signatureChainCount(ctx, request.KeyPage)
		sigChan <- signatureResult{count: count, err: err}
		if err == nil {
			fmt.Printf("[G1] [GOROUTINE-2] Key page P#signature chain: %d entries\n", count)
		}
	}()

	// Wait for both concurrent operations to complete
	authResult := <-authChan
	sigResult := <-sigChan

	// Check authority building result
	if authResult.err != nil {
		return nil, fmt.Errorf("concurrent authority snapshot failed: %v", authResult.err)
	}
	authoritySnapshot := authResult.snapshot

	// Check signature enumeration result
	if sigResult.err != nil {
		return nil, fmt.Errorf("concurrent signature enumeration failed: %v", sigResult.err)
	}

	concurrentDuration := time.Since(startTime)
	fmt.Printf("[G1] [CONCURRENT] Both operations completed successfully in %v - proceeding with validation\n", concurrentDuration)
	fmt.Printf("[G1] [PERFORMANCE] Concurrent execution saved significant time vs sequential processing\n")

	// Step 3: Complete signature validation with authority snapshot.
	//
	// An evidence outage is returned as-is, not wrapped, so the caller can tell
	// "we could not evaluate the signatures" apart from "the signatures do not
	// authorise this transaction". Conflating the two is what recorded nine
	// healthy proofs as governance failures.
	validatedSignatures, timingBasis, routeStatus, err := g1.enumerateAndValidateSignatures(ctx, request, *authoritySnapshot, g0Result.TxHash)
	if err != nil {
		if inc, ok := IsEvidenceIncomplete(err); ok {
			return nil, inc
		}
		if dis, ok := err.(*RouteDisagreement); ok {
			return nil, dis
		}
		return nil, fmt.Errorf("signature validation failed: %v", err)
	}

	// Step 4: Evaluate authorization.
	//
	// The replay source is built HERE, where the execution block is known, and
	// seeded with the principal's snapshot so that page is not replayed twice.
	// Every version comparison downstream is made against a page reconstructed
	// to this block - see authority_exec_state.go for why nothing else will do.
	execSource := newExecPageSource(g1.authorityBuilder, g0Result.ExecMBI, g0Result.ExecWitness,
		map[string]KeyPageState{normalizeAccURL(authoritySnapshot.Page): authoritySnapshot.StateExec})

	// The authorities the TRANSACTION requires beyond the principal's, derived
	// from its body rather than assumed absent. An UpdateKeyPage that adds a
	// delegate requires that delegate's approval; an UpdateAccountAuth must be
	// voted on even by a disabled authority. See g1_extra_authorities.go.
	//
	// A failure here is FATAL, not a fallback to "no extras". Continuing with
	// an empty set would ask a narrower question than the protocol asks and
	// report the answer as though it were the whole one - which is the defect
	// this derivation exists to close, reintroduced as an error path.
	extraAuthorities, err := DeriveExtraAuthorities(ctx, g1.client, request.G0Request.Account, g0Result.TxHash)
	if err != nil {
		return nil, fmt.Errorf("cannot determine which authorities this transaction requires: %w", err)
	}

	authorizationResult, err := g1.signatureVerifier.ValidateSignatureSet(ctx, validatedSignatures, *authoritySnapshot, g0Result.TxHash, g0Result.G0ProofComplete, request.G0Request.Account, execSource, extraAuthorities)
	if err != nil {
		// An evidence outage is returned AS-IS, exactly as step 3 does.
		//
		// Wrapping it with %v would flatten the typed error to a string, and
		// IsEvidenceIncomplete upstream would then classify "we could not
		// establish the page state at execution" as an ordinary authorization
		// failure - which is to say, as a governance rejection. That is the
		// conflation this layer spends its whole length avoiding, and it would
		// have been reintroduced by an error-formatting verb.
		if inc, ok := IsEvidenceIncomplete(err); ok {
			return nil, inc
		}
		return nil, fmt.Errorf("authorization evaluation failed: %v", err)
	}

	// Step 5: Build G1 result
	result := &G1Result{
		G0Result:             *g0Result,
		AuthoritySnapshot:    *authoritySnapshot,
		ValidatedSignatures:  validatedSignatures,
		UniqueValidKeys:      authorizationResult.UniqueValidKeys,
		RequiredThreshold:    authoritySnapshot.StateExec.Threshold,
		ThresholdSatisfied:   authorizationResult.ThresholdSatisfied,
		ExecutionSuccess:     authorizationResult.ExecutionSuccess,
		TimingValid:          authorizationResult.TimingValid,
		G1ProofComplete:      authorizationResult.G1ProofComplete,
		SignatureRouteStatus: routeStatus,
		TimingBasis:          timingBasis,
		UnverifiedPageRules:  g1.authorityBuilder.UnverifiedPageRules(),
	}

	// Rule 8 again, at the point a reader is looking: if any page carried a
	// rule this proof did not re-derive, the summary line must not read as an
	// unqualified "the governance was verified".
	if n := len(result.UnverifiedPageRules); n > 0 {
		fmt.Printf("[G1]   [NOTE] %d page rule(s) recorded but NOT re-derived - "+
			"this proof verifies the ACCEPT threshold, and the pages named in "+
			"unverifiedPageRules demand more than that\n", n)
	}

	fmt.Printf("[G1] G1 proof complete:\n")
	fmt.Printf("[G1]   Valid signatures: %d\n", len(validatedSignatures))
	fmt.Printf("[G1]   Unique valid keys: %d\n", authorizationResult.UniqueValidKeys)
	fmt.Printf("[G1]   Required threshold: %d\n", authoritySnapshot.StateExec.Threshold)
	fmt.Printf("[G1]   Threshold satisfied: %t\n", authorizationResult.ThresholdSatisfied)
	fmt.Printf("[G1]   Authorization verified: %t\n", result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess)

	return result, nil
}

// enumerateAndValidateSignatures collects the transaction's counted signatures
// via BOTH independent routes and requires them to agree.
//
// Previously this tried the signatureSet route and, on ANY failure, fell back
// to validateSignaturesDirectFromTransaction - a stub that returned
// `[]ValidatedSignature{}, nil`. A nil error, so callers saw success with zero
// signatures, and the threshold was then evaluated over nothing. Four distinct
// extraction failures reached that stub, and the error that caused them was
// discarded at the call site.
//
// Now: both routes run, an unavailable route is distinguished from a route
// that legitimately found nothing, and disagreement fails closed.
func (g1 *G1Layer) enumerateAndValidateSignatures(ctx context.Context, request G1Request,
	snapshot AuthoritySnapshot, txHash string) ([]ValidatedSignature, []SignatureTimingBasis, *RouteStatus, error) {

	fmt.Printf("[G1] [EVIDENCE] Collecting signature evidence via both routes...\n")

	// WHICH PAGES MAY CARRY A VOTE, before either route starts looking.
	//
	// Both routes walk outward from a page — one through authority signatures,
	// one through delegate entries — and neither can reach a SIBLING authority,
	// because the account names both books and neither delegates to the other.
	// Seeding them with every authority's pages is what makes the two routes
	// cover the account's whole authority set instead of one book of it.
	//
	// Failing here is fatal on purpose. Not knowing which pages may vote is not
	// the same as there being one, and quietly continuing with the principal's
	// page alone is precisely the under-collection that produced case L's false
	// rejection. See g1_authority_pages.go.
	authorityPages, apErr := g1.accountSignerPages(ctx, request.G0Request.Account, request.KeyPage)
	if apErr != nil {
		return nil, nil, nil, &SignatureEvidenceIncomplete{
			Route:     "authority-pages",
			Requested: 0,
			Unavailable: []UnavailableSignature{{
				MessageID: request.G0Request.Account, Stage: "authority-pages", Err: apErr.Error(),
			}},
		}
	}

	// --- route 1: the transaction's signatureSet for this key page --------
	var setEv *SignatureEvidence
	txMessageID := fmt.Sprintf("acc://%s@%s", txHash, request.G0Request.Account)
	sigData, setErr := g1.ExtractSignatureSetUsingMessageID(ctx, txMessageID, request.KeyPage, authorityPages...)
	if setErr != nil {
		// The extraction error is no longer discarded. It is an outage until
		// proven otherwise, and it is reported.
		setErr = &SignatureEvidenceIncomplete{
			Route:     routeSignatureSet,
			Requested: 0,
			Unavailable: []UnavailableSignature{{
				MessageID: txMessageID, Stage: "extract-signature-set", Err: setErr.Error(),
			}},
		}
	} else {
		setEv, setErr = g1.collectViaSignatureSet(ctx, sigData, snapshot, txHash)
	}

	// --- route 2: enumeration of the key page's P#signature chain ---------
	enumEv, enumErr := g1.collectViaEnumeration(ctx, request.KeyPage, snapshot, txHash, authorityPages...)

	evidence, status, err := ResolveRoutes(nil, setErr, setEv, enumEv, enumErr)
	if err != nil {
		return nil, nil, nil, err
	}

	fmt.Printf("[G1] [EVIDENCE] primary=%s agreed=%t degraded=%t counted=%d rejected=%d candidates=%d\n",
		status.PrimaryRoute, status.RoutesAgreed, status.Degraded,
		len(evidence.Counted), len(evidence.Rejected), evidence.Candidates)
	if status.Degraded {
		fmt.Printf("[G1] [EVIDENCE] [DEGRADED] %s\n", status.DegradedReason)
	}
	for _, r := range evidence.Rejected {
		fmt.Printf("[G1] [EVIDENCE] rejected %s: %s\n", SafeTruncate(r.MessageID, 40), r.Reason)
	}

	// One timing record per counted signature, or nothing is returned at all.
	//
	// These are appended in the same branch, so a mismatch means a counted
	// signature reached the verdict with no record of HOW its ordering was
	// established - which is the precise thing this evidence exists to prevent,
	// arrived at from the inside. A short list would silently understate how
	// many signatures rest on the weaker basis, and understating that is worse
	// than not recording it at all.
	if len(evidence.TimingBasis) != len(evidence.Counted) {
		return nil, nil, nil, fmt.Errorf(
			"internal: %d counted signature(s) but %d timing-basis record(s) on route %q - "+
				"refusing to emit a proof in which a counted signature has no recorded timing basis",
			len(evidence.Counted), len(evidence.TimingBasis), evidence.Route)
	}
	sortTimingBasis(evidence.TimingBasis)
	if w := countWeakened(evidence.TimingBasis); w > 0 {
		fmt.Printf("[G1] [TIMING] %d of %d counted signature(s) are CROSS-PARTITION: their ordering "+
			"before execution rests on execution inclusion, not on a local block comparison\n",
			w, len(evidence.TimingBasis))
	}

	return evidence.Counted, evidence.TimingBasis, status, nil
}

// parseReceiptData parses receipt data from receipt object
func (g1 *G1Layer) parseReceiptData(receiptMap map[string]interface{}) (ReceiptData, error) {
	pu := ProofUtilities{}
	var receipt ReceiptData

	// Extract start
	if start := pu.CaseInsensitiveGet(receiptMap, "start"); start != nil {
		if startStr, ok := start.(string); ok {
			receipt.Start = startStr
		}
	}

	// Extract anchor
	if anchor := pu.CaseInsensitiveGet(receiptMap, "anchor"); anchor != nil {
		if anchorStr, ok := anchor.(string); ok {
			receipt.Anchor = anchorStr
		}
	}

	// Extract localBlock
	localBlock := pu.CaseInsensitiveGet(receiptMap, "localBlock")
	if localBlock == nil {
		return ReceiptData{}, ValidationError{Msg: "Receipt missing localBlock"}
	}

	switch lb := localBlock.(type) {
	case float64:
		receipt.LocalBlock = int64(lb)
	case int:
		receipt.LocalBlock = int64(lb)
	case int64:
		receipt.LocalBlock = lb
	default:
		return ReceiptData{}, ValidationError{Msg: "Invalid localBlock type in receipt"}
	}

	// Validate localBlock > 0
	if receipt.LocalBlock <= 0 {
		return ReceiptData{}, ValidationError{Msg: fmt.Sprintf("Invalid localBlock: %d", receipt.LocalBlock)}
	}

	// Capture the merkle path so the receipt can actually be recomputed.
	entries, err := ParseReceiptEntries(receiptMap)
	if err != nil {
		return ReceiptData{}, err
	}
	receipt.Entries = entries

	return receipt, nil
}

// ExtractSignatureSetUsingMessageID extracts signature set by querying the transaction message ID directly
func (g1 *G1Layer) ExtractSignatureSetUsingMessageID(ctx context.Context, messageID string, keyPage string,
	authorityPages ...string) (*SignatureSetData, error) {
	fmt.Printf("[G1] [SIGNATURESET] Extracting signature set from transaction...\n")
	fmt.Printf("[G1] [SIGNATURESET]   Transaction Hash: %s\n", messageID)
	fmt.Printf("[G1] [SIGNATURESET]   Key Page: %s\n", keyPage)
	fmt.Printf("[G1] [SIGNATURESET]   Scope: %s\n", messageID)

	// Build query for transaction message (following Python approach exactly)
	includeReceipt := map[string]bool{"forAny": true}
	expand := true
	query := g1.queryBuilder.BuildDefaultQuery(includeReceipt, &expand)

	// Execute query and save artifact
	// Create safe filename
	safeName := strings.ReplaceAll(strings.ReplaceAll(messageID, "://", "_"), "@", "_")[:16]
	response, err := g1.artifactManager.SaveRPCArtifact(
		ctx,
		fmt.Sprintf("signature_set_extraction_%s", safeName),
		g1.client,
		messageID, // Query the transaction message ID directly
		query,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query transaction message for signatureSet: %v", err)
	}

	// Enumerate the principal's page AND every page reachable through
	// delegation.
	//
	// Enumerating only the principal's page is complete for a 1-of-1 or a plain
	// M-of-N - every signature is there - and incomplete the moment an entry is
	// delegated: the delegated signer's user signature is on the INNERMOST page,
	// and the principal's page holds only an `authority` record that the delegate
	// approved. The threshold then comes up short and reads as "the institution
	// did not authorize this", about a transaction the network executed.
	//
	// Every page's set is already in this one response, so the walk costs no
	// extra queries. See g1_delegated_enumeration.go.
	messageIDs, pages, err := g1.collectDelegatedMessageIDs(response, keyPage, authorityPages...)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate signature sets: %v", err)
	}
	if len(pages) > 1 {
		fmt.Printf("[G1] [SIGNATURESET] Enumerated %d signer page(s) via delegation: %v\n",
			len(pages), pages)
	}

	// Build SignatureSetData result
	signatureSetData := &SignatureSetData{
		TxScope:        messageID,
		KeyPage:        keyPage,
		SignatureCount: len(messageIDs),
		MessageIDs:     messageIDs,
	}

	fmt.Printf("[G1] [SIGNATURESET] Found %d signature message IDs\n", len(messageIDs))
	for i, msgID := range messageIDs {
		fmt.Printf("[G1] [SIGNATURESET]   [%d] %s\n", i+1, msgID)
	}

	return signatureSetData, nil
}

// =============================================================================
// Canonical SignatureSet Extraction (Python method translation)
// =============================================================================

// pickKeypageSignatureSet selects signatureSet for specific key page from transaction records
// Translation of Python SignatureParser.pick_keypage_signature_set
func (g1 *G1Layer) pickKeypageSignatureSet(txResult map[string]interface{}, pageURL string) (map[string]interface{}, error) {
	pu := ProofUtilities{}

	// Navigate to transaction data (JSON-RPC 2.0 standard format - aligned with Python)
	var data interface{}
	if data = pu.CaseInsensitiveGet(txResult, "result"); data == nil {
		data = pu.CaseInsensitiveGet(txResult, "data") // Fallback
		if data == nil {
			return nil, ValidationError{Msg: "Transaction result missing result{} or data{}"}
		}
	}

	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Transaction data is not an object"}
	}

	// Follow Python approach: look for signatures.records[] at top level
	sigs := pu.CaseInsensitiveGet(dataMap, "signatures")
	if sigs == nil {
		return nil, ValidationError{Msg: "Tx result missing signatures{}"}
	}

	sigsMap, ok := sigs.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Signatures is not an object"}
	}

	records := pu.CaseInsensitiveGet(sigsMap, "records")
	if records == nil {
		return nil, ValidationError{Msg: "Tx signatures missing records[]"}
	}

	recordsArray, ok := records.([]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Transaction signatures.records[] is not an array"}
	}

	// Normalize page URL for comparison (following Python URLUtils.normalize_url)
	uu := URLUtils{}
	pageURLNorm := uu.NormalizeURL(pageURL)

	// Find signatureSet matching the key page (following Python logic exactly)
	for _, recordItem := range recordsArray {
		recordMap, ok := recordItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is a signatureSet record
		recordType := pu.CaseInsensitiveGet(recordMap, "recordType")
		if recordType != "signatureSet" {
			continue
		}

		// Extract account information
		acct := pu.CaseInsensitiveGet(recordMap, "account")
		if acct == nil {
			continue
		}

		acctMap, ok := acct.(map[string]interface{})
		if !ok {
			continue
		}

		// Check account type and URL (following Python logic)
		atype := acctMap["type"]
		aurl := acctMap["url"]

		if atypeStr, ok := atype.(string); ok && strings.ToLower(atypeStr) == "keypage" {
			if aurlStr, ok := aurl.(string); ok {
				if uu.NormalizeURL(aurlStr) == pageURLNorm {
					fmt.Printf("[G1] [SIGNATURESET] Found signatureSet for key page: %s\n", aurlStr)
					return recordMap, nil
				}
			}
		}
	}

	return nil, ValidationError{Msg: fmt.Sprintf("Did not find keyPage signatureSet for page=%s on governed tx record", pageURLNorm)}
}

// extractSignatureMessageIDs extracts message IDs from signatureSet.signatures.records[*].id
// Translation of Python SignatureParser.extract_signature_message_ids
func (g1 *G1Layer) extractSignatureMessageIDs(signatureSet map[string]interface{}) ([]string, error) {
	pu := ProofUtilities{}

	// Navigate to signatures
	signatures := pu.CaseInsensitiveGet(signatureSet, "signatures")
	if signatures == nil {
		return nil, ValidationError{Msg: "SignatureSet missing signatures{}"}
	}

	signaturesMap, ok := signatures.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "SignatureSet signatures is not an object"}
	}

	// Navigate to records
	records := pu.CaseInsensitiveGet(signaturesMap, "records")
	if records == nil {
		return nil, ValidationError{Msg: "SignatureSet signatures missing records{}"}
	}

	recordsArray, ok := records.([]interface{})
	if !ok {
		return nil, ValidationError{Msg: "SignatureSet signatures records is not an array"}
	}

	// Extract message IDs from each record
	var messageIDs []string
	for _, recordItem := range recordsArray {
		recordMap, ok := recordItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract message ID
		id := pu.CaseInsensitiveGet(recordMap, "id")
		idStr, ok := id.(string)
		if !ok || idStr == "" {
			continue
		}

		messageIDs = append(messageIDs, idStr)
	}

	if len(messageIDs) == 0 {
		return nil, ValidationError{Msg: "No signature message IDs found in signatureSet"}
	}

	return messageIDs, nil
}

// =============================================================================
// G1 Validation and Analysis
// =============================================================================

// ValidateG1Result validates G1 proof result for consistency
func (g1 *G1Layer) ValidateG1Result(result *G1Result) error {
	// Validate G0 foundation
	if !result.G0ProofComplete {
		return ValidationError{Msg: "G0 proof not complete"}
	}

	// Validate authority snapshot consistency
	if result.AuthoritySnapshot.ExecTerms.MBI != result.ExecMBI {
		return ValidationError{Msg: "Authority snapshot EXEC_MBI mismatch"}
	}

	if result.AuthoritySnapshot.ExecTerms.Witness != result.ExecWitness {
		return ValidationError{Msg: "Authority snapshot EXEC_WITNESS mismatch"}
	}

	// Validate signature counts
	if len(result.ValidatedSignatures) == 0 && result.ThresholdSatisfied {
		return ValidationError{Msg: "Threshold satisfied with no signatures"}
	}

	if result.UniqueValidKeys > len(result.ValidatedSignatures) {
		return ValidationError{Msg: "Unique valid keys exceeds signature count"}
	}

	// Validate threshold logic
	expectedThresholdSatisfied := uint64(result.UniqueValidKeys) >= result.RequiredThreshold
	if result.ThresholdSatisfied != expectedThresholdSatisfied {
		return ValidationError{
			Msg: fmt.Sprintf("Threshold satisfaction mismatch: got %t, expected %t (%d >= %d)",
				result.ThresholdSatisfied, expectedThresholdSatisfied, result.UniqueValidKeys, result.RequiredThreshold),
		}
	}

	// Validate authorization logic
	expectedAuthVerified := result.ThresholdSatisfied && result.TimingValid
	authorizationVerified := result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess
	if authorizationVerified != expectedAuthVerified {
		return ValidationError{
			Msg: fmt.Sprintf("Authorization verification mismatch: got %t, expected %t",
				authorizationVerified, expectedAuthVerified),
		}
	}

	// Validate G1 completion
	if !result.G1ProofComplete {
		return ValidationError{Msg: "G1 proof not marked complete"}
	}

	return nil
}

// AnalyzeG1Performance provides performance analysis of G1 proof
func (g1 *G1Layer) AnalyzeG1Performance(result *G1Result) map[string]interface{} {
	analysis := make(map[string]interface{})

	// Authority snapshot analysis
	analysis["authority_snapshot"] = map[string]interface{}{
		"genesis_version":    result.AuthoritySnapshot.Genesis.PageState.Version,
		"final_version":      result.AuthoritySnapshot.StateExec.Version,
		"mutations_applied":  len(result.AuthoritySnapshot.Mutations),
		"total_main_entries": result.AuthoritySnapshot.Validation.TotalEntries,
		"final_key_count":    len(result.AuthoritySnapshot.StateExec.Keys),
		"final_threshold":    result.AuthoritySnapshot.StateExec.Threshold,
	}

	// Signature analysis
	timingValidCount := 0
	txHashValidCount := 0
	for _, sig := range result.ValidatedSignatures {
		if sig.TimingVerified {
			timingValidCount++
		}
		if sig.TransactionHashVerified {
			txHashValidCount++
		}
	}

	analysis["signature_analysis"] = map[string]interface{}{
		"total_signatures":    len(result.ValidatedSignatures),
		"unique_valid_keys":   result.UniqueValidKeys,
		"timing_valid_count":  timingValidCount,
		"tx_hash_valid_count": txHashValidCount,
		"threshold_required":  result.RequiredThreshold,
		"threshold_satisfied": result.ThresholdSatisfied,
		"threshold_margin":    int64(result.UniqueValidKeys) - int64(result.RequiredThreshold),
	}

	// Overall validation
	analysis["validation"] = map[string]interface{}{
		"g0_complete":            result.G0ProofComplete,
		"g1_complete":            result.G1ProofComplete,
		"authorization_verified": result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess,
		"timing_valid":           result.TimingValid,
	}

	return analysis
}
