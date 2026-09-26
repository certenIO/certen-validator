package execution

import (
	"reflect"

	"github.com/ethereum/go-ethereum/common"
)

// AnchorWorkflowTxHashes contains all 3 transaction hashes from the Ethereum anchor workflow
// Duplicated here to avoid circular imports with consensus package
type AnchorWorkflowTxHashes struct {
	CreateTxHash     common.Hash // Step 1: createAnchor tx
	VerifyTxHash     common.Hash // Step 2: executeComprehensiveProof tx
	GovernanceTxHash common.Hash // Step 3: executeWithGovernance tx
	PrimaryTxHash    common.Hash // For backwards compatibility
	RawTxHashes      []string    // Native-format hashes for non-EVM chains (e.g. NEAR base58)
}

// extractTxHashesViaReflection uses reflection to extract tx hashes from a struct
// This is used to avoid circular imports between execution and consensus packages
func extractTxHashesViaReflection(txHashes interface{}) *AnchorWorkflowTxHashes {
	if txHashes == nil {
		return nil
	}

	// Use type assertion with interface to extract common.Hash fields
	v := reflect.ValueOf(txHashes)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	result := &AnchorWorkflowTxHashes{}

	// Try to get CreateTxHash field
	if f := v.FieldByName("CreateTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.CreateTxHash = f.Interface().(common.Hash)
	}

	// Try to get VerifyTxHash field
	if f := v.FieldByName("VerifyTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.VerifyTxHash = f.Interface().(common.Hash)
	}

	// Try to get GovernanceTxHash field
	if f := v.FieldByName("GovernanceTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.GovernanceTxHash = f.Interface().(common.Hash)
	}

	// Try to get PrimaryTxHash field
	if f := v.FieldByName("PrimaryTxHash"); f.IsValid() && f.Type() == reflect.TypeOf(common.Hash{}) {
		result.PrimaryTxHash = f.Interface().(common.Hash)
	}

	// Try to get RawTxHashes field (native-format hashes for non-EVM chains)
	if f := v.FieldByName("RawTxHashes"); f.IsValid() && f.Kind() == reflect.Slice {
		if strs, ok := f.Interface().([]string); ok {
			result.RawTxHashes = strs
		}
	}

	return result
}
