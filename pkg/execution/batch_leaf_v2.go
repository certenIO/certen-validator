// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
)

// The v2 batch leaf (RB3-F39), for CertenAccountV7_2 - the account the V8.2 rollout deploys through
// CertenAccountFactoryV10. Deployed CertenAccountV7 accounts keep the v1 leaf (ComputeBatchLeaf).
//
// v1 bound identity, effect and intent, but not the authority that authorized it: the account's
// authority-level check read a level the submitting validator declared, so any level could be claimed.
// v2 binds the index of the ADI key page whose signatures G1 counted - a fact read from Accumulate - and
// the account derives the level every leg needs from it (CertenAccountV7_2.authorityLevelOfPage).

// BatchLeafDomainV2 must equal CertenAccountV7_2.LEAF_DOMAIN.
const BatchLeafDomainV2 = "certen:batchleaf:v2"

// ComputeBatchLeafV2 mirrors CertenAccountV7_2.computeLeaf:
//
//	keccak256(abi.encodePacked(
//	    "certen:batchleaf:v2", chainId, adiURLHash, executionCommitment, operationID, uint64 authorityPage
//	))
//
// The page is 8 bytes big-endian under encodePacked (uint64 is not padded).
func ComputeBatchLeafV2(chainID int64, in BatchLeafInput, authorityPage uint64) [32]byte {
	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)
	adiHash := in.ADIURLHash()
	page := make([]byte, 8)
	binary.BigEndian.PutUint64(page, authorityPage)

	packed := make([]byte, 0, len(BatchLeafDomainV2)+136)
	packed = append(packed, []byte(BatchLeafDomainV2)...)
	packed = append(packed, chainIDBytes...)
	packed = append(packed, adiHash[:]...)
	packed = append(packed, in.ExecutionCommitment[:]...)
	packed = append(packed, in.OperationID[:]...)
	packed = append(packed, page...)
	return ethcrypto.Keccak256Hash(packed)
}

// AuthorityPageIndex is the 1-based index of an Accumulate key page from its URL (acc://<adi>/<book>/<n>),
// as G1 records the page that signed. Anything else is refused: a page the leaf binds must be one the chain
// names.
func AuthorityPageIndex(pageURL string) (uint64, error) {
	u := strings.TrimSpace(pageURL)
	if !strings.HasPrefix(strings.ToLower(u), "acc://") {
		return 0, fmt.Errorf("key page %q is not an acc:// URL", pageURL)
	}
	parts := strings.Split(strings.TrimSuffix(u[len("acc://"):], "/"), "/")
	if len(parts) < 3 {
		return 0, fmt.Errorf("key page %q does not name <adi>/<book>/<index>", pageURL)
	}
	n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("key page %q does not end in a page index of 1 or more", pageURL)
	}
	return n, nil
}

// AuthorityPageOfADI is AuthorityPageIndex for a page that must belong to adiURL: acc://<adi>/<book>/<index> whose
// <adi> is the member's own ADI (canonical spelling). CertenAccountV7_2 reads the index as one of its own ADI's pages,
// so a page of any other identity's book is refused - its index would be read as this ADI's page of that number.
func AuthorityPageOfADI(pageURL, adiURL string) (uint64, error) {
	n, err := AuthorityPageIndex(pageURL)
	if err != nil {
		return 0, err
	}
	page := govvote.CanonicalAccSpelling(pageURL)
	parts := strings.Split(page[len("acc://"):], "/")
	owner := "acc://" + strings.Join(parts[:len(parts)-2], "/")
	if adi := govvote.CanonicalAccSpelling(adiURL); owner != adi {
		return 0, fmt.Errorf("key page %s belongs to %s, not to the member's ADI %s; its account reads page %d as its own",
			pageURL, owner, adi, n)
	}
	return n, nil
}
