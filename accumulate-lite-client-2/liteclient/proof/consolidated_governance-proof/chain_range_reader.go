// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
)

// readChainRange reads the records [start, start+count) of an account chain - exactly those, in index
// order, or an error (RB3-F126).
//
// Pages are at most `page` records; a page that cannot be read is asked for again at half the size, down
// to a single record. The public Kermit endpoint cuts responses near 98 KB (HTTP 200, body ending mid-
// JSON), so a page of 50 expanded entries of an account with large entries - 560 KB for
// acc://certen-kermit-12.acme/data - could never be read, and G1 failed as an infrastructure outage for
// every intent of that account. A single record that still cannot be read is an error.
func readChainRange(ctx context.Context, am *ArtifactManager, client RPCClientInterface, label, scope, chain string,
	start, count, page int, expand bool) ([]map[string]interface{}, error) {
	if count < 0 || page < 1 {
		return nil, fmt.Errorf("read %s %s chain: count %d, page %d", scope, chain, count, page)
	}
	pu := ProofUtilities{}
	out := make([]map[string]interface{}, 0, count)
	end := start + count
	for s := start; s < end; {
		n := page
		if s+n > end {
			n = end - s
		}
		var records []interface{}
		for {
			resp, err := am.SaveRPCArtifact(ctx, fmt.Sprintf("%s_%d_%d", label, s, n), client, scope, map[string]interface{}{
				"queryType": "chain", "name": chain,
				"range": map[string]interface{}{"start": s, "count": n, "expand": expand},
			})
			if err == nil {
				var result map[string]interface{}
				if result, err = pu.ExpectResult(resp); err == nil {
					records, _ = pu.CaseInsensitiveGet(result, "records").([]interface{})
					if len(records) == n {
						break
					}
					err = fmt.Errorf("%d of %d records", len(records), n)
				}
			}
			if n == 1 || ctx.Err() != nil {
				return nil, fmt.Errorf("read %s %s chain entry %d: %w", scope, chain, s, err)
			}
			n /= 2
		}
		for i, r := range records {
			rec, ok := r.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s %s chain entry %d is not a record", scope, chain, s+i)
			}
			if idx, ok := chainIndexOf(rec); !ok || idx != s+i {
				return nil, fmt.Errorf("%s %s chain entry %d reports index %d", scope, chain, s+i, idx)
			}
			out = append(out, rec)
		}
		s += n
	}
	return out, nil
}
