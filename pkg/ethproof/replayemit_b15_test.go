// Copyright 2026 Certen Protocol

package ethproof

import "testing"

// RB10-B15: storedFormLen is the length of the text PostgreSQL's jsonb writes. The pairs below are documents and the
// jsonb::text PostgreSQL 16 wrote for them (captured from a PG 16 server, `select j::jsonb::text`, 2026-10-19); the
// separators are the only difference in length for documents of this kind (keys are re-ordered, which keeps the length).
func TestB15_StoredFormLenIsTheLengthPostgresWritesForJsonb(t *testing.T) {
	for _, c := range []struct{ compact, jsonb string }{
		{`{"version":"v1","state":{"state":"s","reason":"r","chainId":84532,"txHash":"0xab","providers":[{"host":"h","error":"e,f:g"},{"host":"","error":"q\"w,e"}],"detail":"x:y,z \"a:b\", c","before":{},"list":[],"n":[1,2,3]}}`,
			`{"state": {"n": [1, 2, 3], "list": [], "state": "s", "before": {}, "detail": "x:y,z \"a:b\", c", "reason": "r", "txHash": "0xab", "chainId": 84532, "providers": [{"host": "h", "error": "e,f:g"}, {"host": "", "error": "q\"w,e"}]}, "version": "v1"}`},
		{`[[],[[1,2],[3]],{"a":{"b":{"c":[true,false,null,"s,t:u"]}}},"",0,-1.5]`,
			`[[], [[1, 2], [3]], {"a": {"b": {"c": [true, false, null, "s,t:u"]}}}, "", 0, -1.5]`},
		{`{}`, `{}`},
		{`[]`, `[]`},
		{`"a,b:c"`, `"a,b:c"`},
	} {
		if got := storedFormLen([]byte(c.compact)); got != len(c.jsonb) {
			t.Errorf("%s: storedFormLen = %d, PostgreSQL wrote %d bytes: %s", c.compact, got, len(c.jsonb), c.jsonb)
		}
	}
}
