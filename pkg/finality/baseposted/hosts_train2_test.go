// Copyright 2026 Certen Protocol

package baseposted

import "testing"

// RB12-GO-INT N2 (V-T2-2): "distinct beacon hosts" must not be satisfiable by one provider listed twice. The key of a base URL is its
// lower-cased host name without a trailing dot, an IP literal in its canonical form, and the port only when it is not the scheme's default.
func TestRB12GOINTDistinctHostsDoesNotCountOneProviderTwice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bases []string
		want  int
	}{
		{"an explicit default https port", []string{"https://p.io", "https://p.io:443"}, 1},
		{"an explicit default http port", []string{"http://p.io/a", "http://p.io:80/b"}, 1},
		{"case and a trailing dot", []string{"https://P.IO", "https://p.io.", "HTTPS://p.io:443/x"}, 1},
		{"the scheme does not make another provider", []string{"https://p.io", "http://p.io"}, 1},
		{"a non-default port is another service", []string{"https://p.io", "https://p.io:8545"}, 2},
		{"a port that is the default of the OTHER scheme is not dropped", []string{"https://p.io", "https://p.io:80"}, 2},
		{"two hosts", []string{"https://a.example", "https://b.example"}, 2},
		{"an IPv4 literal and its default port", []string{"https://127.0.0.1", "https://127.0.0.1:443"}, 1},
		{"an IPv6 literal in two spellings", []string{"https://[::1]:443", "https://[0:0:0:0:0:0:0:1]", "https://[0::1]/"}, 1},
		{"an IPv4-mapped IPv6 literal", []string{"https://127.0.0.1", "https://[::ffff:127.0.0.1]"}, 1},
		{"blanks and spaces", []string{" https://p.io ", "https://p.io"}, 1},
		{"an unparsable base is its own key", []string{"https://p.io", "%%%", "%%%"}, 2},
		{"none", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := distinctHosts(tc.bases); got != tc.want {
				t.Fatalf("%v: %d distinct hosts, want %d", tc.bases, got, tc.want)
			}
		})
	}
}
