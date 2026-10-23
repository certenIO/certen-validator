// Copyright 2026 Certen Protocol

package finality

// noComponentMemoCap bounds the upgrader's memory of bundles that hold no execution proof: at most this many proofs are
// remembered, and when it is full the oldest remembered proof is forgotten (its bundle is then examined once more, which is
// only a repeated read, never a missed leg).
const noComponentMemoCap = 16384

// bundleMemo remembers, per proof, the id of the one bundle that was examined and found to hold no execution proof. A newer
// bundle of the same proof has another id, so it does not match and is examined at once. It is not safe for concurrent use; the
// upgrader holds its own mutex around it.
type bundleMemo struct {
	cap     int
	byProof map[string]string // proof id -> examined bundle id
	ring    []string          // proof ids in insertion order, filled to cap and then overwritten oldest first
	next    int               // ring slot of the oldest entry once the ring is full
}

func newBundleMemo(cap int) *bundleMemo {
	return &bundleMemo{cap: cap, byProof: map[string]string{}}
}

// has reports whether exactly this bundle of the proof was examined.
func (m *bundleMemo) has(proof, bundle string) bool {
	b, ok := m.byProof[proof]
	return ok && bundle != "" && b == bundle
}

// put remembers the bundle as the proof's examined one, evicting the oldest remembered proof when the memo is full.
func (m *bundleMemo) put(proof, bundle string) {
	if _, ok := m.byProof[proof]; ok {
		m.byProof[proof] = bundle
		return
	}
	if len(m.ring) < m.cap {
		m.ring = append(m.ring, proof)
	} else {
		delete(m.byProof, m.ring[m.next])
		m.ring[m.next] = proof
		m.next = (m.next + 1) % m.cap
	}
	m.byProof[proof] = bundle
}

// forget drops a proof (it holds an execution proof now, or it completed).
func (m *bundleMemo) forget(proof string) { delete(m.byProof, proof) }

func (m *bundleMemo) len() int { return len(m.byProof) }
