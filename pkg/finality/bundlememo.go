// Copyright 2026 Certen Protocol

package finality

// noComponentMemoCap bounds the upgrader's memory of bundles that hold no execution proof: at most this many proofs are
// remembered, and when it is full the oldest remembered proof is forgotten (its bundle is then examined once more, which is
// only a repeated read, never a missed leg).
const noComponentMemoCap = 16384

// bundleMemo remembers, per proof, the id of the one bundle that was examined and found to hold no execution proof. A newer
// bundle of the same proof has another id, so it does not match and is examined at once. It is not safe for concurrent use; the
// upgrader holds its own mutex around it.
//
// Entries are ordered by a ring of slots. Each entry carries the generation of the slot that holds it, so a slot left behind by a
// forgotten proof (or by one that was forgotten and remembered again) never evicts a live entry when it comes round.
type bundleMemo struct {
	cap     int
	gen     uint64
	byProof map[string]memoEntry // proof id -> examined bundle id
	ring    []memoSlot           // filled to cap and then overwritten oldest first
	next    int                  // ring slot of the oldest entry once the ring is full
}

type memoEntry struct {
	bundle string
	gen    uint64
}

type memoSlot struct {
	proof string
	gen   uint64
}

func newBundleMemo(cap int) *bundleMemo {
	return &bundleMemo{cap: cap, byProof: map[string]memoEntry{}}
}

// has reports whether exactly this bundle of the proof was examined.
func (m *bundleMemo) has(proof, bundle string) bool {
	e, ok := m.byProof[proof]
	return ok && bundle != "" && e.bundle == bundle
}

// put remembers the bundle as the proof's examined one, evicting the oldest remembered proof when the memo is full.
func (m *bundleMemo) put(proof, bundle string) {
	if e, ok := m.byProof[proof]; ok {
		e.bundle = bundle
		m.byProof[proof] = e
		return
	}
	m.gen++
	slot := memoSlot{proof: proof, gen: m.gen}
	if len(m.ring) < m.cap {
		m.ring = append(m.ring, slot)
	} else {
		old := m.ring[m.next]
		if e, ok := m.byProof[old.proof]; ok && e.gen == old.gen {
			delete(m.byProof, old.proof)
		}
		m.ring[m.next] = slot
		m.next = (m.next + 1) % m.cap
	}
	m.byProof[proof] = memoEntry{bundle: bundle, gen: slot.gen}
}

// forget drops a proof (it holds an execution proof now, or it completed). Its ring slot stays until it comes round, and evicts
// nothing then: the generation it carries no longer matches an entry.
func (m *bundleMemo) forget(proof string) { delete(m.byProof, proof) }

func (m *bundleMemo) len() int { return len(m.byProof) }
