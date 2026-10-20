// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// The official light_client vectors of ethereum/consensus-specs release v1.7.0-beta.4 (the vectors moved from
// ethereum/consensus-spec-tests to the consensus-specs release assets: general, mainnet, minimal, comptests .tar.gz). The
// committed subset under testdata/official/v1.7.0-beta.4 has the layout of the release (tests/<preset>/<fork>/light_client/...) and
// holds the single_merkle_proof, sync and update_ranking cases of the electra, fulu, gloas and heze forks (the mainnet-preset
// objects are fetched, not committed; their proof.yaml and manifest.yaml are). CERTEN_CS_TESTS names a full extraction (see
// testdata/official/fetch.sh); the same tests then run over every file.

const officialCommitted = "testdata/official/v1.7.0-beta.4"

func officialRoot() (root string, full bool) {
	if p := os.Getenv("CERTEN_CS_TESTS"); p != "" {
		return p, true
	}
	return officialCommitted, false
}

// snappyDecode decodes a raw snappy BLOCK (the format of every .ssz_snappy file of the consensus-spec vectors): a uvarint
// decoded length, then literal and copy elements. No dependency: this is the whole format.
func snappyDecode(src []byte) ([]byte, error) {
	dLen, n := binary.Uvarint(src)
	if n <= 0 || dLen > 1<<30 {
		return nil, errors.New("snappy: bad preamble")
	}
	dst := make([]byte, 0, dLen)
	s := n
	for s < len(src) {
		tag := src[s]
		s++
		var length, offset int
		switch tag & 3 {
		case 0: // literal
			length = int(tag >> 2)
			if length < 60 {
				length++
			} else {
				extra := length - 59 // 60 -> 1 byte ... 63 -> 4 bytes
				if s+extra > len(src) {
					return nil, errors.New("snappy: truncated literal length")
				}
				length = 0
				for i := 0; i < extra; i++ {
					length |= int(src[s+i]) << (8 * uint(i))
				}
				length++
				s += extra
			}
			if length <= 0 || s+length > len(src) {
				return nil, errors.New("snappy: literal overruns the input")
			}
			dst = append(dst, src[s:s+length]...)
			s += length
			continue
		case 1: // copy with a 1-byte offset
			if s+1 > len(src) {
				return nil, errors.New("snappy: truncated copy1")
			}
			length = 4 + int(tag>>2)&7
			offset = int(tag>>5)<<8 | int(src[s])
			s++
		case 2: // copy with a 2-byte offset
			if s+2 > len(src) {
				return nil, errors.New("snappy: truncated copy2")
			}
			length = 1 + int(tag>>2)
			offset = int(binary.LittleEndian.Uint16(src[s:]))
			s += 2
		case 3: // copy with a 4-byte offset
			if s+4 > len(src) {
				return nil, errors.New("snappy: truncated copy4")
			}
			length = 1 + int(tag>>2)
			offset = int(binary.LittleEndian.Uint32(src[s:]))
			s += 4
		}
		if offset <= 0 || offset > len(dst) {
			return nil, errors.New("snappy: copy offset out of range")
		}
		for i := 0; i < length; i++ { // may overlap its own output
			dst = append(dst, dst[len(dst)-offset])
		}
	}
	if uint64(len(dst)) != dLen {
		return nil, fmt.Errorf("snappy: decoded %d bytes, preamble says %d", len(dst), dLen)
	}
	return dst, nil
}

func TestSnappyBlockDecoder(t *testing.T) {
	// literal only: "hello"
	lit := append([]byte{5, (5 - 1) << 2}, []byte("hello")...)
	if got, err := snappyDecode(lit); err != nil || string(got) != "hello" {
		t.Fatalf("literal: %q %v", got, err)
	}
	// "abcd" then copy1 of length 6 at offset 4 (overlapping): "abcdabcdab"
	c1 := []byte{10, 3 << 2, 'a', 'b', 'c', 'd', 0x01 | (6-4)<<2, 4}
	if got, err := snappyDecode(c1); err != nil || string(got) != "abcdabcdab" {
		t.Fatalf("copy1: %q %v", got, err)
	}
	// copy2: literal "xyz", copy of 3 at offset 3 -> "xyzxyz"
	c2 := []byte{6, 2 << 2, 'x', 'y', 'z', 0x02 | (3-1)<<2, 3, 0}
	if got, err := snappyDecode(c2); err != nil || string(got) != "xyzxyz" {
		t.Fatalf("copy2: %q %v", got, err)
	}
	// a 70-byte literal uses the one-extra-byte length form (tag 60<<2)
	long := bytes.Repeat([]byte{7}, 70)
	l := append([]byte{70, 60 << 2, 69}, long...)
	if got, err := snappyDecode(l); err != nil || !bytes.Equal(got, long) {
		t.Fatalf("long literal: %v", err)
	}
	// refusals: bad offset, wrong preamble length, truncated literal
	for name, bad := range map[string][]byte{
		"offset beyond output": {4, 0x01, 9},
		"preamble too short":   {9, 2 << 2, 'x', 'y', 'z'},
		"truncated literal":    {5, 4 << 2, 'h', 'e'},
		"empty":                {},
	} {
		if _, err := snappyDecode(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type officialProof struct {
	Leaf      string   `yaml:"leaf"`
	LeafIndex uint64   `yaml:"leaf_index"`
	Branch    []string `yaml:"branch"`
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var a [32]byte
	copy(a[:], b)
	return a
}

// foldBranch folds a leaf up its branch at gindex (the plain Phase 0 is_valid_merkle_branch construction).
func foldBranch(leaf [32]byte, branch [][32]byte, gindex uint64) [32]byte {
	v := leaf
	for i := range branch {
		if (gindex>>uint(i))&1 == 1 {
			v = sha2(branch[i][:], v[:])
		} else {
			v = sha2(v[:], branch[i][:])
		}
	}
	return v
}

// TestOfficialSingleMerkleProof checks, for the electra, fulu, gloas and heze forks of both presets, that the generalized index of
// every light-client proof the official vectors carry is the one this verifier uses for the layout (169/86/87 and 25 for the electra
// layout; 735/2945/2946 and 2856 for the gloas layout), that the branch has floorlog2(index) nodes, and that the three BeaconState
// proofs of one fork (current committee, next committee, finality root), which the vectors derive from ONE state object, fold to
// the SAME state root: the branches of independent proofs meet only if the gindices and every sibling node are right.
// Remaining part of RB11-C1B deliverable D: binding that root to hash_tree_root(object), which needs a generic SSZ merkleizer for the
// BeaconState and BeaconBlockBody of each fork.
func TestOfficialSingleMerkleProof(t *testing.T) {
	root, full := officialRoot()
	forks := map[string]Layout{"electra": LayoutElectra, "fulu": LayoutElectra, "gloas": LayoutGloas, "heze": LayoutGloas}
	run, bodies, states := 0, 0, 0
	for _, preset := range []string{"mainnet", "minimal"} {
		for _, fork := range []string{"electra", "fulu", "gloas", "heze"} {
			base := filepath.Join(root, "tests", preset, fork, "light_client", "single_merkle_proof")
			if _, err := os.Stat(base); err != nil {
				continue
			}
			layout := forks[fork] // heze has no layout of its own in the Sepolia pins: its body vector carries the Gloas constant 2856
			roots := map[string][32]byte{}
			for _, suite := range []string{"BeaconState", "BeaconBlockBody"} {
				dirs, _ := filepath.Glob(filepath.Join(base, suite, "*"))
				sort.Strings(dirs)
				for _, d := range dirs {
					raw, err := os.ReadFile(filepath.Join(d, "proof.yaml"))
					if err != nil {
						t.Fatalf("%s: %v", d, err)
					}
					var p officialProof
					if err := yaml.Unmarshal(raw, &p); err != nil {
						t.Fatalf("%s: %v", d, err)
					}
					name := filepath.Base(d)
					var wantG uint64
					switch {
					case suite == "BeaconState" && name == "current_sync_committee_merkle_proof":
						wantG = gindicesOf(layout).current
					case suite == "BeaconState" && name == "next_sync_committee_merkle_proof":
						wantG = gindicesOf(layout).next
					case suite == "BeaconState" && name == "finality_root_merkle_proof":
						wantG = gindicesOf(layout).finalized
					case suite == "BeaconBlockBody" && name == "execution_merkle_proof" && layout == LayoutElectra:
						wantG = gindexExecPayloadInBody
					case suite == "BeaconBlockBody" && name == "execution_block_hash_merkle_proof" && layout == LayoutGloas:
						wantG = gindexExecHashGloas
					default:
						t.Errorf("%s/%s/%s/%s: unknown proof", preset, fork, suite, name)
						continue
					}
					t.Run(preset+"/"+fork+"/"+suite+"/"+name, func(t *testing.T) {
						if p.LeafIndex != wantG {
							t.Fatalf("leaf_index %d, this verifier uses %d", p.LeafIndex, wantG)
						}
						if len(p.Branch) != floorLog2(p.LeafIndex) {
							t.Fatalf("branch of %d nodes for gindex %d (depth %d)", len(p.Branch), p.LeafIndex, floorLog2(p.LeafIndex))
						}
						br := make([][32]byte, len(p.Branch))
						for i, n := range p.Branch {
							br[i] = hex32(t, n)
						}
						r := foldBranch(hex32(t, p.Leaf), br, p.LeafIndex)
						if suite == "BeaconState" {
							roots[name] = r
							states++
						} else {
							bodies++
						}
						// the normalized-branch verifier of this package agrees with the plain fold at the vector's own gindex
						if !IsValidNormalizedMerkleBranch(hex32(t, p.Leaf), br, p.LeafIndex, r) {
							t.Fatal("IsValidNormalizedMerkleBranch rejects the vector's own branch")
						}
						run++
					})
				}
			}
			if len(roots) == 3 {
				a, b, c := roots["current_sync_committee_merkle_proof"], roots["next_sync_committee_merkle_proof"], roots["finality_root_merkle_proof"]
				if a != b || b != c {
					t.Errorf("%s/%s: the three BeaconState proofs of one state fold to different roots %x %x %x", preset, fork, a, b, c)
				}
			}
		}
	}
	t.Logf("single_merkle_proof: %d proofs checked (%d BeaconState, %d BeaconBlockBody) over %s (full extraction: %v)", run, states, bodies, root, full)
	if run < 26 {
		t.Errorf("only %d single_merkle_proof cases found under %s; the committed subset holds 26 (mainnet and minimal, electra, fulu, gloas, heze)", run, root)
	}
}

// TestOfficialObjectsDecode: every .ssz_snappy of the subset (or the full extraction) is a valid snappy block.
func TestOfficialObjectsDecode(t *testing.T) {
	root, _ := officialRoot()
	n, bytesOut := 0, 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".ssz_snappy") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out, err := snappyDecode(b)
		if err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		n++
		bytesOut += len(out)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d snappy objects decoded, %d bytes", n, bytesOut)
	if n == 0 {
		t.Fatal("no .ssz_snappy object found")
	}
}

type officialStep map[string]any

// TestOfficialSyncAndRankingInventory enumerates the sync and update_ranking cases of the electra, fulu and gloas forks (minimal preset: the
// release carries them for no other), decodes each bootstrap, parses steps.yaml and counts the steps. The cases are driven through the production
// walker by TestOfficialSyncVectors (official_sync_test.go) under the minimal preset (SYNC_COMMITTEE_SIZE 32, SLOTS_PER_EPOCH 8,
// EPOCHS_PER_SYNC_COMMITTEE_PERIOD 8); this test asserts the premise of that harness on the decoded bytes: a minimal-preset bootstrap is not a size
// the mainnet-preset layouts of the exported verifier accept, so only the preset parameter makes these objects verifiable.
// update_ranking does not apply: the verifier never chooses between updates.
func TestOfficialSyncAndRankingInventory(t *testing.T) {
	root, _ := officialRoot()
	var sync, ranking int
	steps := map[string]int{}
	for _, fork := range []string{"electra", "fulu", "gloas"} {
		for _, handler := range []string{"sync", "update_ranking"} {
			dirs, _ := filepath.Glob(filepath.Join(root, "tests", "minimal", fork, "light_client", handler, "pyspec_tests", "*"))
			sort.Strings(dirs)
			for _, d := range dirs {
				name := fork + "/" + handler + "/" + filepath.Base(d)
				if handler != "sync" {
					ranking++
					continue
				}
				sync++
				b, err := os.ReadFile(filepath.Join(d, "bootstrap.ssz_snappy"))
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				boot, err := snappyDecode(b)
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				// this verifier's accepted bootstrap sizes are the Gloas 25,472 and the electra minimum 25,648 upward (24,624 bytes of
				// committee); a 32-seat committee is 1,584 bytes
				if len(boot) == LightClientBootstrapSize || len(boot) >= electraMinBootstrap {
					t.Errorf("%s: decoded bootstrap of %d bytes would parse under a mainnet-preset layout; the inventory's premise is wrong", name, len(boot))
				}
				raw, err := os.ReadFile(filepath.Join(d, "steps.yaml"))
				if err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				var st []officialStep
				if err := yaml.Unmarshal(raw, &st); err != nil {
					t.Errorf("%s: %v", name, err)
					continue
				}
				for _, s := range st {
					for k := range s {
						steps[k]++
					}
				}
			}
		}
	}
	t.Logf("sync cases: %d (steps by kind: %v); update_ranking cases: %d (ranking does not apply: this verifier never chooses between updates, the prover supplies the chain)", sync, steps, ranking)
	if sync != 15 || ranking != 3 {
		t.Errorf("expected 15 sync and 3 update_ranking cases for electra/fulu/gloas, found %d and %d", sync, ranking)
	}
}

// TestOfficialCommittedSubsetMatchesItsManifest: the committed subset is exactly the files of MANIFEST.sha256 (sha256, two spaces, path).
func TestOfficialCommittedSubsetMatchesItsManifest(t *testing.T) {
	mf, err := os.ReadFile(filepath.Join(officialCommitted, "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(mf)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("bad manifest line %q", line)
		}
		b, err := os.ReadFile(filepath.Join(officialCommitted, filepath.FromSlash(parts[1])))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != parts[0] {
			t.Errorf("%s: sha256 differs from the manifest", parts[1])
		}
		listed[parts[1]] = true
	}
	_ = filepath.Walk(officialCommitted, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(officialCommitted, p)
			rel = filepath.ToSlash(rel)
			if rel != "MANIFEST.sha256" && !listed[rel] {
				t.Errorf("%s is in the committed subset but not in the manifest", rel)
			}
		}
		return nil
	})
	t.Logf("%d files in the committed official subset", len(listed))
}

// ---- the execution payload leaf of the official BeaconBlockBody proofs

var zeroHashes = func() [][32]byte {
	z := make([][32]byte, 40)
	for i := 1; i < len(z); i++ {
		z[i] = sha2(z[i-1][:], z[i-1][:])
	}
	return z
}()

// merkleizeLimit is SSZ merkleize(chunks, limit): the chunks zero-padded to the next power of two of limit (virtual zero subtrees).
func merkleizeLimit(chunks [][32]byte, limit uint64) [32]byte {
	depth := 0
	for uint64(1)<<uint(depth) < limit {
		depth++
	}
	layer := append([][32]byte(nil), chunks...)
	for d := 0; d < depth; d++ {
		if len(layer)%2 == 1 {
			layer = append(layer, zeroHashes[d])
		}
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = sha2(layer[2*i][:], layer[2*i+1][:])
		}
		layer = next
	}
	if len(layer) == 0 {
		return zeroHashes[depth]
	}
	return layer[0]
}

func mixInLength(root [32]byte, n uint64) [32]byte {
	var l [32]byte
	binary.LittleEndian.PutUint64(l[:8], n)
	return sha2(root[:], l[:])
}

func chunksOf(b []byte) [][32]byte {
	var out [][32]byte
	for i := 0; i < len(b); i += 32 {
		var c [32]byte
		copy(c[:], b[i:])
		out = append(out, c)
	}
	return out
}

// TestOfficialExecutionPayloadLeaf closes the loop on hash_tree_root(ExecutionPayloadHeader): the execution_merkle_proof vectors of
// the electra and fulu forks carry the official leaf = hash_tree_root(body.execution_payload). The test parses the payload out of
// the vector's own BeaconBlockBody, builds the ExecutionPayloadHeader from it (transactions and withdrawals replaced by their list
// roots), and requires executionHeaderRoot, the function the verifier uses for every electra-layout header, to return the leaf.
func TestOfficialExecutionPayloadLeaf(t *testing.T) {
	root, _ := officialRoot()
	checked := 0
	for _, preset := range []string{"mainnet", "minimal"} {
		syncAgg, maxWithdrawals := 160, uint64(16)
		if preset == "minimal" {
			syncAgg, maxWithdrawals = 4+96, 4
		}
		for _, fork := range []string{"electra", "fulu"} {
			d := filepath.Join(root, "tests", preset, fork, "light_client", "single_merkle_proof", "BeaconBlockBody", "execution_merkle_proof")
			objRaw, err := os.ReadFile(filepath.Join(d, "object.ssz_snappy"))
			if err != nil {
				continue // the mainnet objects are fetched, not committed
			}
			body, err := snappyDecode(objRaw)
			if err != nil {
				t.Fatal(err)
			}
			var p officialProof
			pr, _ := os.ReadFile(filepath.Join(d, "proof.yaml"))
			if err := yaml.Unmarshal(pr, &p); err != nil {
				t.Fatal(err)
			}
			at := 96 + 72 + 32 + 5*4 + syncAgg // execution_payload offset in the fixed part of the electra/fulu BeaconBlockBody
			start, end := int(binary.LittleEndian.Uint32(body[at:])), int(binary.LittleEndian.Uint32(body[at+4:]))
			pl := body[start:end]
			if len(pl) < 528 {
				t.Fatalf("%s/%s: payload of %d bytes", preset, fork, len(pl))
			}
			offExtra, offTx, offWd := int(binary.LittleEndian.Uint32(pl[436:])), int(binary.LittleEndian.Uint32(pl[504:])), int(binary.LittleEndian.Uint32(pl[508:]))
			if offExtra != 528 || offTx < offExtra || offWd < offTx || offWd > len(pl) {
				t.Fatalf("%s/%s: payload offsets %d %d %d (len %d)", preset, fork, offExtra, offTx, offWd, len(pl))
			}
			extra, txs, wds := pl[offExtra:offTx], pl[offTx:offWd], pl[offWd:]
			// transactions: List[ByteList[2^30], 2^20]
			var txRoots [][32]byte
			if len(txs) > 0 {
				n := int(binary.LittleEndian.Uint32(txs)) / 4
				for i := 0; i < n; i++ {
					a := int(binary.LittleEndian.Uint32(txs[4*i:]))
					b := len(txs)
					if i+1 < n {
						b = int(binary.LittleEndian.Uint32(txs[4*(i+1):]))
					}
					txRoots = append(txRoots, mixInLength(merkleizeLimit(chunksOf(txs[a:b]), 1<<25), uint64(b-a)))
				}
			}
			txRoot := mixInLength(merkleizeLimit(txRoots, 1<<20), uint64(len(txRoots)))
			// withdrawals: List[Withdrawal(index u64, validator_index u64, address 20, amount u64), MAX_WITHDRAWALS_PER_PAYLOAD]
			if len(wds)%44 != 0 {
				t.Fatalf("%s/%s: withdrawals of %d bytes", preset, fork, len(wds))
			}
			var wdRoots [][32]byte
			for i := 0; i < len(wds)/44; i++ {
				w := wds[44*i : 44*i+44]
				var leaves [4][32]byte
				copy(leaves[0][:], w[0:8])
				copy(leaves[1][:], w[8:16])
				copy(leaves[2][:], w[16:36])
				copy(leaves[3][:], w[36:44])
				wdRoots = append(wdRoots, merkleizeLimit(leaves[:], 4))
			}
			wdRoot := mixInLength(merkleizeLimit(wdRoots, maxWithdrawals), uint64(len(wdRoots)))
			hdr := make([]byte, electraExecFixed, electraExecFixed+len(extra))
			copy(hdr[0:436], pl[0:436])
			binary.LittleEndian.PutUint32(hdr[436:], electraExecFixed)
			copy(hdr[440:504], pl[440:504]) // base_fee_per_gas, block_hash
			copy(hdr[504:536], txRoot[:])
			copy(hdr[536:568], wdRoot[:])
			copy(hdr[568:584], pl[512:528]) // blob_gas_used, excess_blob_gas
			hdr = append(hdr, extra...)
			if got, want := executionHeaderRoot(hdr), hex32(t, p.Leaf); got != want {
				t.Errorf("%s/%s: executionHeaderRoot = %x, the official leaf is %x (%d txs, %d withdrawals, %d bytes of extra_data)", preset, fork, got, want, len(txRoots), len(wdRoots), len(extra))
			}
			t.Logf("%s/%s: official leaf reproduced from the vector's payload (%d txs, %d withdrawals, %d bytes of extra_data)", preset, fork, len(txRoots), len(wdRoots), len(extra))
			checked++
		}
	}
	if checked < 2 {
		t.Errorf("only %d execution_merkle_proof objects found (the committed minimal electra and fulu objects must be there)", checked)
	}
}
