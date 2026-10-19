package proofv2_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// certify1F51 is the sha256 of every document of the F5-1 anchored-certify suite as validator 3fdd056 merged it (that commit's manifest.json).
// V-J J3 / RB9-F5 invariant 3: these bytes never move. Evidence 2.1 is unreleased and the verifier has since required more of a 2.1 document
// (the genesis link of F5-3, the update window of F5-3b), so some of these documents are now refused where the F5-1 verifier verified them;
// the files stay as they were, their expectations in the manifest say what the current verifier does, and the regenerated documents are new
// vectors beside them (the "-g" names).
var certify1F51 = map[string]string{
	"continuous-chain-verified":                            "b718fad48518de8dc8637f6447f083e2ea5dcb7180ffe54a2dd1c37901697331",
	"anchored-chain-verified":                              "560403f135b730e40b8e42360bd6f08341bb8c0d6e4814f861486e2100f5670b",
	"mixed-chain-verified":                                 "b4915f1fae6d0011b3eae9ceab3bb442e3e1aafa9f99f6dff2625b9d82cc73c4",
	"anchored-final-only-verified":                         "62b1a4c9516d5cfcf576840dae420ddaabf2870afdf4c510782138e2783dc365",
	"link-absent":                                          "2f44b85b99e194491f656555ae4d758e09ea0fe66deddd4d26f553fb20bb0ba3",
	"link-start-altered":                                   "7a89d3f5b463a95d8b5a35af4a5f72591597ff7d0aa225b8c667b98c0f28c71c",
	"link-end-altered":                                     "2af029d96f5466c94dac88f69a9a9227602ac49bd4f4a2af4f40e68fcccbabb7",
	"link-step-altered":                                    "c071129eb1aefc30aa84542c8116233ef295d4e49f1a463ff13c0bc0a83fa9c2",
	"link-of-a-different-item":                             "dea245ba06677f17f6e581b2c429f2f2a26856f27e68d6b7053e3bc8ef4e9c63",
	"link-surplus":                                         "740ce12de6f7aa80de181fd2d01059c264a192a962574d6088ce594c1c186eda",
	"link-of-the-second-item-missing":                      "9b446698412d983873f37a6074ee13757149fc390248b2144e4189110cea94b4",
	"anchored-item-without-update-not-last":                "f017e1ffa2b51927438d24e584f7f6c944c8f986f91138abc29d48cb88e074ce",
	"anchored-item-with-only-an-unapplied-update-not-last": "11e2006adda65a2ed3cacb12b185e697912c9a6ff77c8bec986f59bd146b8bc0",
	"non-monotone-block":                                   "4be9ceda79fcfd6e9bc38305baa64320ecb5a76635c5b191f70d9d6e7aff6d44",
	"duplicated-update":                                    "42b7bc3b2040cf19bb828bdad881e3fd4a447ba26832da13369fb6379b64466f",
	"continuous-item-wrongly-rooted-then-anchored":         "cf394e10ed3803e494f02a3f441104750f825ca368da48f4c803b37b6544b025",
	"anchored-then-continuous-item-wrongly-rooted":         "2d10ed47f1cfa79ba6762016716a2057dacec3e63aab5054ed16c93e1974ea95",
	"anchor-of-another-chain-genuinely-signed":             "42ac383413bccf484b88f91addf355d978554ba1a979d0082b752989c99e7df6",
	"anchor-re-rooted-off-the-verified-root":               "a7f14920653480b9c7a7b9f6566eeb0268e327d87ceb333d65758b4e75fc8df7",
	"anchor-of-another-incarnation":                        "70757388f7e975c64e460ba35a623756e23c95f8f23e0377c4977ff8d203f92a",
	"root-proof-null-is-absent":                            "8bc6ca827651424310a93021e410c9317455c764fd798af0a6deb7d86b976a26",
	"root-proof-empty-object":                              "e2e0c166757dbdcf17727a841c38528d9600aea1926d8894d2173a90c564024d",
	"root-proof-merkle-state-only":                         "8a453804c69e3646f7fccbf3399e3347948cabf85904e7f0c9664d2330cdda08",
	"record-with-an-unknown-trailing-field":                "d88be9ebb6567634095afe629996ab45c64ff124a583cc1733cb34bc9edb70df",
	"link-with-an-unknown-trailing-field":                  "956bd983cd7c0107ba592fe1da07eae8f455074079a63037a65bd81b64178fce",
	"link-undecodable-before-an-earlier-items-refusal":     "c329eecf152c28baf5a30483b54526ac1af38a1ebf46a6134606b46d8eedd15b",
	"hops-anchored-verified":                               "f542adb05f61ed07d7d6fe1241f67597ef4fc356f6fe3dc72017fa7bb73f5b94",
	"hop-link-absent":                                      "dcae2cd254aca09fd84f32b280f66ab4d5ad353a89dcc2e41661d551f1c52ee7",
	"hop-link-start-altered":                               "509d756543105de484bb7915eb8d903d8a4da3010ef75e77b280aa12fb458859",
	"hop-anchored-item-without-update-not-last":            "b7fb40aff4242a1cf85d08429a0a88f8535db5b4812c6d02dea66f322949085a",
	"hop-duplicated-update":                                "01753d5090c0e381625c45c11abaf6c3f6798a01714e9a35ddcbf3ff735387f0",
	"anchored-item-in-an-evidence-2.0-document":            "1596c11e6bb7a85704f7ac42c0d9b8448782e40ebda7b9141228ae4148766eef",
	"links-member-in-an-evidence-2.0-document":             "10f4676c9fae48a13038ec694045a9f1d0d24be7727f71689f3b7b9b7b8d3439",
}

// A frozen F5-1 document is the F5-1 document, byte for byte, under its original name; its manifest entry carries the pinned hash and says
// whether its verdict moved and why; a vector that is not frozen is never named like one.
func TestCertify1FrozenF51DocumentsKeepTheirBytes(t *testing.T) {
	dir := filepath.Join("testdata", "certify1")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Cases []struct {
			Name   string `json:"name"`
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
			Note   string `json:"note"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	entries := map[string]int{}
	for i, c := range m.Cases {
		entries[c.Name] = i
	}
	moved := 0
	for name, pin := range certify1F51 {
		b, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatalf("%s: a frozen F5-1 document is gone: %v", name, err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != pin {
			t.Fatalf("%s: the document hashes to %x, not the F5-1 document's %s: a frozen vector was regenerated", name, sum, pin)
		}
		i, ok := entries[name]
		if !ok || m.Cases[i].SHA256 != pin || m.Cases[i].File != name+".json" {
			t.Fatalf("%s: the manifest does not list the frozen document under its name with its pinned hash", name)
		}
		if note := m.Cases[i].Note; note != "" {
			if !strings.HasPrefix(note, "frozen F5-1 document; verdict ") {
				t.Fatalf("%s: note %q", name, note)
			}
			if _, sibling := entries[name+"-g"]; !sibling {
				t.Fatalf("%s: a frozen document whose regenerated document is another file has no sibling %s-g", name, name)
			}
			moved++
		} else if _, sibling := entries[name+"-g"]; sibling {
			t.Fatalf("%s: has a regenerated sibling but no note on the frozen entry", name)
		}
	}
	if len(certify1F51) != 33 || moved != 31 {
		t.Fatalf("%d frozen documents, %d with a note; the F5-1 suite had 33, of which 31 were regenerated by F5-3/F5-3b", len(certify1F51), moved)
	}
	for _, c := range m.Cases {
		if strings.HasSuffix(c.Name, "-g") {
			if _, frozen := certify1F51[strings.TrimSuffix(c.Name, "-g")]; !frozen {
				t.Fatalf("%s: a regenerated sibling of no frozen vector", c.Name)
			}
		}
	}
}
