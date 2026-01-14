What Are These Artifacts?

  The artifacts are raw JSON responses from each v3 API query made during proof construction. Each artifact contains:

  L1_chain_main_by_entry.json (6,342 bytes)

  - The complete response from querying acc://testtesttest10.acme/data1 chain main by entry=057c2fc6...
  - Contains the full Merkle receipt with 9 proof steps
  - Shows the transaction is at index: 1 in the account's main chain
  - Receipt proves inclusion in anchor: f0222b509079f55e3eea189e0d1d24a937687e8c7835e1e461fa9bf6f25d7e1e

  L2_dn_anchor_root_by_entry.json (1,672 bytes)

  - Response from querying dn.acme/anchors chain anchor(bvn1)-root by entry=f0222b...
  - Shows BVN anchor is at index: 210 in DN's anchor sequence
  - Provides receipt proving inclusion in DN witness root 537b1b726b35cd51ec562aa899daaa95932da47a23f4d731ab7f1db832144e28

  L2_dn_anchor_bpt_by_index.json (1,658 bytes)

  - Response from querying anchor(bvn1)-bpt at index: 210
  - Contains the BVN StateTreeAnchor: 37c731848fb94c8d822bc67df80299d69d906cf8bf3e699e522be3c95bf11191
  - Receipt shares same anchor as the root query (pairing invariant)

  L3_dn_self_root_by_entry.json & L3_dn_self_bpt_by_index.json

  - Similar structure for DN self-anchoring at index: 251
  - Provides DN StateTreeAnchor: d83dadf35e1c9f2ac772039d70873eb8502ca6e1644436f462dc638e2da85c77

Artifact Value

  1. Offline Verification

  YES! You can reconstruct and verify the entire proof without making any blockchain queries:
  - All Merkle receipts are included
  - All anchor values are preserved
  - All indices and block heights are recorded

  2. Auditability & Forensics

  - Complete transparency: Anyone can see exactly what data was used
  - Immutable evidence: SHA-256 hash of artifacts creates tamper-evident proof bundle
  - Reproducibility: Others can verify your proof construction logic

  3. Performance Benefits

  - Fast re-verification: No network calls needed
  - Caching: Store proof bundles for repeated verification
  - Bandwidth efficiency: ~11KB total vs repeated API calls

Trust Model Considerations

  With Artifacts (Faster, Auditable)

  Verifier trusts: Artifact provider + Cryptographic integrity
  Verification: Offline Merkle proof validation + consensus binding check

  Without Artifacts (Zero-Trust, Slower)

  Verifier trusts: Only genesis hash + cryptography
  Verification: Live blockchain queries + full proof reconstruction

Practical Use Cases

  1. Legal/Regulatory: Immutable proof bundles for compliance
  2. Performance: Fast verification without blockchain dependency
  3. Archival: Long-term storage of cryptographic proofs
  4. Debugging: Forensic analysis of proof construction
  5. Batch verification: Process many proofs offline

The artifacts transform your proof from "live verification required" to "portable cryptographic evidence" - a significant enhancement for production use!