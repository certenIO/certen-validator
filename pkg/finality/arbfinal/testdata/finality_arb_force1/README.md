# finality_arb_force1 - the real owner force-confirmation, judged at the classifier level

See fixture.json. Inputs: the raw confirmation transaction and receipt of tx 0x350518a9...cc16 (Sepolia block 9404699, index 89), the six trie nodes that prove them under the header roots, and the header. The classifier (spec 5.7 O4, pkg/finality/arbfinal.classifyConfirmation) must return `expect` byte for byte. The TypeScript classifier consumes a byte-identical copy.
