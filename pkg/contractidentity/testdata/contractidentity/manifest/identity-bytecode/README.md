The creation code of the pinned builds: the creationArtifacts rows of ../identity-manifest.json name the files `<Contract>.creation.bin` here (7 files,
copied from certen-contracts origin/pv2/rb12-manifest-1-1 @aef3b65, evm/deployments/identity-bytecode/). Manifest.EmbeddedCreationArtifactBytes checks
length, keccak256 and sha256 of each file against its row before returning the bytes (ErrCreationArtifactMismatch otherwise).
