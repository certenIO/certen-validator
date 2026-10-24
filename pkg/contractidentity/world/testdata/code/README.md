# Real code bytes of the world builder

Every `*.template.hex` is the RUNTIME code a live chain serves (`cast code <address> --rpc-url <manifest chains[].rpc>`, 2026-10-23), with every
immutable reference range of the build ZEROED (the manifest maskRule), so its keccak256 is exactly the manifest `maskedKeccak` of the build. The world
builder fills the immutables of its own chain and account into a copy (`world.Fill`); `TestTemplatesAreThePinnedRuntime` re-derives each masked keccak and
length against the manifest (certen-contracts origin/pv2/rb12-manifest-1-1 @991de99, manifest sha256 ee7d56fac3d2a73fa11d546a6e61f1ae2f574b4812dd5e5a40428fb55524d104).
`CertenAccountV7_3.r5.creation.hex` is the account creation code (the CREATE2 input of step 8): sha256 and keccak256 equal the manifest creationArtifacts and
builds[].creation rows. A manifest re-sync that changes a build row needs these files refreshed (re-run the fetch, the test names the file).

| file | build | kind | source | bytes | masked keccak256 (manifest) | file sha256 |
|---|---|---|---|---|---|---|
| CertenAnchorV8_2.r5.template.hex | CertenAnchorV8_2/r5 | runtime | 11155111 0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c | 24337 | 0x5cdb02a069047ceeb9eb66cec304bf0aa1186b2ef86dd6e7e5b2b740d3494e6b | ed33567234db127c1ab51d3c25991385148c938fd0b6397f5ba9907656dc1b65 |
| BLSZKVerifierV2_1.r5.template.hex | BLSZKVerifierV2_1/r5 | runtime | 11155111 0x25ebFbC617e777Ae983a2C22E3B9649E3EB93802 | 3770 | 0x28fd6a57876405c2352e57033782edc33d527565b2c96e61661df6e1985eac8e | f5f20697e50a93073a986b35327c71aa7a2235ef6c4b0a79b48c9fa2d35fc8e0 |
| BLSZKVerifierV2Generated.r7.template.hex | BLSZKVerifierV2Generated/r7 | runtime | 11155111 0x6f9049cdb948bd0B3eDcd8c10E9Ed796C0615100 | 6032 | 0xee840ce838b5ab2170499f85d0c3dcfedf958eede7ceff0084c1a78ed9fc6a23 | d1291781551e8852f9c72fcd0d64df57f235ee237272a5c4064da1e636151339 |
| BLSZKVerifierV2Generated.r5.template.hex | BLSZKVerifierV2Generated/r5 | runtime | 2017 0x8Fe60CbFE71088be68CEA715874f6595E0d2722f | 6032 | 0x3072caf5ed511102bf1907f9f8442a3154f33112b7703960699a3a83936f7d3a | 8ec6e16132a5c76a0fcd824c87a66ecec3a102aa20c1927fb5def986299c3be4 |
| CertenAccountFactoryV11.r5.template.hex | CertenAccountFactoryV11/r5 | runtime | 11155111 0x8387D061830E10Eb42BC25C2A047631164803F25 | 24306 | 0x03468f871a3de23ffaf14d83ccd0aaea0f81d9ac387ae6a515b780e8f84bf22f | 70307f83b27ab8eaa129409af85c8484b593435c90a5e189219c4cb94ea1d840 |
| CertenAccountV7_3.r5.template.hex | CertenAccountV7_3/r5 | runtime | 11155111 0x2ec2d261a4770e42dbe43826489d299d596bc5f7 | 14562 | 0x305e398509246c1ed898744b21ad194a3e2ef59d322c60ac9c77077f71645f20 | 676ac10e9f73bd6e1d30672bbacce81bdb3399f2c6cda45ecac3ec695ab77bdf |
| CertenAccountV7_3.r5.creation.hex | CertenAccountV7_3/r5 | creation | certen-contracts origin/pv2/rb12-manifest-1-1 @991de99 evm/deployments/identity-bytecode/CertenAccountV7_3.creation.bin | 15757 | 0x3a6434305c261de2d978732e0de33d654a94723e67ffa399847e931c4c89cfd0 | aa2f5ea22cc47e96c8f885b9d020d2ae65fc6be067d3c2e6aa4adf35dd2a460f |

**Unpinned generations (RB12-GOVERIFY-2a WORLD-FIX; live runtime bytes, UNMASKED, `eth_getCode`; used by VS8-046, VS8-047, VS8-070):** keccak256 of the bytes equals the codeHash of the generations evidence row and the masked keccak256 (the row references) equals the row maskedKeccak, tested by `generations_test.go`.

| file | generation row (role, kind) | source | bytes | file sha256 |
|---|---|---|---|---|
| v7_catalogued_base.runtime.hex | account CertenAccountV7 catalogued | 84532 0x0497513411524c4109f5cac62cd599002c2d689b @ 49391270 | 12975 | c23953162c0f45744b404b45b29a3f42c40a035469a6b8befa2194421da119b2 |
| v7_observed_sepolia.runtime.hex | account CertenAccountV7 observed | 11155111 0x0bbfc288b997736365fb22ad46c95044e128ff40 (code is immutable; read at latest, evidence block 11980120) | 12975 | 51a43d1e9704f7e660a9935948eb33d8ca1eab61cd085fa181c534d0311241a4 |
| anchor_v8_1_sepolia.runtime.hex | anchor CertenAnchorV8_1 catalogued | 11155111 0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0 @ 11980120 | 22431 | c26b98508b4ccdd300a222a9d89cbc25bb0e2031534ea666ce39a7de18b4fefa |
