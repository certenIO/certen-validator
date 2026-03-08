/**
 * Generate BLS Public Keys for Validators
 *
 * This generates deterministic BLS keys matching the Go code's key derivation:
 *   seed = sha256("CERTEN_BLS_KEY_V1:{validatorID}:{chainID}")
 *
 * The keys are compatible with the BLS12-381 curve used in the certen validator.
 */

const { bls12_381 } = require('@noble/curves/bls12-381');
const { sha256 } = require('@noble/hashes/sha256');
const { ethers } = require('ethers');

// Configuration - Must match docker-compose.yml
const CHAIN_ID = 'certen-testnet';
const VALIDATORS = [
  { name: 'validator-1', ethAddress: '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8' },
  { name: 'validator-2', ethAddress: '0x518273099F5c4b87eEA65141931B78012dfE5c7d' },
  { name: 'validator-3', ethAddress: '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6' },
  { name: 'validator-4', ethAddress: '0x6Ff54041Afef809e93ce6B570545069d2764783f' },
  { name: 'validator-5', ethAddress: '0x9eaA84E3D31479eCC9130187DA9f962625e8C271' },
  { name: 'validator-6', ethAddress: '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf' },
  { name: 'validator-7', ethAddress: '0x0D786D587aBe92f1031506fF3eF88c79a93A8962' }
];

/**
 * Generate BLS key pair from seed (matches Go implementation)
 */
function generateBLSKeyFromSeed(seed) {
  // The seed is used directly as the secret key scalar (mod r)
  // We need to ensure it's a valid scalar in the BLS12-381 field
  const privateKey = bls12_381.G1.normPrivateKeyToScalar(seed);
  const publicKey = bls12_381.G1.ProjectivePoint.fromPrivateKey(privateKey);

  return {
    privateKeyHex: '0x' + Buffer.from(seed).toString('hex'),
    publicKeyHex: '0x' + publicKey.toHex(true),  // compressed
    publicKeyUncompressedHex: '0x' + publicKey.toHex(false)  // uncompressed (for contract)
  };
}

/**
 * Derive BLS key from validator ID and chain ID (matches Go GenerateFromValidatorID)
 */
function deriveBLSKey(validatorID, chainID) {
  const message = `CERTEN_BLS_KEY_V1:${validatorID}:${chainID}`;
  const seed = sha256(new TextEncoder().encode(message));
  return generateBLSKeyFromSeed(seed);
}

async function main() {
  console.log('='.repeat(70));
  console.log('Generate Validator BLS Keys');
  console.log('='.repeat(70));
  console.log('');
  console.log('Chain ID:', CHAIN_ID);
  console.log('');

  const results = [];

  for (const v of VALIDATORS) {
    const keys = deriveBLSKey(v.name, CHAIN_ID);

    console.log(`[${v.name}]`);
    console.log(`  ETH Address: ${v.ethAddress}`);
    console.log(`  BLS PubKey (compressed): ${keys.publicKeyHex}`);
    console.log(`  BLS PubKey Length: ${(keys.publicKeyHex.length - 2) / 2} bytes`);
    console.log('');

    results.push({
      name: v.name,
      address: v.ethAddress,
      votingPower: '100n',
      blsPublicKey: keys.publicKeyHex
    });
  }

  // Output as JavaScript for update_validator_bls_keys.js
  console.log('='.repeat(70));
  console.log('Copy this to update_validator_bls_keys.js:');
  console.log('='.repeat(70));
  console.log('');
  console.log('const VALIDATORS = [');
  for (const r of results) {
    console.log('  {');
    console.log(`    name: '${r.name}',`);
    console.log(`    address: '${r.address}',`);
    console.log(`    votingPower: ${r.votingPower},`);
    console.log(`    blsPublicKey: '${r.blsPublicKey}'`);
    console.log('  },');
  }
  console.log('];');
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
