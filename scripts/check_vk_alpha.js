const { ethers } = require('ethers');
const fs = require('fs');

const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const BLS_VERIFIER_ADDRESS = '0x631B6444216b981561034655349F8a28962DcC5F';

// Load local verification key
const localVK = JSON.parse(fs.readFileSync('../bls_zk_keys/verification_key.json', 'utf8'));

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  
  console.log('Reading VK Storage Directly...\n');
  console.log('Contract:', BLS_VERIFIER_ADDRESS);
  console.log('');
  
  // The VerificationKey struct is stored in storage
  // vk is at slot index 0 (since it's the first state var that's a struct)
  // alpha1_x is the first field
  
  // Read storage slots directly
  // vk struct starts at slot 0
  const alpha1_x = await provider.getStorage(BLS_VERIFIER_ADDRESS, 0);
  const alpha1_y = await provider.getStorage(BLS_VERIFIER_ADDRESS, 1);
  
  // Convert to BigInt
  const contractAlpha1X = BigInt(alpha1_x);
  const contractAlpha1Y = BigInt(alpha1_y);
  
  console.log('Contract Alpha1:');
  console.log('  X:', contractAlpha1X.toString());
  console.log('  Y:', contractAlpha1Y.toString());
  
  console.log('\nLocal Alpha1:');
  console.log('  X:', localVK.alpha1[0].toString());
  console.log('  Y:', localVK.alpha1[1].toString());
  
  // Compare
  const xMatch = contractAlpha1X.toString() === localVK.alpha1[0].toString();
  const yMatch = contractAlpha1Y.toString() === localVK.alpha1[1].toString();
  
  console.log('\n===== RESULT =====');
  if (xMatch && yMatch) {
    console.log('✓ Alpha1 MATCHES - Verification keys are synchronized');
    console.log('  The local proving key should work with the deployed VK');
  } else {
    console.log('✗ Alpha1 MISMATCH - Verification keys do NOT match!');
    console.log('');
    console.log('  Contract has different VK than local files.');
    console.log('  Options:');
    console.log('    1. Update contract with local VK: run deploy_vk.js');
    console.log('    2. Or regenerate local keys to match contract');
  }
}

main().catch(console.error);
