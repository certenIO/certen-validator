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
  
  // Read storage slots directly
  const alpha1_x = await provider.getStorage(BLS_VERIFIER_ADDRESS, 0);
  const alpha1_y = await provider.getStorage(BLS_VERIFIER_ADDRESS, 1);
  
  // Convert to BigInt
  const contractAlpha1X = BigInt(alpha1_x);
  const contractAlpha1Y = BigInt(alpha1_y);
  
  // Convert local values to BigInt as well
  const localAlpha1X = BigInt(localVK.alpha1[0]);
  const localAlpha1Y = BigInt(localVK.alpha1[1]);
  
  console.log('Contract Alpha1:');
  console.log('  X:', contractAlpha1X.toString());
  console.log('  Y:', contractAlpha1Y.toString());
  
  console.log('\nLocal Alpha1:');
  console.log('  X:', localAlpha1X.toString());
  console.log('  Y:', localAlpha1Y.toString());
  
  // Compare using BigInt
  const xMatch = contractAlpha1X === localAlpha1X;
  const yMatch = contractAlpha1Y === localAlpha1Y;
  
  console.log('\n===== RESULT =====');
  if (xMatch && yMatch) {
    console.log('✓ Alpha1 MATCHES - Verification keys are synchronized');
    console.log('  The local proving key should work with the deployed VK');
  } else {
    console.log('✗ Alpha1 MISMATCH');
    console.log('  X match:', xMatch);
    console.log('  Y match:', yMatch);
    console.log('');
    console.log('  Need to update contract VK or regenerate local keys');
  }
}

main().catch(console.error);
