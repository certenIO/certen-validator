const { ethers } = require('ethers');
const fs = require('fs');

const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const BLS_VERIFIER_ADDRESS = '0x631B6444216b981561034655349F8a28962DcC5F';

// Load local verification key
const localVK = JSON.parse(fs.readFileSync('../bls_zk_keys/verification_key.json', 'utf8'));

// Contract ABI for reading VK storage
const ABI = [
  'function vk() view returns (uint256 alpha1_x, uint256 alpha1_y, uint256[2] beta2_x, uint256[2] beta2_y, uint256[2] gamma2_x, uint256[2] gamma2_y, uint256[2] delta2_x, uint256[2] delta2_y)',
  'function vkInitialized() view returns (bool)'
];

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const contract = new ethers.Contract(BLS_VERIFIER_ADDRESS, ABI, provider);
  
  console.log('Comparing Verification Keys...\n');
  console.log('Contract:', BLS_VERIFIER_ADDRESS);
  console.log('');
  
  try {
    const vkInit = await contract.vkInitialized();
    console.log('VK Initialized:', vkInit);
    
    if (!vkInit) {
      console.log('\nERROR: Verification key not set on contract!');
      console.log('Need to run deploy_vk.js to set the verification key.');
      return;
    }
    
    // Read the vk struct
    const vk = await contract.vk();
    
    console.log('\nContract Alpha1:');
    console.log('  X:', vk.alpha1_x.toString().substring(0, 30) + '...');
    console.log('  Y:', vk.alpha1_y.toString().substring(0, 30) + '...');
    
    console.log('\nLocal Alpha1:');
    console.log('  X:', localVK.alpha1[0].toString().substring(0, 30) + '...');
    console.log('  Y:', localVK.alpha1[1].toString().substring(0, 30) + '...');
    
    // Compare
    const alpha1Match = vk.alpha1_x.toString() === localVK.alpha1[0].toString() &&
                        vk.alpha1_y.toString() === localVK.alpha1[1].toString();
    
    console.log('\n===== RESULT =====');
    if (alpha1Match) {
      console.log('✓ Alpha1 MATCHES - VK likely matches');
    } else {
      console.log('✗ Alpha1 MISMATCH - VK does NOT match!');
      console.log('');
      console.log('FIX: Run the deploy_vk.js script to update the contract VK');
    }
    
  } catch (err) {
    console.log('Error:', err.message);
    
    // Try reading storage directly
    console.log('\nTrying direct storage read...');
    
    // Storage slot 0 should have vk data
    const slot0 = await provider.getStorage(BLS_VERIFIER_ADDRESS, 0);
    console.log('Slot 0:', slot0);
  }
}

main();
