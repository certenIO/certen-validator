const { ethers } = require('ethers');

const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const BLS_VERIFIER_ADDRESS = '0x631B6444216b981561034655349F8a28962DcC5F';

const ABI = [
  'function vkInitialized() view returns (bool)',
  'function owner() view returns (address)',
  'function totalVerifications() view returns (uint256)',
  'function successfulVerifications() view returns (uint256)',
  'function alpha1_x() view returns (uint256)',
  'function alpha1_y() view returns (uint256)',
  'function numPublicInputs() view returns (uint256)'
];

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const contract = new ethers.Contract(BLS_VERIFIER_ADDRESS, ABI, provider);
  
  console.log('BLS ZK Verifier Contract:', BLS_VERIFIER_ADDRESS);
  console.log('');
  
  try {
    const vkInit = await contract.vkInitialized();
    console.log('VK Initialized:', vkInit);
    
    const owner = await contract.owner();
    console.log('Owner:', owner);
    
    const total = await contract.totalVerifications();
    console.log('Total Verifications:', total.toString());
    
    const successful = await contract.successfulVerifications();
    console.log('Successful Verifications:', successful.toString());
    
    if (vkInit) {
      try {
        const alpha1x = await contract.alpha1_x();
        console.log('Alpha1 X (first 50 chars):', alpha1x.toString().substring(0, 50) + '...');
      } catch (e) {
        console.log('Could not read alpha1_x - storage structure may be different');
      }
      
      try {
        const numInputs = await contract.numPublicInputs();
        console.log('Num Public Inputs:', numInputs.toString());
      } catch (e) {
        console.log('Could not read numPublicInputs');
      }
    }
  } catch (err) {
    console.log('Error:', err.message);
  }
}

main();
