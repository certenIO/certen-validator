const { ethers } = require('ethers');

const RPC_URL = 'https://sepolia.drpc.org';
const CONTRACT_ADDRESS = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';

const ABI = [
  'function validators(address) view returns (bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)',
  'function getValidatorCount() view returns (uint256)',
  'function validatorList(uint256) view returns (address)'
];

const VALIDATOR_ADDRESSES = [
  '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8', // validator-1
  '0x518273099F5c4b87eEA65141931B78012dfE5c7d', // validator-2
  '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6', // validator-3
  '0x6Ff54041Afef809e93ce6B570545069d2764783f', // validator-4
  '0x9eaA84E3D31479eCC9130187DA9f962625e8C271', // validator-5
  '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf', // validator-6
  '0x0D786D587aBe92f1031506fF3eF88c79a93A8962'  // validator-7
];

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);
  
  console.log('Contract:', CONTRACT_ADDRESS);
  console.log('');
  
  try {
    const count = await contract.getValidatorCount();
    console.log('Total registered validators:', count.toString());
  } catch (e) {
    console.log('Could not get validator count:', e.message);
  }
  console.log('');
  
  for (let i = 0; i < VALIDATOR_ADDRESSES.length; i++) {
    const addr = VALIDATOR_ADDRESSES[i];
    console.log(`validator-${i+1}: ${addr}`);
    try {
      const info = await contract.validators(addr);
      console.log(`  registered: ${info.registered}`);
      console.log(`  votingPower: ${info.votingPower}`);
      console.log(`  blsPublicKey: ${info.blsPublicKey}`);
    } catch (e) {
      console.log(`  Error: ${e.message}`);
    }
    console.log('');
  }
}

main().catch(console.error);
