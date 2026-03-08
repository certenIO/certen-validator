/**
 * Add CERTEN Validators as Operators on CertenAnchorV3 Contract
 *
 * Operators can submit proofs and perform certain contract operations.
 *
 * Usage:
 *   OWNER_PRIVATE_KEY=0x... node add_operators.js
 */

const { ethers } = require('ethers');

// Configuration
const OWNER_PRIVATE_KEY = process.env.OWNER_PRIVATE_KEY || '';
const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const CONTRACT_ADDRESS = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';

// Validators to add as operators
const VALIDATORS = [
  { name: 'validator-1', address: '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8' },
  { name: 'validator-2', address: '0x518273099F5c4b87eEA65141931B78012dfE5c7d' },
  { name: 'validator-3', address: '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6' },
  { name: 'validator-4', address: '0x6Ff54041Afef809e93ce6B570545069d2764783f' },
  { name: 'validator-5', address: '0x9eaA84E3D31479eCC9130187DA9f962625e8C271' },
  { name: 'validator-6', address: '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf' },
  { name: 'validator-7', address: '0x0D786D587aBe92f1031506fF3eF88c79a93A8962' }
];

// Contract ABI (only needed functions)
const ABI = [
  'function owner() view returns (address)',
  'function operators(address) view returns (bool)',
  'function addOperator(address operator)'
];

async function main() {
  console.log('='.repeat(70));
  console.log('Add Validators as Operators on CertenAnchorV3');
  console.log('='.repeat(70));
  console.log('');

  if (!OWNER_PRIVATE_KEY) {
    console.error('ERROR: OWNER_PRIVATE_KEY not set!');
    console.error('Usage: OWNER_PRIVATE_KEY=0x... node add_operators.js');
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  console.log('Contract:', CONTRACT_ADDRESS);
  console.log('Signer:', wallet.address);

  const owner = await contract.owner();
  console.log('Contract Owner:', owner);

  if (wallet.address.toLowerCase() !== owner.toLowerCase()) {
    console.error('ERROR: Signer is not the contract owner!');
    process.exit(1);
  }
  console.log('');

  console.log('-'.repeat(70));
  console.log('Adding Operators');
  console.log('-'.repeat(70));
  console.log('');

  for (const v of VALIDATORS) {
    console.log(`[${v.name}] ${v.address}`);

    const isOperator = await contract.operators(v.address);
    if (isOperator) {
      console.log('  Already an operator');
      console.log('');
      continue;
    }

    console.log('  Adding as operator...');
    try {
      const tx = await contract.addOperator(v.address, { gasLimit: 100000n });
      console.log(`  TX: ${tx.hash}`);
      const receipt = await tx.wait();
      console.log(`  Confirmed in block ${receipt.blockNumber} (gas: ${receipt.gasUsed})`);

      const nowOperator = await contract.operators(v.address);
      console.log(`  Verified: operator=${nowOperator}`);
    } catch (error) {
      console.error(`  Failed: ${error.message}`);
    }
    console.log('');
  }

  console.log('='.repeat(70));
  console.log('Complete');
  console.log('='.repeat(70));

  console.log('Operator Status:');
  for (const v of VALIDATORS) {
    const isOp = await contract.operators(v.address);
    const status = isOp ? 'YES' : 'NO';
    console.log(`  ${v.name}: ${status}`);
  }
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
