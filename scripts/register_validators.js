/**
 * Register CERTEN Validators on CertenAnchorV3 Contract
 *
 * This script registers validator addresses on the contract so they can
 * submit anchors, execute proofs, and perform governance operations.
 *
 * PREREQUISITE: The OWNER_PRIVATE_KEY must be the key for the contract owner:
 *   Owner Address: 0x8B18BE5EE7B4e1f33BAd6f5f0f31588F64F63A4e
 *
 * Usage:
 *   OWNER_PRIVATE_KEY=0x... node register_validators.js
 *
 * Or edit the OWNER_PRIVATE_KEY variable directly below.
 */

const { ethers } = require('ethers');

// ============================================================================
// CONFIGURATION - EDIT IF NEEDED
// ============================================================================

// Owner's private key (contract owner who can register validators)
// Set via environment variable or edit directly here
const OWNER_PRIVATE_KEY = process.env.OWNER_PRIVATE_KEY || '';

// RPC endpoint
const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';

// Contract address
const CONTRACT_ADDRESS = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';

// Validators to register with their voting power
// Updated: 7 validators for Kermit deployment
const VALIDATORS = [
  {
    name: 'validator-1',
    address: '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8',
    votingPower: 100n
  },
  {
    name: 'validator-2',
    address: '0x518273099F5c4b87eEA65141931B78012dfE5c7d',
    votingPower: 100n
  },
  {
    name: 'validator-3',
    address: '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6',
    votingPower: 100n
  },
  {
    name: 'validator-4',
    address: '0x6Ff54041Afef809e93ce6B570545069d2764783f',
    votingPower: 100n
  },
  {
    name: 'validator-5',
    address: '0x9eaA84E3D31479eCC9130187DA9f962625e8C271',
    votingPower: 100n
  },
  {
    name: 'validator-6',
    address: '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf',
    votingPower: 100n
  },
  {
    name: 'validator-7',
    address: '0x0D786D587aBe92f1031506fF3eF88c79a93A8962',
    votingPower: 100n
  }
];

// Contract ABI (only needed functions)
const ABI = [
  'function owner() view returns (address)',
  'function getValidatorCount() view returns (uint256)',
  'function validators(address) view returns (bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)',
  'function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey)',
  'event ValidatorRegistered(address indexed validator, uint256 votingPower)'
];

// ============================================================================
// MAIN SCRIPT
// ============================================================================

async function main() {
  console.log('='.repeat(70));
  console.log('CERTEN Validator Registration Script');
  console.log('='.repeat(70));
  console.log('');

  // Check private key
  if (!OWNER_PRIVATE_KEY) {
    console.error('ERROR: OWNER_PRIVATE_KEY not set!');
    console.error('');
    console.error('Usage:');
    console.error('  OWNER_PRIVATE_KEY=0x... node register_validators.js');
    console.error('');
    console.error('The private key must be for the contract owner:');
    console.error('  0x8B18BE5EE7B4e1f33BAd6f5f0f31588F64F63A4e');
    process.exit(1);
  }

  // Connect to network
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  console.log('Contract:', CONTRACT_ADDRESS);
  console.log('Signer:', wallet.address);

  // Verify ownership
  const owner = await contract.owner();
  console.log('Contract Owner:', owner);

  if (wallet.address.toLowerCase() !== owner.toLowerCase()) {
    console.error('');
    console.error('ERROR: Signer is not the contract owner!');
    console.error('  Your address:', wallet.address);
    console.error('  Owner address:', owner);
    process.exit(1);
  }
  console.log('');
  console.log('✓ Ownership verified');
  console.log('');

  // Check balance
  const balance = await provider.getBalance(wallet.address);
  console.log('Signer Balance:', ethers.formatEther(balance), 'ETH');
  if (balance < ethers.parseEther('0.01')) {
    console.warn('WARNING: Low balance. Ensure you have enough ETH for gas.');
  }
  console.log('');

  // Register each validator
  console.log('-'.repeat(70));
  console.log('Registering Validators');
  console.log('-'.repeat(70));
  console.log('');

  for (const v of VALIDATORS) {
    console.log(`[${v.name}] ${v.address}`);

    // Check if already registered
    const info = await contract.validators(v.address);
    if (info.registered) {
      console.log(`  ✓ Already registered (votingPower: ${info.votingPower})`);
      console.log('');
      continue;
    }

    // Register the validator
    console.log('  Registering...');
    try {
      // Empty BLS public key (48 bytes of zeros) - for testing mode
      const blsPubkey = '0x' + '00'.repeat(48);

      const tx = await contract.registerValidator(
        v.address,
        v.votingPower,
        blsPubkey,
        {
          gasLimit: 300000n
        }
      );

      console.log(`  TX: ${tx.hash}`);
      const receipt = await tx.wait();
      console.log(`  ✓ Confirmed in block ${receipt.blockNumber} (gas: ${receipt.gasUsed})`);

      // Verify
      const newInfo = await contract.validators(v.address);
      console.log(`  ✓ Verified: registered=${newInfo.registered}, votingPower=${newInfo.votingPower}`);

    } catch (error) {
      console.error(`  ✗ Failed: ${error.message}`);
    }
    console.log('');
  }

  // Summary
  console.log('='.repeat(70));
  console.log('Registration Complete');
  console.log('='.repeat(70));

  const count = await contract.getValidatorCount();
  console.log('Total Validators:', count.toString());
  console.log('');

  console.log('Registered Validators:');
  for (const v of VALIDATORS) {
    const info = await contract.validators(v.address);
    const status = info.registered ? '✓' : '✗';
    console.log(`  ${status} ${v.name}: ${v.address} (power: ${info.votingPower})`);
  }
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
