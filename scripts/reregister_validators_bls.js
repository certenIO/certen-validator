/**
 * Re-register CERTEN Validators with Deterministic BLS Keys
 *
 * This script removes existing validators and re-registers them with
 * new deterministic BLS public keys generated from their validator IDs.
 *
 * IMPORTANT: This will change the BLS public keys on-chain!
 *
 * Usage:
 *   OWNER_PRIVATE_KEY=0x... node reregister_validators_bls.js
 */

const { ethers } = require('ethers');

// ============================================================================
// CONFIGURATION
// ============================================================================

const OWNER_PRIVATE_KEY = process.env.OWNER_PRIVATE_KEY || '';
const RPC_URL = 'https://sepolia.drpc.org';
const CONTRACT_ADDRESS = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';

// New deterministic BLS keys (generated from CERTEN_BLS_KEY_V1:{validatorID}:certen-testnet)
const VALIDATORS = [
  {
    name: 'validator-1',
    address: '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8',
    votingPower: 100n,
    blsKey: '0x88eb4560b4147983e3d72bc6ddb04812d84be905d97f400f5c378b1fc0e252d53d9e2069891d56e2696fe43f2cd153df10bebf7f0fd4da4497f6d24f3cf9a82ff27ef2a8b731c609b732202334a4115b034dd18193d860c75837e46729c90a05'
  },
  {
    name: 'validator-2',
    address: '0x518273099F5c4b87eEA65141931B78012dfE5c7d',
    votingPower: 100n,
    blsKey: '0xb6034ecded6be69758a7bfe10dd6f38eba8068433821419762cdad9d1b9d423a02f6fe69f49d720315565700437302ca0edb2af84b1b2ae1114a9f131bcf6fa8ebe00bfa02834ac598ea9aa285a79c07d626e2b89f2784fce679d6e8b25e9ea5'
  },
  {
    name: 'validator-3',
    address: '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6',
    votingPower: 100n,
    blsKey: '0xa060ce250119479f1cb22f0f55941f56204b4d291caff3a268f5f2e4c4a55dddcd5db8f8f7c9251eebbb613ddc8a0db20d59d4f9f90e49f0d91f7c4d87c7f1c5ef4d9106cb17295f807870dc400a6e8f54a0c250f40c66ef0ba0e1ae9e272827'
  },
  {
    name: 'validator-4',
    address: '0x6Ff54041Afef809e93ce6B570545069d2764783f',
    votingPower: 100n,
    blsKey: '0xb3847f042172f34c28ad930ab6ea12057c23b80c018f8db7c073c7656c2b04049cee2accbf0f7162024af91f4c6def2216e55d59ab5203d9958d44ea6555dae20f9b98cd485f883c9cc3be2d3ca0c7fc454edf097f4c4b3dd8130922dda9bded'
  },
  {
    name: 'validator-5',
    address: '0x9eaA84E3D31479eCC9130187DA9f962625e8C271',
    votingPower: 100n,
    blsKey: '0xa41cd7cfa2b90210776218db3e574cf31db620a0db69e0829682826fc0693a67759cd07c0f4c817f43d50f37e643aafe0047a6e84ebb4257dd7aa51208b7efe6814a04638ca2f12ae98e8709552b00fa954164819c283f0c5c52d7f8f7f5bcc0'
  },
  {
    name: 'validator-6',
    address: '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf',
    votingPower: 100n,
    blsKey: '0xa02890dfab5831e608af5794245e5f3204358ff9d5ee6db86d77c08eb66406dfb7e4d19af8600a4f912987a8192b1cb008ec3829bbf78c5b6a62b284130477c6c5372d95b5c4e5f766e9c7d355dbf06495643b7fe62d3c50ceaff89336ed3ba1'
  },
  {
    name: 'validator-7',
    address: '0x0D786D587aBe92f1031506fF3eF88c79a93A8962',
    votingPower: 100n,
    blsKey: '0xa533372f8b8b25660ae1908bf2de04a2fdafcef38d9fe4eb35022858b2e015bffd17423c23bd0ea2db7b5d5ce9dd51900be37c74bddd23d6cf246fef2b156c8878958350934a796b7fd60de9e795e7d19ec6bf5910db3f7770794d9cf4ddf26f'
  }
];

const ABI = [
  'function owner() view returns (address)',
  'function validators(address) view returns (bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)',
  'function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey)',
  'function removeValidator(address validator)',
  'function getValidatorCount() view returns (uint256)',
  'event ValidatorRegistered(address indexed validator, uint256 votingPower)',
  'event ValidatorRemoved(address indexed validator)'
];

// ============================================================================
// MAIN SCRIPT
// ============================================================================

async function main() {
  console.log('='.repeat(70));
  console.log('CERTEN Validator BLS Key Re-Registration');
  console.log('='.repeat(70));
  console.log('');

  if (!OWNER_PRIVATE_KEY) {
    console.error('ERROR: OWNER_PRIVATE_KEY not set!');
    console.error('Usage: OWNER_PRIVATE_KEY=0x... node reregister_validators_bls.js');
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  console.log('Contract:', CONTRACT_ADDRESS);
  console.log('Signer:', wallet.address);

  // Verify ownership
  const owner = await contract.owner();
  if (wallet.address.toLowerCase() !== owner.toLowerCase()) {
    console.error('ERROR: Signer is not the contract owner!');
    process.exit(1);
  }
  console.log('✓ Ownership verified');
  console.log('');

  // Process each validator
  for (const v of VALIDATORS) {
    console.log('-'.repeat(70));
    console.log('Processing ' + v.name + ': ' + v.address);

    // Check current status
    const info = await contract.validators(v.address);
    console.log('  Current: registered=' + info.registered + ', blsKey=' + info.blsPublicKey.slice(0, 20) + '...');

    if (info.registered) {
      // Remove existing registration
      console.log('  Removing existing registration...');
      try {
        const removeTx = await contract.removeValidator(v.address, { gasLimit: 200000n });
        console.log('  Remove TX: ' + removeTx.hash);
        await removeTx.wait();
        console.log('  ✓ Removed');
      } catch (e) {
        console.error('  ✗ Remove failed: ' + e.message);
        continue;
      }
    }

    // Register with new BLS key
    console.log('  Registering with new deterministic BLS key...');
    console.log('  New BLS Key: ' + v.blsKey.slice(0, 20) + '...' + v.blsKey.slice(-16));

    try {
      const registerTx = await contract.registerValidator(
        v.address,
        v.votingPower,
        v.blsKey,
        { gasLimit: 300000n }
      );
      console.log('  Register TX: ' + registerTx.hash);
      const receipt = await registerTx.wait();
      console.log('  ✓ Registered in block ' + receipt.blockNumber);

      // Verify
      const newInfo = await contract.validators(v.address);
      console.log('  ✓ Verified: blsKey=' + newInfo.blsPublicKey.slice(0, 20) + '...');
    } catch (e) {
      console.error('  ✗ Register failed: ' + e.message);
    }
    console.log('');
  }

  // Final summary
  console.log('='.repeat(70));
  console.log('Registration Complete');
  console.log('='.repeat(70));

  const count = await contract.getValidatorCount();
  console.log('Total Validators:', count.toString());
  console.log('');

  for (const v of VALIDATORS) {
    const info = await contract.validators(v.address);
    const status = info.registered ? '✓' : '✗';
    const keyMatch = info.blsPublicKey.toLowerCase() === v.blsKey.toLowerCase() ? '✓' : '✗';
    console.log(status + ' ' + v.name + ': BLS key ' + (keyMatch === '✓' ? 'matches' : 'MISMATCH'));
  }
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
