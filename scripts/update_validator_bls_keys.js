/**
 * Update Validator BLS Keys on CertenAnchorV3 Contract
 *
 * This script removes validators and re-registers them with their real BLS public keys.
 */

const { ethers } = require('ethers');

// Configuration
const OWNER_PRIVATE_KEY = '0xbf90cedf27a3009a2c8a1634971430e853872dc5d1dbb837e02beffa4760d9cf';
const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const CONTRACT_ADDRESS = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';

// Validators with their real BLS public keys (96 bytes compressed G2)
// Keys generated deterministically from sha256("CERTEN_BLS_KEY_V1:{validatorID}:{chainID}")
// with chainID = "certen-testnet"
const VALIDATORS = [
  {
    name: 'validator-1',
    address: '0x2b7d6d99aB37a7c03cE732E6274Db3Fb69BcffE8',
    votingPower: 100n,
    blsPublicKey: '0xafffb7421e8b2ec516e50f4896bf5de12c84413e74a7fc6bbf6437de084dd4e4ece83326f2b2280dfa5704a21a883d0e011a498e268f74c6464adedc0796929f7366ebe6f7aee52da37b035ee00a76760b316ceb544d0ac2c8f64610ef4dee19'
  },
  {
    name: 'validator-2',
    address: '0x518273099F5c4b87eEA65141931B78012dfE5c7d',
    votingPower: 100n,
    blsPublicKey: '0x86289aa10710f09835379445c090fa0b850f27fcca067c4fb5b1ed8d0d3c027d996d251d431565a83cd5f325fb8432ba016581eed4de550ccaa74a5c9315cb7583b61c2288b55a06e6b59b796ea11e7c5cc4564f01a2bcfeaae59c496ad32a3f'
  },
  {
    name: 'validator-3',
    address: '0xa4fA4209FDE5340B0D5b36522a34641a2d50C7c6',
    votingPower: 100n,
    blsPublicKey: '0xba000a200de8370dc2010d85104e674c8cdec4fc27324ebe72c5f09514bc30b479adf0eb23fd12ea9abdc27149df2c1e173b36d8c2a5597aadccc87dc6c2114df0a12910d43ddafedb0476f11b6051c7d21a303a3fb10ae04028d50dc7166fbd'
  },
  {
    name: 'validator-4',
    address: '0x6Ff54041Afef809e93ce6B570545069d2764783f',
    votingPower: 100n,
    blsPublicKey: '0xb515b25cd082599a84b9c37b37c62c29c94f0862a1a5528ab13bf7c8b0630555e9ca2bcca451e3aaf760b64d3f80a2b2123d7817355873ca6d568e06e9c4d87d6280750d40a076b78262631fe2b44fba54d7686f0cdad6f92f56c8aa24798d3d'
  },
  {
    name: 'validator-5',
    address: '0x9eaA84E3D31479eCC9130187DA9f962625e8C271',
    votingPower: 100n,
    blsPublicKey: '0x8298bf809bea29dbdf256f3232b77b5d69c6abd8f7ac42f5815a0f37e7d238d4430d019da73d8941e8ce26c7e53f44950fba4b332945df7a1f494c788324824027e83915153778022c71196d6a10b50111e1e97446a8a74be29eb13d10fc5f53'
  },
  {
    name: 'validator-6',
    address: '0x0368698B330f8AdFC636C46B7e04a875dFbEAaFf',
    votingPower: 100n,
    blsPublicKey: '0x83227407f54d6f1f62e36fda72ee0ca07f41b77157bdce1784523f35baa1bd6471eb73a20397876641623c15782cfc3704b5ebe03ffccafc2cd6854ff4bc08e137d2beb1687a1f5bef8812862f9a769be2ea77996b10bd6e6ac9f8dfc057243c'
  },
  {
    name: 'validator-7',
    address: '0x0D786D587aBe92f1031506fF3eF88c79a93A8962',
    votingPower: 100n,
    blsPublicKey: '0x8f744740b576571df75da116048968a619281b2469f179d7402bd84e637dab16a03b15c0dd90b082c0274c2976ce91b009e1aa226f38ba528ab9d474af497cea5c4ac461b6b9060b3de23abd755f947ef5ac862f923eaaf6fb795f94f325a9f7'
  }
];

// Contract ABI (needed functions only)
const ABI = [
  'function validators(address) view returns (bool registered, uint256 votingPower, bytes blsPublicKey, uint256 registeredAt)',
  'function removeValidator(address validator)',
  'function registerValidator(address validator, uint256 votingPower, bytes blsPublicKey)'
];

async function main() {
  console.log('='.repeat(70));
  console.log('Update Validator BLS Keys');
  console.log('='.repeat(70));
  console.log('');

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  console.log('Contract:', CONTRACT_ADDRESS);
  console.log('Signer:', wallet.address);
  console.log('');

  for (const v of VALIDATORS) {
    console.log(`[${v.name}] ${v.address}`);
    console.log(`  BLS Key: ${v.blsPublicKey.substring(0, 20)}...${v.blsPublicKey.substring(v.blsPublicKey.length - 20)}`);

    // Check current state
    const info = await contract.validators(v.address);
    if (info.registered) {
      const currentKey = info.blsPublicKey;
      if (currentKey.toLowerCase() === v.blsPublicKey.toLowerCase()) {
        console.log('  ✓ Already has correct BLS key');
        console.log('');
        continue;
      }

      console.log('  Current key: ' + (currentKey === '0x' + '00'.repeat(48) ? '(empty)' : currentKey.substring(0, 20) + '...'));
      console.log('  Removing validator...');

      try {
        const removeTx = await contract.removeValidator(v.address, { gasLimit: 200000n });
        console.log(`    TX: ${removeTx.hash}`);
        await removeTx.wait();
        console.log('    ✓ Removed');
      } catch (err) {
        console.log(`    ✗ Error: ${err.message}`);
        continue;
      }
    }

    // Re-register with correct BLS key
    console.log('  Registering with BLS key...');
    try {
      const registerTx = await contract.registerValidator(
        v.address,
        v.votingPower,
        v.blsPublicKey,
        { gasLimit: 300000n }
      );
      console.log(`    TX: ${registerTx.hash}`);
      await registerTx.wait();
      console.log('    ✓ Registered');

      // Verify
      const newInfo = await contract.validators(v.address);
      console.log(`    ✓ Verified: key=${newInfo.blsPublicKey.substring(0, 20)}...`);
    } catch (err) {
      console.log(`    ✗ Error: ${err.message}`);
    }
    console.log('');
  }

  console.log('='.repeat(70));
  console.log('Done!');
  console.log('='.repeat(70));
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
