/**
 * Check Anchor Contract BLS ZK Configuration
 */

const { ethers } = require('ethers');

const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';
const ANCHOR_CONTRACT = '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98';
const EXPECTED_BLS_VERIFIER = '0x631B6444216b981561034655349F8a28962DcC5F';

const ABI = [
    'function blsZKVerifier() view returns (address)',
    'function blsZKVerificationEnabled() view returns (bool)',
    'function getBLSZKVerificationStatus() view returns (bool configured, bool enabled)',
    'function owner() view returns (address)'
];

async function main() {
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const contract = new ethers.Contract(ANCHOR_CONTRACT, ABI, provider);

    console.log('Anchor Contract:', ANCHOR_CONTRACT);
    console.log('Expected BLS Verifier:', EXPECTED_BLS_VERIFIER);
    console.log('');

    try {
        const verifier = await contract.blsZKVerifier();
        console.log('Current BLS ZK Verifier:', verifier);
        console.log('  Match:', verifier.toLowerCase() === EXPECTED_BLS_VERIFIER.toLowerCase() ? 'YES' : 'NO - NEEDS UPDATE');
    } catch (e) {
        console.log('blsZKVerifier() failed:', e.message);
    }

    try {
        const enabled = await contract.blsZKVerificationEnabled();
        console.log('BLS ZK Verification Enabled:', enabled);
    } catch (e) {
        console.log('blsZKVerificationEnabled() failed:', e.message);
    }

    try {
        const status = await contract.getBLSZKVerificationStatus();
        console.log('BLS ZK Status - Configured:', status.configured, 'Enabled:', status.enabled);
    } catch (e) {
        console.log('getBLSZKVerificationStatus() failed:', e.message);
    }

    try {
        const owner = await contract.owner();
        console.log('Contract Owner:', owner);
    } catch (e) {
        console.log('owner() failed:', e.message);
    }
}

main().catch(console.error);
