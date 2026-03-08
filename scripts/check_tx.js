const { ethers } = require('ethers');
const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  
  // TX from validator logs
  const txHash = '0x1f55790bba5d66ea253efc167b758e07b1cfa065097350b68e1e614ab18d64f9';
  
  console.log('Checking TX:', txHash);
  
  const receipt = await provider.getTransactionReceipt(txHash);
  
  if (receipt) {
    console.log('Status:', receipt.status === 1 ? '✓ SUCCESS' : '✗ FAILED');
    console.log('Block:', receipt.blockNumber);
    console.log('Gas Used:', receipt.gasUsed.toString());
    console.log('Logs:', receipt.logs.length);
    
    if (receipt.logs.length > 0) {
      for (const log of receipt.logs) {
        console.log('  Log topic[0]:', log.topics[0]?.substring(0, 20) + '...');
      }
    }
  } else {
    console.log('TX not found or pending');
  }
}

main().catch(console.error);
