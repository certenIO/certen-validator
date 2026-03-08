const { ethers } = require('ethers');
const RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/aosGJNJkUckm6lCldSEmP';

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  
  const txHash = '0x1f55790bba5d66ea253efc167b758e07b1cfa065097350b68e1e614ab18d64f9';
  
  console.log('Getting TX details:', txHash);
  
  const tx = await provider.getTransaction(txHash);
  console.log('To:', tx.to);
  console.log('Data length:', tx.data.length);
  console.log('Data (first 200 chars):', tx.data.substring(0, 200));
  
  // Try to get revert reason
  try {
    const result = await provider.call({
      to: tx.to,
      data: tx.data,
      from: tx.from
    }, tx.blockNumber - 1);
    console.log('Call result:', result);
  } catch (err) {
    console.log('Revert reason:', err.reason || err.message);
    if (err.data) console.log('Error data:', err.data);
  }
}

main().catch(console.error);
