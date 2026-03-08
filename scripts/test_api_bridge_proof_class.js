#!/usr/bin/env node
/**
 * Test API Bridge proof_class implementation with real intent submission
 * Tests both on_demand and on_cadence proof classes
 */

const API_BRIDGE_URL = 'http://116.202.214.38:8085';

// Valid intent payload
const createIntent = (proofClass) => ({
  intent: {
    id: crypto.randomUUID(),
    fromChain: 'ethereum',
    fromChainId: 11155111,
    toChain: 'sepolia',
    toChainId: 11155111,
    fromAddress: '0xc6831da653741afebc14a49e9c6291312a0ba3dd',
    toAddress: '0xbe0043abb10e6db56b8c6c5cb3f639bf7fe69251',
    amount: '0.001',
    tokenSymbol: 'ETH',
    adiUrl: 'acc://certen-kermit-12.acme',
    initiatedBy: 'test-proof-class@certen.io',
    timestamp: Date.now()
  },
  contractAddresses: {
    anchor: '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98',
    anchorV2: '0x9B29771EFA2C6645071C589239590b81ae2C5825',
    abstractAccount: '0x0000000000000000000000000000000000000000',
    entryPoint: '0x0000000000000000000000000000000000000000'
  },
  executionParameters: {
    gasLimit: 500000,
    maxFeePerGas: '50000000000',
    maxPriorityFeePerGas: '2000000000',
    chainId: 11155111
  },
  validationRules: {
    maxAmount: '1000',
    dailyLimit: '10000',
    requiresApproval: false
  },
  expirationMinutes: 95,
  proofClass: proofClass,
  // Use the Kermit testnet key for signing
  adiPrivateKey: '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a2',
  signerKeyPageUrl: 'acc://certen-kermit-12.acme/book/1'
});

async function testProofClass(proofClass) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Testing proof_class: "${proofClass}"`);
  console.log('='.repeat(60));

  const payload = createIntent(proofClass);
  console.log(`Intent ID: ${payload.intent.id}`);

  try {
    const response = await fetch(`${API_BRIDGE_URL}/api/v1/intent/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    console.log(`Status: ${response.status}`);
    console.log(`Response:`, JSON.stringify(data, null, 2));

    if (data.success) {
      console.log(`\n✅ SUCCESS - proof_class="${proofClass}" intent created!`);
      console.log(`   TX Hash: ${data.txHash}`);
      console.log(`   Data Account: ${data.dataAccount}`);
      return { success: true, proofClass, txHash: data.txHash };
    } else {
      console.log(`\n❌ FAILED - ${data.error}`);
      return { success: false, proofClass, error: data.error };
    }
  } catch (error) {
    console.log(`\n❌ ERROR - ${error.message}`);
    return { success: false, proofClass, error: error.message };
  }
}

async function testInvalidProofClass() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Testing INVALID proof_class: "invalid_value"`);
  console.log('='.repeat(60));

  const payload = createIntent('invalid_value');

  try {
    const response = await fetch(`${API_BRIDGE_URL}/api/v1/intent/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    console.log(`Status: ${response.status}`);
    console.log(`Response:`, JSON.stringify(data, null, 2));

    if (response.status === 400 && data.error?.includes('Invalid proof_class')) {
      console.log(`\n✅ CORRECTLY REJECTED - Invalid proof_class was caught!`);
      return { success: true, validated: true };
    } else {
      console.log(`\n❌ VALIDATION FAILED - Invalid proof_class was NOT rejected!`);
      return { success: false, validated: false };
    }
  } catch (error) {
    console.log(`\n❌ ERROR - ${error.message}`);
    return { success: false, error: error.message };
  }
}

async function main() {
  console.log('API Bridge Proof Class Integration Test');
  console.log(`Target: ${API_BRIDGE_URL}`);
  console.log(`Time: ${new Date().toISOString()}`);

  const results = [];

  // Test 1: Invalid proof_class should be rejected
  results.push(await testInvalidProofClass());

  // Test 2: on_demand proof_class
  results.push(await testProofClass('on_demand'));

  // Test 3: on_cadence proof_class
  results.push(await testProofClass('on_cadence'));

  // Summary
  console.log(`\n${'='.repeat(60)}`);
  console.log('SUMMARY');
  console.log('='.repeat(60));

  const allPassed = results.every(r => r.success);

  if (allPassed) {
    console.log('\n✅ ALL TESTS PASSED!');
    console.log('   - Invalid proof_class correctly rejected');
    console.log('   - on_demand intent created successfully');
    console.log('   - on_cadence intent created successfully');
    console.log('\nProof class implementation is 100% working!\n');
  } else {
    console.log('\n❌ SOME TESTS FAILED');
    results.forEach((r, i) => {
      console.log(`   Test ${i + 1}: ${r.success ? 'PASSED' : 'FAILED'}`);
    });
  }
}

main().catch(console.error);
