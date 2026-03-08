#!/usr/bin/env node
/**
 * Test WriteData to execution-results account
 *
 * Tests the write-back configuration for Phase 9 of the proof cycle
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - certen-kermit-12.acme identity (same as intent submission)
const ENDPOINT = 'http://206.191.154.164:8660/v3';
const DATA_ACCOUNT = 'acc://certen-kermit-12.acme/execution-results';
const KEY_PAGE = 'acc://certen-kermit-12.acme/book/1';
const PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Create test write-back data
function createTestWriteBackData() {
    const now = Date.now();
    const testCycleId = crypto.randomUUID();
    const toHex = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('hex');

    return [
        toHex({
            kind: "CERTEN_RESULT",
            version: "1.0",
            cycle_id: testCycleId,
            created_at: new Date().toISOString(),
            result_type: "proof_cycle_completion",
            description: "Test write-back for Phase 9"
        }),
        toHex({
            protocol: "CERTEN",
            version: "1.0",
            intent_id: "test-intent-" + testCycleId.slice(0, 8),
            bundle_id: "0x" + crypto.randomUUID().replace(/-/g, '').padEnd(64, '0'),
            execution_tx_hash: "0x" + crypto.randomUUID().replace(/-/g, '').padEnd(64, '0'),
            target_chain: "ethereum",
            chain_id: 11155111,
            success: true
        }),
        toHex({
            attestation: {
                validator_count: 1,
                threshold_met: true,
                aggregate_signature: "test_bls_signature"
            }
        }),
        toHex({
            nonce: `writeback_test_${now}`,
            created_at: Math.floor(now/1000),
            test: true
        })
    ];
}

async function queryAccount(url) {
    console.log(`\nQuerying account: ${url}`);
    try {
        const resp = await fetch(ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'query',
                params: { scope: url },
                id: 1
            })
        }).then(r => r.json());

        if (resp.error) {
            console.log(`  ERROR: ${resp.error.message}`);
            return null;
        }

        console.log(`  Type: ${resp.result?.account?.type || 'unknown'}`);
        console.log(`  URL: ${resp.result?.account?.url || url}`);
        if (resp.result?.account?.authorities) {
            console.log(`  Authorities: ${JSON.stringify(resp.result.account.authorities)}`);
        }
        return resp.result;
    } catch (e) {
        console.log(`  FETCH ERROR: ${e.message}`);
        return null;
    }
}

async function main() {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(' Testing Write-Back to Accumulate (Phase 9 Configuration)');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`\nEndpoint: ${ENDPOINT}`);
    console.log(`Data Account: ${DATA_ACCOUNT}`);
    console.log(`Key Page: ${KEY_PAGE}`);
    console.log(`Private Key: ${PRIVATE_KEY.slice(0, 16)}...`);

    // Step 1: Verify the data account exists
    console.log('\n─────────────────────────────────────────────────────────────────');
    console.log(' Step 1: Verify Data Account');
    console.log('─────────────────────────────────────────────────────────────────');

    const dataAccountInfo = await queryAccount(DATA_ACCOUNT);
    if (!dataAccountInfo) {
        console.log('\n❌ Data account does not exist or is not accessible!');
        console.log('   You need to create the data account first.');
        return;
    }

    // Step 2: Verify the key page
    console.log('\n─────────────────────────────────────────────────────────────────');
    console.log(' Step 2: Verify Key Page');
    console.log('─────────────────────────────────────────────────────────────────');

    const keyPageInfo = await queryAccount(KEY_PAGE);
    if (!keyPageInfo) {
        console.log('\n❌ Key page does not exist!');
        return;
    }

    // Get key page version
    const keyPageVersion = keyPageInfo?.account?.version || 1;
    console.log(`  Version: ${keyPageVersion}`);

    // Check if our key is in the key page
    const keys = keyPageInfo?.account?.keys || [];
    const publicKey = PRIVATE_KEY.slice(64); // Last 32 bytes is public key
    console.log(`  Looking for public key: ${publicKey}`);

    let keyFound = false;
    for (const key of keys) {
        console.log(`  Key in page: ${key.publicKey || key.publicKeyHash}`);
        if (key.publicKey === publicKey || key.publicKeyHash === publicKey) {
            keyFound = true;
            console.log(`  ✅ Key found in page!`);
        }
    }

    if (!keyFound) {
        console.log(`  ⚠️ Key NOT found in page - transaction may fail authorization`);
    }

    // Step 3: Submit test write data
    console.log('\n─────────────────────────────────────────────────────────────────');
    console.log(' Step 3: Submit Test WriteData Transaction');
    console.log('─────────────────────────────────────────────────────────────────');

    const client = new api_v3.JsonRpcClient(ENDPOINT);
    const key = ED25519Key.from(Buffer.from(PRIVATE_KEY, 'hex'));
    const signer = Signer.forPage(KEY_PAGE, key).withVersion(keyPageVersion);

    const entries = createTestWriteBackData();
    console.log(`\nCreated ${entries.length} data entries for test write-back`);

    const tx = new core.Transaction({
        header: {
            principal: DATA_ACCOUNT,
            memo: "CERTEN_RESULT",
            metadata: "01025f00"  // Same metadata format as intents
        },
        body: {
            type: "writeData",
            entry: {
                type: "doubleHash",
                data: entries
            }
        }
    });

    console.log('\nSigning transaction...');
    const sig = await signer.sign(tx, { timestamp: Date.now() * 1000 });
    console.log('Transaction signed');

    console.log('\nSubmitting to Accumulate...');
    try {
        const result = await client.submit({ transaction: [tx], signatures: [sig] });

        for (const r of result) {
            if (r.success) {
                console.log(`\n✅ SUCCESS: ${r.status?.txID}`);
                console.log('\n═══════════════════════════════════════════════════════════════');
                console.log(' Write-back configuration is WORKING!');
                console.log('═══════════════════════════════════════════════════════════════');
            } else {
                console.log(`\n❌ FAILED: ${r.message || JSON.stringify(r)}`);
                if (r.status) {
                    console.log(`   Status: ${JSON.stringify(r.status)}`);
                }
            }
        }
    } catch (e) {
        console.log(`\n❌ SUBMISSION ERROR: ${e.message}`);
        if (e.response) {
            console.log(`   Response: ${JSON.stringify(e.response)}`);
        }
    }
}

main().catch(console.error);
