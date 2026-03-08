#!/usr/bin/env node
/**
 * Create execution-results data account under certen-kermit-12.acme
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';
const IDENTITY = 'acc://certen-kermit-12.acme';
const KEY_PAGE = 'acc://certen-kermit-12.acme/book/1';
const DATA_ACCOUNT = 'acc://certen-kermit-12.acme/execution-results';
const PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

async function getKeyPageVersion(url) {
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
    return resp?.result?.account?.version || 1;
}

async function waitForTx(client, txId, maxAttempts = 60) {
    console.log(`  Waiting for tx...`);
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 3000));
        try {
            const result = await client.query(txId);
            const status = result?.status;
            if (status === 'delivered' || status === 201) {
                console.log(`  Transaction delivered`);
                return true;
            }
            if (status === 'failed') {
                console.log(`  Transaction failed: ${JSON.stringify(result)}`);
                return false;
            }
            console.log(`  ... status: ${status || 'pending'} (attempt ${i+1}/${maxAttempts})`);
        } catch (e) {
            console.log(`  ... waiting (attempt ${i+1}/${maxAttempts})`);
        }
    }
    return false;
}

async function main() {
    console.log('Creating execution-results data account...\n');

    const client = new api_v3.JsonRpcClient(ENDPOINT);

    // Use first 32 bytes as seed
    const key = ED25519Key.from(Buffer.from(PRIVATE_KEY.substring(0, 64), 'hex'));
    console.log('Key Public Key Hash:', Buffer.from(key.address.publicKeyHash).toString('hex'));

    // Get current key page version
    const version = await getKeyPageVersion(KEY_PAGE);
    console.log(`Key page version: ${version}`);

    // Create signer for the key page
    const signer = Signer.forPage(KEY_PAGE, key).withVersion(version);

    const tx = new core.Transaction({
        header: {
            principal: IDENTITY,
        },
        body: {
            type: 'createDataAccount',
            url: DATA_ACCOUNT,
        }
    });

    const sig = await signer.sign(tx, { timestamp: Date.now() * 1000 });
    console.log('Transaction signed');

    const result = await client.submit({ transaction: [tx], signatures: [sig] });

    for (const r of result) {
        if (r.success) {
            console.log(`Submitted: ${r.status?.txID}`);
            await waitForTx(client, r.status?.txID);
        } else {
            console.log(`Failed: ${r.message || JSON.stringify(r)}`);
        }
    }

    // Verify
    console.log('\nVerifying data account...');
    await new Promise(r => setTimeout(r, 5000));

    const resp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: DATA_ACCOUNT },
            id: 1
        })
    }).then(r => r.json());

    if (resp.result?.account) {
        console.log(`SUCCESS: Data account created at ${DATA_ACCOUNT}`);
        console.log(`Type: ${resp.result.account.type}`);
    } else {
        console.log(`Data account not found yet: ${JSON.stringify(resp.error || resp)}`);
    }
}

main().catch(console.error);
