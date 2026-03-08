#!/usr/bin/env node
/**
 * Add credits to CERTEN Protocol key page on Kermit Testnet
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor account - Lite Identity (funded via faucet 2026-01-22)
const SPONSOR_LITE_ACCOUNT = 'acc://4d07443e23bf3d244facb56f7fd4614d29b21f553c25eef5/ACME';
const SPONSOR_LID = 'acc://4d07443e23bf3d244facb56f7fd4614d29b21f553c25eef5';
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Target key page to add credits to
const TARGET_KEY_PAGE = 'acc://certenprotocol.acme/book/1';

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

async function waitForTx(txId, maxAttempts = 30) {
    console.log(`  Waiting for tx: ${txId}`);
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const resp = await fetch(ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'query',
                params: { scope: txId },
                id: 1
            })
        }).then(r => r.json());

        const status = resp?.result?.status;
        if (status === 'delivered') {
            console.log(`  ✅ Transaction delivered`);
            return true;
        }
        if (status === 'failed' || resp?.error) {
            console.log(`  ❌ Transaction failed: ${resp?.error?.message || status}`);
            return false;
        }
        console.log(`  ... status: ${status || 'pending'}`);
    }
    console.log(`  ⚠️ Transaction timed out`);
    return false;
}

async function main() {
    console.log('='.repeat(60));
    console.log('Add Credits to CERTEN Protocol Key Page - Kermit Testnet');
    console.log('='.repeat(60));
    console.log();

    const client = new api_v3.JsonRpcClient(ENDPOINT);
    const sponsorKey = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY, 'hex'));

    // Check current credits on target
    console.log(`Checking credits on ${TARGET_KEY_PAGE}...`);
    const targetResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: TARGET_KEY_PAGE },
            id: 1
        })
    }).then(r => r.json());
    console.log(`  Current credits: ${targetResp?.result?.account?.creditBalance || 0}`);

    // Get sponsor key page version
    const sponsorVersion = await getKeyPageVersion(SPONSOR_KEY_PAGE);
    console.log(`Sponsor key page version: ${sponsorVersion}`);
    const sponsorSigner = Signer.forPage(SPONSOR_KEY_PAGE, sponsorKey).withVersion(sponsorVersion);

    // Check sponsor key page credits
    console.log(`\nChecking credits on ${SPONSOR_KEY_PAGE}...`);
    const sponsorResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: SPONSOR_KEY_PAGE },
            id: 1
        })
    }).then(r => r.json());
    console.log(`  Sponsor credits: ${sponsorResp?.result?.account?.creditBalance || 0}`);

    // Transfer credits from sponsor key page to target key page
    console.log(`\nTransferring 10000 credits to ${TARGET_KEY_PAGE}...`);

    const transferCreditsTx = new core.Transaction({
        header: { principal: SPONSOR_KEY_PAGE },
        body: {
            type: 'transferCredits',
            to: [{ url: TARGET_KEY_PAGE, amount: BigInt(10000) }]  // 10000 credits (100.00 credits)
        }
    });

    const creditsSig = await sponsorSigner.sign(transferCreditsTx, { timestamp: Date.now() * 1000 });
    const creditsResult = await client.submit({ transaction: [transferCreditsTx], signatures: [creditsSig] });

    for (const r of creditsResult) {
        if (r.success) {
            console.log(`  Submitted: ${r.status?.txID}`);
            await waitForTx(r.status?.txID);
        } else {
            console.log(`  ❌ Failed: ${r.message || JSON.stringify(r)}`);
        }
    }

    // Check new balance
    console.log(`\nChecking new credits on ${TARGET_KEY_PAGE}...`);
    const newTargetResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: TARGET_KEY_PAGE },
            id: 1
        })
    }).then(r => r.json());
    console.log(`  New credits: ${newTargetResp?.result?.account?.creditBalance || 0}`);

    console.log('\n✅ Done');
}

main().catch(console.error);
