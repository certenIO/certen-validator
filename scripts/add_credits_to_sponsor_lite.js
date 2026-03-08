#!/usr/bin/env node
/**
 * Add credits to Sponsor Lite Identity on Kermit Testnet
 * Uses the lite identity directly (no ADI needed)
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import * as crypto from 'crypto';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor key - this is the key we funded with the faucet
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Compute lite account URLs from private key
function computeLiteAccountURLs(privateKeyHex) {
    const publicKeyHex = privateKeyHex.slice(64); // Last 32 bytes
    const publicKey = Buffer.from(publicKeyHex, 'hex');

    // sha256(pubkey)[0:20]
    const hash20 = crypto.createHash('sha256').update(publicKey).digest().slice(0, 20);
    const hash20Hex = hash20.toString('hex');

    // checksum = sha256(lowercase_hex)[28:32]
    const checksumHash = crypto.createHash('sha256').update(hash20Hex.toLowerCase()).digest();
    const checksum = checksumHash.slice(28, 32).toString('hex');

    const liteId = hash20Hex + checksum;
    return {
        lid: `acc://${liteId}`,
        lta: `acc://${liteId}/ACME`
    };
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
            console.log(`  Transaction delivered`);
            return true;
        }
        if (status === 'failed' || resp?.error) {
            console.log(`  Transaction failed: ${resp?.error?.message || status}`);
            return false;
        }
        console.log(`  ... status: ${status || 'pending'}`);
    }
    console.log(`  Transaction timed out`);
    return false;
}

async function getNetworkStatus() {
    const resp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'network-status',
            params: {},
            id: 1
        })
    }).then(r => r.json());
    return resp?.result;
}

async function main() {
    console.log('='.repeat(60));
    console.log('Add Credits to Sponsor Lite Identity - Kermit Testnet');
    console.log('='.repeat(60));
    console.log();

    const urls = computeLiteAccountURLs(SPONSOR_PRIVATE_KEY);
    console.log('Sponsor LID:', urls.lid);
    console.log('Sponsor LTA:', urls.lta);
    console.log();

    const client = new api_v3.JsonRpcClient(ENDPOINT);
    const sponsorKey = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY, 'hex'));

    // Create a signer for the lite identity
    const liteSigner = Signer.forLite(sponsorKey);

    // Check current ACME balance
    console.log('Checking current ACME balance...');
    const ltaResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: urls.lta },
            id: 1
        })
    }).then(r => r.json());

    const acmeBalance = BigInt(ltaResp?.result?.account?.balance || '0');
    console.log(`  ACME Balance: ${Number(acmeBalance) / 1e8} ACME`);

    // Check current credits on LID
    console.log('\nChecking current credits...');
    const lidResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: urls.lid },
            id: 1
        })
    }).then(r => r.json());

    const currentCredits = lidResp?.result?.account?.creditBalance || 0;
    console.log(`  Current credits: ${currentCredits}`);

    // Get oracle price
    console.log('\nGetting oracle price...');
    const networkStatus = await getNetworkStatus();
    const oraclePrice = networkStatus?.oracle?.price || 50000000;
    console.log(`  Oracle price: ${oraclePrice}`);

    // Calculate amount for 500,000 credits
    // credits = (acmeAmount * oraclePrice) / (100 * 1e8)
    // acmeAmount = (credits * 100 * 1e8) / oraclePrice
    const targetCredits = 500000;
    const acmeAmount = BigInt(Math.ceil((targetCredits * 100 * 1e8) / oraclePrice));
    console.log(`\nPurchasing ${targetCredits} credits...`);
    console.log(`  ACME cost: ${Number(acmeAmount) / 1e8} ACME`);

    // Create addCredits transaction
    const addCreditsTx = new core.Transaction({
        header: { principal: urls.lta },
        body: {
            type: 'addCredits',
            recipient: urls.lid,
            amount: acmeAmount,
            oracle: oraclePrice
        }
    });

    const sig = await liteSigner.sign(addCreditsTx, { timestamp: Date.now() * 1000 });
    const result = await client.submit({ transaction: [addCreditsTx], signatures: [sig] });

    for (const r of result) {
        if (r.success) {
            console.log(`  Submitted: ${r.status?.txID}`);
            await waitForTx(r.status?.txID);
        } else {
            console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
        }
    }

    // Check new credits balance
    await new Promise(r => setTimeout(r, 3000));
    console.log('\nChecking new credits balance...');
    const newLidResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: urls.lid },
            id: 1
        })
    }).then(r => r.json());

    const newCredits = newLidResp?.result?.account?.creditBalance || 0;
    console.log(`  New credits: ${newCredits}`);

    console.log('\nDone');
}

main().catch(console.error);
