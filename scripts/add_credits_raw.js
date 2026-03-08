#!/usr/bin/env node
/**
 * Add credits to CERTEN Protocol key page using raw JSON-RPC
 */

import { ED25519Key } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import * as crypto from 'crypto';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor account
const SPONSOR_KEY_PAGE = 'acc://certen-kermit-11.acme/book/1';
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Target key page
const TARGET_KEY_PAGE = 'acc://certenprotocol.acme/book/1';

async function main() {
    console.log('='.repeat(60));
    console.log('Add Credits to CERTEN Protocol Key Page - Kermit Testnet');
    console.log('='.repeat(60));
    console.log();

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

    // Check sponsor key page
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
    const sponsorVersion = sponsorResp?.result?.account?.version || 1;
    console.log(`  Sponsor credits: ${sponsorResp?.result?.account?.creditBalance || 0}`);
    console.log(`  Sponsor version: ${sponsorVersion}`);

    // Create signing key
    const key = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY, 'hex'));
    const publicKeyHash = crypto.createHash('sha256').update(key.publicKey).digest('hex');
    console.log(`  Public key hash: ${publicKeyHash}`);

    // Use the faucet/transfer approach - submit via execute endpoint
    // or we can try using the CLI if available
    console.log('\n Trying to use accumulate CLI to transfer credits...');

    // For now, let's use a workaround - we can create the data account using the sponsor's credits
    // by having the sponsor sign the createDataAccount transaction instead
    console.log('\nAlternative: Use sponsor to create data account directly...');
    console.log('The sponsor can pay for the transaction instead.');
}

main().catch(console.error);
