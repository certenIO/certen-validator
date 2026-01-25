#!/usr/bin/env node
/**
 * Submit CERTEN Intent WriteData to DevNet
 *
 * Simple script - just signs and submits a writeData transaction
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';
const DATA_ACCOUNT = 'acc://certen-kermit-12.acme/data';
const KEY_PAGE = 'acc://certen-kermit-12.acme/book/1';
const PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Create intent data (hex-encoded JSON blobs)
function createIntentData() {
    const intentId = crypto.randomUUID();
    const now = Date.now();
    const toHex = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('hex');

    return [
        toHex({ kind: "CERTEN_INTENT", version: "1.0", proof_class: "on_demand", intent_id: intentId, created_at: new Date().toISOString(), intentType: "cross_chain_transfer", description: "ETH transfer on Sepolia" }),
        toHex({
            protocol: "CERTEN",
            version: "1.0",
            operationGroupId: intentId,
            legs: [{
                legId: "leg-1",
                chain: "ethereum",
                chainId: 11155111,
                from: "0xc6831da653741afebc14a49e9c6291312a0ba3dd",
                to: "0xbe0043abb10e6db56b8c6c5cb3f639bf7fe69251",
                amountWei: "1",  // 1 wei - minimum for testing (contract needs ETH balance to forward)
                anchorContract: {
                    address: "0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98",
                    functionSelector: "createAnchor(bytes32,bytes32,bytes32,bytes32,uint256)"
                }
            }]
        }),
        toHex({ organizationAdi: "acc://certen-kermit-12.acme", authorization: { required_key_book: "acc://certen-kermit-12.acme/book", signature_threshold: 1 } }),
        toHex({ nonce: `certen_${now}`, created_at: Math.floor(now/1000), expires_at: Math.floor(now/1000) + 3600 })
    ];
}

async function main() {
    console.log('Submitting CERTEN Intent to Kermit Testnet...\n');

    const client = new api_v3.JsonRpcClient(ENDPOINT);
    const key = ED25519Key.from(Buffer.from(PRIVATE_KEY, 'hex'));

    // Query key page to get current version dynamically
    const keyPageResp = await fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'query',
            params: { scope: KEY_PAGE },
            id: 1
        })
    }).then(r => r.json());
    const keyPageVersion = keyPageResp?.result?.account?.version || 1;
    console.log(`Key page version: ${keyPageVersion}`);

    const signer = Signer.forPage(KEY_PAGE, key).withVersion(keyPageVersion);

    const entries = createIntentData();
    console.log(`Created ${entries.length} data entries`);

    const tx = new core.Transaction({
        header: { principal: DATA_ACCOUNT, memo: "CERTEN_INTENT", metadata: "01025f00" },
        body: { type: "writeData", entry: { type: "doubleHash", data: entries } }
    });

    const sig = await signer.sign(tx, { timestamp: Date.now() * 1000 });
    console.log('Transaction signed');

    const result = await client.submit({ transaction: [tx], signatures: [sig] });

    for (const r of result) {
        if (r.success) {
            console.log(`SUCCESS: ${r.status?.txID}`);
        } else {
            console.log(`Status: ${r.message || JSON.stringify(r)}`);
        }
    }
}

main().catch(console.error);
