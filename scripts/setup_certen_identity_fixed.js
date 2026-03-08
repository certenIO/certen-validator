#!/usr/bin/env node
/**
 * Setup CERTEN Protocol Identity on Kermit Testnet - FIXED VERSION
 * Based on working api-bridge AccumulateService.ts implementation
 *
 * Creates:
 * - acc://certenprotocol.acme (ADI)
 * - acc://certenprotocol.acme/book (Key Book) - created automatically with ADI
 * - acc://certenprotocol.acme/book/1 (Key Page) - created automatically with ADI
 * - acc://certenprotocol.acme/execution-results (Data Account for write-back)
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor - Lite Identity (funded via faucet 2026-01-22)
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// New CERTEN Protocol identity
const NEW_ADI = 'acc://certenprotocol.acme';
const NEW_BOOK = 'acc://certenprotocol.acme/book';
const NEW_KEY_PAGE = 'acc://certenprotocol.acme/book/1';
const NEW_DATA_ACCOUNT = 'acc://certenprotocol.acme/execution-results';

// CERTEN identity key - use first 32 bytes (64 hex chars) as seed for ED25519Key
const CERTEN_IDENTITY_PRIVATE_KEY_SEED = '0c2576e533a6c4e81c07a9062859462514bf3bdb13bb92a32621d1e849ad1232';

async function queryAccount(url) {
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
            return null;
        }
        return resp.result;
    } catch (e) {
        return null;
    }
}

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
                console.log(`  Transaction failed`);
                return false;
            }
            console.log(`  ... status: ${status || 'pending'} (attempt ${i+1}/${maxAttempts})`);
        } catch (e) {
            console.log(`  ... waiting (attempt ${i+1}/${maxAttempts})`);
        }
    }
    console.log(`  Transaction timed out`);
    return false;
}

async function main() {
    console.log('='.repeat(60));
    console.log('CERTEN Protocol Identity Setup - Kermit Testnet');
    console.log('FIXED VERSION - Based on api-bridge implementation');
    console.log('='.repeat(60));
    console.log();

    const client = new api_v3.JsonRpcClient(ENDPOINT);

    // Setup sponsor (lite identity) - use first 32 bytes as seed
    const sponsorPrivateKeySeed = SPONSOR_PRIVATE_KEY.substring(0, 64);
    const sponsorKey = ED25519Key.from(Buffer.from(sponsorPrivateKeySeed, 'hex'));
    const lid = Signer.forLite(sponsorKey);

    console.log('Sponsor LID:', lid.url.toString());

    // Check sponsor credits
    const sponsorInfo = await queryAccount(lid.url.toString());
    console.log(`Sponsor credits: ${sponsorInfo?.account?.creditBalance || 0}`);
    console.log();

    // Setup CERTEN identity key - use 32 byte seed
    const certenKey = ED25519Key.from(Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY_SEED, 'hex'));
    console.log('CERTEN Key Public Key:', Buffer.from(certenKey.address.publicKey).toString('hex'));
    console.log('CERTEN Key Public Key Hash:', Buffer.from(certenKey.address.publicKeyHash).toString('hex'));
    console.log();

    // Check if ADI already exists
    console.log(`Checking if ${NEW_ADI} exists...`);
    const existingAdi = await queryAccount(NEW_ADI);
    if (existingAdi) {
        console.log(`ADI ${NEW_ADI} already exists`);
    } else {
        console.log(`ADI does not exist, will create it`);

        // Step 1: Create ADI using lite identity as sponsor
        // Following api-bridge AccumulateService.createIdentity pattern exactly
        console.log('\n[Step 1] Creating ADI...');
        console.log(`  ADI: ${NEW_ADI}`);
        console.log(`  Book: ${NEW_BOOK}`);

        const createAdiTx = new core.Transaction({
            header: {
                principal: lid.url,  // Lite identity URL as principal
            },
            body: {
                type: 'createIdentity',
                url: NEW_ADI,
                keyHash: certenKey.address.publicKeyHash,  // Use SDK's publicKeyHash directly
                keyBookUrl: NEW_BOOK,
            }
        });

        const timestamp = Date.now() * 1000;
        console.log(`  Timestamp: ${timestamp}`);

        const adiSig = await lid.sign(createAdiTx, { timestamp });
        const adiResult = await client.submit({ transaction: [createAdiTx], signatures: [adiSig] });

        for (const r of adiResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(client, r.status?.txID);
            } else {
                console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
                return;
            }
        }

        // Wait for ADI to propagate
        console.log('  Waiting for ADI to propagate (30s)...');
        await new Promise(r => setTimeout(r, 30000));
    }

    // Verify ADI was created
    const createdAdi = await queryAccount(NEW_ADI);
    if (!createdAdi) {
        console.log('  ADI still not found - network may be slow, try again later');
        return;
    }
    console.log('  ADI exists!');

    // Step 2: Add credits to the new key page
    console.log('\n[Step 2] Adding credits to new key page...');

    const keyPageExists = await queryAccount(NEW_KEY_PAGE);
    if (!keyPageExists) {
        console.log('  Key page not found yet, waiting 30s...');
        await new Promise(r => setTimeout(r, 30000));
    }

    // Check if keypage already has credits
    const keyPageInfo = await queryAccount(NEW_KEY_PAGE);
    const existingCredits = keyPageInfo?.account?.creditBalance || 0;
    console.log(`  Current keypage credits: ${existingCredits}`);

    if (existingCredits < 10000) {
        const addCreditsTx = new core.Transaction({
            header: { principal: lid.url.join('ACME') },
            body: {
                type: 'addCredits',
                recipient: NEW_KEY_PAGE,
                amount: BigInt(100000000), // 1 ACME worth
                oracle: 10000000
            }
        });

        const creditsSig = await lid.sign(addCreditsTx, { timestamp: Date.now() * 1000 });
        const creditsResult = await client.submit({ transaction: [addCreditsTx], signatures: [creditsSig] });

        for (const r of creditsResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(client, r.status?.txID);
            } else {
                console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
            }
        }

        // Wait for credits to propagate
        await new Promise(r => setTimeout(r, 5000));
    }

    // Step 3: Create Data Account
    console.log(`\n[Step 3] Checking if ${NEW_DATA_ACCOUNT} exists...`);
    const existingData = await queryAccount(NEW_DATA_ACCOUNT);
    if (existingData) {
        console.log(`  Data account already exists`);
    } else {
        console.log('  Creating Data Account...');

        // Get current key page version
        const currentVersion = await getKeyPageVersion(NEW_KEY_PAGE);
        console.log(`  Key page version: ${currentVersion}`);

        // Create ADI signer with keypage - following api-bridge pattern
        const adiSigner = Signer.forPage(NEW_KEY_PAGE, certenKey).withVersion(currentVersion);

        const createDataTx = new core.Transaction({
            header: {
                principal: NEW_ADI,  // ADI is principal for data account creation
            },
            body: {
                type: 'createDataAccount',
                url: NEW_DATA_ACCOUNT,
            }
        });

        const dataSig = await adiSigner.sign(createDataTx, { timestamp: Date.now() * 1000 });
        const dataResult = await client.submit({ transaction: [createDataTx], signatures: [dataSig] });

        for (const r of dataResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(client, r.status?.txID);
            } else {
                console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
            }
        }
    }

    // Print summary
    console.log('\n' + '='.repeat(60));
    console.log('SETUP COMPLETE');
    console.log('='.repeat(60));
    console.log();
    console.log('Add these to your .env files:');
    console.log();
    console.log('# CERTEN Protocol Identity (Kermit)');
    console.log(`CERTEN_IDENTITY=${NEW_ADI}`);
    console.log(`CERTEN_IDENTITY_BOOK=${NEW_BOOK}`);
    console.log(`CERTEN_IDENTITY_KEYPAGE=${NEW_KEY_PAGE}`);
    console.log(`CERTEN_IDENTITY_DATA=${NEW_DATA_ACCOUNT}`);
    console.log(`CERTEN_KEYPAGE_PUBLIC_KEY=${Buffer.from(certenKey.address.publicKey).toString('hex')}`);
    console.log(`CERTEN_KEYPAGE_PRIVATE_KEY=${CERTEN_IDENTITY_PRIVATE_KEY_SEED}${Buffer.from(certenKey.address.publicKey).toString('hex')}`);
    console.log();
}

main().catch(console.error);
