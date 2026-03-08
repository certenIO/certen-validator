#!/usr/bin/env node
/**
 * Setup CERTEN Protocol Identity on Kermit Testnet
 * Uses a Lite Identity as sponsor (no ADI needed)
 *
 * Creates:
 * - acc://certenprotocol.acme (ADI)
 * - acc://certenprotocol.acme/book (Key Book) - created automatically with ADI
 * - acc://certenprotocol.acme/book/1 (Key Page) - created automatically with ADI
 * - acc://certenprotocol.acme/execution-results (Data Account for write-back)
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import * as crypto from 'crypto';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor - Lite Identity (funded via faucet)
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// New CERTEN Protocol identity
const NEW_ADI = 'acc://certenprotocol.acme';
const NEW_BOOK = 'acc://certenprotocol.acme/book';
const NEW_KEY_PAGE = 'acc://certenprotocol.acme/book/1';
const NEW_DATA_ACCOUNT = 'acc://certenprotocol.acme/execution-results';

// CERTEN identity key
const CERTEN_IDENTITY_PRIVATE_KEY = '0c2576e533a6c4e81c07a9062859462514bf3bdb13bb92a32621d1e849ad1232d481f10ac40451048c827ac60327a233e21187043d41676832166b96812cab84';
const CERTEN_IDENTITY_PUBLIC_KEY = 'd481f10ac40451048c827ac60327a233e21187043d41676832166b96812cab84';

// Compute lite account URLs from private key
function computeLiteAccountURLs(privateKeyHex) {
    const publicKeyHex = privateKeyHex.slice(64);
    const publicKey = Buffer.from(publicKeyHex, 'hex');
    const hash20 = crypto.createHash('sha256').update(publicKey).digest().slice(0, 20);
    const hash20Hex = hash20.toString('hex');
    const checksumHash = crypto.createHash('sha256').update(hash20Hex.toLowerCase()).digest();
    const checksum = checksumHash.slice(28, 32).toString('hex');
    const liteId = hash20Hex + checksum;
    return {
        lid: `acc://${liteId}`,
        lta: `acc://${liteId}/ACME`
    };
}

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

async function waitForTx(txId, maxAttempts = 30) {
    console.log(`  Waiting for tx: ${txId}`);
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 2000));
        try {
            const resp = await fetch(ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    method: 'query',
                    params: { scope: txId.toString() },
                    id: 1
                })
            }).then(r => r.json());

            const status = resp?.result?.status;
            if (status === 'delivered') {
                console.log(`  Transaction delivered`);
                return true;
            }
            if (status === 'failed') {
                console.log(`  Transaction failed: ${JSON.stringify(resp?.result)}`);
                return false;
            }
            console.log(`  ... status: ${status || 'pending'}`);
        } catch (e) {
            console.log(`  ... waiting (${e.message})`);
        }
    }
    console.log(`  Transaction timed out`);
    return false;
}

async function main() {
    console.log('='.repeat(60));
    console.log('CERTEN Protocol Identity Setup - Kermit Testnet');
    console.log('Using Lite Identity as Sponsor');
    console.log('='.repeat(60));
    console.log();

    const client = new api_v3.JsonRpcClient(ENDPOINT);

    // Setup sponsor (lite identity)
    const sponsorUrls = computeLiteAccountURLs(SPONSOR_PRIVATE_KEY);
    console.log('Sponsor LID:', sponsorUrls.lid);
    console.log('Sponsor LTA:', sponsorUrls.lta);

    const sponsorKey = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY, 'hex'));
    const liteSigner = Signer.forLite(sponsorKey);

    // Check sponsor credits
    const sponsorInfo = await queryAccount(sponsorUrls.lid);
    console.log(`Sponsor credits: ${sponsorInfo?.account?.creditBalance || 0}`);
    console.log();

    // Check if ADI already exists
    console.log(`Checking if ${NEW_ADI} exists...`);
    const existingAdi = await queryAccount(NEW_ADI);
    if (existingAdi) {
        console.log(`ADI ${NEW_ADI} already exists`);
    } else {
        console.log(`ADI does not exist, will create it`);
    }

    // Setup CERTEN identity key
    console.log('\nUsing predefined key for CERTEN identity...');
    const certenKey = ED25519Key.from(Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY, 'hex'));
    console.log(`  Public Key: ${CERTEN_IDENTITY_PUBLIC_KEY}`);
    console.log();

    if (!existingAdi) {
        // Step 1: Create ADI using lite identity as sponsor
        console.log('\n[Step 1] Creating ADI...');
        console.log(`  ADI: ${NEW_ADI}`);
        console.log(`  Book: ${NEW_BOOK}`);

        const keyHash = crypto.createHash('sha256').update(Buffer.from(CERTEN_IDENTITY_PUBLIC_KEY, 'hex')).digest();
        console.log(`  Key Hash: ${keyHash.toString('hex')}`);

        const createAdiTx = new core.Transaction({
            header: { principal: sponsorUrls.lid },
            body: {
                type: 'createIdentity',
                url: NEW_ADI,
                keyBookUrl: NEW_BOOK,
                keyHash: keyHash
            }
        });

        const adiSig = await liteSigner.sign(createAdiTx, { timestamp: Date.now() * 1000 });
        const adiResult = await client.submit({ transaction: [createAdiTx], signatures: [adiSig] });

        for (const r of adiResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(r.status?.txID);
            } else {
                console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
                return;
            }
        }

        // Wait for ADI to be created
        await new Promise(r => setTimeout(r, 5000));

        // Verify ADI was created
        const createdAdi = await queryAccount(NEW_ADI);
        if (createdAdi) {
            console.log(`  ADI created successfully`);
        } else {
            console.log(`  ADI not found after creation - may still be pending`);
        }
    }

    // Step 2: Add credits to the new key page so it can sign transactions
    console.log('\n[Step 2] Adding credits to new key page...');

    // First check if the key page exists
    await new Promise(r => setTimeout(r, 3000));
    const keyPageInfo = await queryAccount(NEW_KEY_PAGE);
    if (!keyPageInfo) {
        console.log(`  Key page ${NEW_KEY_PAGE} not found yet, waiting...`);
        await new Promise(r => setTimeout(r, 10000));
    }

    const addCreditsTx = new core.Transaction({
        header: { principal: sponsorUrls.lta },
        body: {
            type: 'addCredits',
            recipient: NEW_KEY_PAGE,
            amount: BigInt(100000000), // 1 ACME worth of credits
            oracle: 10000000 // Current oracle price
        }
    });

    const creditsSig = await liteSigner.sign(addCreditsTx, { timestamp: Date.now() * 1000 });
    const creditsResult = await client.submit({ transaction: [addCreditsTx], signatures: [creditsSig] });

    for (const r of creditsResult) {
        if (r.success) {
            console.log(`  Submitted: ${r.status?.txID}`);
            await waitForTx(r.status?.txID);
        } else {
            console.log(`  Failed: ${r.message || JSON.stringify(r)}`);
        }
    }

    // Step 3: Create Data Account for execution results
    console.log(`\n[Step 3] Checking if ${NEW_DATA_ACCOUNT} exists...`);
    const existingData = await queryAccount(NEW_DATA_ACCOUNT);
    if (existingData) {
        console.log(`  Data account already exists`);
    } else {
        console.log('  Creating Data Account for execution-results...');

        // Need to sign with the CERTEN identity key
        const newKeyPageVersion = await getKeyPageVersion(NEW_KEY_PAGE);
        console.log(`  Key page version: ${newKeyPageVersion}`);
        const certenSigner = Signer.forPage(NEW_KEY_PAGE, certenKey).withVersion(newKeyPageVersion);

        const createDataTx = new core.Transaction({
            header: { principal: NEW_ADI },
            body: {
                type: 'createDataAccount',
                url: NEW_DATA_ACCOUNT
            }
        });

        const dataSig = await certenSigner.sign(createDataTx, { timestamp: Date.now() * 1000 });
        const dataResult = await client.submit({ transaction: [createDataTx], signatures: [dataSig] });

        for (const r of dataResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(r.status?.txID);
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
    console.log(`CERTEN_KEYPAGE_PUBLIC_KEY=${CERTEN_IDENTITY_PUBLIC_KEY}`);
    console.log(`CERTEN_KEYPAGE_PRIVATE_KEY=${CERTEN_IDENTITY_PRIVATE_KEY}`);
    console.log();
    console.log('# Enable write-back');
    console.log('PROOF_CYCLE_WRITEBACK=true');
    console.log(`ACCUMULATE_RESULTS_PRINCIPAL=${NEW_DATA_ACCOUNT}`);
    console.log();
}

main().catch(console.error);
