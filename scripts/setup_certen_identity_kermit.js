#!/usr/bin/env node
/**
 * Setup CERTEN Protocol Identity on Kermit Testnet
 *
 * Creates:
 * - acc://certenprotocol.acme (ADI)
 * - acc://certenprotocol.acme/book (Key Book)
 * - acc://certenprotocol.acme/book/1 (Key Page)
 * - acc://certenprotocol.acme/execution-results (Data Account for write-back)
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import * as crypto from 'crypto';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';

// Sponsor account - Lite Identity (funded via faucet 2026-01-22)
// NOTE: Use setup_certen_identity_from_lite.js instead - it uses the lite identity directly
const SPONSOR_LID = 'acc://4d07443e23bf3d244facb56f7fd4614d29b21f553c25eef5';
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// New CERTEN Protocol identity
const NEW_ADI = 'acc://certenprotocol.acme';
const NEW_BOOK = 'acc://certenprotocol.acme/book';
const NEW_KEY_PAGE = 'acc://certenprotocol.acme/book/1';
const NEW_DATA_ACCOUNT = 'acc://certenprotocol.acme/execution-results';

// Use existing CERTEN identity key from certen-protocol/.env
// This key was pre-generated for certenprotocol.acme
const CERTEN_IDENTITY_PRIVATE_KEY = '0c2576e533a6c4e81c07a9062859462514bf3bdb13bb92a32621d1e849ad1232d481f10ac40451048c827ac60327a233e21187043d41676832166b96812cab84';
const CERTEN_IDENTITY_PUBLIC_KEY = 'd481f10ac40451048c827ac60327a233e21187043d41676832166b96812cab84';

function getIdentityKey() {
    return ED25519Key.from(Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY, 'hex'));
}

async function queryAccount(client, url) {
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
    console.log('CERTEN Protocol Identity Setup - Kermit Testnet');
    console.log('='.repeat(60));
    console.log();

    const client = new api_v3.JsonRpcClient(ENDPOINT);
    const sponsorKey = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY, 'hex'));

    // Check if ADI already exists
    console.log(`Checking if ${NEW_ADI} exists...`);
    const existingAdi = await queryAccount(client, NEW_ADI);
    if (existingAdi) {
        console.log(`✅ ADI ${NEW_ADI} already exists`);
    } else {
        console.log(`ADI does not exist, will create it`);
    }

    // Use predefined key for the CERTEN identity
    console.log('\nUsing predefined key for CERTEN identity...');
    const newKey = getIdentityKey();
    const publicKeyHex = CERTEN_IDENTITY_PUBLIC_KEY;
    const privateKeyHex = CERTEN_IDENTITY_PRIVATE_KEY;

    console.log(`  Public Key:  ${publicKeyHex}`);
    console.log(`  Private Key: ${privateKeyHex.substring(0, 20)}...`);
    console.log();

    // Get sponsor key page version
    const sponsorVersion = await getKeyPageVersion(SPONSOR_KEY_PAGE);
    console.log(`Sponsor key page version: ${sponsorVersion}`);
    const sponsorSigner = Signer.forPage(SPONSOR_KEY_PAGE, sponsorKey).withVersion(sponsorVersion);

    if (!existingAdi) {
        // Step 1: Create ADI
        console.log('\n[Step 1] Creating ADI...');
        const createAdiTx = new core.Transaction({
            header: { principal: 'acc://certen-kermit-11.acme' },
            body: {
                type: 'createIdentity',
                url: NEW_ADI,
                keyBookUrl: NEW_BOOK,
                keyHash: crypto.createHash('sha256').update(Buffer.from(CERTEN_IDENTITY_PUBLIC_KEY, 'hex')).digest()
            }
        });

        const adiSig = await sponsorSigner.sign(createAdiTx, { timestamp: Date.now() * 1000 });
        const adiResult = await client.submit({ transaction: [createAdiTx], signatures: [adiSig] });

        for (const r of adiResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(r.status?.txID);
            } else {
                console.log(`  ❌ Failed: ${r.message || JSON.stringify(r)}`);
                return;
            }
        }
    }

    // Check if data account exists
    console.log(`\nChecking if ${NEW_DATA_ACCOUNT} exists...`);
    const existingData = await queryAccount(client, NEW_DATA_ACCOUNT);
    if (existingData) {
        console.log(`✅ Data account already exists`);
    } else {
        // Step 2: Create Data Account for execution results
        console.log('\n[Step 2] Creating Data Account for execution-results...');

        // Need to sign with the new identity's key for authorization
        const newKeyPageVersion = await getKeyPageVersion(NEW_KEY_PAGE);
        console.log(`  New key page version: ${newKeyPageVersion}`);
        const newSigner = Signer.forPage(NEW_KEY_PAGE, newKey).withVersion(newKeyPageVersion);

        // Update sponsor signer version (may have changed)
        const updatedSponsorVersion = await getKeyPageVersion(SPONSOR_KEY_PAGE);
        console.log(`  Updated sponsor key page version: ${updatedSponsorVersion}`);
        const updatedSponsorSigner = Signer.forPage(SPONSOR_KEY_PAGE, sponsorKey).withVersion(updatedSponsorVersion);

        const createDataTx = new core.Transaction({
            header: { principal: NEW_ADI },
            body: {
                type: 'createDataAccount',
                url: NEW_DATA_ACCOUNT
            }
        });

        // The new identity signs for authorization
        // The sponsor signs as initiator to pay the fees (since new key page has 0 credits)
        const timestamp = Date.now() * 1000;
        const dataSig = await newSigner.sign(createDataTx, { timestamp });
        const initiatorSig = await updatedSponsorSigner.sign(createDataTx, { timestamp, initiator: true });
        const dataResult = await client.submit({ transaction: [createDataTx], signatures: [dataSig, initiatorSig] });

        for (const r of dataResult) {
            if (r.success) {
                console.log(`  Submitted: ${r.status?.txID}`);
                await waitForTx(r.status?.txID);
            } else {
                console.log(`  ❌ Failed: ${r.message || JSON.stringify(r)}`);
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
    console.log(`CERTEN_KEYPAGE_PUBLIC_KEY=${publicKeyHex}`);
    console.log(`CERTEN_KEYPAGE_PRIVATE_KEY=${privateKeyHex}`);
    console.log();
    console.log('# Enable write-back');
    console.log('PROOF_CYCLE_WRITEBACK=true');
    console.log(`ACCUMULATE_RESULTS_PRINCIPAL=${NEW_DATA_ACCOUNT}`);
    console.log();
}

main().catch(console.error);
