#!/usr/bin/env node
/**
 * Setup CERTEN Protocol Identity on Kermit Testnet
 * Based EXACTLY on comprehensive_api_v3.ts example
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';
const client = new api_v3.JsonRpcClient(ENDPOINT);

const waitTime = 1000;
const waitLimit = 120000 / waitTime;

// Sponsor - Lite Identity (funded via faucet 2026-01-22)
// Use first 32 bytes as seed
const SPONSOR_PRIVATE_KEY_SEED = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a2';

// CERTEN identity key - use first 32 bytes as seed
const CERTEN_IDENTITY_PRIVATE_KEY_SEED = '0c2576e533a6c4e81c07a9062859462514bf3bdb13bb92a32621d1e849ad1232';

// Target accounts
const IDENTITY_URL = 'acc://certenprotocol.acme';
const BOOK_URL = IDENTITY_URL + '/book';
const KEY_PAGE_URL = BOOK_URL + '/1';
const DATA_ACCOUNT_URL = IDENTITY_URL + '/execution-results';

async function waitForTx(txid) {
    console.log(`Waiting for ${txid}`);
    for (let i = 0; i < waitLimit; i++) {
        try {
            const r = await client.query(txid);
            const status = r.status;

            if (i % 10 === 0) {
                console.log(`  Status check: ${JSON.stringify(status)} (attempt ${i + 1}/${waitLimit})`);
            }

            if (status && (status === 201 || status === 'delivered' || status?.code === 'delivered')) {
                console.log(`  Transaction completed successfully`);
                return r;
            }

            await new Promise(resolve => setTimeout(resolve, waitTime));
        } catch (error) {
            if (i % 10 === 0) {
                console.log(`  Transaction not found yet... (attempt ${i + 1}/${waitLimit})`);
            }
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }
    }
    throw new Error(`Transaction still pending after ${(waitTime * waitLimit) / 1000} seconds`);
}

async function getCurrentKeyPageVersion(keyPageUrl) {
    try {
        const keyPageQuery = await client.query(keyPageUrl);
        const version = keyPageQuery?.data?.version || keyPageQuery?.account?.version;
        if (version !== undefined) {
            console.log(`  Key page ${keyPageUrl} current version: ${version}`);
            return version;
        }
        console.log(`  Key page version not found, assuming version 1`);
        return 1;
    } catch (error) {
        console.log(`  Could not query key page version, assuming version 1`);
        return 1;
    }
}

async function main() {
    console.log('='.repeat(60));
    console.log('CERTEN Protocol Identity Setup - Kermit Testnet');
    console.log('Based on comprehensive_api_v3.ts');
    console.log('='.repeat(60));
    console.log();

    // Setup sponsor (lite identity)
    const sponsorKey = ED25519Key.from(Buffer.from(SPONSOR_PRIVATE_KEY_SEED, 'hex'));
    const lid = Signer.forLite(sponsorKey);
    const lta = lid.url.join('ACME');

    console.log('Sponsor LID:', lid.url.toString());
    console.log('Sponsor LTA:', lta.toString());

    // Setup CERTEN identity key
    const identitySigner = ED25519Key.from(Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY_SEED, 'hex'));
    console.log('CERTEN Identity Public Key:', Buffer.from(identitySigner.address.publicKey).toString('hex'));
    console.log('CERTEN Identity Key Hash:', Buffer.from(identitySigner.address.publicKeyHash).toString('hex'));
    console.log();

    // Check sponsor balance/credits
    try {
        const lidQuery = await client.query(lid.url);
        console.log(`Sponsor credits: ${lidQuery?.account?.creditBalance || 0}`);
    } catch (e) {
        console.log('Could not query sponsor');
    }

    // Check if ADI already exists
    console.log(`\nChecking if ${IDENTITY_URL} exists...`);
    let adiExists = false;
    try {
        const identityQuery = await client.query(IDENTITY_URL);
        if (identityQuery?.account?.type === 'identity') {
            console.log('ADI already exists!');
            adiExists = true;
        }
    } catch (e) {
        console.log('ADI does not exist, will create it');
    }

    if (!adiExists) {
        // Step 1: Create ADI
        console.log('\n[Step 1] Creating ADI...');
        console.log(`  ADI: ${IDENTITY_URL}`);
        console.log(`  Book: ${BOOK_URL}`);

        const txn = new core.Transaction({
            header: {
                principal: lid.url,
            },
            body: {
                type: 'createIdentity',
                url: IDENTITY_URL,
                keyHash: identitySigner.address.publicKeyHash,
                keyBookUrl: BOOK_URL,
            },
        });

        const sig = await lid.sign(txn, { timestamp: Date.now() * 1000 });
        const submitRes = await client.submit({ transaction: [txn], signatures: [sig] });

        for (const r of submitRes) {
            if (!r.success) {
                throw new Error(`Submission failed: ${r.message}`);
            }
            console.log(`  Submitted: ${r.status?.txID}`);
            await waitForTx(r.status.txID);
        }

        console.log('ADI created successfully!');

        // Wait for ADI to propagate
        console.log('  Waiting 5 seconds for ADI to propagate...');
        await new Promise(resolve => setTimeout(resolve, 5000));

        // Verify ADI exists
        for (let i = 0; i < 10; i++) {
            try {
                const identityQuery = await client.query(IDENTITY_URL);
                console.log(`  ADI type: ${identityQuery?.account?.type}`);
                break;
            } catch (error) {
                console.log(`  ADI not yet available, retrying... (${i + 1}/10)`);
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
    }

    // Step 2: Add credits to key page
    console.log('\n[Step 2] Purchasing credits for ADI key page...');
    console.log(`  Key page URL: ${KEY_PAGE_URL}`);

    // Get oracle price
    const { oracle } = await client.networkStatus();
    console.log(`  Oracle price: ${oracle?.price}`);

    const keyPageCreditsAmount = ((500 * 10 ** 2) / oracle.price) * 10 ** 8;
    console.log(`  Purchasing ${keyPageCreditsAmount} ACME (500 credits) for key page`);

    const creditsTxn = new core.Transaction({
        header: {
            principal: lta,
        },
        body: {
            type: 'addCredits',
            recipient: KEY_PAGE_URL,
            amount: keyPageCreditsAmount,
            oracle: oracle.price,
        },
    });

    const creditsSig = await lid.sign(creditsTxn, { timestamp: Date.now() * 1000 });
    const creditsRes = await client.submit({ transaction: [creditsTxn], signatures: [creditsSig] });

    for (const r of creditsRes) {
        if (!r.success) {
            throw new Error(`Credits submission failed: ${r.message}`);
        }
        console.log(`  Submitted: ${r.status?.txID}`);
        await waitForTx(r.status.txID);
    }

    // Wait for key page credits - THIS IS CRITICAL
    console.log('  Waiting 15 seconds for key page credits to be applied...');
    await new Promise(resolve => setTimeout(resolve, 15000));

    // Verify key page has credits
    let keyPageHasCredits = false;
    for (let i = 0; i < 10; i++) {
        try {
            const keyPageQuery = await client.query(KEY_PAGE_URL);
            const credits = keyPageQuery?.account?.creditBalance || keyPageQuery?.data?.creditBalance || 0;
            console.log(`  Key page credits (attempt ${i + 1}): ${credits}`);
            if (credits > 0) {
                console.log(`  Key page now has ${credits} credits`);
                keyPageHasCredits = true;
                break;
            }
        } catch (error) {
            console.log(`  Key page not yet available, retrying... (${i + 1}/10)`);
        }
        await new Promise(resolve => setTimeout(resolve, 3000));
    }

    if (!keyPageHasCredits) {
        console.log('  WARNING: Key page credits not yet visible, but proceeding...');
    }

    // Step 3: Create data account
    console.log('\n[Step 3] Creating data account...');
    console.log(`  Data account: ${DATA_ACCOUNT_URL}`);

    // Check if data account already exists
    try {
        const dataQuery = await client.query(DATA_ACCOUNT_URL);
        if (dataQuery?.account) {
            console.log('  Data account already exists!');
            printSummary(identitySigner);
            return;
        }
    } catch (e) {
        // Data account doesn't exist, create it
    }

    // Get current key page version
    const currentVersion = await getCurrentKeyPageVersion(KEY_PAGE_URL);

    // Create signer for the ADI key page
    const adiSigner = Signer.forPage(KEY_PAGE_URL, identitySigner).withVersion(currentVersion);

    const dataTxn = new core.Transaction({
        header: {
            principal: IDENTITY_URL,
        },
        body: {
            type: 'createDataAccount',
            url: DATA_ACCOUNT_URL,
        },
    });

    const dataSig = await adiSigner.sign(dataTxn, { timestamp: Date.now() * 1000 });
    const dataRes = await client.submit({ transaction: [dataTxn], signatures: [dataSig] });

    for (const r of dataRes) {
        if (!r.success) {
            throw new Error(`Data account submission failed: ${r.message}`);
        }
        console.log(`  Submitted: ${r.status?.txID}`);
        await waitForTx(r.status.txID);
    }

    console.log('Data account created successfully!');

    // Verify data account
    for (let i = 0; i < 10; i++) {
        try {
            const dataQuery = await client.query(DATA_ACCOUNT_URL);
            console.log(`  Data account type: ${dataQuery?.account?.type}`);
            break;
        } catch (error) {
            console.log(`  Data account not yet available, retrying... (${i + 1}/10)`);
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }

    printSummary(identitySigner);
}

function printSummary(identitySigner) {
    console.log('\n' + '='.repeat(60));
    console.log('SETUP COMPLETE');
    console.log('='.repeat(60));
    console.log();
    console.log('Add these to your .env files:');
    console.log();
    console.log('# CERTEN Protocol Identity (Kermit)');
    console.log(`CERTEN_IDENTITY=${IDENTITY_URL}`);
    console.log(`CERTEN_IDENTITY_BOOK=${BOOK_URL}`);
    console.log(`CERTEN_IDENTITY_KEYPAGE=${KEY_PAGE_URL}`);
    console.log(`CERTEN_IDENTITY_DATA=${DATA_ACCOUNT_URL}`);
    console.log(`CERTEN_KEYPAGE_PUBLIC_KEY=${Buffer.from(identitySigner.address.publicKey).toString('hex')}`);
    console.log(`CERTEN_KEYPAGE_PRIVATE_KEY=${CERTEN_IDENTITY_PRIVATE_KEY_SEED}${Buffer.from(identitySigner.address.publicKey).toString('hex')}`);
    console.log();
    console.log('# Enable write-back');
    console.log('PROOF_CYCLE_WRITEBACK=true');
    console.log(`ACCUMULATE_RESULTS_PRINCIPAL=${DATA_ACCOUNT_URL}`);
    console.log();
}

main().catch(console.error);
