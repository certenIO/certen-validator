#!/usr/bin/env node
/**
 * Submit CERTEN Intent WriteData to DevNet
 *
 * Updated 2026-03-18 for security audit 4-blob structure:
 *   CRITICAL-002: Length-prefixed canonical OperationID
 *   CRITICAL-003: executionPayload with executionCommitment in Blob 1
 *   MEDIUM-002: EIP-55 address normalization
 *   MEDIUM-003: crypto.randomBytes nonce
 */

import { api_v3, core, ED25519Key, Signer } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import crypto from 'crypto';
import { ethers } from 'ethers';

// Config - Kermit Testnet
const ENDPOINT = 'http://206.191.154.164:8660/v3';
const DATA_ACCOUNT = 'acc://certen-kermit-12.acme/data';
const KEY_PAGE = 'acc://certen-kermit-12.acme/book/1';
const PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';

// Target chain config
const TARGET_CHAIN_ID = 11155111; // Ethereum Sepolia
const FROM_ADDRESS = '0xc6831DA653741AFEBc14A49e9c6291312a0Ba3dd'; // will be checksummed
const TO_ADDRESS = '0xBe0043Abb10e6DB56b8c6c5cB3F639Bf7fE69251';   // will be checksummed
const AMOUNT_WEI = '1'; // 1 wei — minimum for testing
const ANCHOR_V5_ADDRESS = '0x4C8F0141cE43a77D6b80276B83AB092DeCEa050B';

// =============================================================================
// RFC 8785-compatible canonical JSON (must match Go + TypeScript API bridge)
// =============================================================================
function canonicalizeJSON(obj) {
    if (obj === null || obj === undefined) return 'null';
    if (typeof obj === 'boolean') return obj ? 'true' : 'false';
    if (typeof obj === 'number') return JSON.stringify(obj);
    if (typeof obj === 'string') return JSON.stringify(obj);
    if (Array.isArray(obj)) {
        return '[' + obj.map(item => canonicalizeJSON(item)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys.map(key => {
        return JSON.stringify(key) + ':' + canonicalizeJSON(obj[key]);
    });
    return '{' + entries.join(',') + '}';
}

// CRITICAL-002: Length-prefixed canonical 4-blob OperationID
function calculateOperationId(blob0, blob1, blob2, blob3) {
    const blobs = [blob0, blob1, blob2, blob3];
    const hash = crypto.createHash('sha256');
    for (const blob of blobs) {
        const canonical = Buffer.from(canonicalizeJSON(blob), 'utf8');
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(canonical.length, 0);
        hash.update(lenBuf);
        hash.update(canonical);
    }
    return '0x' + hash.digest('hex');
}

// CRITICAL-003: Compute executionPayload for a native transfer leg
function computeExecutionPayload(toAddress, amountWei, chainId) {
    // Native transfer: target=recipient, value=amount, data=empty
    const target = ethers.getAddress(toAddress); // EIP-55 checksum
    const value = amountWei;
    const callData = new Uint8Array(0);

    // keccak256(data) — empty bytes
    const dataHash = ethers.keccak256(callData);

    // keccak256(abi.encodePacked(uint256 chainId, address target, uint256 value, bytes32 dataHash))
    const packed = ethers.solidityPacked(
        ['uint256', 'address', 'uint256', 'bytes32'],
        [chainId, target, BigInt(value), dataHash]
    );
    const executionCommitment = ethers.keccak256(packed);

    return { target, value, dataHash, chainId, executionCommitment };
}

// =============================================================================
// Create 4-blob intent data (hex-encoded JSON blobs)
// =============================================================================
function createIntentData() {
    const intentId = crypto.randomUUID();
    const nowMs = Date.now();
    const nowSeconds = Math.floor(nowMs / 1000);
    const expiresAtSeconds = nowSeconds + 3600; // 1 hour
    const toHex = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('hex');

    // MEDIUM-002: Normalize addresses
    const fromAddr = ethers.getAddress(FROM_ADDRESS);
    const toAddr = ethers.getAddress(TO_ADDRESS);

    // CRITICAL-003: Compute execution payload
    const execPayload = computeExecutionPayload(toAddr, AMOUNT_WEI, TARGET_CHAIN_ID);

    // Blob 0: intentData (v2.0 format)
    const intentData = {
        kind: "CERTEN_INTENT",
        version: "2.0",
        proof_class: "on_demand",
        intentType: "single_leg_cross_chain_transfer",
        description: `Transfer ${AMOUNT_WEI} wei on Sepolia`,
        organizationAdi: "acc://certen-kermit-12.acme",
        initiator: {
            adi: "acc://certen-kermit-12.acme",
            by: "test-user-" + intentId.substring(0, 8),
            role: "organization_operator"
        },
        priority: "high",
        risk_level: "medium",
        compliance_required: false,
        leg_count: 1,
        execution_mode: "sequential",
        intent_id: intentId,
        created_by: "test-user-" + intentId.substring(0, 8),
        created_at: new Date(nowMs).toISOString(),
        intent_class: "financial_transfer",
        regulatory_jurisdiction: "global",
        tags: ["eth", "sepolia", "test"]
    };

    // Blob 1: crossChainData (v2.0 format with executionPayload)
    const crossChainData = {
        protocol: "CERTEN",
        version: "2.0",
        operationGroupId: intentId,
        legs: [{
            legId: `leg-ethereum-sepolia-${TARGET_CHAIN_ID}-1`,
            role: "payment",
            chain: "ethereum-sepolia",
            chainId: TARGET_CHAIN_ID,
            network: "ethereum-sepolia",
            asset: {
                symbol: "ETH",
                decimals: 18,
                native: true,
                contract_address: null,
                verified: true
            },
            from: fromAddr,
            to: toAddr,
            amountEth: "0.000000000000000001", // 1 wei in ETH
            amountWei: AMOUNT_WEI,
            execution_sequence: 1,
            conditional_execution: false,
            rollback_conditions: {
                timeout_seconds: 3600,
                failure_modes: ["gas_limit_exceeded", "insufficient_balance"]
            },
            anchorContract: {
                type: "evm_contract",
                address: ANCHOR_V5_ADDRESS,
                functionSelector: "createAnchor(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256)",
                version: "v5.0"
            },
            gasPolicy: {
                maxFeePerGasGwei: "20",
                maxPriorityFeePerGasGwei: "2",
                gasLimit: 300000,
                payer: "from",
                gas_estimation_buffer: 1.2
            },
            slippage_tolerance: "0.5%",
            deadline_timestamp: expiresAtSeconds,
            // CRITICAL-003: Execution payload binding
            executionPayload: {
                target: execPayload.target,
                value: execPayload.value,
                dataHash: execPayload.dataHash,
                chainId: execPayload.chainId,
                executionCommitment: execPayload.executionCommitment
            }
        }],
        execution_mode: "sequential",
        atomicity: {
            mode: "single_leg",
            rollback_strategy: "all_or_nothing",
            partial_execution_allowed: false
        },
        execution_constraints: {
            max_execution_time_seconds: 3600,
            required_confirmations: 1,
            parallel_execution: false
        },
        cross_chain_routing: {
            bridge_type: "certen_anchor_v5",
            relay_mechanism: "proof_based",
            finality_requirements: "fast"
        }
    };

    // Blob 2: governanceData
    const governanceData = {
        organizationAdi: "acc://certen-kermit-12.acme",
        authorization: {
            required_key_book: "acc://certen-kermit-12.acme/book",
            required_key_page: "acc://certen-kermit-12.acme/book/page",
            signature_threshold: 1,
            required_signers: ["acc://certen-kermit-12.acme/book"],
            roles: [{
                role: "DEFAULT_SIGNER",
                keyPage: "acc://certen-kermit-12.acme/book/page"
            }],
            authorization_hash: "" // Set after operation_id calculation
        },
        validation_rules: {
            max_amount: "1.0",
            daily_limit: "10.0",
            requires_approval: false,
            risk_level: "medium"
        },
        compliance_checks: {
            aml_required: false,
            kyc_verified: true,
            sanctions_check: "passed",
            jurisdiction: "compliant"
        }
    };

    // Blob 3: replayData
    // MEDIUM-003: crypto.randomBytes for nonce
    const randomPart = crypto.randomBytes(16).toString('hex');
    const replayData = {
        nonce: `certen_${nowMs}_${randomPart}`,
        created_at: nowSeconds,
        expires_at: expiresAtSeconds,
        intent_hash: "", // Set after operation_id calculation
        chain_nonces: {
            "ethereum-sepolia": "latest",
            accumulated: "1"
        },
        execution_window: {
            start_time: nowSeconds,
            end_time: expiresAtSeconds,
            grace_period_minutes: 5,
            max_retries: 3
        },
        security: {
            double_spending_protection: true,
            replay_attack_prevention: true,
            temporal_validation: "strict",
            nonce_validation: "required"
        }
    };

    // CRITICAL-002: Compute operation_id using canonical length-prefixed hash
    const operationId = calculateOperationId(intentData, crossChainData, governanceData, replayData);
    replayData.intent_hash = operationId;
    governanceData.authorization.authorization_hash = operationId;

    console.log(`  Intent ID: ${intentId}`);
    console.log(`  Operation ID: ${operationId}`);
    console.log(`  Execution Commitment: ${execPayload.executionCommitment}`);
    console.log(`  Target: ${execPayload.target}`);
    console.log(`  Value: ${execPayload.value} wei`);
    console.log(`  Nonce: ${replayData.nonce.substring(0, 40)}...`);

    return [
        toHex(intentData),
        toHex(crossChainData),
        toHex(governanceData),
        toHex(replayData)
    ];
}

// =============================================================================
// Main
// =============================================================================
async function main() {
    console.log('Submitting CERTEN Intent to Kermit Testnet (V5 format)...\n');

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
    console.log(`\nCreated ${entries.length} data entries (4-blob V5 format)`);

    const tx = new core.Transaction({
        header: { principal: DATA_ACCOUNT, memo: "CERTEN_INTENT" },
        body: { type: "writeData", entry: { type: "doubleHash", data: entries } }
    });

    const sig = await signer.sign(tx, { timestamp: Date.now() * 1000 });
    console.log('Transaction signed');

    const result = await client.submit({ transaction: [tx], signatures: [sig] });

    for (const r of result) {
        if (r.success) {
            console.log(`\nSUCCESS: ${r.status?.txID}`);
        } else {
            console.log(`\nStatus: ${r.message || JSON.stringify(r)}`);
        }
    }
}

main().catch(console.error);
