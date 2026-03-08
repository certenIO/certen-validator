#!/usr/bin/env node
// ============================================================================
// Certen Protocol - Non-EVM Chain Key Generator
// ============================================================================
// Generates 35 keypairs (7 validators x 5 non-EVM chains):
//   Solana, Aptos, Sui, NEAR, TON
//
// Usage:
//   npm install
//   node generate.mjs
//
// Output (in ./output/):
//   all-keys.json       - Complete keypairs (SENSITIVE!)
//   addresses.json      - Public addresses only (safe to share)
//   validator-N.env     - Per-validator env snippets (N=1..7)
//   shared.env          - Shared config (RPC URLs, contract addresses)
// ============================================================================

import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { sha3_256 } from '@noble/hashes/sha3';
import { blake2b } from '@noble/hashes/blake2b';
import { bech32 } from 'bech32';
import { mnemonicNew, mnemonicToPrivateKey } from '@ton/crypto';
import { WalletContractV4 } from '@ton/ton';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = join(__dirname, 'output');
const NUM_VALIDATORS = 7;

// ============================================================================
// Solana: Ed25519 keypair, base58 encoding
// ============================================================================
function generateSolanaKeypair() {
  const keypair = nacl.sign.keyPair();
  return {
    // Solana "private key" is the full 64-byte secret (32 seed + 32 pubkey)
    privateKey: bs58.encode(keypair.secretKey),
    publicKey: bs58.encode(keypair.publicKey),
  };
}

// ============================================================================
// Aptos: Ed25519 keypair, SHA3-256 address derivation
// Address = SHA3-256(pubkey_32bytes || 0x00_scheme_byte)
// ============================================================================
function generateAptosKeypair() {
  const keypair = nacl.sign.keyPair();
  const seed = keypair.secretKey.slice(0, 32);
  const privateKeyHex = '0x' + Buffer.from(seed).toString('hex');

  // Aptos single-key auth: SHA3-256(pubkey || 0x00)
  const authKeyInput = new Uint8Array(33);
  authKeyInput.set(keypair.publicKey, 0);
  authKeyInput[32] = 0x00; // Ed25519 scheme
  const address = '0x' + Buffer.from(sha3_256(authKeyInput)).toString('hex');

  return {
    privateKey: privateKeyHex,
    publicKey: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
    address,
  };
}

// ============================================================================
// Sui: Ed25519 keypair, Bech32 private key, Blake2b-256 address
// Private key = bech32("suiprivkey", [0x00_flag] + 32_seed)
// Address = Blake2b-256([0x00_flag] + pubkey_32bytes)
// ============================================================================
function generateSuiKeypair() {
  const keypair = nacl.sign.keyPair();
  const seed = keypair.secretKey.slice(0, 32);

  // Encode private key as Sui bech32 format
  const privKeyWithFlag = new Uint8Array(33);
  privKeyWithFlag[0] = 0x00; // Ed25519 flag
  privKeyWithFlag.set(seed, 1);
  const words = bech32.toWords(privKeyWithFlag);
  const suiPrivKey = bech32.encode('suiprivkey', words, 128);

  // Derive Sui address: Blake2b-256([flag] + pubkey)
  const pubkeyWithFlag = new Uint8Array(33);
  pubkeyWithFlag[0] = 0x00; // Ed25519 flag
  pubkeyWithFlag.set(keypair.publicKey, 1);
  const addressBytes = blake2b(pubkeyWithFlag, { dkLen: 32 });
  const address = '0x' + Buffer.from(addressBytes).toString('hex');

  return {
    privateKey: suiPrivKey,
    publicKey: '0x' + Buffer.from(keypair.publicKey).toString('hex'),
    address,
  };
}

// ============================================================================
// NEAR: Ed25519 keypair, ed25519:base58 encoding
// Account names: certen-v{N}.testnet (created separately via NEAR CLI)
// ============================================================================
function generateNEARKeypair(validatorNum) {
  const keypair = nacl.sign.keyPair();
  return {
    // NEAR encodes the full 64-byte secret key as ed25519:base58
    privateKey: 'ed25519:' + bs58.encode(keypair.secretKey),
    publicKey: 'ed25519:' + bs58.encode(keypair.publicKey),
    accountId: `certen-v${validatorNum}.testnet`,
  };
}

// ============================================================================
// TON: 24-word mnemonic, v4r2 wallet address derivation
// ============================================================================
async function generateTONKeypair() {
  const mnemonic = await mnemonicNew(24);
  const keyPair = await mnemonicToPrivateKey(mnemonic);

  const wallet = WalletContractV4.create({
    workchain: 0,
    publicKey: keyPair.publicKey,
  });

  return {
    mnemonic: mnemonic.join(' '),
    // Testnet bounceable address (kQ... format)
    address: wallet.address.toString({ testOnly: true, bounceable: true }),
    // Raw address for reference
    addressRaw: wallet.address.toRawString(),
    publicKey: keyPair.publicKey.toString('hex'),
  };
}

// ============================================================================
// Main
// ============================================================================
async function main() {
  mkdirSync(OUTPUT_DIR, { recursive: true });

  console.log('Certen Protocol - Non-EVM Key Generator');
  console.log('========================================');
  console.log(`Generating keys for ${NUM_VALIDATORS} validators x 5 chains...\n`);

  const allKeys = {};
  const addresses = {};

  for (let i = 1; i <= NUM_VALIDATORS; i++) {
    process.stdout.write(`  Validator ${i}/${NUM_VALIDATORS}...`);

    const solana = generateSolanaKeypair();
    const aptos = generateAptosKeypair();
    const sui = generateSuiKeypair();
    const near = generateNEARKeypair(i);
    const ton = await generateTONKeypair();

    const vid = `validator-${i}`;

    allKeys[vid] = { solana, aptos, sui, near, ton };

    addresses[vid] = {
      solana: solana.publicKey,
      aptos: aptos.address,
      sui: sui.address,
      near: { accountId: near.accountId, publicKey: near.publicKey },
      ton: { address: ton.address, addressRaw: ton.addressRaw },
    };

    // Write per-validator .env snippet
    const envLines = [
      `# Validator ${i} - Non-EVM Chain Keys`,
      `# Generated ${new Date().toISOString()}`,
      ``,
      `# Solana (address: ${solana.publicKey})`,
      `SOLANA_PRIVATE_KEY=${solana.privateKey}`,
      ``,
      `# Aptos (address: ${aptos.address})`,
      `APTOS_PRIVATE_KEY=${aptos.privateKey}`,
      ``,
      `# Sui (address: ${sui.address})`,
      `SUI_PRIVATE_KEY=${sui.privateKey}`,
      ``,
      `# NEAR (account: ${near.accountId})`,
      `NEAR_SIGNER_ACCOUNT_ID=${near.accountId}`,
      `NEAR_PRIVATE_KEY=${near.privateKey}`,
      ``,
      `# TON (address: ${ton.address})`,
      `TON_WALLET_MNEMONIC=${ton.mnemonic}`,
      ``,
    ];
    writeFileSync(join(OUTPUT_DIR, `validator-${i}.env`), envLines.join('\n'));

    console.log(' done');
  }

  // Write complete key dump
  writeFileSync(
    join(OUTPUT_DIR, 'all-keys.json'),
    JSON.stringify(allKeys, null, 2)
  );

  // Write addresses only (safe to share)
  writeFileSync(
    join(OUTPUT_DIR, 'addresses.json'),
    JSON.stringify(addresses, null, 2)
  );

  // Write shared env config
  const sharedEnv = [
    '# Certen Protocol - Shared Non-EVM Chain Configuration',
    `# Generated ${new Date().toISOString()}`,
    '',
    '# ── RPC URLs ──────────────────────────────────────────────',
    'SOLANA_DEVNET_RPC_URL=https://api.devnet.solana.com',
    'APTOS_TESTNET_RPC_URL=https://fullnode.testnet.aptoslabs.com/v1',
    'SUI_TESTNET_RPC_URL=https://fullnode.testnet.sui.io:443',
    'NEAR_TESTNET_RPC_URL=https://rpc.testnet.near.org',
    'TON_TESTNET_API_URL=https://testnet.toncenter.com/api/v2',
    'TON_TESTNET_API_KEY=',
    '',
    '# ── Contract Addresses ────────────────────────────────────',
    '# Solana Devnet',
    'SOLANA_ANCHOR_PROGRAM_ID=FBcWmM1w7wJ9gmzEMNhDFCVKGryGaM8yYuDfjGpdD1Nc',
    'SOLANA_BLS_VERIFIER_PROGRAM_ID=2uYnieNHceDYc1LWJsM11SYUK9hDCDrH5pfQjh5m2Hoa',
    '',
    '# Aptos Testnet',
    'APTOS_ANCHOR_PACKAGE=0xf3cb210860525f9137f0ba9a088124393e12ce6758ee08d167d92b779d9c5894',
    'APTOS_BLS_VERIFIER_PACKAGE=0xf3cb210860525f9137f0ba9a088124393e12ce6758ee08d167d92b779d9c5894',
    '',
    '# Sui Testnet',
    'SUI_ANCHOR_PACKAGE=0xf9f8f5c8349e04404631531f2420cd45805934839867daa1f4c043ec06b6ade2',
    'SUI_ANCHOR_STATE_OBJECT=0xecc27b868c0dd75544068d7fc61657aee94aa7e348876ca2104cb9c45a4cfb9a',
    'SUI_BLS_VERIFIER_STATE=0x9380a3764b1ca7a2cb7fb83cba0a7bca44aaf15b21fe8fce89f7859f35b5ba5b',
    '',
    '# NEAR Testnet',
    'NEAR_ANCHOR_CONTRACT=certen-anchor.testnet',
    'NEAR_BLS_VERIFIER_CONTRACT=certen-bls-verifier.testnet',
    '',
    '# TON Testnet',
    'TON_ANCHOR_CONTRACT=kQCIMusQr3j4ExEfyX_W8c-B_n6zWQdjAkBovyKpP-wGWe7v',
    'TON_BLS_VERIFIER_CONTRACT=kQDEy6Qaq_iptycLCngQeEGAX9f46UH_66cEQ6JjFqqi3and',
    '',
  ];
  writeFileSync(join(OUTPUT_DIR, 'shared.env'), sharedEnv.join('\n'));

  // Print summary table
  console.log('\n========================================');
  console.log('Generated Addresses');
  console.log('========================================');
  for (let i = 1; i <= NUM_VALIDATORS; i++) {
    const v = `validator-${i}`;
    const a = addresses[v];
    console.log(`\n${v}:`);
    console.log(`  Solana:  ${a.solana}`);
    console.log(`  Aptos:   ${a.aptos}`);
    console.log(`  Sui:     ${a.sui}`);
    console.log(`  NEAR:    ${a.near.accountId} (${a.near.publicKey})`);
    console.log(`  TON:     ${a.ton.address}`);
  }

  console.log('\n========================================');
  console.log('Output files:');
  console.log(`  ${join(OUTPUT_DIR, 'all-keys.json')}     (SENSITIVE!)`)
  console.log(`  ${join(OUTPUT_DIR, 'addresses.json')}    (safe to share)`)
  console.log(`  ${join(OUTPUT_DIR, 'validator-N.env')}   (per-validator env)`)
  console.log(`  ${join(OUTPUT_DIR, 'shared.env')}        (shared config)`)
  console.log('\nNext steps:');
  console.log('  1. Create NEAR accounts:  near create-account certen-vN.testnet --useAccount certen-sponsor.testnet --publicKey <key>');
  console.log('  2. Fund all 35 addresses from faucets / sponsor wallets');
  console.log('  3. Deploy TON v4r2 wallets (first tx from each activates the contract)');
  console.log('  4. Append validator-N.env + shared.env to each node\'s .env file');
  console.log('  5. Restart validator containers');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
