#!/usr/bin/env node
// ============================================================================
// Certen Protocol - Fund Non-EVM Validator Accounts
// ============================================================================
// Uses testnet faucets for Solana/Aptos/Sui and sponsor transfers for NEAR/TON.
//
// Usage: node fund-accounts.mjs
// ============================================================================

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mnemonicToPrivateKey } from '@ton/crypto';
import { WalletContractV4, TonClient, internal, toNano } from '@ton/ton';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load addresses
const addresses = JSON.parse(
  readFileSync(join(__dirname, 'output', 'addresses.json'), 'utf8')
);
const validators = Object.keys(addresses).sort();

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Solana Devnet Airdrop ───────────────────────────────────────────────────
async function fundSolana() {
  console.log('\n=== Solana Devnet Airdrop (1 SOL each) ===');
  const rpc = 'https://api.devnet.solana.com';

  for (const vid of validators) {
    const pubkey = typeof addresses[vid].solana === 'string'
      ? addresses[vid].solana
      : addresses[vid].solana?.publicKey;

    try {
      const resp = await fetch(rpc, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'requestAirdrop',
          params: [pubkey, 1_000_000_000], // 1 SOL in lamports
        }),
      });
      const data = await resp.json();
      if (data.error) {
        console.log(`  ${vid}: ERROR - ${data.error.message}`);
      } else {
        console.log(`  ${vid}: OK (tx: ${data.result?.slice(0, 16)}...)`);
      }
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message}`);
    }
    await sleep(3000); // rate limit - devnet is strict
  }
}

// ── Aptos Testnet Faucet ────────────────────────────────────────────────────
async function fundAptos() {
  console.log('\n=== Aptos Testnet Faucet (1 APT each) ===');

  for (const vid of validators) {
    const addr = typeof addresses[vid].aptos === 'string'
      ? addresses[vid].aptos
      : addresses[vid].aptos?.address;

    try {
      const resp = await fetch(
        `https://faucet.testnet.aptoslabs.com/mint?amount=100000000&address=${addr}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' } }
      );
      if (resp.ok) {
        const txns = await resp.json();
        console.log(`  ${vid}: OK (${Array.isArray(txns) ? txns.length + ' txns' : 'funded'})`);
      } else {
        const text = await resp.text();
        console.log(`  ${vid}: ERROR ${resp.status} - ${text.slice(0, 100)}`);
      }
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message}`);
    }
    await sleep(1000);
  }
}

// ── Sui Testnet Faucet ──────────────────────────────────────────────────────
async function fundSui() {
  console.log('\n=== Sui Testnet Faucet ===');

  for (const vid of validators) {
    const addr = typeof addresses[vid].sui === 'string'
      ? addresses[vid].sui
      : addresses[vid].sui?.address;

    try {
      const resp = await fetch('https://faucet.testnet.sui.io/v1/gas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ FixedAmountRequest: { recipient: addr } }),
      });
      if (resp.ok) {
        const data = await resp.json();
        console.log(`  ${vid}: OK (task: ${data.task?.slice(0, 16) || 'queued'}...)`);
      } else {
        const text = await resp.text();
        console.log(`  ${vid}: ERROR ${resp.status} - ${text.slice(0, 100)}`);
      }
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message}`);
    }
    await sleep(6000); // Sui faucet is strict on rate limits
  }
}

// ── NEAR Testnet - Create & Fund Accounts ───────────────────────────────────
async function fundNEAR() {
  console.log('\n=== NEAR Testnet Account Creation ===');
  // NEAR testnet has a helper service for creating accounts
  // POST https://helper.testnet.near.org/account with {newAccountId, newAccountPublicKey}

  for (const vid of validators) {
    const near = addresses[vid].near;
    const accountId = typeof near === 'string' ? near : near?.accountId;
    const publicKey = typeof near === 'string' ? null : near?.publicKey;

    if (!publicKey) {
      console.log(`  ${vid}: SKIP (no public key in addresses.json)`);
      continue;
    }

    try {
      const resp = await fetch('https://helper.testnet.near.org/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          newAccountId: accountId,
          newAccountPublicKey: publicKey,
        }),
      });
      if (resp.ok) {
        console.log(`  ${vid}: OK - created ${accountId}`);
      } else {
        const text = await resp.text();
        if (text.includes('already exists')) {
          console.log(`  ${vid}: EXISTS - ${accountId}`);
        } else {
          console.log(`  ${vid}: ERROR ${resp.status} - ${text.slice(0, 120)}`);
        }
      }
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message}`);
    }
    await sleep(1000);
  }
}

// ── TON Testnet - Fund from Deployer Wallet ─────────────────────────────────
async function fundTON() {
  console.log('\n=== TON Testnet Funding (0.15 TON each from deployer) ===');

  const deployerMnemonic = [
    'grain', 'door', 'deliver', 'stamp', 'rent', 'glass',
    'east', 'believe', 'method', 'flock', 'company', 'where',
    'front', 'endless', 'angle', 'dragon', 'blush', 'object',
    'inquiry', 'place', 'purpose', 'border', 'north', 'owner',
  ];

  try {
    const keyPair = await mnemonicToPrivateKey(deployerMnemonic);
    const wallet = WalletContractV4.create({
      workchain: 0,
      publicKey: keyPair.publicKey,
    });

    const client = new TonClient({
      endpoint: 'https://testnet.toncenter.com/api/v2/jsonRPC',
      apiKey: process.env.TON_TESTNET_API_KEY || undefined,
    });

    const contract = client.open(wallet);
    const seqno = await contract.getSeqno();
    console.log(`  Deployer: ${wallet.address.toString({ testOnly: true })}`);
    console.log(`  Seqno: ${seqno}`);

    // Check deployer balance
    const balance = await client.getBalance(wallet.address);
    console.log(`  Balance: ${Number(balance) / 1e9} TON`);

    if (Number(balance) < 1_200_000_000) { // need ~1.05 TON for 7 x 0.15
      console.log('  INSUFFICIENT BALANCE - need at least 1.2 TON');
      return;
    }

    // Send to each validator sequentially (incrementing seqno)
    for (let i = 0; i < validators.length; i++) {
      const vid = validators[i];
      const tonAddr = typeof addresses[vid].ton === 'string'
        ? addresses[vid].ton
        : addresses[vid].ton?.address;

      try {
        await contract.sendTransfer({
          seqno: seqno + i,
          secretKey: keyPair.secretKey,
          messages: [
            internal({
              to: tonAddr,
              value: toNano('0.15'),
              bounce: false, // non-bounceable for uninitialized wallets
            }),
          ],
        });
        console.log(`  ${vid}: SENT 0.15 TON to ${tonAddr.slice(0, 16)}...`);
      } catch (e) {
        console.log(`  ${vid}: ERROR - ${e.message}`);
      }
      await sleep(5000); // wait for seqno to increment on-chain
    }
  } catch (e) {
    console.log(`  FATAL: ${e.message}`);
  }
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  console.log('Certen Protocol - Non-EVM Account Funding');
  console.log('==========================================');

  await fundSolana();
  await fundAptos();
  await fundSui();
  await fundNEAR();
  await fundTON();

  console.log('\n==========================================');
  console.log('Done! Run "node check-balances.mjs" to verify.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
