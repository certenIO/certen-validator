#!/usr/bin/env node
// ============================================================================
// Certen Protocol - Fund Validator Accounts from Sponsor Wallets
// ============================================================================
// Transfers native tokens from sponsor/deployer wallets to each validator.
// Sponsor keys from api-bridge/.env
//
// Usage: node fund-from-sponsors.mjs [chain]
//   chain: solana, aptos, sui, near, ton, all (default: all)
// ============================================================================

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load validator addresses
const addresses = JSON.parse(
  readFileSync(join(__dirname, 'output', 'addresses.json'), 'utf8')
);
const validators = Object.keys(addresses).sort();

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Solana: Transfer from sponsor ──────────────────────────────────────────
async function fundSolana() {
  console.log('\n=== Solana Devnet: Transfer from Sponsor ===');

  const { Connection, Keypair, SystemProgram, Transaction, sendAndConfirmTransaction, LAMPORTS_PER_SOL, PublicKey } =
    await import('@solana/web3.js');

  const sponsorKeyB64 = 'dcFk2Snk3V5FMY/s72UWiqw+AJjUfPjK/HAEfW2MlYmfv3XyGNqU6PTWP6lL1H32dmNYz+eAm5UCMhUvPCh1Kg==';
  const sponsorSecret = Buffer.from(sponsorKeyB64, 'base64');
  const sponsor = Keypair.fromSecretKey(new Uint8Array(sponsorSecret));
  console.log(`  Sponsor: ${sponsor.publicKey.toBase58()}`);

  const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  const balance = await connection.getBalance(sponsor.publicKey);
  console.log(`  Balance: ${balance / LAMPORTS_PER_SOL} SOL`);

  const amountPerValidator = 0.5 * LAMPORTS_PER_SOL; // 0.5 SOL each
  const totalNeeded = amountPerValidator * validators.length;
  if (balance < totalNeeded + 0.01 * LAMPORTS_PER_SOL) {
    console.log(`  INSUFFICIENT: need ${totalNeeded / LAMPORTS_PER_SOL} SOL + fees`);
    return;
  }

  for (const vid of validators) {
    const pubkey = typeof addresses[vid].solana === 'string'
      ? addresses[vid].solana
      : addresses[vid].solana?.publicKey;

    try {
      const tx = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: sponsor.publicKey,
          toPubkey: new PublicKey(pubkey),
          lamports: amountPerValidator,
        })
      );
      const sig = await sendAndConfirmTransaction(connection, tx, [sponsor]);
      console.log(`  ${vid}: OK - 0.5 SOL (tx: ${sig.slice(0, 16)}...)`);
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message.slice(0, 120)}`);
    }
    await sleep(2000);
  }
}

// ── Aptos: Transfer from sponsor ──────────────────────────────────────────
async function fundAptos() {
  console.log('\n=== Aptos Testnet: Transfer from Sponsor ===');

  const { Aptos, AptosConfig, Network, Ed25519PrivateKey, Account } =
    await import('@aptos-labs/ts-sdk');

  const config = new AptosConfig({ network: Network.TESTNET });
  const aptos = new Aptos(config);

  const privKeyHex = '0x0bab6c15b8e9e8d53c03c361eff6ce25d6175ebaecb9258127ddc9d0f0bf33d9';
  const privateKey = new Ed25519PrivateKey(privKeyHex);
  const sponsor = Account.fromPrivateKey({ privateKey });
  console.log(`  Sponsor: ${sponsor.accountAddress.toString()}`);

  // Check balance
  try {
    const resources = await aptos.getAccountResource({
      accountAddress: sponsor.accountAddress,
      resourceType: '0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>',
    });
    const bal = Number(resources.coin.value) / 1e8;
    console.log(`  Balance: ${bal} APT`);
  } catch (e) {
    console.log(`  Balance check error: ${e.message}`);
  }

  const amountPerValidator = 100_000_000; // 1 APT (8 decimals)

  for (const vid of validators) {
    const addr = typeof addresses[vid].aptos === 'string'
      ? addresses[vid].aptos
      : addresses[vid].aptos?.address;

    try {
      const tx = await aptos.transferCoinTransaction({
        sender: sponsor.accountAddress,
        recipient: addr,
        amount: amountPerValidator,
      });
      const committed = await aptos.signAndSubmitTransaction({
        signer: sponsor,
        transaction: tx,
      });
      const result = await aptos.waitForTransaction({ transactionHash: committed.hash });
      console.log(`  ${vid}: OK - 1 APT (tx: ${committed.hash.slice(0, 16)}...)`);
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message.slice(0, 120)}`);
    }
    await sleep(1500);
  }
}

// ── Sui: Transfer from sponsor ────────────────────────────────────────────
async function fundSui() {
  console.log('\n=== Sui Testnet: Transfer from Sponsor ===');

  const { SuiClient, getFullnodeUrl } = await import('@mysten/sui/client');
  const { Transaction: SuiTransaction } = await import('@mysten/sui/transactions');
  const { Ed25519Keypair } = await import('@mysten/sui/keypairs/ed25519');
  const { decodeSuiPrivateKey } = await import('@mysten/sui/cryptography');

  const client = new SuiClient({ url: getFullnodeUrl('testnet') });

  const suiPrivKey = 'suiprivkey1qpdvxf3yzluhe9hsh0pcp8xpce8gkemwwcvhgn9xmzcch2qgssfcslsje0l';
  const { secretKey } = decodeSuiPrivateKey(suiPrivKey);
  const sponsor = Ed25519Keypair.fromSecretKey(secretKey);
  const sponsorAddr = sponsor.getPublicKey().toSuiAddress();
  console.log(`  Sponsor: ${sponsorAddr}`);

  // Check balance
  const balance = await client.getBalance({ owner: sponsorAddr });
  console.log(`  Balance: ${Number(balance.totalBalance) / 1e9} SUI`);

  const amountPerValidator = 200_000_000; // 0.2 SUI (9 decimals)

  for (const vid of validators) {
    const addr = typeof addresses[vid].sui === 'string'
      ? addresses[vid].sui
      : addresses[vid].sui?.address;

    try {
      const tx = new SuiTransaction();
      const [coin] = tx.splitCoins(tx.gas, [amountPerValidator]);
      tx.transferObjects([coin], addr);

      const result = await client.signAndExecuteTransaction({
        signer: sponsor,
        transaction: tx,
      });
      console.log(`  ${vid}: OK - 0.2 SUI (tx: ${result.digest.slice(0, 16)}...)`);
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message.slice(0, 120)}`);
    }
    await sleep(2000);
  }
}

// ── NEAR: Transfer from sponsor ───────────────────────────────────────────
async function fundNEAR() {
  console.log('\n=== NEAR Testnet: Transfer from Sponsor ===');

  const nearAPI = await import('near-api-js');
  const { connect, keyStores, KeyPair, utils } = nearAPI;

  const keyStore = new keyStores.InMemoryKeyStore();
  const sponsorKey = 'ed25519:4oKHfnH6zWMtZzarWdDm66xvqqvVooJdhytzAawwifCajZX7SeFgFVfDFRftbReyhPDYBtvqRUqCLAYSakBeZUbx';
  const sponsorAccountId = 'certen-sponsor.testnet';

  await keyStore.setKey('testnet', sponsorAccountId, KeyPair.fromString(sponsorKey));

  const near = await connect({
    networkId: 'testnet',
    keyStore,
    nodeUrl: 'https://rpc.testnet.near.org',
  });

  const sponsorAccount = await near.account(sponsorAccountId);
  const state = await sponsorAccount.state();
  const balNEAR = Number(BigInt(state.amount) / BigInt(1e18)) / 1e6;
  console.log(`  Sponsor: ${sponsorAccountId}`);
  console.log(`  Balance: ~${balNEAR.toFixed(2)} NEAR`);

  const amountPerValidator = '500000000000000000000000'; // 0.5 NEAR (24 decimals)

  for (const vid of validators) {
    const nearAcct = typeof addresses[vid].near === 'string'
      ? addresses[vid].near
      : addresses[vid].near?.accountId;

    try {
      const result = await sponsorAccount.sendMoney(nearAcct, BigInt(amountPerValidator));
      const txHash = result.transaction?.hash || result.transaction_outcome?.id || 'OK';
      console.log(`  ${vid}: OK - 0.5 NEAR to ${nearAcct} (tx: ${String(txHash).slice(0, 16)}...)`);
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message.slice(0, 120)}`);
    }
    await sleep(1500);
  }
}

// ── TON: Transfer from sponsor ────────────────────────────────────────────
async function fundTON() {
  console.log('\n=== TON Testnet: Transfer from Sponsor ===');

  const { mnemonicToPrivateKey } = await import('@ton/crypto');
  const { WalletContractV4, TonClient, internal, toNano } = await import('@ton/ton');

  const sponsorMnemonic = 'effort twelve hedgehog flip crash fury trigger vocal cabin input senior length renew genuine decide leave mother speak already middle ill forward scissors panel'.split(' ');

  const keyPair = await mnemonicToPrivateKey(sponsorMnemonic);
  const wallet = WalletContractV4.create({
    workchain: 0,
    publicKey: keyPair.publicKey,
  });

  const client = new TonClient({
    endpoint: 'https://testnet.toncenter.com/api/v2/jsonRPC',
    apiKey: process.env.TON_TESTNET_API_KEY || undefined,
  });

  // Retry helper for rate-limited TON API
  async function withRetry(fn, label, maxRetries = 5) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await fn();
      } catch (e) {
        if (e.message?.includes('429') || e.response?.status === 429) {
          const wait = 10000 + attempt * 5000;
          console.log(`  ${label}: 429 rate limit, waiting ${wait / 1000}s (attempt ${attempt + 1}/${maxRetries})`);
          await sleep(wait);
        } else {
          throw e;
        }
      }
    }
    throw new Error('Max retries exceeded');
  }

  const contract = client.open(wallet);
  const sponsorAddr = wallet.address.toString({ testOnly: true });
  console.log(`  Sponsor: ${sponsorAddr}`);

  const balance = await withRetry(() => client.getBalance(wallet.address), 'balance');
  console.log(`  Balance: ${Number(balance) / 1e9} TON`);

  await sleep(3000);
  const seqno = await withRetry(() => contract.getSeqno(), 'seqno');
  console.log(`  Seqno: ${seqno}`);

  const amountPerValidator = '0.1'; // 0.1 TON each

  for (let i = 0; i < validators.length; i++) {
    const vid = validators[i];
    const tonAddr = typeof addresses[vid].ton === 'string'
      ? addresses[vid].ton
      : addresses[vid].ton?.address;

    try {
      await withRetry(async () => {
        await contract.sendTransfer({
          seqno: seqno + i,
          secretKey: keyPair.secretKey,
          messages: [
            internal({
              to: tonAddr,
              value: toNano(amountPerValidator),
              bounce: false,
            }),
          ],
        });
      }, vid);
      console.log(`  ${vid}: SENT ${amountPerValidator} TON to ${tonAddr.slice(0, 20)}...`);
    } catch (e) {
      console.log(`  ${vid}: ERROR - ${e.message.slice(0, 120)}`);
    }
    await sleep(8000); // wait for seqno to update on-chain
  }
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  const chain = process.argv[2] || 'all';
  console.log('Certen Protocol - Fund Validators from Sponsor Wallets');
  console.log('======================================================');
  console.log(`Funding ${validators.length} validators on: ${chain}`);

  if (chain === 'all' || chain === 'solana') await fundSolana();
  if (chain === 'all' || chain === 'aptos') await fundAptos();
  if (chain === 'all' || chain === 'sui') await fundSui();
  if (chain === 'all' || chain === 'near') await fundNEAR();
  if (chain === 'all' || chain === 'ton') await fundTON();

  console.log('\n======================================================');
  console.log('Done! Run "node check-balances.mjs" to verify.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
