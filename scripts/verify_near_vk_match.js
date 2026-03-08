#!/usr/bin/env node
/**
 * Verify NEAR Contract VK matches Validator VK Cryptographically
 *
 * This script:
 * 1. Fetches the raw borsh-serialized STATE from the NEAR BLS ZK Verifier contract
 * 2. Parses the borsh layout to extract the stored VK points
 * 3. Also reads the local verification_key.json and converts to the same byte format
 * 4. Computes SHA256 of both and compares
 *
 * The Go VK hash format (ComputeVKHash in prover.go):
 *   alpha1(x,y) + beta2(x.A0, x.A1, y.A0, y.A1) + gamma2(...) + delta2(...) + IC[0..4](x,y)
 *   All as 32-byte big-endian. Total: 768 bytes (2*32 + 3*4*32 + 5*2*32)
 *
 * The NEAR contract stores VK as G1PointStored{x:[u8;32], y:[u8;32]}
 * and G2PointStored{x:[[u8;32];2], y:[[u8;32];2]} in borsh format.
 * Borsh layout: owner(string) + operators_prefix + vk(alpha1,beta2,gamma2,delta2,ic) + ...
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const NEAR_RPC = 'https://rpc.testnet.fastnear.com';
const CONTRACT = 'certen-bls-verifier.testnet';
const EXPECTED_VK_HASH = 'a24900953140aad8a9caf8647ec21a596aebd2e384537842ba942e0c6fcc6e65';

function fetchJSON(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(parsed, { method: 'POST', headers: { 'Content-Type': 'application/json' } }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

// Borsh reader helper
class BorshReader {
  constructor(buf) {
    this.buf = buf;
    this.offset = 0;
  }

  readBytes(n) {
    const slice = this.buf.slice(this.offset, this.offset + n);
    this.offset += n;
    return slice;
  }

  readU8() {
    return this.buf[this.offset++];
  }

  readU32() {
    const val = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return val;
  }

  readU64() {
    const lo = this.buf.readUInt32LE(this.offset);
    const hi = this.buf.readUInt32LE(this.offset + 4);
    this.offset += 8;
    return BigInt(lo) | (BigInt(hi) << 32n);
  }

  readString() {
    const len = this.readU32();
    const bytes = this.readBytes(len);
    return bytes.toString('utf8');
  }

  readBool() {
    return this.readU8() !== 0;
  }

  // Read [u8; 32]
  readBytes32() {
    return this.readBytes(32);
  }

  // Read G1PointStored { x: [u8;32], y: [u8;32] }
  readG1Stored() {
    const x = this.readBytes32();
    const y = this.readBytes32();
    return { x: Buffer.from(x), y: Buffer.from(y) };
  }

  // Read G2PointStored { x: [[u8;32];2], y: [[u8;32];2] }
  readG2Stored() {
    const x0 = this.readBytes32();
    const x1 = this.readBytes32();
    const y0 = this.readBytes32();
    const y1 = this.readBytes32();
    return {
      x: [Buffer.from(x0), Buffer.from(x1)],
      y: [Buffer.from(y0), Buffer.from(y1)],
    };
  }
}

function bigIntTo32BytesBE(val) {
  const bn = BigInt(val);
  const hex = bn.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

// Build the VK hash buffer the same way Go does (ComputeVKHash)
// Order: alpha1(x,y) + beta2(x.A0, x.A1, y.A0, y.A1) + gamma2(...) + delta2(...) + IC[i](x,y)
function buildVKHashBuffer(vk) {
  const parts = [];

  // alpha1 (G1): x, y
  parts.push(vk.alpha1.x);
  parts.push(vk.alpha1.y);

  // beta2 (G2): x[0]=A0=c0, x[1]=A1=c1, y[0]=A0=c0, y[1]=A1=c1
  parts.push(vk.beta2.x[0]);
  parts.push(vk.beta2.x[1]);
  parts.push(vk.beta2.y[0]);
  parts.push(vk.beta2.y[1]);

  // gamma2
  parts.push(vk.gamma2.x[0]);
  parts.push(vk.gamma2.x[1]);
  parts.push(vk.gamma2.y[0]);
  parts.push(vk.gamma2.y[1]);

  // delta2
  parts.push(vk.delta2.x[0]);
  parts.push(vk.delta2.x[1]);
  parts.push(vk.delta2.y[0]);
  parts.push(vk.delta2.y[1]);

  // IC points
  for (const ic of vk.ic) {
    parts.push(ic.x);
    parts.push(ic.y);
  }

  return Buffer.concat(parts);
}

async function main() {
  console.log('=== NEAR Contract VK vs Validator VK Cryptographic Verification ===\n');

  // -----------------------------------------------------------------------
  // STEP 1: Fetch raw contract state from NEAR RPC
  // -----------------------------------------------------------------------
  console.log('Step 1: Fetching contract state from NEAR RPC...');
  const rpcRes = await fetchJSON(NEAR_RPC, {
    jsonrpc: '2.0',
    id: 1,
    method: 'query',
    params: {
      request_type: 'view_state',
      finality: 'final',
      account_id: CONTRACT,
      prefix_base64: '',
    },
  });

  const stateEntry = rpcRes.result.values.find(v => Buffer.from(v.key, 'base64').toString() === 'STATE');
  if (!stateEntry) {
    console.error('ERROR: No STATE key found in contract storage');
    process.exit(1);
  }

  const stateBuf = Buffer.from(stateEntry.value, 'base64');
  console.log(`  Contract STATE: ${stateBuf.length} bytes`);

  // -----------------------------------------------------------------------
  // STEP 2: Parse borsh-serialized state to extract VK
  // -----------------------------------------------------------------------
  console.log('\nStep 2: Parsing borsh state...');

  // BLSZKVerifier borsh layout:
  //   owner: String (u32 len + utf8 bytes)
  //   operators: UnorderedSet<AccountId> - borsh prefix (StorageKey::Operators = 0x01 + "e" prefix)
  //     UnorderedSet is stored as: StorageKey prefix bytes (borsh), then the length u64
  //     But NEAR SDK UnorderedSet only stores the prefix in the struct, elements go to separate storage keys
  //   vk: VerificationKeyStored
  //     alpha1: G1PointStored { x: [u8;32], y: [u8;32] }
  //     beta2: G2PointStored { x: [[u8;32];2], y: [[u8;32];2] }
  //     gamma2: G2PointStored
  //     delta2: G2PointStored
  //     ic: Vec<G1PointStored> (u32 len + elements)
  //   vk_initialized: bool
  //   verified_proofs: LookupMap (prefix only)
  //   total_verifications: u64
  //   successful_verifications: u64
  //   created_at: u64
  //   updated_at: u64

  const reader = new BorshReader(stateBuf);

  // owner: String
  const owner = reader.readString();
  console.log(`  Owner: ${owner}`);

  // operators: UnorderedSet<AccountId>
  // UnorderedSet borsh: the StorageKey enum variant + data
  // StorageKey::Operators is #[borsh(skip)] in storage, but the UnorderedSet stores its prefix
  // For near_sdk UnorderedSet, borsh serialization is just the prefix bytes (Vec<u8>)
  // The prefix is a borsh-serialized StorageKey enum variant
  // Looking at the hex, after owner string we see: 02 00 00 00 01 69
  // That's: Vec<u8> length=2, then bytes [0x01, 0x69] = StorageKey variant 1 (Operators) + 'i'
  // Wait, let me re-examine. UnorderedSet in near-sdk stores:
  //   element_index_prefix: Vec<u8>  (len + data)
  //   ... actually it stores the full set length and prefix
  // Let me just look at the actual bytes and find the VK start

  // Actually the near_sdk UnorderedSet borsh layout for contract state is just the storage prefix.
  // Let's read it:
  const operatorsPrefixLen = reader.readU32();
  const operatorsPrefix = reader.readBytes(operatorsPrefixLen);
  console.log(`  Operators prefix: ${Buffer.from(operatorsPrefix).toString('hex')} (${operatorsPrefixLen} bytes)`);

  // UnorderedSet also stores the length
  const operatorsLen = reader.readU64();
  console.log(`  Operators count: ${operatorsLen}`);

  // An UnorderedSet<AccountId> in near-sdk v5 borsh stores:
  //   elements_prefix: Vec<u8>
  //   len: u64
  //   indices_prefix: Vec<u8>  -- for the lookup from element -> index
  // Wait, we need to check how many prefix fields UnorderedSet has...
  // Actually near-sdk UnorderedSet stores: FreeList + LookupMap
  // The borsh for the struct state is: prefix (vec<u8>), and that's it for the state field
  // No wait, let me re-examine. The state stores the entire struct, and collections
  // only store their prefix in the main state blob. Elements are stored as separate storage keys.

  // For near_sdk::collections::UnorderedSet (legacy), it stores:
  //   element_index_set: TreeMap<T, bool> -- prefix vec<u8>
  //     But actually, UnorderedSet stores a Vector + LookupMap
  //     Vector: len: u64, prefix: Vec<u8>
  //     LookupMap: prefix: Vec<u8>

  // Let me try a different approach: just scan for the VK data.
  // We know the VK's alpha1.x from the JSON file. Let's compute what it should be:
  const vkJson = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'bls_zk_keys', 'verification_key.json'), 'utf8')
      .replace(/(\d{15,})/g, '"$1"')
  );

  const expectedAlpha1X = bigIntTo32BytesBE(vkJson.alpha1[0]);
  console.log(`\n  Expected alpha1.x (first 16 bytes): ${expectedAlpha1X.slice(0, 16).toString('hex')}`);

  // Search for this pattern in the state buffer
  const alpha1XHex = expectedAlpha1X.toString('hex');
  const stateHex = stateBuf.toString('hex');
  const vkOffset = stateHex.indexOf(alpha1XHex);

  if (vkOffset === -1) {
    console.error('\n  ERROR: Could not find alpha1.x in contract state!');
    console.error('  This means either:');
    console.error('    1. The VK stored on-chain is DIFFERENT from the local VK');
    console.error('    2. The borsh encoding transforms the bytes in an unexpected way');
    console.error('\n  Dumping state hex for manual inspection:');
    for (let i = 0; i < stateHex.length; i += 64) {
      console.error(`    ${(i/2).toString().padStart(4)}: ${stateHex.slice(i, i + 64)}`);
    }
    process.exit(1);
  }

  const vkByteOffset = vkOffset / 2;
  console.log(`\n  Found alpha1.x at byte offset ${vkByteOffset} in STATE`);

  // Now extract VK from this offset
  // alpha1: 64 bytes (2x32)
  // beta2: 128 bytes (4x32)
  // gamma2: 128 bytes (4x32)
  // delta2: 128 bytes (4x32)
  // ic: 4 bytes (u32 len) + n * 64 bytes
  const vkReader = new BorshReader(stateBuf.slice(vkByteOffset));

  const onChainVK = {
    alpha1: vkReader.readG1Stored(),
    beta2: vkReader.readG2Stored(),
    gamma2: vkReader.readG2Stored(),
    delta2: vkReader.readG2Stored(),
    ic: [],
  };

  const icLen = vkReader.readU32();
  console.log(`  IC length on-chain: ${icLen}`);
  for (let i = 0; i < icLen; i++) {
    onChainVK.ic.push(vkReader.readG1Stored());
  }

  // -----------------------------------------------------------------------
  // STEP 3: Build hash buffer from on-chain VK
  // -----------------------------------------------------------------------
  console.log('\nStep 3: Computing on-chain VK hash...');
  const onChainBuf = buildVKHashBuffer(onChainVK);
  console.log(`  On-chain VK buffer: ${onChainBuf.length} bytes`);
  console.log(`  First 16 bytes: ${onChainBuf.slice(0, 16).toString('hex')}`);

  const onChainHash = crypto.createHash('sha256').update(onChainBuf).digest('hex');
  console.log(`  On-chain VK SHA256: ${onChainHash}`);

  // -----------------------------------------------------------------------
  // STEP 4: Build hash buffer from local VK JSON
  // -----------------------------------------------------------------------
  console.log('\nStep 4: Computing local VK hash from verification_key.json...');
  const localVK = {
    alpha1: {
      x: bigIntTo32BytesBE(vkJson.alpha1[0]),
      y: bigIntTo32BytesBE(vkJson.alpha1[1]),
    },
    beta2: {
      x: [bigIntTo32BytesBE(vkJson.beta2[0][0]), bigIntTo32BytesBE(vkJson.beta2[0][1])],
      y: [bigIntTo32BytesBE(vkJson.beta2[1][0]), bigIntTo32BytesBE(vkJson.beta2[1][1])],
    },
    gamma2: {
      x: [bigIntTo32BytesBE(vkJson.gamma2[0][0]), bigIntTo32BytesBE(vkJson.gamma2[0][1])],
      y: [bigIntTo32BytesBE(vkJson.gamma2[1][0]), bigIntTo32BytesBE(vkJson.gamma2[1][1])],
    },
    delta2: {
      x: [bigIntTo32BytesBE(vkJson.delta2[0][0]), bigIntTo32BytesBE(vkJson.delta2[0][1])],
      y: [bigIntTo32BytesBE(vkJson.delta2[1][0]), bigIntTo32BytesBE(vkJson.delta2[1][1])],
    },
    ic: vkJson.ic.map(pt => ({
      x: bigIntTo32BytesBE(pt[0]),
      y: bigIntTo32BytesBE(pt[1]),
    })),
  };

  const localBuf = buildVKHashBuffer(localVK);
  console.log(`  Local VK buffer: ${localBuf.length} bytes`);
  console.log(`  First 16 bytes: ${localBuf.slice(0, 16).toString('hex')}`);

  const localHash = crypto.createHash('sha256').update(localBuf).digest('hex');
  console.log(`  Local VK SHA256: ${localHash}`);

  // -----------------------------------------------------------------------
  // STEP 5: Compare
  // -----------------------------------------------------------------------
  console.log('\n' + '='.repeat(70));
  console.log('RESULTS:');
  console.log('='.repeat(70));
  console.log(`  Expected (validator logs):  ${EXPECTED_VK_HASH}`);
  console.log(`  Local VK JSON hash:         ${localHash}`);
  console.log(`  On-chain contract hash:     ${onChainHash}`);
  console.log();

  if (localHash === onChainHash) {
    console.log('  ✅ MATCH: On-chain VK and local VK are CRYPTOGRAPHICALLY IDENTICAL');
  } else {
    console.log('  ❌ MISMATCH: On-chain VK differs from local VK!');
    console.log('\n  Detailed point comparison:');

    // Compare each point
    const comparePoint = (name, a, b) => {
      const match = a.x.equals(b.x) && a.y.equals(b.y);
      console.log(`    ${name}: ${match ? '✅' : '❌'}`);
      if (!match) {
        console.log(`      local  x: ${a.x.toString('hex')}`);
        console.log(`      chain  x: ${b.x.toString('hex')}`);
        console.log(`      local  y: ${a.y.toString('hex')}`);
        console.log(`      chain  y: ${b.y.toString('hex')}`);
      }
    };

    const compareG2 = (name, a, b) => {
      const match = a.x[0].equals(b.x[0]) && a.x[1].equals(b.x[1]) &&
                    a.y[0].equals(b.y[0]) && a.y[1].equals(b.y[1]);
      console.log(`    ${name}: ${match ? '✅' : '❌'}`);
      if (!match) {
        console.log(`      local  x0: ${a.x[0].toString('hex')}`);
        console.log(`      chain  x0: ${b.x[0].toString('hex')}`);
        console.log(`      local  x1: ${a.x[1].toString('hex')}`);
        console.log(`      chain  x1: ${b.x[1].toString('hex')}`);
        console.log(`      local  y0: ${a.y[0].toString('hex')}`);
        console.log(`      chain  y0: ${b.y[0].toString('hex')}`);
        console.log(`      local  y1: ${a.y[1].toString('hex')}`);
        console.log(`      chain  y1: ${b.y[1].toString('hex')}`);
      }
    };

    comparePoint('alpha1', localVK.alpha1, onChainVK.alpha1);
    compareG2('beta2', localVK.beta2, onChainVK.beta2);
    compareG2('gamma2', localVK.gamma2, onChainVK.gamma2);
    compareG2('delta2', localVK.delta2, onChainVK.delta2);

    for (let i = 0; i < Math.max(localVK.ic.length, onChainVK.ic.length); i++) {
      if (i < localVK.ic.length && i < onChainVK.ic.length) {
        comparePoint(`IC[${i}]`, localVK.ic[i], onChainVK.ic[i]);
      } else if (i < localVK.ic.length) {
        console.log(`    IC[${i}]: ❌ exists in local but NOT on-chain`);
      } else {
        console.log(`    IC[${i}]: ❌ exists on-chain but NOT in local`);
      }
    }
  }

  if (localHash === EXPECTED_VK_HASH) {
    console.log(`\n  ✅ Local VK hash matches expected validator log hash`);
  } else {
    console.log(`\n  ⚠️  Local VK hash does NOT match expected validator log hash`);
    console.log(`     This may indicate the Go code uses a different byte ordering`);
    console.log(`     or the VK was regenerated since the logs were captured`);
  }

  console.log();
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
