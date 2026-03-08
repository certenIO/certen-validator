#!/usr/bin/env node
/**
 * Get lite account address for CERTEN key
 */

import { ED25519Key } from 'file:///C:/Accumulate_Stuff/typescript-sdk-accumulate-mod/javascript/lib/index.js';
import * as crypto from 'crypto';

const CERTEN_IDENTITY_PRIVATE_KEY = '0c2576e533a6c4e81c07a9062859462514bf3bdb13bb92a32621d1e849ad1232d481f10ac40451048c827ac60327a233e21187043d41676832166b96812cab84';

const key = ED25519Key.from(Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY, 'hex'));
// Get public key from private key (last 32 bytes of 64-byte private key)
const publicKey = Buffer.from(CERTEN_IDENTITY_PRIVATE_KEY.slice(64), 'hex');
console.log('Public Key:', publicKey.toString('hex'));

// Lite account address is sha256(publicKey)[0:20] in hex
const hash = crypto.createHash('sha256').update(publicKey).digest();
const liteId = hash.slice(0, 20).toString('hex');
console.log('Lite ID:', liteId);
console.log('Lite Token Account:', `acc://${liteId}/ACME`);

// Also compute for sponsor key
const SPONSOR_PRIVATE_KEY = '7cf706620841738ec5f876f955601c6198967eac5e918667e699e288f5b568a29d7f15934ee37295c9c9480c8ae53cd11d38f067dde67231ecefc4eea38c82a7';
const sponsorPubKey = Buffer.from(SPONSOR_PRIVATE_KEY.slice(64), 'hex');
const sponsorHash = crypto.createHash('sha256').update(sponsorPubKey).digest();
const sponsorLiteId = sponsorHash.slice(0, 20).toString('hex');
console.log('\nSponsor Public Key:', sponsorPubKey.toString('hex'));
console.log('Sponsor Lite Token Account:', `acc://${sponsorLiteId}/ACME`);
