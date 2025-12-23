import { describe, it } from 'vitest';
import { generateKey, partialSign, combineSignatures, verify } from './index.js';
import { modPow } from '../utils/mod-arithmetic.js';
import { sha256 } from '@noble/hashes/sha256';

describe('Debug threshold RSA', () => {
  it('should debug the signing process', async () => {
    const config = {
      bits: 2048,
      threshold: 2,
      totalShares: 3,
    };

    const keyPair = await generateKey(config);
    const message = new TextEncoder().encode('test');

    // Hash the message
    const hash = sha256(message);
    let x = 0n;
    for (const byte of hash) {
      x = (x << 8n) | BigInt(byte);
    }
    x = x % keyPair.n;

    console.log('Message hash (x):', x.toString(16).slice(0, 20) + '...');
    console.log('n:', keyPair.n.toString(16).slice(0, 20) + '...');
    console.log('e:', keyPair.e);

    // Create partials
    const partial1 = partialSign(message, keyPair.shares[0], keyPair.n, config.totalShares);
    const partial2 = partialSign(message, keyPair.shares[1], keyPair.n, config.totalShares);

    console.log('Partial 1:', partial1.value.toString(16).slice(0, 20) + '...');
    console.log('Partial 2:', partial2.value.toString(16).slice(0, 20) + '...');

    // Combine
    const signature = combineSignatures(
      [partial1, partial2],
      config.threshold,
      keyPair.n,
      keyPair.e,
      config.totalShares
    );

    console.log('Combined signature:', signature.toString(16).slice(0, 20) + '...');

    // Verify manually
    const verification = modPow(signature, keyPair.e, keyPair.n);
    console.log('signature^e mod n:', verification.toString(16).slice(0, 20) + '...');
    console.log('Expected (x):', x.toString(16).slice(0, 20) + '...');
    console.log('Match:', verification === x);

    const isValid = verify(message, signature, keyPair.n, keyPair.e);
    console.log('Verify result:', isValid);
  });
});
