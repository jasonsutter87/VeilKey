import { describe, it } from 'vitest';
import { generateKey, partialSign, combineSignatures } from './index.js';
import { modPow, gcd, modInverse } from '../utils/mod-arithmetic.js';
import { sha256 } from '@noble/hashes/sha256';

function factorial(n: number): bigint {
  let result = 1n;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

describe('Debug Shoup protocol math', () => {
  it('should verify the mathematical relationship', async () => {
    const config = {
      bits: 2048,
      threshold: 2,
      totalShares: 3,
    };

    const keyPair = await generateKey(config);
    const message = new TextEncoder().encode('test');

    // Hash
    const hash = sha256(message);
    let x = 0n;
    for (const byte of hash) {
      x = (x << 8n) | BigInt(byte);
    }
    x = x % keyPair.n;

    const delta = factorial(config.totalShares);
    console.log('Δ =', delta);
    console.log('e =', keyPair.e);
    console.log('gcd(e, Δ) =', gcd(keyPair.e, delta));

    // Check if e and Δ are coprime
    if (gcd(keyPair.e, delta) !== 1n) {
      console.log('ERROR: e and Δ are not coprime!');
      return;
    }

    const eInv = modInverse(keyPair.e, delta);
    console.log('e^(-1) mod Δ =', eInv);
    console.log('e * e^(-1) mod Δ =', (keyPair.e * eInv) % delta);

    // Create partials and combine
    const partial1 = partialSign(message, keyPair.shares[0], keyPair.n, config.totalShares);
    const partial2 = partialSign(message, keyPair.shares[1], keyPair.n, config.totalShares);
    const w = combineSignatures(
      [partial1, partial2],
      config.threshold,
      keyPair.n,
      keyPair.e,
      config.totalShares
    );

    console.log('\nTesting relationship...');
    console.log('w^e mod n:', modPow(w, keyPair.e, keyPair.n).toString(16).slice(0, 20) + '...');
    console.log('x^Δ mod n:', modPow(x, delta, keyPair.n).toString(16).slice(0, 20) + '...');
    console.log('Should match:', modPow(w, keyPair.e, keyPair.n) === modPow(x, delta, keyPair.n));
  });
});
