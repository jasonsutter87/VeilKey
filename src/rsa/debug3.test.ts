import { describe, it } from 'vitest';
import { generateKey } from './index.js';

function factorial(n: number): bigint {
  let result = 1n;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

function lagrangeCoefficient(
  index: number,
  indices: number[],
  delta: bigint
): bigint {
  let numerator = delta;
  let denominator = 1n;

  for (const j of indices) {
    if (j !== index) {
      numerator *= BigInt(j);
      const diff = j - index;
      denominator *= diff < 0 ? BigInt(-diff) : BigInt(diff);
    }
  }

  console.log(`  λ_${index}: numerator=${numerator}, denom=${denominator}, result=${numerator/denominator}`);

  let result = numerator / denominator;

  // Check sign
  let negativeCount = 0;
  for (const j of indices) {
    if (j !== index && j - index < 0) {
      negativeCount++;
    }
  }

  if (negativeCount % 2 === 1) {
    result = -result;
  }

  return result;
}

describe('Debug Lagrange coefficients', () => {
  it('should verify Lagrange interpolation', async () => {
    const config = {
      bits: 2048,
      threshold: 2,
      totalShares: 3,
    };

    const keyPair = await generateKey(config);
    const delta = factorial(config.totalShares);

    console.log('Testing Lagrange interpolation for indices [1, 2]');
    console.log('Δ =', delta);

    const indices = [1, 2];
    const lambda1 = lagrangeCoefficient(1, indices, delta);
    const lambda2 = lagrangeCoefficient(2, indices, delta);

    console.log('\nShares:');
    console.log('d_1 =', keyPair.shares[0].value.toString(16).slice(0, 20) + '...');
    console.log('d_2 =', keyPair.shares[1].value.toString(16).slice(0, 20) + '...');

    console.log('\nLagrange coefficients:');
    console.log('λ_1 =', lambda1);
    console.log('λ_2 =', lambda2);

    console.log('\nInterpolated sum (should give Δ*d):');
    const interpolated = lambda1 * keyPair.shares[0].value + lambda2 * keyPair.shares[1].value;
    console.log('λ_1*d_1 + λ_2*d_2 =', interpolated.toString(16).slice(0, 20) + '...');

    // Check if this is actually Δ * d by using the fact that e * d ≡ 1 (mod φ(n))
    // We can't verify directly without φ(n), but we can check the pattern
  });
});
