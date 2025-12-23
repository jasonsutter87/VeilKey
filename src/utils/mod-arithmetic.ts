/**
 * Modular arithmetic utilities for threshold cryptography
 */

/**
 * Modular exponentiation: (base^exp) mod m
 * Uses square-and-multiply for efficiency
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  if (exp < 0n) {
    throw new Error('Negative exponent not supported directly, use modInverse first');
  }

  let result = 1n;
  base = ((base % m) + m) % m;

  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp >> 1n;
    base = (base * base) % m;
  }

  return result;
}

/**
 * Extended Euclidean Algorithm
 * Returns [gcd, x, y] such that ax + by = gcd(a, b)
 */
export function extendedGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (a === 0n) {
    return [b, 0n, 1n];
  }

  const [gcd, x1, y1] = extendedGcd(b % a, a);
  const x = y1 - (b / a) * x1;
  const y = x1;

  return [gcd, x, y];
}

/**
 * Modular multiplicative inverse: a^(-1) mod m
 * Throws if inverse doesn't exist (gcd(a, m) !== 1)
 */
export function modInverse(a: bigint, m: bigint): bigint {
  // Handle negative numbers
  a = ((a % m) + m) % m;

  const [gcd, x] = extendedGcd(a, m);

  if (gcd !== 1n) {
    throw new Error(`Modular inverse does not exist: gcd(${a}, ${m}) = ${gcd}`);
  }

  return ((x % m) + m) % m;
}

/**
 * Positive modulo operation (always returns positive result)
 */
export function mod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

/**
 * Generate a random bigint in range [min, max)
 */
export function randomBigInt(min: bigint, max: bigint): bigint {
  const range = max - min;
  const bytesNeeded = Math.ceil(range.toString(2).length / 8) + 8; // Extra bytes for uniformity

  const randomBytes = new Uint8Array(bytesNeeded);
  crypto.getRandomValues(randomBytes);

  let randomValue = 0n;
  for (const byte of randomBytes) {
    randomValue = (randomValue << 8n) | BigInt(byte);
  }

  return min + (randomValue % range);
}

/**
 * Check if a number is probably prime using Miller-Rabin
 */
export function isProbablePrime(n: bigint, k: number = 20): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  // Write n-1 as 2^r * d
  let r = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    r++;
    d /= 2n;
  }

  // Witness loop
  witnessLoop: for (let i = 0; i < k; i++) {
    const a = randomBigInt(2n, n - 2n);
    let x = modPow(a, d, n);

    if (x === 1n || x === n - 1n) continue;

    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) continue witnessLoop;
    }

    return false;
  }

  return true;
}

/**
 * Generate a random prime of specified bit length
 */
export function generatePrime(bits: number): bigint {
  while (true) {
    const min = 1n << BigInt(bits - 1);
    const max = 1n << BigInt(bits);
    let candidate = randomBigInt(min, max);

    // Make sure it's odd
    if (candidate % 2n === 0n) candidate++;

    if (isProbablePrime(candidate)) {
      return candidate;
    }
  }
}

/**
 * Greatest common divisor
 */
export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * Least common multiple
 */
export function lcm(a: bigint, b: bigint): bigint {
  return (a * b) / gcd(a, b);
}
