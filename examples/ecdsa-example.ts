/**
 * Threshold ECDSA Example
 *
 * Demonstrates threshold ECDSA signing for Bitcoin/Ethereum wallets
 * and general-purpose digital signatures.
 */

import { ThresholdECDSA } from '../src/ecdsa/index.js';
import type { ThresholdECDSAConfig } from '../src/ecdsa/types.js';

// =============================================================================
// Example 1: Bitcoin Wallet (secp256k1)
// =============================================================================

async function bitcoinWalletExample() {
  console.log('\n=== Example 1: Bitcoin Multi-Sig Wallet (2-of-3) ===\n');

  // Setup: Create a 2-of-3 threshold wallet
  const config: ThresholdECDSAConfig = {
    curve: 'secp256k1',
    threshold: 2,
    totalShares: 3,
  };

  console.log('1. Generating threshold keypair...');
  const keypair = await ThresholdECDSA.generateKey(config);
  console.log(`   ✓ Public key: ${keypair.publicKey.value.slice(0, 20)}...`);
  console.log(`   ✓ Generated ${keypair.shares.length} shares`);

  // Verify shares
  console.log('\n2. Verifying shares...');
  const allValid = ThresholdECDSA.verifyAllShares(keypair);
  console.log(`   ✓ All shares valid: ${allValid}`);

  // Simulate Bitcoin transaction signing
  console.log('\n3. Signing Bitcoin transaction...');
  const txHash = new TextEncoder().encode('bitcoin_tx_hash_placeholder');

  // Generate presignature (parties 1 and 2 will sign)
  const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
  console.log(`   ✓ Generated presignature with r = ${presignature.r.toString(16).slice(0, 16)}...`);

  // Party 1 creates partial signature
  const partial1 = ThresholdECDSA.partialSign(txHash, keypair.shares[0], presignature);
  console.log(`   ✓ Party 1 signed`);

  // Party 2 creates partial signature
  const partial2 = ThresholdECDSA.partialSign(txHash, keypair.shares[1], presignature);
  console.log(`   ✓ Party 2 signed`);

  // Combine signatures
  const signature = ThresholdECDSA.combineSignatures([partial1, partial2], 2, presignature);
  console.log(`   ✓ Combined signature:`);
  console.log(`     r = ${signature.r.toString(16).slice(0, 32)}...`);
  console.log(`     s = ${signature.s.toString(16).slice(0, 32)}...`);

  // Verify signature
  console.log('\n4. Verifying signature...');
  const result = ThresholdECDSA.verify(txHash, signature, keypair.publicKey);
  console.log(`   ✓ Signature valid: ${result.valid}`);

  return keypair;
}

// =============================================================================
// Example 2: TLS Certificate Authority (P-256)
// =============================================================================

async function tlsCertificateExample() {
  console.log('\n\n=== Example 2: Distributed CA (3-of-5, P-256) ===\n');

  // Setup: Create a 3-of-5 certificate authority
  const config: ThresholdECDSAConfig = {
    curve: 'P-256',
    threshold: 3,
    totalShares: 5,
  };

  console.log('1. Generating CA keypair...');
  const keypair = await ThresholdECDSA.generateKey(config);
  console.log(`   ✓ CA public key: ${keypair.publicKey.value.slice(0, 20)}...`);
  console.log(`   ✓ Distributed to ${keypair.shares.length} trustees`);

  // Simulate certificate signing request
  console.log('\n2. Processing certificate signing request...');
  const certTBS = new TextEncoder().encode('tls_certificate_to_be_signed');

  // Generate presignature (trustees 1, 3, and 5 approve)
  const presignature = ThresholdECDSA.generatePresignature('P-256', [1, 3, 5]);

  // Trustees create partial signatures
  console.log('   ✓ Trustee 1 approved');
  const partial1 = ThresholdECDSA.partialSign(certTBS, keypair.shares[0], presignature);

  console.log('   ✓ Trustee 3 approved');
  const partial3 = ThresholdECDSA.partialSign(certTBS, keypair.shares[2], presignature);

  console.log('   ✓ Trustee 5 approved');
  const partial5 = ThresholdECDSA.partialSign(certTBS, keypair.shares[4], presignature);

  // Combine approvals
  console.log('\n3. Combining approvals...');
  const signature = ThresholdECDSA.combineSignatures(
    [partial1, partial3, partial5],
    3,
    presignature
  );
  console.log(`   ✓ Certificate signed`);

  // Verify
  console.log('\n4. Verifying certificate signature...');
  const result = ThresholdECDSA.verify(certTBS, signature, keypair.publicKey);
  console.log(`   ✓ Certificate valid: ${result.valid}`);

  return keypair;
}

// =============================================================================
// Example 3: Different Signing Groups
// =============================================================================

async function flexibleThresholdExample() {
  console.log('\n\n=== Example 3: Flexible Threshold (2-of-4) ===\n');

  const config: ThresholdECDSAConfig = {
    curve: 'secp256k1',
    threshold: 2,
    totalShares: 4,
  };

  console.log('1. Generating keypair...');
  const keypair = await ThresholdECDSA.generateKey(config);

  const message = new TextEncoder().encode('Important document');

  // Scenario A: Parties 1 and 2 sign
  console.log('\n2. Scenario A: Parties 1 and 2 sign');
  const presigA = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
  const partialsA = [
    ThresholdECDSA.partialSign(message, keypair.shares[0], presigA),
    ThresholdECDSA.partialSign(message, keypair.shares[1], presigA),
  ];
  const sigA = ThresholdECDSA.combineSignatures(partialsA, 2, presigA);
  console.log(`   ✓ Signature valid: ${ThresholdECDSA.verify(message, sigA, keypair.publicKey).valid}`);

  // Scenario B: Parties 2 and 4 sign
  console.log('\n3. Scenario B: Parties 2 and 4 sign');
  const presigB = ThresholdECDSA.generatePresignature('secp256k1', [2, 4]);
  const partialsB = [
    ThresholdECDSA.partialSign(message, keypair.shares[1], presigB),
    ThresholdECDSA.partialSign(message, keypair.shares[3], presigB),
  ];
  const sigB = ThresholdECDSA.combineSignatures(partialsB, 2, presigB);
  console.log(`   ✓ Signature valid: ${ThresholdECDSA.verify(message, sigB, keypair.publicKey).valid}`);

  // Scenario C: Parties 1, 3, and 4 sign (more than threshold)
  console.log('\n4. Scenario C: Parties 1, 3, and 4 sign (over-threshold)');
  const presigC = ThresholdECDSA.generatePresignature('secp256k1', [1, 3, 4]);
  const partialsC = [
    ThresholdECDSA.partialSign(message, keypair.shares[0], presigC),
    ThresholdECDSA.partialSign(message, keypair.shares[2], presigC),
    ThresholdECDSA.partialSign(message, keypair.shares[3], presigC),
  ];
  // Only use first 2 partials (threshold requirement)
  const sigC = ThresholdECDSA.combineSignatures(partialsC.slice(0, 2), 2, presigC);
  console.log(`   ✓ Signature valid: ${ThresholdECDSA.verify(message, sigC, keypair.publicKey).valid}`);
}

// =============================================================================
// Example 4: Batch Verification
// =============================================================================

async function batchVerificationExample() {
  console.log('\n\n=== Example 4: Batch Verification ===\n');

  const config: ThresholdECDSAConfig = {
    curve: 'secp256k1',
    threshold: 2,
    totalShares: 3,
  };

  const keypair = await ThresholdECDSA.generateKey(config);

  console.log('1. Creating multiple signatures...');
  const items = [];

  for (let i = 0; i < 5; i++) {
    const message = new TextEncoder().encode(`Document ${i}`);
    const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
    const partials = [
      ThresholdECDSA.partialSign(message, keypair.shares[0], presignature),
      ThresholdECDSA.partialSign(message, keypair.shares[1], presignature),
    ];
    const signature = ThresholdECDSA.combineSignatures(partials, 2, presignature);

    items.push({ message, signature, publicKey: keypair.publicKey });
    console.log(`   ✓ Document ${i} signed`);
  }

  console.log('\n2. Batch verifying all signatures...');
  const result = ThresholdECDSA.batchVerify(items);
  console.log(`   ✓ All ${items.length} signatures valid: ${result.valid}`);
}

// =============================================================================
// Example 5: Error Handling
// =============================================================================

async function errorHandlingExample() {
  console.log('\n\n=== Example 5: Error Handling ===\n');

  const config: ThresholdECDSAConfig = {
    curve: 'secp256k1',
    threshold: 3,
    totalShares: 5,
  };

  const keypair = await ThresholdECDSA.generateKey(config);
  const message = new TextEncoder().encode('Test message');

  // Insufficient partials
  console.log('1. Testing insufficient partials...');
  try {
    const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
    const partials = [
      ThresholdECDSA.partialSign(message, keypair.shares[0], presignature),
      ThresholdECDSA.partialSign(message, keypair.shares[1], presignature),
    ];
    ThresholdECDSA.combineSignatures(partials, 3, presignature);
  } catch (error) {
    console.log(`   ✓ Caught error: ${(error as Error).message}`);
  }

  // Wrong message verification
  console.log('\n2. Testing wrong message verification...');
  const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2, 3]);
  const partials = [
    ThresholdECDSA.partialSign(message, keypair.shares[0], presignature),
    ThresholdECDSA.partialSign(message, keypair.shares[1], presignature),
    ThresholdECDSA.partialSign(message, keypair.shares[2], presignature),
  ];
  const signature = ThresholdECDSA.combineSignatures(partials, 3, presignature);

  const wrongMessage = new TextEncoder().encode('Different message');
  const result = ThresholdECDSA.verify(wrongMessage, signature, keypair.publicKey);
  console.log(`   ✓ Wrong message rejected: ${!result.valid}`);

  // Tampered signature
  console.log('\n3. Testing tampered signature...');
  const tamperedSig = { ...signature, s: signature.s + 1n };
  const tamperedResult = ThresholdECDSA.verify(message, tamperedSig, keypair.publicKey);
  console.log(`   ✓ Tampered signature rejected: ${!tamperedResult.valid}`);
}

// =============================================================================
// Run All Examples
// =============================================================================

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         VeilKey Threshold ECDSA Examples                  ║');
  console.log('╚════════════════════════════════════════════════════════════╝');

  try {
    await bitcoinWalletExample();
    await tlsCertificateExample();
    await flexibleThresholdExample();
    await batchVerificationExample();
    await errorHandlingExample();

    console.log('\n\n✓ All examples completed successfully!\n');
  } catch (error) {
    console.error('\n✗ Error:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main };
