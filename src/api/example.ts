/**
 * VeilKey API Example
 *
 * Demonstrates how to use the VeilKey REST API
 */

import { createServer } from './server.js';

async function main() {
  console.log('VeilKey API Example\n');

  // Create server (without auth for demo)
  const server = await createServer({
    logger: false,
    enableAuth: false,
    enableRateLimit: false,
  });

  try {
    // 1. Create a 2-of-3 threshold key group
    console.log('1. Creating 2-of-3 threshold key group...');
    const createResponse = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    const group = JSON.parse(createResponse.body);
    console.log(`   Created group: ${group.id}`);
    console.log(`   Public key: ${group.publicKey.substring(0, 20)}...`);
    console.log(`   Shares: ${group.shares.length}\n`);

    // 2. Create partial signatures
    const message = 'Hello, VeilKey!';
    console.log(`2. Creating partial signatures for message: "${message}"`);

    const partial1Response = await server.inject({
      method: 'POST',
      url: `/v1/groups/${group.id}/sign/partial`,
      payload: {
        message,
        shareIndex: 1,
      },
    });
    const partial1 = JSON.parse(partial1Response.body);
    console.log(`   Partial 1 (share ${partial1.index}): ${partial1.partial.substring(0, 20)}...`);

    const partial2Response = await server.inject({
      method: 'POST',
      url: `/v1/groups/${group.id}/sign/partial`,
      payload: {
        message,
        shareIndex: 2,
      },
    });
    const partial2 = JSON.parse(partial2Response.body);
    console.log(`   Partial 2 (share ${partial2.index}): ${partial2.partial.substring(0, 20)}...\n`);

    // 3. Combine partial signatures
    console.log('3. Combining partial signatures...');
    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${group.id}/sign/combine`,
      payload: {
        message,
        partials: [partial1, partial2],
      },
    });
    const { signature } = JSON.parse(combineResponse.body);
    console.log(`   Signature: ${signature.substring(0, 40)}...\n`);

    // 4. Verify signature
    console.log('4. Verifying signature...');
    const verifyResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${group.id}/verify`,
      payload: {
        message,
        signature,
      },
    });
    const { valid } = JSON.parse(verifyResponse.body);
    console.log(`   Valid: ${valid} ✓\n`);

    // 5. Try to verify with wrong message
    console.log('5. Verifying with wrong message...');
    const verifyWrongResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${group.id}/verify`,
      payload: {
        message: 'Wrong message',
        signature,
      },
    });
    const { valid: validWrong } = JSON.parse(verifyWrongResponse.body);
    console.log(`   Valid: ${validWrong} ✗\n`);

    // 6. Get key group info
    console.log('6. Retrieving key group info...');
    const getResponse = await server.inject({
      method: 'GET',
      url: `/v1/groups/${group.id}`,
    });
    const groupInfo = JSON.parse(getResponse.body);
    console.log(`   Group ID: ${groupInfo.id}`);
    console.log(`   Algorithm: ${groupInfo.algorithm}`);
    console.log(`   Threshold: ${groupInfo.threshold}/${groupInfo.parties}`);
    console.log(`   Share info (no values): ${groupInfo.shareInfo.length} shares\n`);

    console.log('Example completed successfully! ✓');
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await server.close();
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { main };
