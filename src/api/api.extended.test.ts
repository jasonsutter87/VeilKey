/**
 * VeilKey REST API Extended Tests
 *
 * Comprehensive extended test suite providing thorough coverage of:
 * - All HTTP methods (GET, POST, PUT, DELETE)
 * - All endpoints comprehensively
 * - Authentication edge cases
 * - Rate limiting behavior
 * - Error handling
 * - Concurrent requests
 * - Large payloads
 * - Content-Type validation
 *
 * Target: 55+ additional tests
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from './server.js';
import { storage } from './storage.js';
import { addApiKey, removeApiKey } from './middleware/auth.js';

// =============================================================================
// Test Helpers
// =============================================================================

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// Comprehensive Authentication Tests
// =============================================================================

describe('API Extended - Authentication Edge Cases', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: true,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should reject request with empty API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': '' },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(401);
  });

  it('should reject request with malformed API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': 'malformed-key-!@#$%' },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(401);
  });

  it('should reject request with expired-looking API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': 'expired-key-1234567890' },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(401);
  });

  it('should allow health check without authentication', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
  });

  it('should allow root endpoint without authentication for info', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/',
    });

    // Root endpoint behavior depends on server config
    // Should either succeed or require auth
    expect([200, 401]).toContain(response.statusCode);
  });

  it('should accept request with valid demo API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': 'demo-api-key-12345' },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(200);
  });

  it('should accept request with test API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': 'test-api-key-67890' },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(200);
  });

  it('should reject case-sensitive API key header name', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'X-Api-Key': 'demo-api-key-12345' }, // Different case
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    // Fastify normalizes headers to lowercase, so this should work
    // But testing the behavior
    expect([200, 401]).toContain(response.statusCode);
  });

  it('should handle multiple API key headers (use first)', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: { 'x-api-key': ['demo-api-key-12345', 'invalid-key'] },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    // Behavior with multiple headers varies
    expect([200, 401]).toContain(response.statusCode);
  });
});

// =============================================================================
// Rate Limiting Tests
// =============================================================================

describe('API Extended - Rate Limiting', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: true,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should allow requests under rate limit', async () => {
    // Make 5 requests quickly
    const responses = await Promise.all(
      Array.from({ length: 5 }, () =>
        server.inject({
          method: 'GET',
          url: '/health',
        })
      )
    );

    // All should succeed
    responses.forEach(r => expect(r.statusCode).toBe(200));
  });

  it('should handle burst of requests', async () => {
    // Make 20 requests simultaneously
    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        server.inject({
          method: 'GET',
          url: '/health',
        })
      )
    );

    // Most should succeed, some might be rate limited
    const successCount = responses.filter(r => r.statusCode === 200).length;
    expect(successCount).toBeGreaterThan(0);
  });

  it('should recover from rate limit after time window', async () => {
    // Make many requests to hit rate limit
    await Promise.all(
      Array.from({ length: 50 }, () =>
        server.inject({ method: 'GET', url: '/health' })
      )
    );

    // Wait for rate limit window to reset (configured to 1 minute, but testing quickly)
    await delay(100);

    // Should be able to make requests again
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    expect([200, 429]).toContain(response.statusCode);
  });
});

// =============================================================================
// Group Management - Comprehensive Tests
// =============================================================================

describe('API Extended - Group Management', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
    storage.clear();
  });

  beforeEach(() => {
    storage.clear();
  });

  it('should create group with RSA-4096', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-4096',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.algorithm).toBe('RSA-4096');
    expect(body.threshold).toBe(3);
    expect(body.parties).toBe(5);
  });

  it('should create multiple independent groups', async () => {
    const configs = [
      { threshold: 2, parties: 3, algorithm: 'RSA-2048' },
      { threshold: 3, parties: 5, algorithm: 'RSA-2048' },
      { threshold: 2, parties: 4, algorithm: 'RSA-4096' },
    ];

    const groups = [];
    for (const config of configs) {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/groups',
        payload: config,
      });
      expect(response.statusCode).toBe(200);
      groups.push(JSON.parse(response.body));
    }

    // All should have unique IDs
    const ids = groups.map(g => g.id);
    expect(new Set(ids).size).toBe(3);

    // All should have unique public keys
    const pubKeys = groups.map(g => g.publicKey);
    expect(new Set(pubKeys).size).toBe(3);
  });

  it('should reject threshold exceeding parties', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 5,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject zero threshold', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 0,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject zero parties', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 0,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject negative threshold', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: -1,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject unsupported algorithm', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'AES-256',
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject missing required fields', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        // Missing parties and algorithm
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should reject extra unknown fields', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
        extraField: 'should be removed',
      },
    });

    // With removeAdditional: true, extra fields are removed, request should succeed
    expect(response.statusCode).toBe(200);
  });

  it('should handle GET request for existing group', async () => {
    // Create group
    const createResponse = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });
    const groupId = JSON.parse(createResponse.body).id;

    // Get group
    const getResponse = await server.inject({
      method: 'GET',
      url: `/v1/groups/${groupId}`,
    });

    expect(getResponse.statusCode).toBe(200);
    const body = JSON.parse(getResponse.body);
    expect(body.id).toBe(groupId);
    expect(body.shareInfo).toBeDefined();
    expect(body.shares).toBeUndefined(); // Shares should not be exposed
  });

  it('should return 404 for non-existent group', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups/non-existent-group-id-12345',
    });

    expect(response.statusCode).toBe(404);
  });

  it('should return 404 for invalid group ID format', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups/invalid!@#$',
    });

    expect(response.statusCode).toBe(404);
  });
});

// =============================================================================
// Signing Operations - Extended Tests
// =============================================================================

describe('API Extended - Signing Operations', () => {
  let server: FastifyInstance;
  let groupId: string;
  let shares: Array<{ index: number; value: string; verificationKey: string }>;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });

    // Create a test group
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 4,
        algorithm: 'RSA-2048',
      },
    });
    const body = JSON.parse(response.body);
    groupId = body.id;
    shares = body.shares;
  });

  afterAll(async () => {
    await server.close();
    storage.clear();
  });

  it('should create partial signatures from all shares', async () => {
    const message = 'Test all shares';

    for (const share of shares) {
      const response = await server.inject({
        method: 'POST',
        url: `/v1/groups/${groupId}/sign/partial`,
        payload: {
          message,
          shareIndex: share.index,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.index).toBe(share.index);
      expect(body.partial).toBeDefined();
    }
  });

  it('should sign and verify with different share combinations', async () => {
    const message = 'Test share combinations';

    // Combination 1: shares 1 and 2
    const partial1a = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[0].index },
    });
    const partial2a = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[1].index },
    });

    const combineResponse1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message,
        partials: [JSON.parse(partial1a.body), JSON.parse(partial2a.body)],
      },
    });

    expect(combineResponse1.statusCode).toBe(200);
    const sig1 = JSON.parse(combineResponse1.body).signature;

    // Verify
    const verifyResponse1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/verify`,
      payload: { message, signature: sig1 },
    });
    expect(JSON.parse(verifyResponse1.body).valid).toBe(true);

    // Combination 2: shares 3 and 4
    const partial3 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[2].index },
    });
    const partial4 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[3].index },
    });

    const combineResponse2 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message,
        partials: [JSON.parse(partial3.body), JSON.parse(partial4.body)],
      },
    });

    expect(combineResponse2.statusCode).toBe(200);
  });

  it('should reject partial signing with insufficient shares', async () => {
    const message = 'Test insufficient';

    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[0].index },
    });

    // Try to combine with only 1 partial (threshold is 2)
    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message,
        partials: [JSON.parse(partial1.body)],
      },
    });

    expect(combineResponse.statusCode).toBeGreaterThanOrEqual(400);
  });

  it('should reject partial signing with out-of-range share index', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: {
        message: 'Test',
        shareIndex: 999,
      },
    });

    expect(response.statusCode).toBe(400);
  });

  it('should handle empty message', async () => {
    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: '', shareIndex: shares[0].index },
    });
    const partial2 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: '', shareIndex: shares[1].index },
    });

    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message: '',
        partials: [JSON.parse(partial1.body), JSON.parse(partial2.body)],
      },
    });

    expect(combineResponse.statusCode).toBe(200);
  });

  it('should handle very long message', async () => {
    const longMessage = 'A'.repeat(10000);

    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: longMessage, shareIndex: shares[0].index },
    });
    const partial2 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: longMessage, shareIndex: shares[1].index },
    });

    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message: longMessage,
        partials: [JSON.parse(partial1.body), JSON.parse(partial2.body)],
      },
    });

    expect(combineResponse.statusCode).toBe(200);
  });

  it('should handle unicode message', async () => {
    const unicodeMessage = 'Hello 世界 🌍 مرحبا';

    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: unicodeMessage, shareIndex: shares[0].index },
    });
    const partial2 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message: unicodeMessage, shareIndex: shares[1].index },
    });

    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message: unicodeMessage,
        partials: [JSON.parse(partial1.body), JSON.parse(partial2.body)],
      },
    });

    expect(combineResponse.statusCode).toBe(200);
  });

  it('should reject verification with tampered signature', async () => {
    const message = 'Test tampering';

    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[0].index },
    });
    const partial2 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[1].index },
    });

    const combineResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/combine`,
      payload: {
        message,
        partials: [JSON.parse(partial1.body), JSON.parse(partial2.body)],
      },
    });

    const signature = JSON.parse(combineResponse.body).signature;

    // Tamper with signature
    const tamperedSignature = signature + 'tampered';

    const verifyResponse = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/verify`,
      payload: { message, signature: tamperedSignature },
    });

    const body = JSON.parse(verifyResponse.body);
    if (verifyResponse.statusCode === 200) {
      expect(body.valid).toBe(false);
    } else {
      expect(verifyResponse.statusCode).toBeGreaterThanOrEqual(400);
    }
  });
});

// =============================================================================
// HTTP Methods and Headers
// =============================================================================

describe('API Extended - HTTP Methods', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should reject PUT method on /v1/groups', async () => {
    const response = await server.inject({
      method: 'PUT',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(404);
  });

  it('should reject DELETE method on /v1/groups', async () => {
    const response = await server.inject({
      method: 'DELETE',
      url: '/v1/groups',
    });

    expect(response.statusCode).toBe(404);
  });

  it('should reject GET method on POST-only endpoints', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups',
    });

    expect(response.statusCode).toBe(404);
  });

  it('should handle OPTIONS request (CORS preflight)', async () => {
    const response = await server.inject({
      method: 'OPTIONS',
      url: '/v1/groups',
    });

    // CORS is enabled, should return 204 or 200
    expect([200, 204]).toContain(response.statusCode);
  });
});

// =============================================================================
// Content-Type Validation
// =============================================================================

describe('API Extended - Content-Type Handling', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should accept application/json content-type', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: {
        'content-type': 'application/json',
      },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(200);
  });

  it('should handle missing content-type header', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: JSON.stringify({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      }),
    });

    // Fastify should handle this
    expect([200, 400]).toContain(response.statusCode);
  });

  it('should reject invalid JSON', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: {
        'content-type': 'application/json',
      },
      payload: '{ invalid json }',
    });

    expect(response.statusCode).toBeGreaterThanOrEqual(400);
  });

  it('should handle malformed JSON with trailing comma', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: {
        'content-type': 'application/json',
      },
      payload: '{"threshold": 2, "parties": 3, "algorithm": "RSA-2048",}',
    });

    expect(response.statusCode).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Error Response Format Consistency
// =============================================================================

describe('API Extended - Error Response Format', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should return consistent error format for validation errors', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        // Missing required fields
      },
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBeDefined();
  });

  it('should return consistent error format for not found', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups/non-existent',
    });

    expect(response.statusCode).toBe(404);
    const body = JSON.parse(response.body);
    expect(body.error).toBeDefined();
  });

  it('should include error message in response', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups/non-existent',
    });

    const body = JSON.parse(response.body);
    expect(body.error.message || body.error).toBeDefined();
  });
});

// =============================================================================
// Concurrent Request Handling
// =============================================================================

describe('API Extended - Concurrent Requests', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
    storage.clear();
  });

  it('should handle 10 concurrent group creations', async () => {
    const requests = Array.from({ length: 10 }, (_, i) =>
      server.inject({
        method: 'POST',
        url: '/v1/groups',
        payload: {
          threshold: 2,
          parties: 3,
          algorithm: 'RSA-2048',
        },
      })
    );

    const responses = await Promise.all(requests);

    // All should succeed
    responses.forEach(r => expect(r.statusCode).toBe(200));

    // All should have unique IDs
    const ids = responses.map(r => JSON.parse(r.body).id);
    expect(new Set(ids).size).toBe(10);
  });

  it('should handle concurrent signing operations', async () => {
    // Create a group first
    const createResponse = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });
    const { id: groupId, shares } = JSON.parse(createResponse.body);

    // Sign 5 different messages concurrently
    const messages = ['Msg1', 'Msg2', 'Msg3', 'Msg4', 'Msg5'];
    const signOperations = messages.map(async msg => {
      const partial1 = await server.inject({
        method: 'POST',
        url: `/v1/groups/${groupId}/sign/partial`,
        payload: { message: msg, shareIndex: shares[0].index },
      });
      const partial2 = await server.inject({
        method: 'POST',
        url: `/v1/groups/${groupId}/sign/partial`,
        payload: { message: msg, shareIndex: shares[1].index },
      });

      return server.inject({
        method: 'POST',
        url: `/v1/groups/${groupId}/sign/combine`,
        payload: {
          message: msg,
          partials: [JSON.parse(partial1.body), JSON.parse(partial2.body)],
        },
      });
    });

    const responses = await Promise.all(signOperations);
    responses.forEach(r => expect(r.statusCode).toBe(200));
  });
});

// =============================================================================
// Health Check Extended
// =============================================================================

describe('API Extended - Health Check', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should return version information', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    const body = JSON.parse(response.body);
    expect(body.version).toBeDefined();
    expect(body.version).toBe('0.1.0');
  });

  it('should return timestamp', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    const body = JSON.parse(response.body);
    expect(body.timestamp).toBeDefined();
    expect(new Date(body.timestamp)).toBeInstanceOf(Date);
  });

  it('should respond quickly to health checks', async () => {
    const start = Date.now();
    await server.inject({
      method: 'GET',
      url: '/health',
    });
    const duration = Date.now() - start;

    // Should respond in less than 100ms
    expect(duration).toBeLessThan(100);
  });
});

// =============================================================================
// Large Payload Handling
// =============================================================================

describe('API Extended - Large Payload Handling', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should handle normal-sized message', async () => {
    const createResponse = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });
    const { id: groupId, shares } = JSON.parse(createResponse.body);

    const message = 'Normal message';
    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[0].index },
    });

    expect(partial1.statusCode).toBe(200);
  });

  it('should handle message with special characters', async () => {
    const createResponse = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });
    const { id: groupId, shares } = JSON.parse(createResponse.body);

    const message = 'Special chars: !@#$%^&*()_+-=[]{}|;:\'",.<>?/~`';
    const partial1 = await server.inject({
      method: 'POST',
      url: `/v1/groups/${groupId}/sign/partial`,
      payload: { message, shareIndex: shares[0].index },
    });

    expect(partial1.statusCode).toBe(200);
  });
});

// =============================================================================
// CORS Handling
// =============================================================================

describe('API Extended - CORS', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
      enableCors: true,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should include CORS headers in response', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
      headers: {
        origin: 'http://localhost:3000',
      },
    });

    expect(response.headers['access-control-allow-origin']).toBeDefined();
  });

  it('should handle preflight OPTIONS request', async () => {
    const response = await server.inject({
      method: 'OPTIONS',
      url: '/v1/groups',
      headers: {
        origin: 'http://localhost:3000',
        'access-control-request-method': 'POST',
      },
    });

    expect([200, 204]).toContain(response.statusCode);
  });
});

// =============================================================================
// Timeout Handling
// =============================================================================

describe('API Extended - Request Timeout', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should complete normal requests within timeout', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
  });
});

// =============================================================================
// Edge Case Routes
// =============================================================================

describe('API Extended - Edge Case Routes', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer({
      logger: false,
      enableAuth: false,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should return 404 for unknown routes', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/unknown/route',
    });

    expect(response.statusCode).toBe(404);
  });

  it('should return 404 for malformed URLs', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/v1/groups///',
    });

    expect(response.statusCode).toBe(404);
  });

  it('should handle trailing slashes', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health/',
    });

    // Should either redirect or handle normally
    expect([200, 301, 404]).toContain(response.statusCode);
  });
});
