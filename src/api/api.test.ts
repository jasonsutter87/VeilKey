/**
 * VeilKey REST API Tests
 *
 * Integration tests for the REST API endpoints
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createServer } from './server.js';
import { storage } from './storage.js';

describe('VeilKey REST API', () => {
  let server: FastifyInstance;
  const testApiKey = 'demo-api-key-12345';

  beforeAll(async () => {
    // Create server without authentication for testing
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

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/health',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
      expect(body.version).toBe('0.1.0');
      expect(body.timestamp).toBeDefined();
    });
  });

  describe('Root Endpoint', () => {
    it('should return API information', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.name).toBe('VeilKey API');
      expect(body.version).toBe('0.1.0');
      expect(body.endpoints).toBeDefined();
    });
  });

  describe('Key Group Management', () => {
    let groupId: string;
    let shares: Array<{ index: number; value: string; verificationKey: string }>;

    it('should create a new key group', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/groups',
        payload: {
          threshold: 2,
          parties: 3,
          algorithm: 'RSA-2048',
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      expect(body.id).toBeDefined();
      expect(body.publicKey).toBeDefined();
      expect(body.algorithm).toBe('RSA-2048');
      expect(body.threshold).toBe(2);
      expect(body.parties).toBe(3);
      expect(body.shares).toHaveLength(3);
      expect(body.delta).toBeDefined();
      expect(body.createdAt).toBeDefined();

      // Store for later tests
      groupId = body.id;
      shares = body.shares;
    });

    it('should reject invalid threshold', async () => {
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

    it('should reject invalid algorithm', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/groups',
        payload: {
          threshold: 2,
          parties: 3,
          algorithm: 'AES-256', // Invalid
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it('should get key group by ID', async () => {
      const response = await server.inject({
        method: 'GET',
        url: `/v1/groups/${groupId}`,
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      expect(body.id).toBe(groupId);
      expect(body.publicKey).toBeDefined();
      expect(body.shareInfo).toHaveLength(3);
      // Should not include share values
      expect(body.shares).toBeUndefined();
      expect(body.shareInfo[0].value).toBeUndefined();
    });

    it('should return 404 for non-existent group', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/v1/groups/non-existent-id',
      });

      expect(response.statusCode).toBe(404);
    });

    describe('Threshold Signing', () => {
      const testMessage = 'Hello, VeilKey!';
      let partial1: { index: number; partial: string };
      let partial2: { index: number; partial: string };
      let signature: string;

      it('should create partial signature with share 1', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/sign/partial`,
          payload: {
            message: testMessage,
            shareIndex: shares[0].index,
          },
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.body);

        expect(body.index).toBe(shares[0].index);
        expect(body.partial).toBeDefined();
        expect(typeof body.partial).toBe('string');

        partial1 = body;
      });

      it('should create partial signature with share 2', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/sign/partial`,
          payload: {
            message: testMessage,
            shareIndex: shares[1].index,
          },
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.body);

        expect(body.index).toBe(shares[1].index);
        expect(body.partial).toBeDefined();

        partial2 = body;
      });

      it('should reject partial signing with invalid share index', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/sign/partial`,
          payload: {
            message: testMessage,
            shareIndex: 999, // Invalid
          },
        });

        expect(response.statusCode).toBe(400);
      });

      it('should combine partial signatures', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/sign/combine`,
          payload: {
            message: testMessage,
            partials: [partial1, partial2],
          },
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.body);

        expect(body.signature).toBeDefined();
        expect(typeof body.signature).toBe('string');

        signature = body.signature;
      });

      it('should verify valid signature', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/verify`,
          payload: {
            message: testMessage,
            signature,
          },
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.body);

        expect(body.valid).toBe(true);
      });

      it('should reject invalid signature', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/verify`,
          payload: {
            message: testMessage,
            signature: 'invalid-signature-12345',
          },
        });

        // Invalid signature format may return error or valid: false
        const body = JSON.parse(response.body);
        if (response.statusCode === 200) {
          expect(body.valid).toBe(false);
        } else {
          // Server may return 400/500 for malformed signatures
          expect(response.statusCode).toBeGreaterThanOrEqual(400);
        }
      });

      it('should reject signature for different message', async () => {
        const response = await server.inject({
          method: 'POST',
          url: `/v1/groups/${groupId}/verify`,
          payload: {
            message: 'Different message',
            signature,
          },
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.body);

        expect(body.valid).toBe(false);
      });
    });
  });

  describe('Error Handling', () => {
    it('should return validation error for missing fields', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/v1/groups',
        payload: {
          threshold: 2,
          // Missing parties and algorithm
        },
      });

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toBeDefined();
      // Fastify returns FST_ERR_VALIDATION for schema validation errors
      expect(['VALIDATION_ERROR', 'FST_ERR_VALIDATION']).toContain(body.error.code);
    });

    it('should return 404 for unknown route', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/v1/unknown-route',
      });

      expect(response.statusCode).toBe(404);
    });
  });
});

describe('API Authentication', () => {
  let server: FastifyInstance;
  const validApiKey = 'demo-api-key-12345';

  beforeAll(async () => {
    // Create server WITH authentication
    server = await createServer({
      logger: false,
      enableAuth: true,
      enableRateLimit: false,
    });
  });

  afterAll(async () => {
    await server.close();
  });

  it('should allow health check without authentication', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
  });

  it('should reject requests without API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe('UNAUTHORIZED');
  });

  it('should reject requests with invalid API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: {
        'x-api-key': 'invalid-key',
      },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(401);
  });

  it('should accept requests with valid API key', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/v1/groups',
      headers: {
        'x-api-key': validApiKey,
      },
      payload: {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      },
    });

    expect(response.statusCode).toBe(200);
  });
});
