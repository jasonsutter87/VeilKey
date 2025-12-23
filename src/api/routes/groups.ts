/**
 * Key Group Routes
 *
 * API endpoints for key group management and cryptographic operations
 */

import type { FastifyInstance } from 'fastify';
import { VeilKey } from '../../veilkey.js';
import { storage } from '../storage.js';
import { notFound, badRequest } from '../middleware/index.js';
import {
  CreateGroupSchema,
  PartialSignSchema,
  CombineSignaturesSchema,
  VerifySignatureSchema,
  type KeyGroupWithShares,
  type KeyGroupResponse,
  type ShareInfo,
  type PartialSignatureResponse,
  type CombineSignaturesResponse,
  type VerifySignatureResponse,
} from '../types.js';

/**
 * Convert KeyGroup to public response (without share values)
 */
function toPublicKeyGroup(group: any): KeyGroupResponse {
  return {
    id: group.id,
    publicKey: group.publicKey,
    algorithm: group.algorithm,
    threshold: group.threshold,
    parties: group.parties,
    shareInfo: group.shares.map((s: any): ShareInfo => ({
      index: s.index,
      verificationKey: s.verificationKey,
    })),
    delta: group.delta,
    createdAt: group.createdAt.toISOString(),
  };
}

/**
 * Convert KeyGroup to response with shares (only on creation)
 */
function toKeyGroupWithShares(group: any): KeyGroupWithShares {
  return {
    id: group.id,
    publicKey: group.publicKey,
    algorithm: group.algorithm,
    threshold: group.threshold,
    parties: group.parties,
    shares: group.shares.map((s: any) => ({
      index: s.index,
      value: s.value,
      verificationKey: s.verificationKey,
    })),
    delta: group.delta,
    createdAt: group.createdAt.toISOString(),
  };
}

export async function groupRoutes(fastify: FastifyInstance): Promise<void> {
  /**
   * POST /v1/groups
   * Create a new key group
   */
  fastify.post<{
    Body: unknown;
    Reply: KeyGroupWithShares;
  }>('/v1/groups', {
    schema: {
      description: 'Create a new threshold key group',
      tags: ['groups'],
      body: {
        type: 'object',
        required: ['threshold', 'parties', 'algorithm'],
        properties: {
          threshold: { type: 'number', minimum: 1 },
          parties: { type: 'number', minimum: 1 },
          algorithm: { type: 'string', enum: ['RSA-2048', 'RSA-4096'] },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            publicKey: { type: 'string' },
            algorithm: { type: 'string' },
            threshold: { type: 'number' },
            parties: { type: 'number' },
            shares: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  index: { type: 'number' },
                  value: { type: 'string' },
                  verificationKey: { type: 'string' },
                },
              },
            },
            delta: { type: 'string' },
            createdAt: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    // Validate request body
    const body = CreateGroupSchema.parse(request.body);

    // Generate key group
    const group = await VeilKey.generate(body);

    // Store in memory
    storage.set(group);

    // Return with shares (only time shares are exposed)
    reply.send(toKeyGroupWithShares(group));
  });

  /**
   * GET /v1/groups/:id
   * Get key group by ID (public info only)
   */
  fastify.get<{
    Params: { id: string };
    Reply: KeyGroupResponse;
  }>('/v1/groups/:id', {
    schema: {
      description: 'Get key group information (public data only)',
      tags: ['groups'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            publicKey: { type: 'string' },
            algorithm: { type: 'string' },
            threshold: { type: 'number' },
            parties: { type: 'number' },
            shareInfo: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  index: { type: 'number' },
                  verificationKey: { type: 'string' },
                },
              },
            },
            delta: { type: 'string' },
            createdAt: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params;

    const group = storage.get(id);
    if (!group) {
      throw notFound('Key group', id);
    }

    reply.send(toPublicKeyGroup(group));
  });

  /**
   * POST /v1/groups/:id/sign/partial
   * Create a partial signature
   */
  fastify.post<{
    Params: { id: string };
    Body: unknown;
    Reply: PartialSignatureResponse;
  }>('/v1/groups/:id/sign/partial', {
    schema: {
      description: 'Create a partial signature using a share',
      tags: ['signing'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        required: ['message', 'shareIndex'],
        properties: {
          message: { type: 'string' },
          shareIndex: { type: 'number', minimum: 1 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            index: { type: 'number' },
            partial: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params;
    const body = PartialSignSchema.parse(request.body);

    const group = storage.get(id);
    if (!group) {
      throw notFound('Key group', id);
    }

    // Find the share
    const share = group.shares.find(s => s.index === body.shareIndex);
    if (!share) {
      throw badRequest(`Share with index ${body.shareIndex} not found`);
    }

    // Create partial signature
    const partial = await VeilKey.partialSign(body.message, share, group);

    reply.send(partial);
  });

  /**
   * POST /v1/groups/:id/sign/combine
   * Combine partial signatures into a complete signature
   */
  fastify.post<{
    Params: { id: string };
    Body: unknown;
    Reply: CombineSignaturesResponse;
  }>('/v1/groups/:id/sign/combine', {
    schema: {
      description: 'Combine partial signatures into a complete signature',
      tags: ['signing'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        required: ['message', 'partials'],
        properties: {
          message: { type: 'string' },
          partials: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                index: { type: 'number' },
                partial: { type: 'string' },
              },
            },
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            signature: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params;
    const body = CombineSignaturesSchema.parse(request.body);

    const group = storage.get(id);
    if (!group) {
      throw notFound('Key group', id);
    }

    // Combine signatures
    const signature = await VeilKey.combineSignatures(
      body.message,
      body.partials,
      group
    );

    reply.send({ signature });
  });

  /**
   * POST /v1/groups/:id/verify
   * Verify a signature
   */
  fastify.post<{
    Params: { id: string };
    Body: unknown;
    Reply: VerifySignatureResponse;
  }>('/v1/groups/:id/verify', {
    schema: {
      description: 'Verify a signature',
      tags: ['signing'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        required: ['message', 'signature'],
        properties: {
          message: { type: 'string' },
          signature: { type: 'string' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            valid: { type: 'boolean' },
          },
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params;
    const body = VerifySignatureSchema.parse(request.body);

    const group = storage.get(id);
    if (!group) {
      throw notFound('Key group', id);
    }

    // Verify signature
    const valid = await VeilKey.verify(body.message, body.signature, group);

    reply.send({ valid });
  });
}
