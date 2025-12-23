/**
 * Health Check Route
 *
 * Simple health check endpoint for monitoring and load balancers
 */

import type { FastifyInstance } from 'fastify';
import type { HealthResponse } from '../types.js';

export async function healthRoutes(fastify: FastifyInstance): Promise<void> {
  /**
   * GET /health
   * Health check endpoint
   */
  fastify.get<{
    Reply: HealthResponse;
  }>('/health', {
    schema: {
      description: 'Health check endpoint',
      tags: ['health'],
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            timestamp: { type: 'string' },
            version: { type: 'string' },
          },
        },
      },
    },
  }, async (_request, reply) => {
    const response: HealthResponse = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '0.1.0',
    };

    reply.send(response);
  });
}
