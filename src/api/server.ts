/**
 * VeilKey REST API Server
 *
 * Fastify-based REST API for threshold cryptography operations
 */

import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { errorHandler, authenticateApiKey } from './middleware/index.js';
import { healthRoutes, groupRoutes } from './routes/index.js';

export interface ServerConfig {
  /** Port to listen on */
  port?: number;

  /** Host to bind to */
  host?: string;

  /** Enable CORS */
  enableCors?: boolean;

  /** Enable rate limiting */
  enableRateLimit?: boolean;

  /** Enable API key authentication */
  enableAuth?: boolean;

  /** Fastify logger configuration */
  logger?: FastifyServerOptions['logger'];
}

/**
 * Create and configure Fastify server
 */
export async function createServer(config: ServerConfig = {}): Promise<FastifyInstance> {
  const {
    enableCors = true,
    enableRateLimit = true,
    enableAuth = true,
    logger = true,
  } = config;

  // Create Fastify instance
  const fastify = Fastify({
    logger,
    ajv: {
      customOptions: {
        removeAdditional: 'all',
        coerceTypes: true,
        useDefaults: true,
      },
    },
  });

  // Register error handler
  fastify.setErrorHandler(errorHandler);

  // Register CORS plugin
  if (enableCors) {
    await fastify.register(cors, {
      origin: true, // Allow all origins in development
      credentials: true,
    });
  }

  // Register rate limiting
  if (enableRateLimit) {
    await fastify.register(rateLimit, {
      max: 100, // 100 requests
      timeWindow: '1 minute',
      errorResponseBuilder: () => ({
        error: {
          message: 'Rate limit exceeded. Please try again later.',
          code: 'RATE_LIMIT_EXCEEDED',
          statusCode: 429,
        },
      }),
    });
  }

  // Register authentication hook
  if (enableAuth) {
    fastify.addHook('onRequest', authenticateApiKey);
  }

  // Register routes
  await fastify.register(healthRoutes);
  await fastify.register(groupRoutes);

  // Root endpoint
  fastify.get('/', async (_request, reply) => {
    reply.send({
      name: 'VeilKey API',
      version: '0.1.0',
      description: 'Threshold Cryptography REST API',
      endpoints: {
        health: 'GET /health',
        groups: {
          create: 'POST /v1/groups',
          get: 'GET /v1/groups/:id',
          partialSign: 'POST /v1/groups/:id/sign/partial',
          combineSignatures: 'POST /v1/groups/:id/sign/combine',
          verify: 'POST /v1/groups/:id/verify',
        },
      },
      documentation: 'Use X-API-Key header for authentication',
    });
  });

  return fastify;
}

/**
 * Start the server
 */
export async function startServer(config: ServerConfig = {}): Promise<FastifyInstance> {
  const { port = 3000, host = '0.0.0.0' } = config;

  const fastify = await createServer(config);

  try {
    await fastify.listen({ port, host });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

// Start server if running directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const host = process.env.HOST || '0.0.0.0';

  startServer({ port, host }).then((server) => {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   VeilKey API Server                                           ║
║   Threshold Cryptography REST API                              ║
║                                                                ║
║   Server running at: http://${host}:${port}                   ║
║                                                                ║
║   Endpoints:                                                   ║
║   • GET  /health                     - Health check            ║
║   • POST /v1/groups                  - Create key group        ║
║   • GET  /v1/groups/:id              - Get key group           ║
║   • POST /v1/groups/:id/sign/partial - Partial signature       ║
║   • POST /v1/groups/:id/sign/combine - Combine signatures      ║
║   • POST /v1/groups/:id/verify       - Verify signature        ║
║                                                                ║
║   Authentication: X-API-Key header                             ║
║   Demo API Key: demo-api-key-12345                             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    `);
  }).catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
