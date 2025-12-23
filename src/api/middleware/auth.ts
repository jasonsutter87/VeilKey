/**
 * API Key Authentication Middleware
 *
 * Simple API key authentication for demo purposes.
 * In production, use proper authentication (JWT, OAuth2, etc.)
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import { unauthorized } from './error-handler.js';

/**
 * Valid API keys for demonstration
 * In production, store these securely (environment variables, key management service)
 */
const VALID_API_KEYS = new Set([
  'demo-api-key-12345',
  'test-api-key-67890',
]);

/**
 * API key authentication hook
 *
 * Checks for valid API key in X-API-Key header
 */
export async function authenticateApiKey(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  // Skip authentication for health check
  if (request.url === '/health') {
    return;
  }

  const apiKey = request.headers['x-api-key'];

  if (!apiKey) {
    throw unauthorized('API key required. Provide X-API-Key header.');
  }

  if (typeof apiKey !== 'string' || !VALID_API_KEYS.has(apiKey)) {
    throw unauthorized('Invalid API key');
  }

  // API key is valid, continue
}

/**
 * Add a valid API key (for testing/demo purposes)
 */
export function addApiKey(key: string): void {
  VALID_API_KEYS.add(key);
}

/**
 * Remove an API key
 */
export function removeApiKey(key: string): void {
  VALID_API_KEYS.delete(key);
}

/**
 * Check if an API key is valid
 */
export function isValidApiKey(key: string): boolean {
  return VALID_API_KEYS.has(key);
}
