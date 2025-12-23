/**
 * Error Handler Middleware
 *
 * Global error handler for Fastify with proper error formatting
 */

import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';
import type { ErrorResponse } from '../types.js';

/**
 * Custom API error with status code
 */
export class ApiError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Error handler function for Fastify
 */
export function errorHandler(
  error: FastifyError | Error,
  _request: FastifyRequest,
  reply: FastifyReply
): void {
  // Handle Zod validation errors
  if (error instanceof ZodError) {
    const response: ErrorResponse = {
      error: {
        message: 'Validation error',
        code: 'VALIDATION_ERROR',
        statusCode: 400,
      },
    };

    reply.status(400).send({
      ...response,
      validationErrors: error.errors,
    });
    return;
  }

  // Handle custom API errors
  if (error instanceof ApiError) {
    const response: ErrorResponse = {
      error: {
        message: error.message,
        code: error.code,
        statusCode: error.statusCode,
      },
    };

    reply.status(error.statusCode).send(response);
    return;
  }

  // Handle Fastify errors
  if ('statusCode' in error) {
    const response: ErrorResponse = {
      error: {
        message: error.message,
        code: (error as FastifyError).code,
        statusCode: (error as FastifyError).statusCode || 500,
      },
    };

    reply.status((error as FastifyError).statusCode || 500).send(response);
    return;
  }

  // Handle generic errors
  const response: ErrorResponse = {
    error: {
      message: error.message || 'Internal server error',
      code: 'INTERNAL_ERROR',
      statusCode: 500,
    },
  };

  reply.status(500).send(response);
}

/**
 * Helper to create not found error
 */
export function notFound(resource: string, id: string): ApiError {
  return new ApiError(404, `${resource} not found: ${id}`, 'NOT_FOUND');
}

/**
 * Helper to create bad request error
 */
export function badRequest(message: string): ApiError {
  return new ApiError(400, message, 'BAD_REQUEST');
}

/**
 * Helper to create unauthorized error
 */
export function unauthorized(message = 'Unauthorized'): ApiError {
  return new ApiError(401, message, 'UNAUTHORIZED');
}

/**
 * Helper to create forbidden error
 */
export function forbidden(message = 'Forbidden'): ApiError {
  return new ApiError(403, message, 'FORBIDDEN');
}
