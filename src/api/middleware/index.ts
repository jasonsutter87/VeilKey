/**
 * Middleware exports
 */

export { errorHandler, ApiError, notFound, badRequest, unauthorized, forbidden } from './error-handler.js';
export { authenticateApiKey, addApiKey, removeApiKey, isValidApiKey } from './auth.js';
