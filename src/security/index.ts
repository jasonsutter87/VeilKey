/**
 * VeilKey Security Module
 *
 * Provides mutual TLS (mTLS) authentication, certificate management,
 * hardware token authentication, geofencing, time-based access control,
 * and security operations.
 *
 * @module security
 */

// Types
export * from './types.js';

// Certificate Management
export { CertificateManager } from './certificate.js';

// mTLS Service
export { MTLSServiceImpl } from './mtls.js';
export type { MTLSService } from './mtls.js';

// Hardware Token Authentication (FIDO2/WebAuthn)
export {
  HardwareTokenManager,
  HardwareTokenError,
  HardwareTokenErrorCode,
} from './hardware-token.js';
export type {
  HardwareTokenType,
  AttestationType,
  TokenRegistration,
  AuthenticatorTransport,
  AuthenticationChallenge,
  AuthenticationResponse,
  TokenVerificationResult,
  RegistrationOptions,
  RegistrationChallenge,
  RegistrationResponse,
  TokenPolicy,
} from './hardware-token.js';

// Geofencing (Location-Based Access Control)
export {
  GeofenceManager,
  GeofenceError,
  GeofenceErrorCode,
} from './geofencing.js';
export type {
  GeoCoordinate,
  GeoRegion,
  GeoZone,
  CountryRegion,
  IPRange,
  LocationSource,
  LocationData,
  GeofenceAction,
  GeofenceRule,
  GeofencePolicy,
  GeofenceEvaluationResult,
  LocationVerificationResult,
  GeofenceAuditEntry,
} from './geofencing.js';

// Time-Based Access Control
export {
  TimeAccessManager,
  TimeAccessError,
  TimeAccessErrorCode,
} from './time-access.js';
export type {
  DayOfWeek,
  TimeOfDay,
  TimeWindow,
  DateRange,
  MaintenanceWindow,
  Holiday,
  TimeAction,
  TimeAccessRule,
  TimeAccessPolicy,
  TimeContext,
  TimeAccessResult,
  RateLimitState,
  TimeAccessAuditEntry,
} from './time-access.js';
