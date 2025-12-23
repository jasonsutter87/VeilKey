/**
 * VeilKey Geofencing Module
 *
 * Provides location-based access control for threshold cryptography operations.
 * Supports IP-based geolocation, geographic regions, and custom zones.
 *
 * @module security/geofencing
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Geographic Coordinate
 */
export interface GeoCoordinate {
  latitude: number;
  longitude: number;
}

/**
 * Geographic Region (circular)
 */
export interface GeoRegion {
  id: string;
  name: string;
  center: GeoCoordinate;
  radiusKm: number;
  description?: string;
}

/**
 * Geographic Zone (polygon)
 */
export interface GeoZone {
  id: string;
  name: string;
  vertices: GeoCoordinate[];
  description?: string;
}

/**
 * Country-based Region
 */
export interface CountryRegion {
  id: string;
  name: string;
  countryCodes: string[]; // ISO 3166-1 alpha-2
  includeSubdivisions?: string[]; // ISO 3166-2
  excludeSubdivisions?: string[];
}

/**
 * IP Range
 */
export interface IPRange {
  id: string;
  name: string;
  cidr: string; // CIDR notation (e.g., "192.168.1.0/24")
  description?: string;
}

/**
 * Location Source
 */
export type LocationSource = 'ip' | 'gps' | 'wifi' | 'cell' | 'manual';

/**
 * Location Data
 */
export interface LocationData {
  coordinate?: GeoCoordinate;
  ipAddress?: string;
  countryCode?: string;
  subdivisionCode?: string;
  city?: string;
  source: LocationSource;
  accuracy?: number; // meters
  timestamp: Date;
}

/**
 * Geofence Policy Action
 */
export type GeofenceAction = 'allow' | 'deny' | 'mfa_required' | 'audit';

/**
 * Geofence Policy Rule
 */
export interface GeofenceRule {
  id: string;
  name: string;
  priority: number; // Lower = higher priority
  action: GeofenceAction;
  regions?: string[]; // Region IDs
  zones?: string[]; // Zone IDs
  countries?: string[]; // Country region IDs
  ipRanges?: string[]; // IP range IDs
  operations?: string[]; // Crypto operations this applies to
  enabled: boolean;
}

/**
 * Geofence Policy
 */
export interface GeofencePolicy {
  id: string;
  name: string;
  defaultAction: GeofenceAction;
  rules: GeofenceRule[];
  enabled: boolean;
  requireLocationProof: boolean;
  maxLocationAge: number; // seconds
}

/**
 * Geofence Evaluation Result
 */
export interface GeofenceEvaluationResult {
  allowed: boolean;
  action: GeofenceAction;
  matchedRules: string[];
  location: LocationData;
  reasons: string[];
  timestamp: Date;
}

/**
 * Location Verification Result
 */
export interface LocationVerificationResult {
  verified: boolean;
  location: LocationData;
  matchedRegions: string[];
  matchedZones: string[];
  matchedCountries: string[];
  matchedIpRanges: string[];
  errors: string[];
}

/**
 * Geofence Audit Entry
 */
export interface GeofenceAuditEntry {
  id: string;
  userId: string;
  operation: string;
  location: LocationData;
  result: GeofenceEvaluationResult;
  timestamp: Date;
  hash: string;
  previousHash: string;
}

/**
 * Geofencing Error
 */
export class GeofenceError extends Error {
  constructor(
    message: string,
    public readonly code: GeofenceErrorCode,
    public readonly location?: LocationData
  ) {
    super(message);
    this.name = 'GeofenceError';
  }
}

/**
 * Error Codes
 */
export enum GeofenceErrorCode {
  LOCATION_REQUIRED = 'LOCATION_REQUIRED',
  LOCATION_EXPIRED = 'LOCATION_EXPIRED',
  LOCATION_OUTSIDE_BOUNDS = 'LOCATION_OUTSIDE_BOUNDS',
  IP_NOT_ALLOWED = 'IP_NOT_ALLOWED',
  COUNTRY_NOT_ALLOWED = 'COUNTRY_NOT_ALLOWED',
  POLICY_DENIED = 'POLICY_DENIED',
  INVALID_COORDINATES = 'INVALID_COORDINATES',
  REGION_NOT_FOUND = 'REGION_NOT_FOUND',
  ZONE_NOT_FOUND = 'ZONE_NOT_FOUND',
}

/**
 * Earth radius in kilometers
 */
const EARTH_RADIUS_KM = 6371;

/**
 * Geofence Manager
 * Manages location-based access control
 */
export class GeofenceManager {
  private regions: Map<string, GeoRegion> = new Map();
  private zones: Map<string, GeoZone> = new Map();
  private countries: Map<string, CountryRegion> = new Map();
  private ipRanges: Map<string, IPRange> = new Map();
  private policies: Map<string, GeofencePolicy> = new Map();
  private auditLog: GeofenceAuditEntry[] = [];
  private lastAuditHash = '0'.repeat(64);

  /**
   * Add a circular geographic region
   */
  addRegion(region: GeoRegion): void {
    this.validateCoordinate(region.center);
    if (region.radiusKm <= 0) {
      throw new GeofenceError(
        'Radius must be positive',
        GeofenceErrorCode.INVALID_COORDINATES
      );
    }
    this.regions.set(region.id, region);
  }

  /**
   * Add a polygon geographic zone
   */
  addZone(zone: GeoZone): void {
    if (zone.vertices.length < 3) {
      throw new GeofenceError(
        'Zone must have at least 3 vertices',
        GeofenceErrorCode.INVALID_COORDINATES
      );
    }
    for (const vertex of zone.vertices) {
      this.validateCoordinate(vertex);
    }
    this.zones.set(zone.id, zone);
  }

  /**
   * Add a country-based region
   */
  addCountryRegion(country: CountryRegion): void {
    this.countries.set(country.id, country);
  }

  /**
   * Add an IP range
   */
  addIPRange(ipRange: IPRange): void {
    // Validate CIDR notation
    if (!this.isValidCIDR(ipRange.cidr)) {
      throw new GeofenceError(
        'Invalid CIDR notation',
        GeofenceErrorCode.INVALID_COORDINATES
      );
    }
    this.ipRanges.set(ipRange.id, ipRange);
  }

  /**
   * Create a geofence policy
   */
  createPolicy(policy: GeofencePolicy): void {
    // Sort rules by priority
    policy.rules.sort((a, b) => a.priority - b.priority);
    this.policies.set(policy.id, policy);
  }

  /**
   * Evaluate location against a policy
   */
  evaluatePolicy(
    policyId: string,
    location: LocationData,
    operation?: string
  ): GeofenceEvaluationResult {
    const policy = this.policies.get(policyId);

    if (!policy) {
      return {
        allowed: false,
        action: 'deny',
        matchedRules: [],
        location,
        reasons: ['Policy not found'],
        timestamp: new Date(),
      };
    }

    if (!policy.enabled) {
      return {
        allowed: true,
        action: 'allow',
        matchedRules: [],
        location,
        reasons: ['Policy disabled'],
        timestamp: new Date(),
      };
    }

    // Check location age
    if (policy.maxLocationAge > 0) {
      const age = (Date.now() - location.timestamp.getTime()) / 1000;
      if (age > policy.maxLocationAge) {
        return {
          allowed: false,
          action: 'deny',
          matchedRules: [],
          location,
          reasons: [`Location data expired (${Math.round(age)}s > ${policy.maxLocationAge}s)`],
          timestamp: new Date(),
        };
      }
    }

    // Evaluate rules in priority order
    const matchedRules: string[] = [];
    const reasons: string[] = [];

    for (const rule of policy.rules) {
      if (!rule.enabled) continue;

      // Check if rule applies to this operation
      if (operation && rule.operations && rule.operations.length > 0) {
        if (!rule.operations.includes(operation)) continue;
      }

      // Check if location matches any rule criteria
      const matches = this.checkRuleMatch(rule, location);

      if (matches.matched) {
        matchedRules.push(rule.id);
        reasons.push(...matches.reasons);

        // Return immediately based on rule action
        const allowed = rule.action === 'allow';
        return {
          allowed,
          action: rule.action,
          matchedRules,
          location,
          reasons,
          timestamp: new Date(),
        };
      }
    }

    // No rules matched, use default action
    const allowed = policy.defaultAction === 'allow';
    return {
      allowed,
      action: policy.defaultAction,
      matchedRules: [],
      location,
      reasons: ['No matching rules, using default action'],
      timestamp: new Date(),
    };
  }

  /**
   * Verify location against all applicable regions/zones
   */
  verifyLocation(location: LocationData): LocationVerificationResult {
    const result: LocationVerificationResult = {
      verified: false,
      location,
      matchedRegions: [],
      matchedZones: [],
      matchedCountries: [],
      matchedIpRanges: [],
      errors: [],
    };

    // Check coordinate-based regions
    if (location.coordinate) {
      // Check circular regions
      for (const [id, region] of this.regions) {
        if (this.isPointInRegion(location.coordinate, region)) {
          result.matchedRegions.push(id);
        }
      }

      // Check polygon zones
      for (const [id, zone] of this.zones) {
        if (this.isPointInZone(location.coordinate, zone)) {
          result.matchedZones.push(id);
        }
      }
    }

    // Check country
    if (location.countryCode) {
      for (const [id, country] of this.countries) {
        if (this.isInCountryRegion(location, country)) {
          result.matchedCountries.push(id);
        }
      }
    }

    // Check IP ranges
    if (location.ipAddress) {
      for (const [id, ipRange] of this.ipRanges) {
        if (this.isIPInRange(location.ipAddress, ipRange.cidr)) {
          result.matchedIpRanges.push(id);
        }
      }
    }

    result.verified =
      result.matchedRegions.length > 0 ||
      result.matchedZones.length > 0 ||
      result.matchedCountries.length > 0 ||
      result.matchedIpRanges.length > 0;

    return result;
  }

  /**
   * Calculate distance between two coordinates (Haversine formula)
   */
  calculateDistance(coord1: GeoCoordinate, coord2: GeoCoordinate): number {
    const lat1Rad = this.toRadians(coord1.latitude);
    const lat2Rad = this.toRadians(coord2.latitude);
    const deltaLat = this.toRadians(coord2.latitude - coord1.latitude);
    const deltaLon = this.toRadians(coord2.longitude - coord1.longitude);

    const a =
      Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
      Math.cos(lat1Rad) * Math.cos(lat2Rad) * Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return EARTH_RADIUS_KM * c;
  }

  /**
   * Check if a point is within a circular region
   */
  isPointInRegion(point: GeoCoordinate, region: GeoRegion): boolean {
    const distance = this.calculateDistance(point, region.center);
    return distance <= region.radiusKm;
  }

  /**
   * Check if a point is within a polygon zone (ray casting algorithm)
   */
  isPointInZone(point: GeoCoordinate, zone: GeoZone): boolean {
    const vertices = zone.vertices;
    const n = vertices.length;
    let inside = false;

    for (let i = 0, j = n - 1; i < n; j = i++) {
      const xi = vertices[i].longitude;
      const yi = vertices[i].latitude;
      const xj = vertices[j].longitude;
      const yj = vertices[j].latitude;

      if (
        yi > point.latitude !== yj > point.latitude &&
        point.longitude < ((xj - xi) * (point.latitude - yi)) / (yj - yi) + xi
      ) {
        inside = !inside;
      }
    }

    return inside;
  }

  /**
   * Check if location is in a country region
   */
  isInCountryRegion(location: LocationData, country: CountryRegion): boolean {
    if (!location.countryCode) return false;

    // Check if country code matches
    if (!country.countryCodes.includes(location.countryCode.toUpperCase())) {
      return false;
    }

    // Check subdivision exclusions
    if (
      country.excludeSubdivisions &&
      location.subdivisionCode &&
      country.excludeSubdivisions.includes(location.subdivisionCode)
    ) {
      return false;
    }

    // Check subdivision inclusions
    if (country.includeSubdivisions && country.includeSubdivisions.length > 0) {
      if (!location.subdivisionCode) return false;
      if (!country.includeSubdivisions.includes(location.subdivisionCode)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Check if IP is in CIDR range
   */
  isIPInRange(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);

    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);

    if (ipNum === null || rangeNum === null) return false;

    const maskNum = (-1 << (32 - mask)) >>> 0;
    return (ipNum & maskNum) === (rangeNum & maskNum);
  }

  /**
   * Record geofence evaluation in audit log
   */
  recordAudit(
    userId: string,
    operation: string,
    location: LocationData,
    result: GeofenceEvaluationResult
  ): GeofenceAuditEntry {
    const entry: GeofenceAuditEntry = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      userId,
      operation,
      location,
      result,
      timestamp: new Date(),
      hash: '',
      previousHash: this.lastAuditHash,
    };

    // Calculate hash
    const dataToHash = JSON.stringify({
      ...entry,
      hash: undefined,
    });
    entry.hash = bytesToHex(sha256(new TextEncoder().encode(dataToHash)));

    this.auditLog.push(entry);
    this.lastAuditHash = entry.hash;

    return entry;
  }

  /**
   * Get audit log entries
   */
  getAuditLog(
    filters?: {
      userId?: string;
      startDate?: Date;
      endDate?: Date;
      operation?: string;
    },
    limit = 100
  ): GeofenceAuditEntry[] {
    let entries = [...this.auditLog];

    if (filters) {
      if (filters.userId) {
        entries = entries.filter(e => e.userId === filters.userId);
      }
      if (filters.startDate) {
        entries = entries.filter(e => e.timestamp >= filters.startDate!);
      }
      if (filters.endDate) {
        entries = entries.filter(e => e.timestamp <= filters.endDate!);
      }
      if (filters.operation) {
        entries = entries.filter(e => e.operation === filters.operation);
      }
    }

    return entries.slice(-limit);
  }

  /**
   * Verify audit log integrity
   */
  verifyAuditLogIntegrity(): { valid: boolean; invalidEntries: string[] } {
    const invalidEntries: string[] = [];
    let previousHash = '0'.repeat(64);

    for (const entry of this.auditLog) {
      // Verify previous hash chain
      if (entry.previousHash !== previousHash) {
        invalidEntries.push(entry.id);
        continue;
      }

      // Verify entry hash
      const dataToHash = JSON.stringify({
        ...entry,
        hash: undefined,
      });
      const expectedHash = bytesToHex(sha256(new TextEncoder().encode(dataToHash)));

      if (entry.hash !== expectedHash) {
        invalidEntries.push(entry.id);
      }

      previousHash = entry.hash;
    }

    return {
      valid: invalidEntries.length === 0,
      invalidEntries,
    };
  }

  /**
   * Get region by ID
   */
  getRegion(id: string): GeoRegion | undefined {
    return this.regions.get(id);
  }

  /**
   * Get zone by ID
   */
  getZone(id: string): GeoZone | undefined {
    return this.zones.get(id);
  }

  /**
   * Get country region by ID
   */
  getCountryRegion(id: string): CountryRegion | undefined {
    return this.countries.get(id);
  }

  /**
   * Get IP range by ID
   */
  getIPRange(id: string): IPRange | undefined {
    return this.ipRanges.get(id);
  }

  /**
   * Get policy by ID
   */
  getPolicy(id: string): GeofencePolicy | undefined {
    return this.policies.get(id);
  }

  /**
   * Remove a region
   */
  removeRegion(id: string): boolean {
    return this.regions.delete(id);
  }

  /**
   * Remove a zone
   */
  removeZone(id: string): boolean {
    return this.zones.delete(id);
  }

  /**
   * Remove a country region
   */
  removeCountryRegion(id: string): boolean {
    return this.countries.delete(id);
  }

  /**
   * Remove an IP range
   */
  removeIPRange(id: string): boolean {
    return this.ipRanges.delete(id);
  }

  /**
   * Remove a policy
   */
  removePolicy(id: string): boolean {
    return this.policies.delete(id);
  }

  /**
   * List all regions
   */
  listRegions(): GeoRegion[] {
    return Array.from(this.regions.values());
  }

  /**
   * List all zones
   */
  listZones(): GeoZone[] {
    return Array.from(this.zones.values());
  }

  /**
   * List all country regions
   */
  listCountryRegions(): CountryRegion[] {
    return Array.from(this.countries.values());
  }

  /**
   * List all IP ranges
   */
  listIPRanges(): IPRange[] {
    return Array.from(this.ipRanges.values());
  }

  /**
   * List all policies
   */
  listPolicies(): GeofencePolicy[] {
    return Array.from(this.policies.values());
  }

  // Private helper methods

  private checkRuleMatch(
    rule: GeofenceRule,
    location: LocationData
  ): { matched: boolean; reasons: string[] } {
    const reasons: string[] = [];
    let hasAnyCriteria = false;
    let anyMatch = false;

    // Check regions
    if (rule.regions && rule.regions.length > 0) {
      hasAnyCriteria = true;
      if (location.coordinate) {
        for (const regionId of rule.regions) {
          const region = this.regions.get(regionId);
          if (region && this.isPointInRegion(location.coordinate, region)) {
            anyMatch = true;
            reasons.push(`Location in region: ${region.name}`);
          }
        }
      }
    }

    // Check zones
    if (rule.zones && rule.zones.length > 0) {
      hasAnyCriteria = true;
      if (location.coordinate) {
        for (const zoneId of rule.zones) {
          const zone = this.zones.get(zoneId);
          if (zone && this.isPointInZone(location.coordinate, zone)) {
            anyMatch = true;
            reasons.push(`Location in zone: ${zone.name}`);
          }
        }
      }
    }

    // Check countries
    if (rule.countries && rule.countries.length > 0) {
      hasAnyCriteria = true;
      for (const countryId of rule.countries) {
        const country = this.countries.get(countryId);
        if (country && this.isInCountryRegion(location, country)) {
          anyMatch = true;
          reasons.push(`Location in country region: ${country.name}`);
        }
      }
    }

    // Check IP ranges
    if (rule.ipRanges && rule.ipRanges.length > 0) {
      hasAnyCriteria = true;
      if (location.ipAddress) {
        for (const rangeId of rule.ipRanges) {
          const ipRange = this.ipRanges.get(rangeId);
          if (ipRange && this.isIPInRange(location.ipAddress, ipRange.cidr)) {
            anyMatch = true;
            reasons.push(`IP in range: ${ipRange.name}`);
          }
        }
      }
    }

    // If no criteria specified, rule matches everything
    if (!hasAnyCriteria) {
      return { matched: true, reasons: ['Rule matches all locations'] };
    }

    return { matched: anyMatch, reasons };
  }

  private validateCoordinate(coord: GeoCoordinate): void {
    if (coord.latitude < -90 || coord.latitude > 90) {
      throw new GeofenceError(
        'Latitude must be between -90 and 90',
        GeofenceErrorCode.INVALID_COORDINATES
      );
    }
    if (coord.longitude < -180 || coord.longitude > 180) {
      throw new GeofenceError(
        'Longitude must be between -180 and 180',
        GeofenceErrorCode.INVALID_COORDINATES
      );
    }
  }

  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;

    let num = 0;
    for (const part of parts) {
      const octet = parseInt(part, 10);
      if (isNaN(octet) || octet < 0 || octet > 255) return null;
      num = (num << 8) + octet;
    }

    return num >>> 0;
  }

  private isValidCIDR(cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return false;

    const ip = parts[0];
    const bits = parseInt(parts[1], 10);

    if (isNaN(bits) || bits < 0 || bits > 32) return false;
    if (this.ipToNumber(ip) === null) return false;

    return true;
  }
}
