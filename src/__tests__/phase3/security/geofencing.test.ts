/**
 * Geofencing Tests
 *
 * Tests for location-based access control
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  GeofenceManager,
  GeofenceError,
  GeofenceErrorCode,
  GeoRegion,
  GeoZone,
  CountryRegion,
  IPRange,
  GeofencePolicy,
  LocationData,
} from '../../../security/geofencing.js';

describe('GeofenceManager', () => {
  let manager: GeofenceManager;

  beforeEach(() => {
    manager = new GeofenceManager();
  });

  describe('Geographic Regions (Circular)', () => {
    it('should add a circular region', () => {
      const region: GeoRegion = {
        id: 'hq',
        name: 'Headquarters',
        center: { latitude: 37.7749, longitude: -122.4194 }, // San Francisco
        radiusKm: 10,
      };

      manager.addRegion(region);
      expect(manager.getRegion('hq')).toEqual(region);
    });

    it('should reject invalid coordinates', () => {
      const region: GeoRegion = {
        id: 'invalid',
        name: 'Invalid',
        center: { latitude: 91, longitude: -122.4194 }, // Invalid latitude
        radiusKm: 10,
      };

      expect(() => manager.addRegion(region)).toThrow(GeofenceError);
    });

    it('should reject negative radius', () => {
      const region: GeoRegion = {
        id: 'invalid',
        name: 'Invalid',
        center: { latitude: 37.7749, longitude: -122.4194 },
        radiusKm: -10,
      };

      expect(() => manager.addRegion(region)).toThrow(GeofenceError);
    });

    it('should detect point inside circular region', () => {
      const region: GeoRegion = {
        id: 'sf',
        name: 'San Francisco',
        center: { latitude: 37.7749, longitude: -122.4194 },
        radiusKm: 20,
      };

      manager.addRegion(region);

      // Point within radius
      const inside = manager.isPointInRegion(
        { latitude: 37.78, longitude: -122.42 },
        region
      );
      expect(inside).toBe(true);

      // Point outside radius (Los Angeles)
      const outside = manager.isPointInRegion(
        { latitude: 34.0522, longitude: -118.2437 },
        region
      );
      expect(outside).toBe(false);
    });

    it('should calculate distance correctly', () => {
      // San Francisco to Los Angeles (~559 km)
      const sf = { latitude: 37.7749, longitude: -122.4194 };
      const la = { latitude: 34.0522, longitude: -118.2437 };

      const distance = manager.calculateDistance(sf, la);
      expect(distance).toBeGreaterThan(550);
      expect(distance).toBeLessThan(570);
    });
  });

  describe('Geographic Zones (Polygon)', () => {
    it('should add a polygon zone', () => {
      const zone: GeoZone = {
        id: 'office-park',
        name: 'Office Park',
        vertices: [
          { latitude: 37.78, longitude: -122.42 },
          { latitude: 37.78, longitude: -122.40 },
          { latitude: 37.76, longitude: -122.40 },
          { latitude: 37.76, longitude: -122.42 },
        ],
      };

      manager.addZone(zone);
      expect(manager.getZone('office-park')).toEqual(zone);
    });

    it('should reject zone with fewer than 3 vertices', () => {
      const zone: GeoZone = {
        id: 'invalid',
        name: 'Invalid',
        vertices: [
          { latitude: 37.78, longitude: -122.42 },
          { latitude: 37.78, longitude: -122.40 },
        ],
      };

      expect(() => manager.addZone(zone)).toThrow(GeofenceError);
    });

    it('should detect point inside polygon zone', () => {
      const zone: GeoZone = {
        id: 'square',
        name: 'Square Zone',
        vertices: [
          { latitude: 38, longitude: -123 },
          { latitude: 38, longitude: -121 },
          { latitude: 36, longitude: -121 },
          { latitude: 36, longitude: -123 },
        ],
      };

      manager.addZone(zone);

      // Point inside
      const inside = manager.isPointInZone({ latitude: 37, longitude: -122 }, zone);
      expect(inside).toBe(true);

      // Point outside
      const outside = manager.isPointInZone({ latitude: 35, longitude: -122 }, zone);
      expect(outside).toBe(false);
    });

    it('should handle complex polygon shapes', () => {
      // L-shaped zone
      const zone: GeoZone = {
        id: 'l-shape',
        name: 'L-Shaped Zone',
        vertices: [
          { latitude: 40, longitude: -74 },
          { latitude: 40, longitude: -73 },
          { latitude: 39.5, longitude: -73 },
          { latitude: 39.5, longitude: -73.5 },
          { latitude: 39, longitude: -73.5 },
          { latitude: 39, longitude: -74 },
        ],
      };

      manager.addZone(zone);

      // Point in upper part of L
      expect(manager.isPointInZone({ latitude: 39.8, longitude: -73.5 }, zone)).toBe(true);

      // Point in lower part of L
      expect(manager.isPointInZone({ latitude: 39.2, longitude: -73.8 }, zone)).toBe(true);

      // Point in the cut-out
      expect(manager.isPointInZone({ latitude: 39.3, longitude: -73.2 }, zone)).toBe(false);
    });
  });

  describe('Country Regions', () => {
    it('should add a country region', () => {
      const country: CountryRegion = {
        id: 'usa',
        name: 'United States',
        countryCodes: ['US'],
      };

      manager.addCountryRegion(country);
      expect(manager.getCountryRegion('usa')).toEqual(country);
    });

    it('should detect location in country', () => {
      const country: CountryRegion = {
        id: 'usa',
        name: 'United States',
        countryCodes: ['US'],
      };

      manager.addCountryRegion(country);

      const location: LocationData = {
        countryCode: 'US',
        source: 'ip',
        timestamp: new Date(),
      };

      expect(manager.isInCountryRegion(location, country)).toBe(true);
    });

    it('should handle subdivision inclusions', () => {
      const country: CountryRegion = {
        id: 'usa-west',
        name: 'US West Coast',
        countryCodes: ['US'],
        includeSubdivisions: ['CA', 'OR', 'WA'],
      };

      manager.addCountryRegion(country);

      const california: LocationData = {
        countryCode: 'US',
        subdivisionCode: 'CA',
        source: 'ip',
        timestamp: new Date(),
      };

      const texas: LocationData = {
        countryCode: 'US',
        subdivisionCode: 'TX',
        source: 'ip',
        timestamp: new Date(),
      };

      expect(manager.isInCountryRegion(california, country)).toBe(true);
      expect(manager.isInCountryRegion(texas, country)).toBe(false);
    });

    it('should handle subdivision exclusions', () => {
      const country: CountryRegion = {
        id: 'usa-no-ny',
        name: 'US except NY',
        countryCodes: ['US'],
        excludeSubdivisions: ['NY'],
      };

      manager.addCountryRegion(country);

      const newYork: LocationData = {
        countryCode: 'US',
        subdivisionCode: 'NY',
        source: 'ip',
        timestamp: new Date(),
      };

      const california: LocationData = {
        countryCode: 'US',
        subdivisionCode: 'CA',
        source: 'ip',
        timestamp: new Date(),
      };

      expect(manager.isInCountryRegion(newYork, country)).toBe(false);
      expect(manager.isInCountryRegion(california, country)).toBe(true);
    });

    it('should support multiple country codes', () => {
      const region: CountryRegion = {
        id: 'eu',
        name: 'European Union',
        countryCodes: ['DE', 'FR', 'IT', 'ES', 'NL'],
      };

      manager.addCountryRegion(region);

      const germany: LocationData = {
        countryCode: 'DE',
        source: 'ip',
        timestamp: new Date(),
      };

      const japan: LocationData = {
        countryCode: 'JP',
        source: 'ip',
        timestamp: new Date(),
      };

      expect(manager.isInCountryRegion(germany, region)).toBe(true);
      expect(manager.isInCountryRegion(japan, region)).toBe(false);
    });
  });

  describe('IP Ranges', () => {
    it('should add an IP range', () => {
      const ipRange: IPRange = {
        id: 'office',
        name: 'Office Network',
        cidr: '192.168.1.0/24',
      };

      manager.addIPRange(ipRange);
      expect(manager.getIPRange('office')).toEqual(ipRange);
    });

    it('should reject invalid CIDR', () => {
      expect(() =>
        manager.addIPRange({
          id: 'invalid',
          name: 'Invalid',
          cidr: 'not-a-cidr',
        })
      ).toThrow(GeofenceError);
    });

    it('should detect IP in range', () => {
      expect(manager.isIPInRange('192.168.1.100', '192.168.1.0/24')).toBe(true);
      expect(manager.isIPInRange('192.168.2.100', '192.168.1.0/24')).toBe(false);
    });

    it('should handle /32 (single IP)', () => {
      expect(manager.isIPInRange('10.0.0.1', '10.0.0.1/32')).toBe(true);
      expect(manager.isIPInRange('10.0.0.2', '10.0.0.1/32')).toBe(false);
    });

    it('should handle /16 range', () => {
      expect(manager.isIPInRange('172.16.0.1', '172.16.0.0/16')).toBe(true);
      expect(manager.isIPInRange('172.16.255.255', '172.16.0.0/16')).toBe(true);
      expect(manager.isIPInRange('172.17.0.1', '172.16.0.0/16')).toBe(false);
    });

    it('should handle /8 range', () => {
      expect(manager.isIPInRange('10.1.2.3', '10.0.0.0/8')).toBe(true);
      expect(manager.isIPInRange('10.255.255.255', '10.0.0.0/8')).toBe(true);
      expect(manager.isIPInRange('11.0.0.1', '10.0.0.0/8')).toBe(false);
    });
  });

  describe('Policy Evaluation', () => {
    beforeEach(() => {
      // Set up test data
      manager.addRegion({
        id: 'hq',
        name: 'Headquarters',
        center: { latitude: 37.7749, longitude: -122.4194 },
        radiusKm: 10,
      });

      manager.addCountryRegion({
        id: 'usa',
        name: 'United States',
        countryCodes: ['US'],
      });

      manager.addIPRange({
        id: 'vpn',
        name: 'VPN Network',
        cidr: '10.0.0.0/8',
      });
    });

    it('should allow access with matching allow rule', () => {
      const policy: GeofencePolicy = {
        id: 'office-policy',
        name: 'Office Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-hq',
            name: 'Allow HQ',
            priority: 1,
            action: 'allow',
            regions: ['hq'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        coordinate: { latitude: 37.78, longitude: -122.42 },
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('office-policy', location);

      expect(result.allowed).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.matchedRules).toContain('allow-hq');
    });

    it('should deny access with matching deny rule', () => {
      const policy: GeofencePolicy = {
        id: 'restricted-policy',
        name: 'Restricted Policy',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-external',
            name: 'Deny External',
            priority: 1,
            action: 'deny',
            countries: ['usa'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        countryCode: 'US',
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('restricted-policy', location);

      expect(result.allowed).toBe(false);
      expect(result.action).toBe('deny');
    });

    it('should use default action when no rules match', () => {
      const policy: GeofencePolicy = {
        id: 'default-allow',
        name: 'Default Allow',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-hq',
            name: 'Deny HQ',
            priority: 1,
            action: 'deny',
            regions: ['hq'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        coordinate: { latitude: 34.0522, longitude: -118.2437 }, // LA, outside HQ
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('default-allow', location);

      expect(result.allowed).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.matchedRules).toHaveLength(0);
    });

    it('should respect rule priority', () => {
      const policy: GeofencePolicy = {
        id: 'priority-policy',
        name: 'Priority Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'deny-usa',
            name: 'Deny USA',
            priority: 10, // Lower priority
            action: 'deny',
            countries: ['usa'],
            enabled: true,
          },
          {
            id: 'allow-vpn',
            name: 'Allow VPN',
            priority: 1, // Higher priority
            action: 'allow',
            ipRanges: ['vpn'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        countryCode: 'US',
        ipAddress: '10.0.0.100',
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('priority-policy', location);

      expect(result.allowed).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.matchedRules).toContain('allow-vpn');
    });

    it('should reject expired location data', () => {
      const policy: GeofencePolicy = {
        id: 'fresh-location',
        name: 'Fresh Location Required',
        defaultAction: 'allow',
        rules: [],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 60, // 60 seconds
      };

      manager.createPolicy(policy);

      const oldLocation: LocationData = {
        coordinate: { latitude: 37.78, longitude: -122.42 },
        source: 'gps',
        timestamp: new Date(Date.now() - 120000), // 2 minutes ago
      };

      const result = manager.evaluatePolicy('fresh-location', oldLocation);

      expect(result.allowed).toBe(false);
      expect(result.reasons[0]).toContain('expired');
    });

    it('should skip disabled rules', () => {
      const policy: GeofencePolicy = {
        id: 'disabled-rule',
        name: 'Disabled Rule Test',
        defaultAction: 'allow',
        rules: [
          {
            id: 'disabled-deny',
            name: 'Disabled Deny',
            priority: 1,
            action: 'deny',
            regions: ['hq'],
            enabled: false, // Disabled
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        coordinate: { latitude: 37.78, longitude: -122.42 },
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('disabled-rule', location);

      expect(result.allowed).toBe(true);
    });

    it('should filter rules by operation', () => {
      const policy: GeofencePolicy = {
        id: 'operation-policy',
        name: 'Operation Policy',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-sign',
            name: 'Deny Sign Outside HQ',
            priority: 1,
            action: 'deny',
            operations: ['sign'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      // Signing should be denied
      const signResult = manager.evaluatePolicy('operation-policy', location, 'sign');
      expect(signResult.allowed).toBe(false);

      // Verify should be allowed (rule doesn't apply)
      const verifyResult = manager.evaluatePolicy('operation-policy', location, 'verify');
      expect(verifyResult.allowed).toBe(true);
    });

    it('should allow when policy is disabled', () => {
      const policy: GeofencePolicy = {
        id: 'disabled-policy',
        name: 'Disabled Policy',
        defaultAction: 'deny',
        rules: [],
        enabled: false, // Disabled
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('disabled-policy', location);

      expect(result.allowed).toBe(true);
      expect(result.reasons).toContain('Policy disabled');
    });

    it('should return error for non-existent policy', () => {
      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('non-existent', location);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('Policy not found');
    });
  });

  describe('Location Verification', () => {
    beforeEach(() => {
      manager.addRegion({
        id: 'hq',
        name: 'HQ',
        center: { latitude: 37.7749, longitude: -122.4194 },
        radiusKm: 10,
      });

      manager.addZone({
        id: 'office',
        name: 'Office',
        vertices: [
          { latitude: 38, longitude: -123 },
          { latitude: 38, longitude: -121 },
          { latitude: 36, longitude: -121 },
          { latitude: 36, longitude: -123 },
        ],
      });

      manager.addCountryRegion({
        id: 'usa',
        name: 'USA',
        countryCodes: ['US'],
      });

      manager.addIPRange({
        id: 'office-net',
        name: 'Office Network',
        cidr: '192.168.1.0/24',
      });
    });

    it('should verify location against all criteria', () => {
      const location: LocationData = {
        coordinate: { latitude: 37.78, longitude: -122.42 },
        countryCode: 'US',
        ipAddress: '192.168.1.100',
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.verifyLocation(location);

      expect(result.verified).toBe(true);
      expect(result.matchedRegions).toContain('hq');
      expect(result.matchedZones).toContain('office');
      expect(result.matchedCountries).toContain('usa');
      expect(result.matchedIpRanges).toContain('office-net');
    });

    it('should not verify location outside all criteria', () => {
      const location: LocationData = {
        coordinate: { latitude: 0, longitude: 0 }, // Middle of Atlantic
        countryCode: 'JP',
        ipAddress: '8.8.8.8', // Google DNS
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.verifyLocation(location);

      expect(result.verified).toBe(false);
      expect(result.matchedRegions).toHaveLength(0);
      expect(result.matchedZones).toHaveLength(0);
      expect(result.matchedCountries).toHaveLength(0);
      expect(result.matchedIpRanges).toHaveLength(0);
    });
  });

  describe('Audit Logging', () => {
    it('should record audit entries', () => {
      const location: LocationData = {
        coordinate: { latitude: 37.78, longitude: -122.42 },
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('test', location);
      const entry = manager.recordAudit('user-123', 'sign', location, result);

      expect(entry.userId).toBe('user-123');
      expect(entry.operation).toBe('sign');
      expect(entry.hash).toBeDefined();
      expect(entry.hash.length).toBe(64);
    });

    it('should maintain hash chain', () => {
      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('test', location);

      const entry1 = manager.recordAudit('user-1', 'sign', location, result);
      const entry2 = manager.recordAudit('user-2', 'sign', location, result);

      expect(entry2.previousHash).toBe(entry1.hash);
    });

    it('should filter audit log', () => {
      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('test', location);

      manager.recordAudit('user-1', 'sign', location, result);
      manager.recordAudit('user-1', 'verify', location, result);
      manager.recordAudit('user-2', 'sign', location, result);

      const user1Entries = manager.getAuditLog({ userId: 'user-1' });
      expect(user1Entries).toHaveLength(2);

      const signEntries = manager.getAuditLog({ operation: 'sign' });
      expect(signEntries).toHaveLength(2);
    });

    it('should verify audit log integrity', () => {
      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('test', location);

      manager.recordAudit('user-1', 'sign', location, result);
      manager.recordAudit('user-2', 'verify', location, result);
      manager.recordAudit('user-3', 'decrypt', location, result);

      const integrity = manager.verifyAuditLogIntegrity();
      expect(integrity.valid).toBe(true);
      expect(integrity.invalidEntries).toHaveLength(0);
    });
  });

  describe('Resource Management', () => {
    it('should list all regions', () => {
      manager.addRegion({ id: 'r1', name: 'R1', center: { latitude: 0, longitude: 0 }, radiusKm: 1 });
      manager.addRegion({ id: 'r2', name: 'R2', center: { latitude: 1, longitude: 1 }, radiusKm: 1 });

      const regions = manager.listRegions();
      expect(regions).toHaveLength(2);
    });

    it('should list all zones', () => {
      const vertices = [
        { latitude: 0, longitude: 0 },
        { latitude: 1, longitude: 0 },
        { latitude: 0, longitude: 1 },
      ];

      manager.addZone({ id: 'z1', name: 'Z1', vertices });
      manager.addZone({ id: 'z2', name: 'Z2', vertices });

      const zones = manager.listZones();
      expect(zones).toHaveLength(2);
    });

    it('should remove resources', () => {
      manager.addRegion({ id: 'r1', name: 'R1', center: { latitude: 0, longitude: 0 }, radiusKm: 1 });
      expect(manager.getRegion('r1')).toBeDefined();

      manager.removeRegion('r1');
      expect(manager.getRegion('r1')).toBeUndefined();
    });
  });

  describe('MFA Required Action', () => {
    it('should return mfa_required action', () => {
      manager.addRegion({
        id: 'remote',
        name: 'Remote',
        center: { latitude: 0, longitude: 0 },
        radiusKm: 1000,
      });

      const policy: GeofencePolicy = {
        id: 'mfa-policy',
        name: 'MFA Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'mfa-remote',
            name: 'MFA for Remote',
            priority: 1,
            action: 'mfa_required',
            regions: ['remote'],
            enabled: true,
          },
        ],
        enabled: true,
        requireLocationProof: false,
        maxLocationAge: 300,
      };

      manager.createPolicy(policy);

      const location: LocationData = {
        coordinate: { latitude: 0, longitude: 0 },
        source: 'gps',
        timestamp: new Date(),
      };

      const result = manager.evaluatePolicy('mfa-policy', location);

      expect(result.allowed).toBe(false);
      expect(result.action).toBe('mfa_required');
    });
  });

  describe('Error Codes', () => {
    it('should have correct error codes', () => {
      expect(GeofenceErrorCode.LOCATION_REQUIRED).toBe('LOCATION_REQUIRED');
      expect(GeofenceErrorCode.LOCATION_EXPIRED).toBe('LOCATION_EXPIRED');
      expect(GeofenceErrorCode.LOCATION_OUTSIDE_BOUNDS).toBe('LOCATION_OUTSIDE_BOUNDS');
      expect(GeofenceErrorCode.IP_NOT_ALLOWED).toBe('IP_NOT_ALLOWED');
      expect(GeofenceErrorCode.COUNTRY_NOT_ALLOWED).toBe('COUNTRY_NOT_ALLOWED');
      expect(GeofenceErrorCode.POLICY_DENIED).toBe('POLICY_DENIED');
      expect(GeofenceErrorCode.INVALID_COORDINATES).toBe('INVALID_COORDINATES');
      expect(GeofenceErrorCode.REGION_NOT_FOUND).toBe('REGION_NOT_FOUND');
      expect(GeofenceErrorCode.ZONE_NOT_FOUND).toBe('ZONE_NOT_FOUND');
    });

    it('should create GeofenceError with properties', () => {
      const location: LocationData = {
        source: 'ip',
        timestamp: new Date(),
      };

      const error = new GeofenceError(
        'Test error',
        GeofenceErrorCode.LOCATION_OUTSIDE_BOUNDS,
        location
      );

      expect(error.message).toBe('Test error');
      expect(error.code).toBe(GeofenceErrorCode.LOCATION_OUTSIDE_BOUNDS);
      expect(error.location).toBe(location);
      expect(error.name).toBe('GeofenceError');
    });
  });
});
