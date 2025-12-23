/**
 * VeilKey Data Residency Controls
 *
 * Implements geographic data residency controls for compliance with
 * data sovereignty requirements (GDPR, CCPA, etc.).
 *
 * @module compliance/data-residency
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  DataRegion,
  DataResidencyPolicy,
  DataLocationRecord,
  DataClassification,
  ComplianceError,
  ComplianceErrorCode,
} from './types.js';

/**
 * Data Transfer Request
 */
export interface DataTransferRequest {
  id: string;
  resourceType: string;
  resourceId: string;
  sourceRegion: string;
  targetRegion: string;
  requestedBy: string;
  requestedAt: Date;
  reason: string;
  status: 'pending' | 'approved' | 'rejected' | 'completed';
  approvedBy?: string;
  approvedAt?: Date;
  completedAt?: Date;
}

/**
 * Residency Validation Result
 */
export interface ResidencyValidationResult {
  valid: boolean;
  violations: ResidencyViolation[];
  region: string;
  classification: DataClassification;
}

/**
 * Residency Violation
 */
export interface ResidencyViolation {
  policyId: string;
  policyName: string;
  message: string;
  severity: 'warning' | 'error';
}

/**
 * Data Residency Manager
 */
export class DataResidencyManager {
  private regions: Map<string, DataRegion> = new Map();
  private policies: Map<string, DataResidencyPolicy> = new Map();
  private locationRecords: Map<string, DataLocationRecord> = new Map();
  private transferRequests: Map<string, DataTransferRequest> = new Map();
  private auditLog: DataResidencyAuditEntry[] = [];
  private lastAuditHash = '0'.repeat(64);

  /**
   * Define a data region
   */
  defineRegion(region: DataRegion): void {
    this.regions.set(region.id, region);
  }

  /**
   * Get region by ID
   */
  getRegion(regionId: string): DataRegion | undefined {
    return this.regions.get(regionId);
  }

  /**
   * Get all regions
   */
  getAllRegions(): DataRegion[] {
    return Array.from(this.regions.values());
  }

  /**
   * Get regions by country code
   */
  getRegionsByCountry(countryCode: string): DataRegion[] {
    return this.getAllRegions().filter(r => r.countryCodes.includes(countryCode.toUpperCase()));
  }

  /**
   * Create a data residency policy
   */
  createPolicy(policy: DataResidencyPolicy): void {
    // Validate allowed regions exist
    for (const regionId of policy.allowedRegions) {
      if (!this.regions.has(regionId)) {
        throw new ComplianceError(
          `Region ${regionId} not found`,
          ComplianceErrorCode.POLICY_VIOLATION
        );
      }
    }

    this.policies.set(policy.id, policy);
  }

  /**
   * Get policy by ID
   */
  getPolicy(policyId: string): DataResidencyPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Get all policies
   */
  getAllPolicies(): DataResidencyPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Record data location
   */
  recordLocation(
    resourceType: string,
    resourceId: string,
    region: string,
    classification: DataClassification
  ): DataLocationRecord {
    const existingRecord = this.getLocationRecord(resourceType, resourceId);

    const record: DataLocationRecord = {
      id: `${resourceType}:${resourceId}`,
      resourceType,
      resourceId,
      region,
      classification,
      createdAt: existingRecord?.createdAt || new Date(),
      movedAt: existingRecord ? new Date() : undefined,
      previousRegion: existingRecord?.region,
    };

    this.locationRecords.set(record.id, record);

    // Audit the location change
    this.recordAudit('location_recorded', record);

    return record;
  }

  /**
   * Get location record
   */
  getLocationRecord(resourceType: string, resourceId: string): DataLocationRecord | undefined {
    return this.locationRecords.get(`${resourceType}:${resourceId}`);
  }

  /**
   * Validate data location against policies
   */
  validateLocation(
    resourceType: string,
    resourceId: string,
    region: string,
    classification: DataClassification
  ): ResidencyValidationResult {
    const violations: ResidencyViolation[] = [];

    // Check each enabled policy
    for (const policy of this.policies.values()) {
      if (!policy.enabled) continue;

      // Check if policy applies to this resource type
      if (!policy.resourceTypes.includes(resourceType) && !policy.resourceTypes.includes('*')) {
        continue;
      }

      // Check if policy applies to this classification
      if (!policy.dataClassifications.includes(classification)) {
        continue;
      }

      // Check if region is allowed
      if (!policy.allowedRegions.includes(region)) {
        violations.push({
          policyId: policy.id,
          policyName: policy.name,
          message: `Region ${region} is not allowed for ${classification} ${resourceType} data`,
          severity: 'error',
        });
      }
    }

    return {
      valid: violations.length === 0,
      violations,
      region,
      classification,
    };
  }

  /**
   * Request data transfer to new region
   */
  requestTransfer(
    resourceType: string,
    resourceId: string,
    targetRegion: string,
    requestedBy: string,
    reason: string
  ): DataTransferRequest {
    const currentLocation = this.getLocationRecord(resourceType, resourceId);

    if (!currentLocation) {
      throw new ComplianceError(
        `No location record for ${resourceType}:${resourceId}`,
        ComplianceErrorCode.DATA_RESIDENCY_VIOLATION
      );
    }

    const request: DataTransferRequest = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      resourceType,
      resourceId,
      sourceRegion: currentLocation.region,
      targetRegion,
      requestedBy,
      requestedAt: new Date(),
      reason,
      status: 'pending',
    };

    // Validate the transfer
    const validation = this.validateLocation(
      resourceType,
      resourceId,
      targetRegion,
      currentLocation.classification
    );

    if (!validation.valid) {
      request.status = 'rejected';
    }

    this.transferRequests.set(request.id, request);
    this.recordAudit('transfer_requested', { request, validation });

    return request;
  }

  /**
   * Approve transfer request
   */
  approveTransfer(requestId: string, approvedBy: string): void {
    const request = this.transferRequests.get(requestId);

    if (!request) {
      throw new ComplianceError(
        `Transfer request ${requestId} not found`,
        ComplianceErrorCode.DATA_RESIDENCY_VIOLATION
      );
    }

    if (request.status !== 'pending') {
      throw new ComplianceError(
        `Transfer request is not pending`,
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    request.status = 'approved';
    request.approvedBy = approvedBy;
    request.approvedAt = new Date();

    this.transferRequests.set(requestId, request);
    this.recordAudit('transfer_approved', { request });
  }

  /**
   * Complete transfer
   */
  completeTransfer(requestId: string): void {
    const request = this.transferRequests.get(requestId);

    if (!request) {
      throw new ComplianceError(
        `Transfer request ${requestId} not found`,
        ComplianceErrorCode.DATA_RESIDENCY_VIOLATION
      );
    }

    if (request.status !== 'approved') {
      throw new ComplianceError(
        `Transfer request is not approved`,
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    // Get current record to preserve classification
    const currentRecord = this.getLocationRecord(request.resourceType, request.resourceId);

    if (!currentRecord) {
      throw new ComplianceError(
        `Location record not found`,
        ComplianceErrorCode.DATA_RESIDENCY_VIOLATION
      );
    }

    // Update location
    this.recordLocation(
      request.resourceType,
      request.resourceId,
      request.targetRegion,
      currentRecord.classification
    );

    request.status = 'completed';
    request.completedAt = new Date();

    this.transferRequests.set(requestId, request);
    this.recordAudit('transfer_completed', { request });
  }

  /**
   * Reject transfer request
   */
  rejectTransfer(requestId: string, rejectedBy: string, reason?: string): void {
    const request = this.transferRequests.get(requestId);

    if (!request) {
      throw new ComplianceError(
        `Transfer request ${requestId} not found`,
        ComplianceErrorCode.DATA_RESIDENCY_VIOLATION
      );
    }

    request.status = 'rejected';
    this.transferRequests.set(requestId, request);
    this.recordAudit('transfer_rejected', { request, rejectedBy, reason });
  }

  /**
   * Get transfer requests
   */
  getTransferRequests(filters?: {
    status?: DataTransferRequest['status'];
    resourceType?: string;
  }): DataTransferRequest[] {
    let requests = Array.from(this.transferRequests.values());

    if (filters) {
      if (filters.status) {
        requests = requests.filter(r => r.status === filters.status);
      }
      if (filters.resourceType) {
        requests = requests.filter(r => r.resourceType === filters.resourceType);
      }
    }

    return requests;
  }

  /**
   * Get data by region
   */
  getDataByRegion(region: string): DataLocationRecord[] {
    return Array.from(this.locationRecords.values()).filter(r => r.region === region);
  }

  /**
   * Get data by classification
   */
  getDataByClassification(classification: DataClassification): DataLocationRecord[] {
    return Array.from(this.locationRecords.values()).filter(r => r.classification === classification);
  }

  /**
   * Check cross-border transfer requirements
   */
  checkCrossBorderRequirements(
    sourceRegion: string,
    targetRegion: string
  ): { allowed: boolean; requirements: string[] } {
    const source = this.regions.get(sourceRegion);
    const target = this.regions.get(targetRegion);

    if (!source || !target) {
      return { allowed: false, requirements: ['Invalid region'] };
    }

    const requirements: string[] = [];

    // Check data protection law requirements
    if (source.dataProtectionLaw === 'GDPR') {
      if (!target.dataProtectionLaw || target.dataProtectionLaw !== 'GDPR') {
        requirements.push('Standard Contractual Clauses (SCCs) required');
        requirements.push('Data Processing Agreement required');
      }
    }

    // Check jurisdiction changes
    if (source.jurisdiction !== target.jurisdiction) {
      requirements.push(`Transfer crosses jurisdictions: ${source.jurisdiction} -> ${target.jurisdiction}`);
    }

    return {
      allowed: true,
      requirements,
    };
  }

  /**
   * Get compliance summary by region
   */
  getRegionalSummary(): Map<string, { total: number; byClassification: Record<DataClassification, number> }> {
    const summary = new Map<string, { total: number; byClassification: Record<DataClassification, number> }>();

    for (const record of this.locationRecords.values()) {
      let regionSummary = summary.get(record.region);

      if (!regionSummary) {
        regionSummary = {
          total: 0,
          byClassification: {
            public: 0,
            internal: 0,
            confidential: 0,
            restricted: 0,
          },
        };
      }

      regionSummary.total++;
      regionSummary.byClassification[record.classification]++;

      summary.set(record.region, regionSummary);
    }

    return summary;
  }

  /**
   * Remove region
   */
  removeRegion(regionId: string): boolean {
    return this.regions.delete(regionId);
  }

  /**
   * Remove policy
   */
  removePolicy(policyId: string): boolean {
    return this.policies.delete(policyId);
  }

  /**
   * Record audit entry
   */
  private recordAudit(action: string, details: unknown): void {
    const entry: DataResidencyAuditEntry = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      action,
      details,
      timestamp: new Date(),
      hash: '',
      previousHash: this.lastAuditHash,
    };

    const hashData = JSON.stringify({ ...entry, hash: undefined });
    entry.hash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

    this.auditLog.push(entry);
    this.lastAuditHash = entry.hash;
  }

  /**
   * Get audit log
   */
  getAuditLog(limit = 100): DataResidencyAuditEntry[] {
    return this.auditLog.slice(-limit);
  }
}

/**
 * Data Residency Audit Entry
 */
interface DataResidencyAuditEntry {
  id: string;
  action: string;
  details: unknown;
  timestamp: Date;
  hash: string;
  previousHash: string;
}
