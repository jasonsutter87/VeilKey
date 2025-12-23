/**
 * Role-Based Access Control (RBAC) for share management
 *
 * Defines roles, permissions, and policy evaluation logic.
 */

import type {
  Role,
  Permission,
  AccessPolicy,
  PolicyCondition,
  ShareHolder,
} from './types.js';

// =============================================================================
// Default Policies
// =============================================================================

/**
 * Default access policies for each role
 */
export const DEFAULT_POLICIES: AccessPolicy[] = [
  {
    role: 'admin',
    permissions: [
      'share:create',
      'share:read',
      'share:use',
      'share:delete',
      'share:assign',
      'holder:create',
      'holder:read',
      'holder:update',
      'holder:delete',
      'audit:read',
      'audit:export',
    ],
  },
  {
    role: 'trustee',
    permissions: [
      'share:read',
      'share:use',
      'holder:read',
    ],
  },
  {
    role: 'auditor',
    permissions: [
      'audit:read',
      'audit:export',
      'holder:read',
    ],
  },
];

// =============================================================================
// Access Control Manager
// =============================================================================

/**
 * Manages access control policies and permission checks
 */
export class AccessControl {
  private policies: Map<Role, AccessPolicy>;

  constructor(policies: AccessPolicy[] = DEFAULT_POLICIES) {
    this.policies = new Map();
    for (const policy of policies) {
      this.policies.set(policy.role, policy);
    }
  }

  /**
   * Check if a role has a specific permission
   *
   * @param role - Role to check
   * @param permission - Permission to verify
   * @returns true if role has permission
   *
   * @example
   * ```typescript
   * const ac = new AccessControl();
   * if (ac.hasPermission('trustee', 'share:read')) {
   *   // Allow access
   * }
   * ```
   */
  hasPermission(role: Role, permission: Permission): boolean {
    const policy = this.policies.get(role);
    if (!policy) {
      return false;
    }
    return policy.permissions.includes(permission);
  }

  /**
   * Check if a holder has a specific permission
   *
   * @param holder - Share holder
   * @param permission - Permission to verify
   * @returns true if holder has permission
   */
  holderHasPermission(holder: ShareHolder, permission: Permission): boolean {
    if (!holder.active) {
      return false;
    }
    return this.hasPermission(holder.role, permission);
  }

  /**
   * Get all permissions for a role
   *
   * @param role - Role to query
   * @returns Array of permissions
   */
  getPermissions(role: Role): Permission[] {
    const policy = this.policies.get(role);
    return policy ? [...policy.permissions] : [];
  }

  /**
   * Add a custom policy
   *
   * @param policy - Policy to add
   */
  addPolicy(policy: AccessPolicy): void {
    this.policies.set(policy.role, policy);
  }

  /**
   * Remove a policy
   *
   * @param role - Role to remove policy for
   */
  removePolicy(role: Role): void {
    this.policies.delete(role);
  }

  /**
   * Check if a holder can access a specific share
   *
   * Checks:
   * 1. Holder is active
   * 2. Holder has share:read permission
   * 3. Holder is assigned to the share (unless admin)
   *
   * @param holder - Share holder
   * @param shareId - Share ID
   * @param assignedShareIds - IDs of shares assigned to this holder
   * @returns true if holder can access the share
   */
  canAccessShare(
    holder: ShareHolder,
    shareId: string,
    assignedShareIds: string[]
  ): boolean {
    // Must be active
    if (!holder.active) {
      return false;
    }

    // Must have read permission
    if (!this.hasPermission(holder.role, 'share:read')) {
      return false;
    }

    // Admins can access any share
    if (holder.role === 'admin') {
      return true;
    }

    // Others can only access assigned shares
    return assignedShareIds.includes(shareId);
  }

  /**
   * Check if a holder can use a share for cryptographic operations
   *
   * @param holder - Share holder
   * @param shareId - Share ID
   * @param assignedShareIds - IDs of shares assigned to this holder
   * @returns true if holder can use the share
   */
  canUseShare(
    holder: ShareHolder,
    shareId: string,
    assignedShareIds: string[]
  ): boolean {
    // Must have use permission
    if (!this.holderHasPermission(holder, 'share:use')) {
      return false;
    }

    // Must be able to access the share
    return this.canAccessShare(holder, shareId, assignedShareIds);
  }

  /**
   * Evaluate policy conditions
   *
   * This is a placeholder for future condition evaluation.
   * Could be extended to support time-based access, IP restrictions, etc.
   *
   * @param conditions - Conditions to evaluate
   * @param context - Context for evaluation
   * @returns true if all conditions are met
   */
  evaluateConditions(
    conditions: PolicyCondition[] | undefined,
    context: Record<string, unknown>
  ): boolean {
    if (!conditions || conditions.length === 0) {
      return true;
    }

    for (const condition of conditions) {
      if (!this.evaluateCondition(condition, context)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluate a single condition
   *
   * @param condition - Condition to evaluate
   * @param context - Context for evaluation
   * @returns true if condition is met
   */
  private evaluateCondition(
    condition: PolicyCondition,
    context: Record<string, unknown>
  ): boolean {
    switch (condition.type) {
      case 'time':
        return this.evaluateTimeCondition(condition.data, context);
      case 'ip':
        return this.evaluateIpCondition(condition.data, context);
      case 'custom':
        return this.evaluateCustomCondition(condition.data, context);
      default:
        return false;
    }
  }

  /**
   * Evaluate time-based condition
   */
  private evaluateTimeCondition(
    data: unknown,
    context: Record<string, unknown>
  ): boolean {
    // Placeholder - could check if current time is within allowed hours
    return true;
  }

  /**
   * Evaluate IP-based condition
   */
  private evaluateIpCondition(
    data: unknown,
    context: Record<string, unknown>
  ): boolean {
    // Placeholder - could check if IP is in allowed list
    return true;
  }

  /**
   * Evaluate custom condition
   */
  private evaluateCustomCondition(
    data: unknown,
    context: Record<string, unknown>
  ): boolean {
    // Placeholder - could support custom condition functions
    return true;
  }
}

// =============================================================================
// Authorization Errors
// =============================================================================

/**
 * Error thrown when access is denied
 */
export class UnauthorizedError extends Error {
  constructor(
    public holder: string,
    public permission: Permission,
    public resource?: string
  ) {
    super(
      `Unauthorized: ${holder} does not have permission '${permission}'${
        resource ? ` for ${resource}` : ''
      }`
    );
    this.name = 'UnauthorizedError';
  }
}

/**
 * Error thrown when a holder is not found
 */
export class HolderNotFoundError extends Error {
  constructor(public holderId: string) {
    super(`Holder not found: ${holderId}`);
    this.name = 'HolderNotFoundError';
  }
}

/**
 * Error thrown when a share is not assigned to a holder
 */
export class ShareNotAssignedError extends Error {
  constructor(
    public shareId: string,
    public holderId: string
  ) {
    super(`Share ${shareId} is not assigned to holder ${holderId}`);
    this.name = 'ShareNotAssignedError';
  }
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Assert that a holder has a specific permission
 *
 * @param ac - Access control instance
 * @param holder - Holder to check
 * @param permission - Required permission
 * @param resource - Optional resource identifier
 * @throws UnauthorizedError if permission is denied
 */
export function assertPermission(
  ac: AccessControl,
  holder: ShareHolder,
  permission: Permission,
  resource?: string
): void {
  if (!ac.holderHasPermission(holder, permission)) {
    throw new UnauthorizedError(holder.name, permission, resource);
  }
}

/**
 * Assert that a holder can access a share
 *
 * @param ac - Access control instance
 * @param holder - Holder to check
 * @param shareId - Share to access
 * @param assignedShareIds - Shares assigned to holder
 * @throws UnauthorizedError if access is denied
 */
export function assertShareAccess(
  ac: AccessControl,
  holder: ShareHolder,
  shareId: string,
  assignedShareIds: string[]
): void {
  if (!ac.canAccessShare(holder, shareId, assignedShareIds)) {
    throw new UnauthorizedError(holder.name, 'share:read', shareId);
  }
}
