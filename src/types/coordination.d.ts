export type CoordinationMode = 'disabled' | 'file-lease-fencing';

export interface TenantLeaseOwner {
  format: 'basitclaw-workforce-audit-file-lease';
  version: 1;
  tenantHash: string;
  ownerId: string;
  pid: number;
  hostname: string;
  fencingToken: number;
  acquiredAt: string;
  heartbeatAt: string;
  expiresAt: string;
}

export interface CoordinationHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  mode: CoordinationMode;
  directory?: string;
  ownerId?: string;
  leaseMs?: number;
  acquireTimeoutMs?: number;
  activeLeaseCount?: number;
  staleLeaseCount?: number;
  error?: string;
}

export interface TenantCoordinationStatus extends CoordinationHealth {
  tenant: {
    status: 'available' | 'leased' | 'stale' | 'disabled';
    tenantId: string;
    owner: TenantLeaseOwner | null;
  };
  latestFencingToken: number;
}

export interface FencedSnapshotVersion {
  fencingToken: number;
  path: string;
}

export interface FencedPersistenceHealth {
  status: 'ready' | 'unavailable';
  mode: 'encrypted-file-fenced';
  coordinated: true;
  directory: string;
  primaryKeyId: string;
  persistedTenantCount: number;
  retainedVersions: number;
  error?: string;
}
