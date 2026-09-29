export interface Paged<T> {
  items: T[];
  page: number;
  pageSize: number;
  total: number;
}

export interface UserDto {
  id: string;
  email: string;
  displayName: string;
  isActive: boolean;
  roles: string[];
  createdAt: string;
  mfaEnabled: boolean;
  lockedUntil: string | null;
}

export interface RoleDto {
  id: string;
  name: string;
  description: string;
  scopes: string[];
}

export interface ScopeDto {
  name: string;
  description: string;
}

export interface SessionDto {
  id: string;
  userId: string;
  email: string | null;
  clientId: string | null;
  createdAt: string | null;
  expiresAt: string | null;
}

export interface AuditEventDto {
  id: number;
  occurredAt: string;
  eventType: string;
  success: boolean;
  userId: string | null;
  actorId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  details: Record<string, unknown> | null;
}

export interface AuditFilter {
  eventType?: string;
  success?: string; // '', 'true', 'false'
  userId?: string;
  ip?: string;
  from?: string;
  to?: string;
  page: number;
  pageSize: number;
}
