import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { config } from './config';
import { AuditEventDto, AuditFilter, Paged, RoleDto, ScopeDto, SessionDto, UserDto } from './models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private url = (path: string) => `${config().apiUrl}${path}`;

  users(page: number, pageSize: number, search: string) {
    let params = new HttpParams().set('page', page).set('pageSize', pageSize);
    if (search.trim()) params = params.set('search', search.trim());
    return this.http.get<Paged<UserDto>>(this.url('/api/users'), { params });
  }

  createUser(body: { email: string; password: string; displayName: string; roles: string[] }) {
    return this.http.post<UserDto>(this.url('/api/users'), body);
  }

  setUserRoles(id: string, roles: string[]) {
    return this.http.put<UserDto>(this.url(`/api/users/${id}/roles`), { roles });
  }

  setUserActive(id: string, isActive: boolean) {
    return this.http.put<UserDto>(this.url(`/api/users/${id}/status`), { isActive });
  }

  roles() {
    return this.http.get<RoleDto[]>(this.url('/api/roles'));
  }

  scopes() {
    return this.http.get<ScopeDto[]>(this.url('/api/scopes'));
  }

  createRole(body: { name: string; description: string; scopes: string[] }) {
    return this.http.post<RoleDto>(this.url('/api/roles'), body);
  }

  sessions() {
    return this.http.get<SessionDto[]>(this.url('/api/sessions'));
  }

  revokeSession(id: string) {
    return this.http.delete<void>(this.url(`/api/sessions/${id}`));
  }

  audit(f: AuditFilter) {
    let params = new HttpParams().set('page', f.page).set('pageSize', f.pageSize);
    for (const key of ['eventType', 'success', 'userId', 'ip', 'from', 'to'] as const) {
      const v = f[key]?.trim();
      if (v) params = params.set(key, key === 'from' || key === 'to' ? new Date(v).toISOString() : v);
    }
    return this.http.get<Paged<AuditEventDto>>(this.url('/api/audit'), { params });
  }
}

/** Turns an RFC 7807 problem+json response into one readable line. */
export function problemMessage(e: unknown): string {
  if (!(e instanceof HttpErrorResponse)) return 'Something went wrong.';
  const p = e.error as { title?: string; detail?: string; errors?: Record<string, string[]> } | null;
  if (p?.errors) return Object.values(p.errors).flat().join(' ');
  return p?.detail ?? p?.title ?? `Request failed (${e.status}).`;
}
