import { HttpErrorResponse, provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ApiService, problemMessage } from './api.service';
import { setConfig } from './config';

describe('ApiService', () => {
  let api: ApiService;
  let http: HttpTestingController;

  beforeEach(() => {
    setConfig({ apiUrl: 'https://idp.test', clientId: 'c', scope: 's' });
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    api = TestBed.inject(ApiService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('audit sends only the filters that are set, with ISO dates', () => {
    api.audit({ page: 2, pageSize: 25, eventType: 'login.*', success: '', userId: '  ', from: '2026-01-02T03:04' }).subscribe();
    const req = http.expectOne((r) => r.url === 'https://idp.test/api/audit');
    expect(req.request.params.get('eventType')).toBe('login.*');
    expect(req.request.params.get('page')).toBe('2');
    expect(req.request.params.has('success')).toBeFalse();
    expect(req.request.params.has('userId')).toBeFalse();
    expect(req.request.params.get('from')).toMatch(/^2026-01-0\dT\d\d:\d\d:00\.000Z$/);
    req.flush({ items: [], page: 2, pageSize: 25, total: 0 });
  });

  it('user search is trimmed and omitted when empty', () => {
    api.users(1, 10, '  ').subscribe();
    const first = http.expectOne((r) => r.url === 'https://idp.test/api/users');
    expect(first.request.params.has('search')).toBeFalse();
    first.flush({ items: [], page: 1, pageSize: 10, total: 0 });

    api.users(1, 10, ' bob ').subscribe();
    const second = http.expectOne((r) => r.url === 'https://idp.test/api/users');
    expect(second.request.params.get('search')).toBe('bob');
    second.flush({ items: [], page: 1, pageSize: 10, total: 0 });
  });

  it('uses the expected verbs and paths for mutations', () => {
    api.setUserRoles('u1', ['admin']).subscribe();
    const roles = http.expectOne('https://idp.test/api/users/u1/roles');
    expect(roles.request.method).toBe('PUT');
    expect(roles.request.body).toEqual({ roles: ['admin'] });
    roles.flush({});

    api.revokeSession('s1').subscribe();
    const del = http.expectOne('https://idp.test/api/sessions/s1');
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
  });
});

describe('problemMessage', () => {
  const err = (body: unknown) => new HttpErrorResponse({ status: 400, error: body });

  it('prefers validation errors, then detail, then title', () => {
    expect(problemMessage(err({ errors: { email: ['Bad email.'], password: ['Too short.'] } }))).toBe('Bad email. Too short.');
    expect(problemMessage(err({ title: 'Conflict', detail: 'Already exists.' }))).toBe('Already exists.');
    expect(problemMessage(err({ title: 'Not found' }))).toBe('Not found');
  });

  it('falls back to a generic message', () => {
    expect(problemMessage(new Error('boom'))).toBe('Something went wrong.');
    expect(problemMessage(new HttpErrorResponse({ status: 500 }))).toBe('Request failed (500).');
  });
});
