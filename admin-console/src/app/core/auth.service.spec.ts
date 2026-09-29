import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service';
import { setConfig } from './config';

function tokenResponse(access: string, refresh: string, expiresIn = 600): Response {
  return new Response(JSON.stringify({ access_token: access, refresh_token: refresh, expires_in: expiresIn }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('AuthService', () => {
  let auth: AuthService;

  beforeEach(() => {
    setConfig({ apiUrl: 'https://idp.test', clientId: 'admin-console', scope: 'openid' });
    sessionStorage.clear();
    auth = TestBed.inject(AuthService);
  });

  async function signIn(fetchSpy: jasmine.Spy, expiresIn: number): Promise<void> {
    sessionStorage.setItem('oauth.pending', JSON.stringify({ verifier: 'v', state: 's1', returnUrl: '/users' }));
    fetchSpy.and.resolveTo(tokenResponse('access-1', 'refresh-1', expiresIn));
    const back = await auth.handleCallback(new URLSearchParams('code=abc&state=s1'));
    expect(back).toBe('/users');
  }

  it('rejects a callback whose state does not match (CSRF)', async () => {
    sessionStorage.setItem('oauth.pending', JSON.stringify({ verifier: 'v', state: 'expected', returnUrl: '/' }));
    await expectAsync(auth.handleCallback(new URLSearchParams('code=abc&state=forged'))).toBeRejectedWithError('State mismatch.');
  });

  it('surfaces an error returned by the authorization server', async () => {
    sessionStorage.setItem('oauth.pending', JSON.stringify({ verifier: 'v', state: 's', returnUrl: '/' }));
    await expectAsync(auth.handleCallback(new URLSearchParams('error=access_denied&state=s'))).toBeRejected();
  });

  it('sends the PKCE verifier (never the challenge) in the code exchange', async () => {
    const fetchSpy = spyOn(window, 'fetch');
    await signIn(fetchSpy, 600);
    const body = fetchSpy.calls.mostRecent().args[1]!.body as URLSearchParams;
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code_verifier')).toBe('v');
    expect(body.get('client_id')).toBe('admin-console');
  });

  it('does not touch localStorage: tokens stay in memory', async () => {
    const fetchSpy = spyOn(window, 'fetch');
    await signIn(fetchSpy, 600);
    expect(JSON.stringify({ ...localStorage })).not.toContain('access-1');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('refresh-1');
  });

  it('returns the current token without a network call while it is fresh', async () => {
    const fetchSpy = spyOn(window, 'fetch');
    await signIn(fetchSpy, 600);
    fetchSpy.calls.reset();
    expect(await auth.getAccessToken()).toBe('access-1');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refreshes once when many callers ask at the same time (avoids self-inflicted reuse detection)', async () => {
    const fetchSpy = spyOn(window, 'fetch');
    await signIn(fetchSpy, 10); // expires inside the refresh skew
    fetchSpy.calls.reset();
    fetchSpy.and.resolveTo(tokenResponse('access-2', 'refresh-2'));

    const tokens = await Promise.all([auth.getAccessToken(), auth.getAccessToken(), auth.getAccessToken()]);

    expect(tokens).toEqual(['access-2', 'access-2', 'access-2']);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const body = fetchSpy.calls.mostRecent().args[1]!.body as URLSearchParams;
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('refresh-1');
  });

  it('signs the user out when the refresh is rejected', async () => {
    const fetchSpy = spyOn(window, 'fetch');
    await signIn(fetchSpy, 10);
    fetchSpy.and.resolveTo(new Response('{"error":"invalid_grant"}', { status: 400 }));

    expect(await auth.getAccessToken()).toBeNull();
    expect(auth.isAuthenticated()).toBeFalse();
  });

  it('has no token before sign-in', async () => {
    expect(await auth.getAccessToken()).toBeNull();
  });
});
