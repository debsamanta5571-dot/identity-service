import { Injectable, signal } from '@angular/core';
import { config } from './config';
import { challengeFor, randomString } from './pkce';

export interface CurrentUser {
  sub: string;
  email?: string;
  name?: string;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
}

const PENDING = 'oauth.pending';
const SKEW_MS = 30_000; // refresh a little early

/**
 * Authorization code + PKCE against our own identity service, as a public client.
 *
 * Tokens live in memory only. A page reload loses them, and the app simply runs the authorize redirect again;
 * the identity service's session cookie makes that instant, with no password prompt. That keeps tokens out of
 * localStorage, where any XSS could read them. Production hardening: a BFF, or oidc-client-ts (see README).
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private expiresAt = 0;
  private refreshing: Promise<void> | null = null;

  readonly user = signal<CurrentUser | null>(null);

  isAuthenticated(): boolean {
    return this.accessToken !== null && Date.now() < this.expiresAt;
  }

  /** Redirects the browser to the authorization endpoint. */
  async login(returnUrl = '/'): Promise<void> {
    const verifier = randomString(48);
    const state = randomString(16);
    sessionStorage.setItem(PENDING, JSON.stringify({ verifier, state, returnUrl }));

    const c = config();
    const params = new URLSearchParams({
      client_id: c.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri(),
      scope: c.scope,
      state,
      code_challenge: await challengeFor(verifier),
      code_challenge_method: 'S256',
    });
    window.location.assign(`${c.apiUrl}/connect/authorize?${params}`);
  }

  /** Finishes the redirect: checks state, exchanges the code. Returns where to send the user next. */
  async handleCallback(query: URLSearchParams): Promise<string> {
    const raw = sessionStorage.getItem(PENDING);
    sessionStorage.removeItem(PENDING);
    if (!raw) throw new Error('No sign-in in progress.');
    const pending = JSON.parse(raw) as { verifier: string; state: string; returnUrl: string };

    if (query.get('error')) throw new Error(query.get('error_description') ?? query.get('error')!);
    if (query.get('state') !== pending.state) throw new Error('State mismatch.'); // CSRF protection
    const code = query.get('code');
    if (!code) throw new Error('No authorization code returned.');

    await this.tokenRequest({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri(),
      code_verifier: pending.verifier,
    });
    return pending.returnUrl;
  }

  /** A valid access token, refreshing first if needed. Null when the user must sign in again. */
  async getAccessToken(): Promise<string | null> {
    if (this.accessToken && Date.now() < this.expiresAt - SKEW_MS) return this.accessToken;
    if (!this.refreshToken) return null;

    // One refresh at a time. Two parallel requests presenting the same refresh token would look exactly like
    // token theft to the server's reuse detection and end the whole session.
    this.refreshing ??= this.tokenRequest({ grant_type: 'refresh_token', refresh_token: this.refreshToken })
      .catch(() => this.clear())
      .finally(() => (this.refreshing = null));
    await this.refreshing;
    return this.accessToken;
  }

  async logout(): Promise<void> {
    const c = config();
    const rt = this.refreshToken;
    this.clear();
    if (rt) {
      await fetch(`${c.apiUrl}/connect/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: c.clientId, token: rt, token_type_hint: 'refresh_token' }),
      }).catch(() => undefined);
    }
    const back = encodeURIComponent(window.location.origin + '/');
    window.location.assign(`${c.apiUrl}/account/logout?post_logout_redirect_uri=${back}`);
  }

  private redirectUri(): string {
    return `${window.location.origin}/auth/callback`;
  }

  private clear(): void {
    this.accessToken = this.refreshToken = null;
    this.expiresAt = 0;
    this.user.set(null);
  }

  private async tokenRequest(body: Record<string, string>): Promise<void> {
    const c = config();
    const res = await fetch(`${c.apiUrl}/connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: c.clientId, ...body }),
    });
    if (!res.ok) throw new Error(`Token request failed (${res.status}).`);
    const t = (await res.json()) as TokenResponse;

    this.accessToken = t.access_token;
    this.refreshToken = t.refresh_token ?? this.refreshToken;
    this.expiresAt = Date.now() + t.expires_in * 1000;
    if (t.id_token) this.user.set(this.readUser(t.id_token));
  }

  // The id token came straight from our token endpoint over TLS, so only its claims are read here.
  private readUser(idToken: string): CurrentUser {
    const payload = JSON.parse(atob(idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return { sub: payload.sub, email: payload.email, name: payload.name };
  }
}
