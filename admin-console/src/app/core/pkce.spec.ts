import { base64Url, challengeFor, randomString } from './pkce';

describe('pkce', () => {
  it('matches the RFC 7636 appendix B test vector', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await challengeFor(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('base64url has no padding or url-unsafe characters', () => {
    const s = base64Url(new Uint8Array([251, 255, 254, 253]));
    expect(s).not.toMatch(/[+/=]/);
  });

  it('random strings are url-safe, long enough, and different every time', () => {
    const a = randomString(48);
    const b = randomString(48);
    expect(a).toMatch(/^[A-Za-z0-9_-]{64}$/); // 48 bytes -> 64 chars, within RFC 7636's 43..128
    expect(a).not.toBe(b);
  });
});
