import { createRemoteJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { keySetFromJwks, generatePrivateJwk, MemoryStore } from '../src/index';
import {
  authorizeParams,
  CONFIDENTIAL,
  getCode,
  pkce,
  PUBLIC,
  signIn,
  signInAndGetTokens,
  startProvider,
  token,
  type Harness,
} from './harness';

let h: Harness;
beforeAll(async () => {
  h = await startProvider();
});
afterAll(() => h.servers.forEach((s) => s.close()));
beforeEach(() => {
  h.clock.now = Date.now();
});

const exchange = (code: string, verifier: string) =>
  token(h, { grant_type: 'authorization_code', code, redirect_uri: CONFIDENTIAL.redirectUri, code_verifier: verifier });

describe('discovery', () => {
  it('publishes endpoints and public signing keys', async () => {
    const config = await (await fetch(`${h.url}/.well-known/openid-configuration`)).json();
    expect(config.issuer).toBe(h.url);
    expect(config.code_challenge_methods_supported).toEqual(['S256']);
    const jwks = await (await fetch(config.jwks_uri)).json();
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(jwks.keys[0].d).toBeUndefined();
  });
});

describe('authorization code + PKCE', () => {
  it('signs in and issues ID, Access and Refresh Tokens', async () => {
    const { code, verifier, location } = await getCode(h, 'alice');
    expect(location.origin + location.pathname).toBe(CONFIDENTIAL.redirectUri);
    expect(location.searchParams.get('state')).toBe('state-123');
    expect(location.searchParams.get('iss')).toBe(h.url);

    const res = await exchange(code, verifier);
    expect(res.status).toBe(200);
    expect(res.body.refresh_token).toBeTruthy();

    const jwks = createRemoteJWKSet(new URL(`${h.url}/jwks`));
    const id = await jwtVerify(res.body.id_token!, jwks, { issuer: h.url, audience: CONFIDENTIAL.clientId });
    expect(id.payload).toMatchObject({ sub: 'u-alice', nonce: 'nonce-456', name: 'Alice Admin' });
    expect(decodeJwt(res.body.access_token!)).toMatchObject({ sub: 'u-alice', aud: 'documents-api', roles: ['admin'] });
    expect(decodeProtectedHeader(res.body.access_token!).typ).toBe('at+jwt');
  });

  it('works for a Public Client with no secret', async () => {
    const { code, verifier } = await getCode(h, 'bob', { client_id: PUBLIC.clientId, redirect_uri: PUBLIC.redirectUri });
    const res = await token(
      h,
      { grant_type: 'authorization_code', code, redirect_uri: PUBLIC.redirectUri, code_verifier: verifier },
      { clientId: PUBLIC.clientId },
    );
    expect(res.status).toBe(200);
  });

  it('only issues a Refresh Token when offline_access is requested', async () => {
    const tokens = await signInAndGetTokens(h, 'alice', { scope: 'openid' });
    expect(tokens.refresh_token).toBeUndefined();
  });

  it('rejects a wrong password and keeps the username', async () => {
    const res = await signIn(h, 'alice', authorizeParams({ code_challenge: pkce().challenge }), { password: 'nope' });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('value="alice"');
  });

  it('rejects a sign-in without a matching CSRF token', async () => {
    const params = authorizeParams({ code_challenge: pkce().challenge });
    expect((await signIn(h, 'alice', params, { csrf: 'omit' })).status).toBe(403);
    expect((await signIn(h, 'alice', params, { csrf: 'wrong' })).status).toBe(403);
  });

  it('sends security headers on the sign-in page', async () => {
    const res = await fetch(`${h.url}/authorize?${new URLSearchParams(authorizeParams({ code_challenge: 'x' }))}`);
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(res.headers.get('set-cookie')).toMatch(/HttpOnly/i);
  });

  it('refuses to redirect to an unregistered redirect_uri', async () => {
    const params = authorizeParams({ code_challenge: 'x', redirect_uri: 'https://evil.example/cb' });
    const res = await fetch(`${h.url}/authorize?${new URLSearchParams(params)}`, { redirect: 'manual' });
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });

  it('requires PKCE', async () => {
    const res = await fetch(`${h.url}/authorize?${new URLSearchParams(authorizeParams())}`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
  });

  it('rejects a wrong code_verifier', async () => {
    const { code } = await getCode(h, 'alice');
    expect(await exchange(code, pkce().verifier)).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
  });

  it('lets each code be redeemed only once', async () => {
    const { code, verifier } = await getCode(h, 'alice');
    expect((await exchange(code, verifier)).status).toBe(200);
    expect(await exchange(code, verifier)).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
  });

  it('rejects an expired code', async () => {
    const { code, verifier } = await getCode(h, 'alice');
    h.clock.now += 61_000;
    expect(await exchange(code, verifier)).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
  });

  it('rejects a Confidential Client without its secret', async () => {
    const { code, verifier } = await getCode(h, 'alice');
    const res = await token(
      h,
      { grant_type: 'authorization_code', code, redirect_uri: CONFIDENTIAL.redirectUri, code_verifier: verifier },
      { clientId: CONFIDENTIAL.clientId },
    );
    expect(res).toMatchObject({ status: 401, body: { error: 'invalid_client' } });
  });
});

describe('refresh tokens', () => {
  it('rotate and pick up Role changes', async () => {
    const tokens = await signInAndGetTokens(h, 'carol');
    expect(decodeJwt(tokens.access_token!).roles).toEqual(['viewer']);

    const carol = h.users.find((u) => u.sub === 'u-carol')!;
    carol.roles = ['editor'];
    try {
      const refreshed = await token(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token! });
      expect(refreshed.status).toBe(200);
      expect(refreshed.body.refresh_token).not.toBe(tokens.refresh_token);
      expect(decodeJwt(refreshed.body.access_token!).roles).toEqual(['editor']);
    } finally {
      carol.roles = ['viewer'];
    }
  });

  it('revoke the whole family when a replaced token is reused', async () => {
    const tokens = await signInAndGetTokens(h, 'alice');
    const first = await token(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token! });
    expect(first.status).toBe(200);

    const replay = await token(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token! });
    expect(replay).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });

    const legit = await token(h, { grant_type: 'refresh_token', refresh_token: first.body.refresh_token! });
    expect(legit).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
  });

  it('cannot be used by another Client', async () => {
    const tokens = await signInAndGetTokens(h, 'alice');
    const res = await token(h, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }, { clientId: PUBLIC.clientId });
    expect(res).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
  });
});

describe('userinfo', () => {
  it('returns claims allowed by the granted scopes', async () => {
    const tokens = await signInAndGetTokens(h, 'bob', { scope: 'openid email' });
    const res = await fetch(`${h.url}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(await res.json()).toEqual({ sub: 'u-bob', email: 'bob@example.com' });
  });
});

describe('storage', () => {
  it('never stores codes or refresh tokens in plain text', async () => {
    const store = new MemoryStore();
    const local = await startProvider({ store });
    try {
      const tokens = await signInAndGetTokens(local, 'alice');
      expect(await store.findRefreshToken(tokens.refresh_token!)).toBeUndefined();
    } finally {
      local.servers.forEach((s) => s.close());
    }
  });
});

describe('key rotation', () => {
  it('signs with the first key and publishes all of them', async () => {
    const [fresh, old] = [await generatePrivateJwk(), await generatePrivateJwk()];
    const local = await startProvider({ keys: await keySetFromJwks({ keys: [fresh, old] }) });
    try {
      const jwks = await (await fetch(`${local.url}/jwks`)).json();
      expect(jwks.keys.map((k: { kid: string }) => k.kid)).toEqual([fresh.kid, old.kid]);
      const tokens = await signInAndGetTokens(local, 'alice');
      expect(decodeProtectedHeader(tokens.access_token!).kid).toBe(fresh.kid);
    } finally {
      local.servers.forEach((s) => s.close());
    }
  });
});

describe('rate limiting', () => {
  it('limits sign-in attempts per IP', async () => {
    const local = await startProvider({ rateLimit: { login: { windowMs: 60_000, max: 2 } } });
    try {
      const params = authorizeParams({ code_challenge: pkce().challenge });
      const statuses = [];
      for (let i = 0; i < 3; i++) statuses.push((await signIn(local, 'alice', params, { password: 'nope' })).status);
      expect(statuses).toEqual([401, 401, 429]);
    } finally {
      local.servers.forEach((s) => s.close());
    }
  });
});
