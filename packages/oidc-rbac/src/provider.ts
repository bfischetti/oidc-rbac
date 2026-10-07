import { randomUUID } from 'node:crypto';
import express, { type Request, type Response, type Router } from 'express';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';
import { randomToken, s256, sha256, verifySecret } from './crypto';
import { staticClients } from './directory';
import type { KeySet } from './keys';
import { rateLimit, readCookie, safeEqual, securityHeaders, type RateLimitOptions } from './security';
import { MemoryStore } from './store/memory';
import type { Store } from './store/types';
import { silentLogger, type Client, type ClientSource, type Logger, type User, type UserSource } from './types';
import { defaultLoginPage, errorPage, escapeHtml, type LoginPageRenderer } from './views';

export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export interface TokenLifetimes {
  // All in seconds.
  accessToken: number;
  idToken: number;
  refreshToken: number;
  authorizationCode: number;
}

export const DEFAULT_LIFETIMES: TokenLifetimes = {
  accessToken: 5 * 60,
  idToken: 5 * 60,
  refreshToken: 8 * 60 * 60,
  authorizationCode: 60,
};

export interface ProviderOptions {
  // Public URL of the provider, e.g. https://auth.example.com. Mount the router at its path.
  issuer: string;
  // `aud` of every Access Token: the Resource Server(s) they are meant for.
  audience: string | string[];
  keys: KeySet;
  users: UserSource;
  clients: ClientSource | Client[];
  // Defaults to an in-memory store (single process, lost on restart).
  store?: Store;
  lifetimes?: Partial<TokenLifetimes>;
  // Name shown on the sign-in page. Defaults to "oidc-rbac".
  name?: string;
  loginPage?: LoginPageRenderer;
  // Per-IP limits for sign-in attempts and token requests. `false` disables both.
  rateLimit?: false | { login?: RateLimitOptions; token?: RateLimitOptions };
  logger?: Logger;
  // Injectable clock in milliseconds, for tests.
  now?: () => number;
}

type AuthorizeParams = {
  client: Client;
  redirectUri: string;
  scope: string[];
  state?: string;
  nonce?: string;
  codeChallenge: string;
};

type AuthorizeValidation =
  | { ok: true; params: AuthorizeParams }
  // The redirect_uri can't be trusted, so the error is shown on our own page.
  | { ok: false; show: string }
  // The redirect_uri is trusted, so the error goes back to the Client.
  | { ok: false; redirect: string };

const CSRF_COOKIE = 'oidc_rbac_csrf';
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

export function createProvider(options: ProviderOptions): Router {
  const issuer = options.issuer.replace(/\/$/, '');
  const basePath = new URL(issuer).pathname.replace(/\/$/, '');
  const secureCookies = issuer.startsWith('https://');
  const lifetimes = { ...DEFAULT_LIFETIMES, ...options.lifetimes };
  const store = options.store ?? new MemoryStore();
  const clients = Array.isArray(options.clients) ? staticClients(options.clients) : options.clients;
  const { users, keys } = options;
  const brand = options.name ?? 'oidc-rbac';
  const renderLogin = options.loginPage ?? defaultLoginPage;
  const logger = options.logger ?? silentLogger;
  const now = options.now ?? Date.now;
  const nowSeconds = () => Math.floor(now() / 1000);

  const router = express.Router();
  router.use(securityHeaders);
  router.use((req, res, next) => {
    res.on('finish', () => logger.info(`${req.method} ${req.path} -> ${res.statusCode}`));
    next();
  });

  const limits = options.rateLimit === false ? undefined : options.rateLimit;
  const noLimit: express.RequestHandler = (_req, _res, next) => next();
  const loginLimit =
    options.rateLimit === false ? noLimit : rateLimit(limits?.login ?? { windowMs: 60_000, max: 10 }, now);
  const tokenLimit =
    options.rateLimit === false ? noLimit : rateLimit(limits?.token ?? { windowMs: 60_000, max: 60 }, now);

  // Expired codes and tokens are swept at most every ten minutes, piggybacking on requests.
  let nextCleanup = 0;
  function maybeCleanup() {
    if (now() < nextCleanup) return;
    nextCleanup = now() + CLEANUP_INTERVAL_MS;
    store.deleteExpired(now()).catch((err) => logger.error(`cleanup failed: ${err}`));
  }

  // --- Discovery -----------------------------------------------------------

  router.get('/.well-known/openid-configuration', (_req, res) => {
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: SUPPORTED_SCOPES,
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'name', 'email', 'roles'],
      authorization_response_iss_parameter_supported: true,
    });
  });

  router.get('/jwks', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json({ keys: keys.all.map((k) => k.publicJwk) });
  });

  // --- Authorization endpoint ----------------------------------------------

  async function validateAuthorizeRequest(input: Record<string, unknown>): Promise<AuthorizeValidation> {
    const str = (name: string) => (typeof input[name] === 'string' ? input[name] : undefined);

    const client = await clients.findById(str('client_id') ?? '');
    if (!client) return { ok: false, show: 'This application is not registered.' };

    // Exact match only: a loose match here is how authorization codes get stolen.
    const redirectUri = str('redirect_uri');
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return { ok: false, show: 'The redirect_uri is not registered for this application.' };
    }

    const state = str('state');
    const fail = (error: string, description: string) => ({
      ok: false as const,
      redirect: buildRedirect(redirectUri, { error, error_description: description, state }),
    });

    if (str('response_type') !== 'code') {
      return fail('unsupported_response_type', 'Only response_type=code is supported.');
    }
    const requested = (str('scope') ?? '').split(' ').filter(Boolean);
    if (!requested.includes('openid')) {
      return fail('invalid_scope', 'The openid scope is required.');
    }
    const codeChallenge = str('code_challenge');
    if (!codeChallenge || str('code_challenge_method') !== 'S256') {
      return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required.');
    }

    return {
      ok: true,
      params: {
        client,
        redirectUri,
        scope: requested.filter((s) => SUPPORTED_SCOPES.includes(s)),
        state,
        nonce: str('nonce'),
        codeChallenge,
      },
    };
  }

  function buildRedirect(redirectUri: string, params: Record<string, string | undefined>) {
    const url = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
    // RFC 9207: tell the Client which issuer is answering (mix-up attack defence).
    url.searchParams.set('iss', issuer);
    return url.toString();
  }

  // Carries the original request and the CSRF token through the login form as hidden fields.
  function hiddenFields(p: AuthorizeParams, csrfToken: string): string {
    const params: Record<string, string> = {
      client_id: p.client.clientId,
      redirect_uri: p.redirectUri,
      response_type: 'code',
      scope: p.scope.join(' '),
      code_challenge: p.codeChallenge,
      code_challenge_method: 'S256',
      csrf_token: csrfToken,
    };
    if (p.state) params.state = p.state;
    if (p.nonce) params.nonce = p.nonce;
    return Object.entries(params)
      .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
      .join('');
  }

  function sendLoginPage(res: Response, status: number, p: AuthorizeParams, csrfToken: string, extra: { error?: string; username?: string } = {}) {
    res
      .status(status)
      .set('Cache-Control', 'no-store')
      .type('html')
      .send(
        renderLogin({
          brand,
          clientName: p.client.name,
          action: `${basePath}/authorize`,
          hiddenFields: hiddenFields(p, csrfToken),
          ...extra,
        }),
      );
  }

  function sendError(res: Response, status: number, message: string) {
    res.status(status).set('Cache-Control', 'no-store').type('html').send(errorPage(brand, message));
  }

  // Step 1: the browser arrives here from the Client; show the login form.
  router.get('/authorize', async (req, res) => {
    const result = await validateAuthorizeRequest(req.query);
    if (!result.ok) {
      if ('show' in result) return sendError(res, 400, result.show);
      return res.redirect(302, result.redirect);
    }
    // Double-submit CSRF token: the form field must match this SameSite cookie.
    const csrfToken = readCookie(req, CSRF_COOKIE) ?? randomToken(16);
    res.cookie(CSRF_COOKIE, csrfToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: secureCookies,
      path: `${basePath}/authorize`,
    });
    sendLoginPage(res, 200, result.params, csrfToken);
  });

  // Step 2: the login form posts back; on success, redirect to the Client with a code.
  router.post('/authorize', express.urlencoded({ extended: false }), loginLimit, async (req, res) => {
    const cookieToken = readCookie(req, CSRF_COOKIE);
    const formToken = typeof req.body.csrf_token === 'string' ? req.body.csrf_token : '';
    if (!cookieToken || !safeEqual(cookieToken, formToken)) {
      return sendError(res, 403, 'Your sign-in form expired. Go back to the application and try again.');
    }

    const result = await validateAuthorizeRequest(req.body);
    if (!result.ok) {
      if ('show' in result) return sendError(res, 400, result.show);
      return res.redirect(302, result.redirect);
    }
    const p = result.params;

    const username = String(req.body.username ?? '');
    const user = await users.authenticate(username, String(req.body.password ?? ''));
    if (!user) {
      logger.warn(`failed sign-in for "${username}" from ${req.ip}`);
      return sendLoginPage(res, 401, p, cookieToken, { error: 'Invalid username or password.', username });
    }

    const code = randomToken();
    await store.saveCode({
      codeHash: sha256(code),
      clientId: p.client.clientId,
      sub: user.sub,
      redirectUri: p.redirectUri,
      scope: p.scope,
      nonce: p.nonce,
      codeChallenge: p.codeChallenge,
      authTime: nowSeconds(),
      expiresAt: now() + lifetimes.authorizationCode * 1000,
    });
    res.redirect(302, buildRedirect(p.redirectUri, { code, state: p.state }));
  });

  // --- Token endpoint ------------------------------------------------------

  function tokenError(res: Response, status: number, error: string, description: string) {
    res.status(status).set('Cache-Control', 'no-store').json({ error, error_description: description });
  }

  // Confidential Clients prove themselves with their secret; Public Clients only name themselves.
  async function authenticateClient(req: Request): Promise<Client | undefined> {
    let clientId: string | undefined;
    let secret: string | undefined;
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep === -1) return undefined;
      try {
        clientId = decodeURIComponent(decoded.slice(0, sep));
        secret = decodeURIComponent(decoded.slice(sep + 1));
      } catch {
        return undefined;
      }
    } else {
      clientId = req.body.client_id;
      secret = req.body.client_secret;
    }

    const client = await clients.findById(clientId ?? '');
    if (!client) return undefined;
    if (client.secretHash && !(secret && verifySecret(secret, client.secretHash))) return undefined;
    return client;
  }

  async function issueAccessToken(user: User, client: Client, scope: string[]) {
    const iat = nowSeconds();
    return new SignJWT({ client_id: client.clientId, scope: scope.join(' '), roles: user.roles })
      // RFC 9068: `at+jwt` stops an ID Token from being accepted as an Access Token.
      .setProtectedHeader({ alg: 'RS256', kid: keys.active.kid, typ: 'at+jwt' })
      .setIssuer(issuer)
      .setSubject(user.sub)
      .setAudience(options.audience)
      .setIssuedAt(iat)
      .setExpirationTime(iat + lifetimes.accessToken)
      .setJti(randomUUID())
      .sign(keys.active.privateKey);
  }

  async function issueIdToken(user: User, client: Client, scope: string[], extra: { nonce?: string; authTime: number }) {
    const iat = nowSeconds();
    const claims: Record<string, unknown> = { auth_time: extra.authTime, ...profileClaims(user, scope) };
    if (extra.nonce) claims.nonce = extra.nonce;
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: keys.active.kid, typ: 'JWT' })
      .setIssuer(issuer)
      .setSubject(user.sub)
      .setAudience(client.clientId)
      .setIssuedAt(iat)
      .setExpirationTime(iat + lifetimes.idToken)
      .sign(keys.active.privateKey);
  }

  async function issueRefreshToken(user: User, client: Client, scope: string[], familyId: string) {
    const token = randomToken();
    await store.saveRefreshToken({
      tokenHash: sha256(token),
      familyId,
      clientId: client.clientId,
      sub: user.sub,
      scope,
      expiresAt: now() + lifetimes.refreshToken * 1000,
      replaced: false,
    });
    return token;
  }

  router.post('/token', express.urlencoded({ extended: false }), tokenLimit, async (req, res) => {
    maybeCleanup();
    const client = await authenticateClient(req);
    if (!client) {
      if (req.headers.authorization) res.set('WWW-Authenticate', 'Basic realm="token"');
      return tokenError(res, 401, 'invalid_client', 'Client authentication failed.');
    }

    if (req.body.grant_type === 'authorization_code') {
      const code = await store.consumeCode(sha256(String(req.body.code ?? '')));
      if (!code || code.clientId !== client.clientId || code.expiresAt <= now()) {
        return tokenError(res, 400, 'invalid_grant', 'Authorization code is invalid, used or expired.');
      }
      if (req.body.redirect_uri !== code.redirectUri) {
        return tokenError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorize request.');
      }
      const verifier = req.body.code_verifier;
      if (typeof verifier !== 'string' || s256(verifier) !== code.codeChallenge) {
        return tokenError(res, 400, 'invalid_grant', 'PKCE code_verifier does not match code_challenge.');
      }
      const user = await users.findById(code.sub);
      if (!user) return tokenError(res, 400, 'invalid_grant', 'User no longer exists.');

      const body: Record<string, unknown> = {
        token_type: 'Bearer',
        expires_in: lifetimes.accessToken,
        scope: code.scope.join(' '),
        access_token: await issueAccessToken(user, client, code.scope),
        id_token: await issueIdToken(user, client, code.scope, { nonce: code.nonce, authTime: code.authTime }),
      };
      if (code.scope.includes('offline_access')) {
        body.refresh_token = await issueRefreshToken(user, client, code.scope, randomUUID());
      }
      return res.set('Cache-Control', 'no-store').json(body);
    }

    if (req.body.grant_type === 'refresh_token') {
      const presented = await store.findRefreshToken(sha256(String(req.body.refresh_token ?? '')));
      if (!presented || presented.clientId !== client.clientId) {
        return tokenError(res, 400, 'invalid_grant', 'Refresh token is invalid or revoked.');
      }
      if (presented.expiresAt <= now()) {
        return tokenError(res, 400, 'invalid_grant', 'Refresh token expired.');
      }
      // Reuse detection: a replaced token coming back means someone else holds a copy.
      // markRefreshTokenReplaced is atomic, so two concurrent uses can't both succeed.
      if (presented.replaced || !(await store.markRefreshTokenReplaced(presented.tokenHash))) {
        await store.revokeRefreshTokenFamily(presented.familyId);
        logger.warn(`refresh token reuse detected for ${presented.sub}; revoked family ${presented.familyId}`);
        return tokenError(res, 400, 'invalid_grant', 'Refresh token reuse detected; family revoked.');
      }
      const user = await users.findById(presented.sub);
      if (!user) return tokenError(res, 400, 'invalid_grant', 'User no longer exists.');

      // The new Access Token reflects the User's Roles as they are now.
      return res.set('Cache-Control', 'no-store').json({
        token_type: 'Bearer',
        expires_in: lifetimes.accessToken,
        scope: presented.scope.join(' '),
        access_token: await issueAccessToken(user, client, presented.scope),
        refresh_token: await issueRefreshToken(user, client, presented.scope, presented.familyId),
      });
    }

    tokenError(res, 400, 'unsupported_grant_type', 'Use authorization_code or refresh_token.');
  });

  // --- UserInfo ------------------------------------------------------------

  const ownJwks = createLocalJWKSet({ keys: keys.all.map((k) => k.publicJwk) });

  router.get('/userinfo', async (req, res) => {
    const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
    try {
      if (!token) throw new Error('missing token');
      const { payload } = await jwtVerify(token, ownJwks, {
        issuer,
        typ: 'at+jwt',
        algorithms: ['RS256'],
        currentDate: new Date(now()),
      });
      const user = await users.findById(String(payload.sub));
      if (!user) throw new Error('unknown user');
      const scope = String(payload.scope ?? '').split(' ');
      res.set('Cache-Control', 'no-store').json({ sub: user.sub, ...profileClaims(user, scope) });
    } catch {
      res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').end();
    }
  });

  return router;
}

function profileClaims(user: User, scope: string[]): Record<string, string> {
  const claims: Record<string, string> = {};
  if (scope.includes('profile') && user.name) claims.name = user.name;
  if (scope.includes('email') && user.email) claims.email = user.email;
  return claims;
}
