import { createHash, randomBytes } from 'node:crypto';
import { createServer, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { expect } from 'vitest';
import {
  createProvider,
  generateKeySet,
  hashSecret,
  staticUsers,
  type Client,
  type KeySet,
  type ProviderOptions,
  type StaticUser,
} from '../src/index';

export const PASSWORD = 'correct horse battery staple';
export const CONFIDENTIAL = { clientId: 'web', secret: 'web-secret', redirectUri: 'http://localhost:4002/callback' };
export const PUBLIC = { clientId: 'spa', redirectUri: 'http://localhost:4003/callback' };

const passwordHash = hashSecret(PASSWORD);

export function makeUsers(): StaticUser[] {
  return [
    { sub: 'u-alice', username: 'alice', passwordHash, name: 'Alice Admin', email: 'alice@example.com', roles: ['admin'] },
    { sub: 'u-bob', username: 'bob', passwordHash, name: 'Bob Editor', email: 'bob@example.com', roles: ['editor'] },
    { sub: 'u-carol', username: 'carol', passwordHash, name: 'Carol Viewer', email: 'carol@example.com', roles: ['viewer'] },
  ];
}

export const clients: Client[] = [
  { clientId: CONFIDENTIAL.clientId, name: 'Web App', secretHash: hashSecret(CONFIDENTIAL.secret), redirectUris: [CONFIDENTIAL.redirectUri] },
  { clientId: PUBLIC.clientId, name: 'Single Page App', redirectUris: [PUBLIC.redirectUri] },
];

// Starts a server on a random port; the handler is resolved lazily so the provider can learn its own URL.
export async function listen(handler: () => RequestListener, servers: Server[]): Promise<string> {
  const server = createServer((req, res) => handler()(req, res));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

export interface Harness {
  url: string;
  users: StaticUser[];
  keys: KeySet;
  clock: { now: number };
  servers: Server[];
}

export async function startProvider(overrides: Partial<ProviderOptions> = {}): Promise<Harness> {
  const servers: Server[] = [];
  const users = makeUsers();
  const keys = overrides.keys ?? (await generateKeySet());
  const clock = { now: Date.now() };
  let app: RequestListener;
  const url = await listen(() => app, servers);
  const express_ = express();
  express_.use(
    createProvider({
      issuer: url,
      audience: 'documents-api',
      keys,
      users: staticUsers(users),
      clients,
      rateLimit: false,
      now: () => clock.now,
      ...overrides,
    }),
  );
  app = express_;
  return { url, users, keys, clock, servers };
}

export function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

export function authorizeParams(overrides: Record<string, string | undefined> = {}) {
  const params: Record<string, string | undefined> = {
    response_type: 'code',
    client_id: CONFIDENTIAL.clientId,
    redirect_uri: CONFIDENTIAL.redirectUri,
    scope: 'openid profile email offline_access',
    state: 'state-123',
    nonce: 'nonce-456',
    code_challenge_method: 'S256',
    ...overrides,
  };
  return Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined)) as Record<string, string>;
}

// Plays the browser: load the login form (picking up the CSRF cookie and field), then submit credentials.
export async function signIn(
  h: Harness,
  username: string,
  params: Record<string, string>,
  opts: { password?: string; csrf?: 'omit' | 'wrong' } = {},
) {
  const form = await fetch(`${h.url}/authorize?${new URLSearchParams(params)}`);
  expect(form.status).toBe(200);
  const cookie = form.headers.get('set-cookie')!.split(';')[0]!;
  const csrf = (await form.text()).match(/name="csrf_token" value="([^"]+)"/)![1]!;
  const body: Record<string, string> = { ...params, username, password: opts.password ?? PASSWORD };
  if (opts.csrf !== 'omit') body.csrf_token = opts.csrf === 'wrong' ? 'nope' : csrf;
  return fetch(`${h.url}/authorize`, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie },
    body: new URLSearchParams(body),
  });
}

export async function getCode(h: Harness, username: string, overrides: Record<string, string | undefined> = {}) {
  const { verifier, challenge } = pkce();
  const params = authorizeParams({ code_challenge: challenge, ...overrides });
  const res = await signIn(h, username, params);
  expect(res.status).toBe(302);
  const location = new URL(res.headers.get('location')!);
  return { code: location.searchParams.get('code')!, verifier, location };
}

export async function token(
  h: Harness,
  body: Record<string, string>,
  client: { clientId: string; secret?: string } = CONFIDENTIAL,
) {
  const headers: Record<string, string> = {};
  if (client.secret) {
    headers.Authorization = `Basic ${Buffer.from(`${client.clientId}:${client.secret}`).toString('base64')}`;
  } else {
    body = { ...body, client_id: client.clientId };
  }
  const res = await fetch(`${h.url}/token`, { method: 'POST', headers, body: new URLSearchParams(body) });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

export async function signInAndGetTokens(h: Harness, username: string, overrides: Record<string, string | undefined> = {}) {
  const { code, verifier } = await getCode(h, username, overrides);
  const res = await token(h, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: CONFIDENTIAL.redirectUri,
    code_verifier: verifier,
  });
  expect(res.status).toBe(200);
  return res.body;
}
