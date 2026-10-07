import express from 'express';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { listen, signInAndGetTokens, startProvider, type Harness } from '../../oidc-rbac/test/harness';
import { oidcRbac } from '../src/index';

let h: Harness;
let apiUrl: string;

beforeAll(async () => {
  h = await startProvider();
  const { requirePermission, requireRole } = oidcRbac({
    issuer: h.url,
    audience: 'documents-api',
    permissions: {
      admin: ['documents:read', 'documents:write', 'documents:delete'],
      editor: ['documents:read', 'documents:write'],
      viewer: ['documents:read'],
    },
    now: () => h.clock.now,
  });
  const app = express();
  app.get('/documents', ...requirePermission('documents:read'), (req, res) => {
    res.json({ sub: req.auth!.sub, permissions: [...req.auth!.permissions] });
  });
  app.post('/documents', ...requirePermission('documents:write'), (_req, res) => {
    res.status(201).end();
  });
  app.delete('/documents/:id', ...requirePermission('documents:delete'), (_req, res) => {
    res.status(204).end();
  });
  app.get('/admin', ...requireRole('admin'), (_req, res) => {
    res.end('ok');
  });
  apiUrl = await listen(() => app, h.servers);
});

afterAll(() => h.servers.forEach((s) => s.close()));
beforeEach(() => {
  h.clock.now = Date.now();
});

const call = (method: string, path: string, token?: string) =>
  fetch(`${apiUrl}${path}`, { method, headers: token ? { Authorization: `Bearer ${token}` } : {} });

describe('oidc-rbac-express', () => {
  it('maps Roles to Permissions', async () => {
    const admin = (await signInAndGetTokens(h, 'alice')).access_token!;
    const editor = (await signInAndGetTokens(h, 'bob')).access_token!;
    const viewer = (await signInAndGetTokens(h, 'carol')).access_token!;

    const read = await call('GET', '/documents', viewer);
    expect(await read.json()).toEqual({ sub: 'u-carol', permissions: ['documents:read'] });
    expect((await call('POST', '/documents', viewer)).status).toBe(403);
    expect((await call('POST', '/documents', editor)).status).toBe(201);
    expect((await call('DELETE', '/documents/1', editor)).status).toBe(403);
    expect((await call('DELETE', '/documents/1', admin)).status).toBe(204);
    expect((await call('GET', '/admin', editor)).status).toBe(403);
    expect((await call('GET', '/admin', admin)).status).toBe(200);
  });

  it('rejects requests without a token', async () => {
    const res = await call('GET', '/documents');
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Bearer');
  });

  it('rejects an ID Token presented as an Access Token', async () => {
    const tokens = await signInAndGetTokens(h, 'alice');
    expect((await call('GET', '/documents', tokens.id_token)).status).toBe(401);
  });

  it('rejects an expired Access Token', async () => {
    const tokens = await signInAndGetTokens(h, 'alice');
    h.clock.now += 5 * 60_000 + 10_000;
    expect((await call('GET', '/documents', tokens.access_token)).status).toBe(401);
  });

  it('rejects a token for another audience', async () => {
    const other = oidcRbac({ issuer: h.url, audience: 'billing-api', now: () => h.clock.now });
    const app = express();
    app.get('/', other.authenticate, (_req, res) => {
      res.end('ok');
    });
    const url = await listen(() => app, h.servers);
    const tokens = await signInAndGetTokens(h, 'alice');
    const res = await fetch(url, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(res.status).toBe(401);
  });
});
