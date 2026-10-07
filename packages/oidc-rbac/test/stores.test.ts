import { describe, expect, it } from 'vitest';
import { MemoryStore, type Store } from '../src/index';
import { SqliteStore } from '../src/sqlite';
import { PostgresStore } from '../src/postgres';

const factories: [string, () => Promise<Store>][] = [
  ['memory', async () => new MemoryStore()],
  ['sqlite', async () => new SqliteStore(':memory:')],
];

// Postgres runs only when a database is available, e.g. TEST_DATABASE_URL=postgres://localhost/oidc_rbac_test
if (process.env.TEST_DATABASE_URL) {
  factories.push([
    'postgres',
    async () => {
      const { default: pg } = await import('pg');
      const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
      await pool.query('DROP TABLE IF EXISTS oidc_codes, oidc_refresh_tokens');
      const store = new PostgresStore(pool);
      await store.migrate();
      return store;
    },
  ]);
}

const code = (codeHash: string, expiresAt = Date.now() + 60_000) => ({
  codeHash,
  clientId: 'web',
  sub: 'u-1',
  redirectUri: 'http://localhost/cb',
  scope: ['openid', 'email'],
  nonce: 'n',
  codeChallenge: 'c',
  authTime: 1,
  expiresAt,
});

const refresh = (tokenHash: string, familyId = 'f1', expiresAt = Date.now() + 60_000) => ({
  tokenHash,
  familyId,
  clientId: 'web',
  sub: 'u-1',
  scope: ['openid', 'offline_access'],
  expiresAt,
  replaced: false,
});

describe.each(factories)('%s store', (_name, create) => {
  it('consumes a code exactly once', async () => {
    const store = await create();
    await store.saveCode(code('a'));
    expect(await store.consumeCode('a')).toMatchObject({ codeHash: 'a', scope: ['openid', 'email'], nonce: 'n', authTime: 1 });
    expect(await store.consumeCode('a')).toBeUndefined();
  });

  it('marks a refresh token replaced only once', async () => {
    const store = await create();
    await store.saveRefreshToken(refresh('r1'));
    expect(await store.markRefreshTokenReplaced('r1')).toBe(true);
    expect(await store.markRefreshTokenReplaced('r1')).toBe(false);
    expect((await store.findRefreshToken('r1'))?.replaced).toBe(true);
  });

  it('revokes a whole family', async () => {
    const store = await create();
    await store.saveRefreshToken(refresh('r1', 'f1'));
    await store.saveRefreshToken(refresh('r2', 'f1'));
    await store.saveRefreshToken(refresh('r3', 'f2'));
    await store.revokeRefreshTokenFamily('f1');
    expect(await store.findRefreshToken('r1')).toBeUndefined();
    expect(await store.findRefreshToken('r2')).toBeUndefined();
    expect(await store.findRefreshToken('r3')).toMatchObject({ scope: ['openid', 'offline_access'] });
  });

  it('deletes expired entries', async () => {
    const store = await create();
    await store.saveCode(code('old', 1000));
    await store.saveRefreshToken(refresh('old', 'f', 1000));
    await store.saveRefreshToken(refresh('new', 'f', 5000));
    await store.deleteExpired(2000);
    expect(await store.consumeCode('old')).toBeUndefined();
    expect(await store.findRefreshToken('old')).toBeUndefined();
    expect(await store.findRefreshToken('new')).toBeDefined();
  });
});
