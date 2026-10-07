import { describe, expect, it } from 'vitest';
import { ConfigError, hashSecret, loadConfigFile, parseConfig } from '../src/index';

const hash = hashSecret('x');
const base = {
  issuer: 'https://auth.example.com',
  audience: 'api',
  users: [{ sub: 'u1', username: 'ann', passwordHash: hash, roles: ['admin'] }],
  clients: [{ clientId: 'web', name: 'Web', redirectUris: ['https://app.example.com/cb'] }],
};

describe('config', () => {
  it('applies defaults', () => {
    const config = parseConfig(base);
    expect(config.store).toEqual({ type: 'memory' });
  });

  it('accepts the example config', async () => {
    const config = await loadConfigFile(new URL('../../../examples/oidc-rbac.config.json', import.meta.url).pathname);
    expect(config.users.map((u) => u.username)).toEqual(['alice', 'bob', 'carol']);
  });

  it('reports every problem with its path', () => {
    const bad = {
      ...base,
      issuer: 'not a url',
      users: [{ sub: 'u1', username: 'ann', passwordHash: 'plaintext' }],
      clients: [{ clientId: 'web', name: 'Web', redirectUris: [] }],
    };
    expect(() => parseConfig(bad)).toThrowError(ConfigError);
    try {
      parseConfig(bad);
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain('issuer');
      expect(message).toContain('users[0].passwordHash');
      expect(message).toContain('clients[0].redirectUris');
    }
  });

  it('rejects duplicate usernames', () => {
    const users = [base.users[0], { ...base.users[0], sub: 'u2' }];
    expect(() => parseConfig({ ...base, users })).toThrowError(/duplicate username "ann"/);
  });

  it('substitutes environment variables', () => {
    const config = parseConfig(
      { ...base, store: { type: 'postgres', connectionString: '${DATABASE_URL}' } },
      { env: { DATABASE_URL: 'postgres://db/auth' } },
    );
    expect(config.store).toEqual({ type: 'postgres', connectionString: 'postgres://db/auth' });
    expect(() => parseConfig({ ...base, name: '${MISSING}' }, { env: {} })).toThrowError(/MISSING is not set/);
  });

  it('resolves file paths relative to the config file', () => {
    const config = parseConfig({ ...base, keys: './keys.json', store: { type: 'sqlite', path: 'data/db.sqlite' } }, { baseDir: '/etc/oidc' });
    expect(config.keys).toBe('/etc/oidc/keys.json');
    expect(config.store).toEqual({ type: 'sqlite', path: '/etc/oidc/data/db.sqlite' });
  });
});
