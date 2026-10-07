import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifySecret } from '../src/index';

const cli = new URL('../src/cli.ts', import.meta.url).pathname;
const tsx = new URL('../../../node_modules/.bin/tsx', import.meta.url).pathname;
const run = (args: string[], cwd: string, input?: string) =>
  execFileSync(tsx, [cli, ...args], { cwd, input, encoding: 'utf8', stdio: 'pipe' });

describe('cli', () => {
  it('init creates a config and keys that pass check', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oidc-rbac-'));
    const out = run(['init'], dir);
    const password = out.match(/admin \/ (\S+)/)![1]!;
    const config = JSON.parse(readFileSync(join(dir, 'oidc-rbac.config.json'), 'utf8'));
    expect(verifySecret(password, config.users[0].passwordHash)).toBe(true);
    expect(run(['check'], dir)).toContain('is valid');
    expect(() => run(['init'], dir)).toThrow();
  });

  it('keygen rotates keys and keeps the newest', () => {
    const dir = mkdtempSync(join(tmpdir(), 'oidc-rbac-'));
    for (let i = 0; i < 3; i++) run(['keygen'], dir);
    expect(JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8')).keys).toHaveLength(2);
  });

  it('hash reads the secret from stdin', () => {
    const hash = run(['hash'], tmpdir(), 's3cret\n').trim();
    expect(verifySecret('s3cret', hash)).toBe(true);
  });
});
