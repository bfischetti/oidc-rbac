import { DatabaseSync } from 'node:sqlite';
import type { AuthorizationCode, RefreshToken, Store } from './types';

interface CodeRow {
  code_hash: string;
  client_id: string;
  sub: string;
  redirect_uri: string;
  scope: string;
  nonce: string | null;
  code_challenge: string;
  auth_time: number;
  expires_at: number;
}

interface RefreshRow {
  token_hash: string;
  family_id: string;
  client_id: string;
  sub: string;
  scope: string;
  expires_at: number;
  replaced: number;
}

// Uses Node's built-in SQLite (node:sqlite), so there is nothing extra to install.
export class SqliteStore implements Store {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS oidc_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        sub TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        nonce TEXT,
        code_challenge TEXT NOT NULL,
        auth_time INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        sub TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        replaced INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_family ON oidc_refresh_tokens (family_id);
    `);
  }

  close() {
    this.db.close();
  }

  async saveCode(c: AuthorizationCode) {
    this.db
      .prepare(
        `INSERT INTO oidc_codes (code_hash, client_id, sub, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(c.codeHash, c.clientId, c.sub, c.redirectUri, c.scope.join(' '), c.nonce ?? null, c.codeChallenge, c.authTime, c.expiresAt);
  }

  async consumeCode(codeHash: string) {
    const row = this.db.prepare('DELETE FROM oidc_codes WHERE code_hash = ? RETURNING *').get(codeHash) as
      | CodeRow
      | undefined;
    if (!row) return undefined;
    return {
      codeHash: row.code_hash,
      clientId: row.client_id,
      sub: row.sub,
      redirectUri: row.redirect_uri,
      scope: row.scope.split(' ').filter(Boolean),
      nonce: row.nonce ?? undefined,
      codeChallenge: row.code_challenge,
      authTime: row.auth_time,
      expiresAt: row.expires_at,
    };
  }

  async saveRefreshToken(t: RefreshToken) {
    this.db
      .prepare(
        `INSERT INTO oidc_refresh_tokens (token_hash, family_id, client_id, sub, scope, expires_at, replaced)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(t.tokenHash, t.familyId, t.clientId, t.sub, t.scope.join(' '), t.expiresAt, t.replaced ? 1 : 0);
  }

  async findRefreshToken(tokenHash: string) {
    const row = this.db.prepare('SELECT * FROM oidc_refresh_tokens WHERE token_hash = ?').get(tokenHash) as
      | RefreshRow
      | undefined;
    if (!row) return undefined;
    return {
      tokenHash: row.token_hash,
      familyId: row.family_id,
      clientId: row.client_id,
      sub: row.sub,
      scope: row.scope.split(' ').filter(Boolean),
      expiresAt: row.expires_at,
      replaced: row.replaced === 1,
    };
  }

  async markRefreshTokenReplaced(tokenHash: string) {
    const result = this.db
      .prepare('UPDATE oidc_refresh_tokens SET replaced = 1 WHERE token_hash = ? AND replaced = 0')
      .run(tokenHash);
    return Number(result.changes) === 1;
  }

  async revokeRefreshTokenFamily(familyId: string) {
    this.db.prepare('DELETE FROM oidc_refresh_tokens WHERE family_id = ?').run(familyId);
  }

  async deleteExpired(now: number) {
    this.db.prepare('DELETE FROM oidc_codes WHERE expires_at <= ?').run(now);
    this.db.prepare('DELETE FROM oidc_refresh_tokens WHERE expires_at <= ?').run(now);
  }
}
