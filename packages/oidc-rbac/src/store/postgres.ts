import type { Pool } from 'pg';
import type { AuthorizationCode, RefreshToken, Store } from './types';

// Requires the `pg` package. Pass your own Pool; call migrate() once at startup.
export class PostgresStore implements Store {
  constructor(private pool: Pool) {}

  async migrate() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS oidc_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        sub TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL,
        nonce TEXT,
        code_challenge TEXT NOT NULL,
        auth_time BIGINT NOT NULL,
        expires_at BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        sub TEXT NOT NULL,
        scope TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        replaced BOOLEAN NOT NULL DEFAULT FALSE
      );
      CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_family ON oidc_refresh_tokens (family_id);
    `);
  }

  async saveCode(c: AuthorizationCode) {
    await this.pool.query(
      `INSERT INTO oidc_codes (code_hash, client_id, sub, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [c.codeHash, c.clientId, c.sub, c.redirectUri, c.scope.join(' '), c.nonce ?? null, c.codeChallenge, c.authTime, c.expiresAt],
    );
  }

  async consumeCode(codeHash: string) {
    const { rows } = await this.pool.query('DELETE FROM oidc_codes WHERE code_hash = $1 RETURNING *', [codeHash]);
    const row = rows[0];
    if (!row) return undefined;
    return {
      codeHash: row.code_hash,
      clientId: row.client_id,
      sub: row.sub,
      redirectUri: row.redirect_uri,
      scope: String(row.scope).split(' ').filter(Boolean),
      nonce: row.nonce ?? undefined,
      codeChallenge: row.code_challenge,
      authTime: Number(row.auth_time),
      expiresAt: Number(row.expires_at),
    };
  }

  async saveRefreshToken(t: RefreshToken) {
    await this.pool.query(
      `INSERT INTO oidc_refresh_tokens (token_hash, family_id, client_id, sub, scope, expires_at, replaced)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [t.tokenHash, t.familyId, t.clientId, t.sub, t.scope.join(' '), t.expiresAt, t.replaced],
    );
  }

  async findRefreshToken(tokenHash: string) {
    const { rows } = await this.pool.query('SELECT * FROM oidc_refresh_tokens WHERE token_hash = $1', [tokenHash]);
    const row = rows[0];
    if (!row) return undefined;
    return {
      tokenHash: row.token_hash,
      familyId: row.family_id,
      clientId: row.client_id,
      sub: row.sub,
      scope: String(row.scope).split(' ').filter(Boolean),
      expiresAt: Number(row.expires_at),
      replaced: row.replaced,
    };
  }

  async markRefreshTokenReplaced(tokenHash: string) {
    const { rowCount } = await this.pool.query(
      'UPDATE oidc_refresh_tokens SET replaced = TRUE WHERE token_hash = $1 AND replaced = FALSE',
      [tokenHash],
    );
    return rowCount === 1;
  }

  async revokeRefreshTokenFamily(familyId: string) {
    await this.pool.query('DELETE FROM oidc_refresh_tokens WHERE family_id = $1', [familyId]);
  }

  async deleteExpired(now: number) {
    await this.pool.query('DELETE FROM oidc_codes WHERE expires_at <= $1', [now]);
    await this.pool.query('DELETE FROM oidc_refresh_tokens WHERE expires_at <= $1', [now]);
  }
}
