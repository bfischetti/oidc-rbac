import type { AuthorizationCode, RefreshToken, Store } from './types';

// Single-process store. State is lost on restart.
export class MemoryStore implements Store {
  private codes = new Map<string, AuthorizationCode>();
  private refreshTokens = new Map<string, RefreshToken>();

  async saveCode(code: AuthorizationCode) {
    this.codes.set(code.codeHash, code);
  }

  async consumeCode(codeHash: string) {
    const found = this.codes.get(codeHash);
    this.codes.delete(codeHash);
    return found;
  }

  async saveRefreshToken(token: RefreshToken) {
    this.refreshTokens.set(token.tokenHash, { ...token });
  }

  async findRefreshToken(tokenHash: string) {
    const found = this.refreshTokens.get(tokenHash);
    return found && { ...found };
  }

  async markRefreshTokenReplaced(tokenHash: string) {
    const found = this.refreshTokens.get(tokenHash);
    if (!found || found.replaced) return false;
    found.replaced = true;
    return true;
  }

  async revokeRefreshTokenFamily(familyId: string) {
    for (const [key, token] of this.refreshTokens) {
      if (token.familyId === familyId) this.refreshTokens.delete(key);
    }
  }

  async deleteExpired(now: number) {
    for (const [key, code] of this.codes) if (code.expiresAt <= now) this.codes.delete(key);
    for (const [key, token] of this.refreshTokens) if (token.expiresAt <= now) this.refreshTokens.delete(key);
  }
}
