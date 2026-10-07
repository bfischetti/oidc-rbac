// The Store only holds short-lived grant state. Users and Clients come from a UserSource / ClientSource.
// Codes and Refresh Tokens are passed in already hashed, so a leaked database can't be replayed.

export interface AuthorizationCode {
  codeHash: string;
  clientId: string;
  sub: string;
  redirectUri: string;
  scope: string[];
  nonce?: string;
  codeChallenge: string;
  authTime: number;
  expiresAt: number;
}

export interface RefreshToken {
  tokenHash: string;
  familyId: string;
  clientId: string;
  sub: string;
  scope: string[];
  expiresAt: number;
  replaced: boolean;
}

export interface Store {
  saveCode(code: AuthorizationCode): Promise<void>;
  // Returns the code and deletes it atomically, so each code can be redeemed at most once.
  consumeCode(codeHash: string): Promise<AuthorizationCode | undefined>;
  saveRefreshToken(token: RefreshToken): Promise<void>;
  findRefreshToken(tokenHash: string): Promise<RefreshToken | undefined>;
  // Atomically flips `replaced`. Returns false if it was already replaced (a concurrent reuse).
  markRefreshTokenReplaced(tokenHash: string): Promise<boolean>;
  revokeRefreshTokenFamily(familyId: string): Promise<void>;
  // Removes expired codes and tokens. Called periodically by the provider.
  deleteExpired(now: number): Promise<void>;
}
