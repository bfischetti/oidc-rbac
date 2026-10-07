import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

// Passwords and client secrets are stored as `scrypt$<salt>$<hash>`.
export function hashSecret(secret: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(secret, salt, 32);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifySecret(secret: string, stored: string): boolean {
  const [alg, salt, hash] = stored.split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const actual = scryptSync(secret, Buffer.from(salt, 'base64url'), expected.length);
  return timingSafeEqual(actual, expected);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

// PKCE S256: BASE64URL(SHA256(code_verifier)) must equal the code_challenge.
export function s256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

// Codes and Refresh Tokens are stored as hashes, never in plain text.
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}
