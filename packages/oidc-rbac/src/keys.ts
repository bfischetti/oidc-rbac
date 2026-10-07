import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from 'jose';

export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

// The first key signs new tokens; every key is published in the JWKS so tokens
// signed before a rotation keep verifying until they expire.
export interface KeySet {
  active: SigningKey;
  all: SigningKey[];
}

export async function generatePrivateJwk(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  return { ...(await exportJWK(privateKey)), kid: randomUUID(), alg: 'RS256', use: 'sig' };
}

async function toSigningKey(jwk: JWK): Promise<SigningKey> {
  if (!jwk.kid) throw new Error('Every signing key needs a "kid".');
  if (!jwk.d) throw new Error(`Key ${jwk.kid} is not a private key.`);
  const privateKey = (await importJWK({ ...jwk, alg: 'RS256' }, 'RS256')) as CryptoKey;
  const { kty, n, e } = jwk;
  return { kid: jwk.kid, privateKey, publicJwk: { kty, n, e, kid: jwk.kid, alg: 'RS256', use: 'sig' } };
}

export async function keySetFromJwks(jwks: { keys: JWK[] }): Promise<KeySet> {
  if (!jwks.keys?.length) throw new Error('The key set is empty. Run `oidc-rbac keygen` to create one.');
  const all = await Promise.all(jwks.keys.map(toSigningKey));
  return { active: all[0]!, all };
}

// A throwaway key set: tokens stop verifying when the process restarts.
export async function generateKeySet(): Promise<KeySet> {
  return keySetFromJwks({ keys: [await generatePrivateJwk()] });
}

export async function readJwksFile(path: string): Promise<{ keys: JWK[] }> {
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function loadKeySet(path: string): Promise<KeySet> {
  return keySetFromJwks(await readJwksFile(path));
}

// Adds a new active key in front and keeps at most `keep` keys in total.
export async function rotateKeysFile(path: string, keep = 2): Promise<{ added: string; removed: string[] }> {
  let existing: JWK[] = [];
  try {
    existing = (await readJwksFile(path)).keys;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  const fresh = await generatePrivateJwk();
  const keys = [fresh, ...existing];
  const removed = keys.slice(keep).map((k) => String(k.kid));
  await writeFile(path, JSON.stringify({ keys: keys.slice(0, keep) }, null, 2) + '\n', { mode: 0o600 });
  return { added: String(fresh.kid), removed };
}
