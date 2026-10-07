import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';

export interface AuthInfo {
  sub: string;
  roles: string[];
  permissions: Set<string>;
  claims: JWTPayload;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthInfo;
    }
  }
}

export interface OidcRbacOptions {
  // The provider's issuer URL; must match the `iss` claim exactly.
  issuer: string;
  // This API's identifier; Access Tokens must list it in `aud`.
  audience: string;
  // This API's own Role-to-Permission table, e.g. { editor: ['documents:read', 'documents:write'] }.
  permissions?: Record<string, string[]>;
  // Defaults to the jwks_uri from the issuer's discovery document.
  jwksUri?: string;
  // Seconds of clock skew to tolerate when checking exp/iat. Default 5.
  clockTolerance?: number;
  // Injectable clock in milliseconds, for tests.
  now?: () => number;
}

export interface OidcRbac {
  // Verifies the Bearer Access Token and sets req.auth. Responds 401 if it is missing or invalid.
  authenticate: RequestHandler;
  // Authenticates, then requires every listed Permission. Responds 403 if one is missing.
  requirePermission: (...permissions: string[]) => RequestHandler[];
  // Authenticates, then requires at least one of the listed Roles. Prefer requirePermission.
  requireRole: (...roles: string[]) => RequestHandler[];
  permissionsFor: (roles: string[]) => Set<string>;
}

export function oidcRbac(options: OidcRbacOptions): OidcRbac {
  const issuer = options.issuer.replace(/\/$/, '');
  const table = options.permissions ?? {};
  const now = options.now ?? Date.now;
  let jwks: JWTVerifyGetKey | undefined;

  // jose caches the keys and refetches when it sees an unknown `kid` (key rotation).
  async function getJwks(): Promise<JWTVerifyGetKey> {
    if (jwks) return jwks;
    let uri = options.jwksUri;
    if (!uri) {
      const res = await fetch(`${issuer}/.well-known/openid-configuration`);
      if (!res.ok) throw new Error(`discovery failed with HTTP ${res.status}`);
      uri = ((await res.json()) as { jwks_uri: string }).jwks_uri;
    }
    jwks = createRemoteJWKSet(new URL(uri));
    return jwks;
  }

  function permissionsFor(roles: string[]): Set<string> {
    return new Set(roles.flatMap((role) => table[role] ?? []));
  }

  const authenticate: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    if (req.auth) return next();
    const token = req.headers.authorization?.match(/^Bearer (.+)$/i)?.[1];
    if (!token) {
      res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'missing_token' });
      return;
    }
    let keys: JWTVerifyGetKey;
    try {
      keys = await getJwks();
    } catch (err) {
      res.status(503).json({ error: 'issuer_unavailable', error_description: (err as Error).message });
      return;
    }
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer,
        audience: options.audience,
        typ: 'at+jwt',
        algorithms: ['RS256'],
        clockTolerance: options.clockTolerance ?? 5,
        currentDate: new Date(now()),
      });
      const roles = Array.isArray(payload.roles) ? payload.roles.map(String) : [];
      req.auth = { sub: String(payload.sub), roles, permissions: permissionsFor(roles), claims: payload };
      next();
    } catch (err) {
      res
        .status(401)
        .set('WWW-Authenticate', 'Bearer error="invalid_token"')
        .json({ error: 'invalid_token', error_description: (err as Error).message });
    }
  };

  function requirePermission(...permissions: string[]): RequestHandler[] {
    return [
      authenticate,
      (req, res, next) => {
        const missing = permissions.filter((p) => !req.auth!.permissions.has(p));
        if (missing.length === 0) return next();
        res.status(403).json({ error: 'forbidden', missing });
      },
    ];
  }

  function requireRole(...roles: string[]): RequestHandler[] {
    return [
      authenticate,
      (req, res, next) => {
        if (roles.some((r) => req.auth!.roles.includes(r))) return next();
        res.status(403).json({ error: 'forbidden', requiredRoles: roles });
      },
    ];
  }

  return { authenticate, requirePermission, requireRole, permissionsFor };
}
