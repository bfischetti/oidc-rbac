# oidc-rbac-express

Express middleware that verifies OpenID Connect Access Tokens and enforces permissions derived from the roles inside them. Each API keeps its own role-to-permission table, so the identity provider only needs to know role names.

Built for [`oidc-rbac`](https://www.npmjs.com/package/oidc-rbac), and works with any provider that issues RS256 JWT Access Tokens (`typ: at+jwt`) with a `roles` claim.

```bash
npm install oidc-rbac-express
```

## Usage

```ts
import express from 'express';
import { oidcRbac } from 'oidc-rbac-express';

const { requirePermission, requireRole } = oidcRbac({
  issuer: 'https://auth.example.com',
  audience: 'documents-api',
  permissions: {
    admin: ['documents:read', 'documents:write', 'documents:delete'],
    editor: ['documents:read', 'documents:write'],
    viewer: ['documents:read'],
  },
});

const app = express();

app.get('/documents', ...requirePermission('documents:read'), (req, res) => {
  res.json({ user: req.auth!.sub });
});

app.delete('/documents/:id', ...requirePermission('documents:delete'), handler);
```

- `authenticate` verifies the Bearer token's signature (keys from the issuer's discovery document, cached and refreshed on rotation), issuer, audience, type and expiry, then sets `req.auth = { sub, roles, permissions, claims }`.
- `requirePermission(...permissions)` authenticates and requires all listed permissions.
- `requireRole(...roles)` authenticates and requires any of the listed roles. Prefer permissions, so you can change what a role means without touching routes.
- `permissionsFor(roles)` resolves a role list against your table.

Responses: `401` with `WWW-Authenticate: Bearer` for a missing or invalid token, `403 { error: "forbidden", missing: [...] }` for a missing permission, and `503` if the issuer cannot be reached for keys.

## Options

| Option | Default | |
| --- | --- | --- |
| `issuer` | required | Must equal the token's `iss`. |
| `audience` | required | Must appear in the token's `aud`. |
| `permissions` | `{}` | Role-to-permission table. |
| `jwksUri` | from discovery | Skip discovery by giving the JWKS URL. |
| `clockTolerance` | `5` | Seconds of allowed clock skew. |

## License

MIT
