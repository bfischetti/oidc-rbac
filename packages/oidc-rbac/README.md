# oidc-rbac

An OpenID Connect provider with role-based access control. It signs users in with Authorization Code + PKCE, issues JWT Access Tokens that carry each user's roles, and rotates Refresh Tokens with reuse detection. Run it as a standalone server from a config file, or mount it in your own Express app.

Pair it with [`oidc-rbac-express`](https://www.npmjs.com/package/oidc-rbac-express) to turn those roles into permissions in your APIs.

## Quick start

```bash
npx oidc-rbac init
npx oidc-rbac start
```

`init` writes `oidc-rbac.config.json` and a signing key file `keys.json`, and prints a generated admin password and client secret. The provider then runs at `http://localhost:4000` with discovery at `/.well-known/openid-configuration`.

Requires Node.js 22.13 or later.

## Features

- Authorization Code flow with mandatory PKCE (S256), for both Confidential and Public Clients
- JWT Access Tokens (`typ: at+jwt`, RFC 9068) with a `roles` claim and a configurable audience
- ID Tokens with `nonce`, `auth_time`, and `name`/`email` by scope
- Refresh Tokens (with `offline_access`) that rotate on every use; replaying a spent token revokes the whole family
- Discovery, JWKS with key rotation, and UserInfo
- Codes and Refresh Tokens stored only as SHA-256 hashes
- Memory, SQLite (built into Node) and Postgres storage
- CSRF protection, per-IP rate limiting and strict security headers on the sign-in page
- Exact-match redirect URIs and the RFC 9207 `iss` response parameter

## Configuration

```json
{
  "issuer": "https://auth.example.com",
  "audience": "my-api",
  "name": "Example Inc.",
  "keys": "./keys.json",
  "store": { "type": "postgres", "connectionString": "${DATABASE_URL}" },
  "lifetimes": { "accessToken": 300, "idToken": 300, "refreshToken": 28800, "authorizationCode": 60 },
  "rateLimit": { "login": { "windowMs": 60000, "max": 10 }, "token": { "windowMs": 60000, "max": 60 } },
  "trustProxy": 1,
  "users": [
    { "sub": "u-1", "username": "ana", "passwordHash": "scrypt$…", "name": "Ana", "email": "ana@example.com", "roles": ["admin"] }
  ],
  "clients": [
    { "clientId": "web", "name": "Web App", "secretHash": "scrypt$…", "redirectUris": ["https://app.example.com/callback"] },
    { "clientId": "spa", "name": "Single Page App", "redirectUris": ["https://spa.example.com/callback"] }
  ]
}
```

| Field | Default | Notes |
| --- | --- | --- |
| `issuer` | required | Public URL. A path (e.g. `https://example.com/auth`) mounts the provider there. |
| `audience` | required | `aud` of every Access Token. A string or a list. |
| `keys` | throwaway key | Private JWKS from `oidc-rbac keygen`. Keep it secret. |
| `store` | `memory` | `memory`, `sqlite` (`path`) or `postgres` (`connectionString`, needs `npm install pg`). |
| `lifetimes` | 300 / 300 / 28800 / 60 | Seconds. |
| `rateLimit` | 10 sign-ins and 60 token requests per IP per minute | `false` disables it. |
| `trustProxy` | unset | Express "trust proxy" value; set it behind a load balancer so rate limits see real client IPs. |
| `port`, `host` | issuer port or `PORT`, all interfaces | |
| `name` | `oidc-rbac` | Shown on the sign-in page. |

`${VAR}` anywhere in the file is replaced with that environment variable. Relative paths are relative to the config file. A client without `secretHash` is a Public Client and must use PKCE alone. `oidc-rbac check` validates a file and reports every problem with its path.

Users and clients from the config file are loaded at start, so role changes take effect after a restart and then reach Access Tokens at their next refresh.

## CLI

| Command | |
| --- | --- |
| `oidc-rbac init [--force]` | Create a config file and signing keys in the current folder |
| `oidc-rbac start [-c file]` | Start the provider (`GET /healthz` reports liveness) |
| `oidc-rbac check [-c file]` | Validate a config file |
| `oidc-rbac hash [secret]` | Hash a password or client secret; reads stdin when no argument is given |
| `oidc-rbac keygen [--out keys.json] [--keep 2]` | Add a new signing key in front and keep the newest `n` |

To rotate keys, run `oidc-rbac keygen` and restart. The new key signs new tokens and the previous one stays in the JWKS until tokens signed with it have expired.

## Embedding in your app

```ts
import express from 'express';
import { createProvider, loadKeySet, staticClients } from 'oidc-rbac';
import { SqliteStore } from 'oidc-rbac/sqlite';

const app = express();
app.set('trust proxy', 1);
app.use(
  '/auth',
  createProvider({
    issuer: 'https://example.com/auth',
    audience: 'my-api',
    keys: await loadKeySet('./keys.json'),
    store: new SqliteStore('./oidc-rbac.db'),
    clients: [{ clientId: 'web', name: 'Web App', secretHash: '…', redirectUris: ['https://example.com/callback'] }],
    // Bring your own user database:
    users: {
      findById: (sub) => db.users.find(sub),
      authenticate: async (username, password) => {
        const user = await db.users.findByUsername(username);
        return user && (await checkPassword(user, password)) ? user : undefined;
      },
    },
    loginPage: (ctx) => myTemplate(ctx), // optional, see LoginPageContext
    logger: console, // optional, silent by default
  }),
);
app.listen(3000);
```

With your own `UserSource`, role changes reach Access Tokens at the next refresh without a restart. `clients` also accepts a `ClientSource` (`findById`). For Postgres, `import { PostgresStore } from 'oidc-rbac/postgres'`, pass it a `pg` Pool and call `await store.migrate()` once.

## Endpoints

| Endpoint | |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /jwks` | Public signing keys |
| `GET /authorize`, `POST /authorize` | Sign-in page and code issuance |
| `POST /token` | `authorization_code` and `refresh_token` grants; `client_secret_basic`, `client_secret_post` or `none` |
| `GET /userinfo` | Claims for the Access Token's subject |

## License

MIT
