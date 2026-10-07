# oidc-rbac

An OpenID Connect provider with role-based access control, and the Express middleware to enforce it.

| Package | |
| --- | --- |
| [`oidc-rbac`](packages/oidc-rbac) | The provider: signs users in with Authorization Code + PKCE, issues JWT Access Tokens carrying roles, rotates Refresh Tokens with reuse detection. Runs standalone (`npx oidc-rbac start`) or inside your Express app. |
| [`oidc-rbac-express`](packages/oidc-rbac-express) | Middleware for your APIs: verifies Access Tokens and maps roles to permissions (`requirePermission('documents:write')`). |

The provider only knows users and their roles. Each API decides what a role allows in its own permission table ([ADR 0002](docs/adr/0002-roles-in-token-permissions-at-resource-server.md)). Terms are defined in [CONTEXT.md](CONTEXT.md).

## Get started

```bash
npx oidc-rbac init     # writes oidc-rbac.config.json and keys.json, prints an admin password and client secret
npx oidc-rbac start    # http://localhost:4000
```

Then protect an API:

```bash
npm install oidc-rbac-express
```

```ts
import { oidcRbac } from 'oidc-rbac-express';

const { requirePermission } = oidcRbac({
  issuer: 'http://localhost:4000',
  audience: 'my-api',
  permissions: { admin: ['things:read', 'things:write'] },
});

app.get('/things', ...requirePermission('things:read'), handler);
```

See the [provider README](packages/oidc-rbac/README.md) for configuration, storage, key rotation and embedding, and the [middleware README](packages/oidc-rbac-express/README.md) for its options.

## Example stack

The [`examples`](examples) folder runs all three pieces together: the provider ([config](examples/oidc-rbac.config.json)), a documents API using the middleware, and the **Console**, a web app that signs you in, shows your decoded tokens, calls the API and logs every HTTP hop.

```bash
npm install
npm run dev
```

Open <http://localhost:4002> and sign in as `alice` (admin), `bob` (editor) or `carol` (viewer), all with the password `password`.

```
Browser            Console (4002)                Provider (4000)            API (4001)
   |-- GET /login ---->|                               |                          |
   |<-- 302 /authorize?client_id&redirect_uri&scope&state&nonce&code_challenge ---|
   |-- GET /authorize ------------------------------->| sign-in page + CSRF cookie
   |-- POST /authorize (username, password) --------->| check password, store code hash
   |<-- 302 /callback?code&state&iss ------------------|                          |
   |-- GET /callback -->| check state + iss            |                          |
   |                    |-- POST /token (code, code_verifier, client secret) ---->| verify PKCE
   |                    |<-- id_token, access_token, refresh_token --------------|
   |                    | verify id_token (JWKS, aud, nonce)                      |
   |                    |-- GET /documents (Bearer access_token) -------------------------------->|
   |                    |                               |<--- GET /jwks (cached) -|
   |                    |<-- 200 or 403, by role -> permission -----------------------------------|
```

## Development

```bash
npm install
npm test           # end-to-end, store, config, CLI and middleware tests
npm run typecheck
npm run build      # builds both packages into dist/
```

Postgres store tests run when `TEST_DATABASE_URL` is set, as they do in CI.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`), scoped by package where it helps, e.g. `feat(oidc-rbac-express): …`.

## Releasing

1. Bump `version` in both `packages/*/package.json` and add a `CHANGELOG.md` entry.
2. Push a `v<version>` tag. The [release workflow](.github/workflows/release.yml) tests, builds and publishes both packages with npm provenance.

Publishing uses npm trusted publishing: on npmjs.com, add this repository and `release.yml` as a trusted publisher for each package. For the very first publish, before the packages exist on npm, run `npm publish --workspace oidc-rbac --workspace oidc-rbac-express --access public` locally after `npm run build`.

## Roadmap

- `/revoke` and RP-initiated `/logout`, plus a provider session for single sign-on
- API-specific scopes intersected with role permissions
- Client Credentials grant for service-to-service calls
- Consent screen
- Shared rate limiting across instances

## License

MIT
