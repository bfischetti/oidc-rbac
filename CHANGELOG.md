# Changelog

## 0.1.0

First release of `oidc-rbac` and `oidc-rbac-express`.

- OpenID Provider with Authorization Code + PKCE, Confidential and Public Clients
- JWT Access Tokens with roles, ID Tokens, UserInfo, discovery and JWKS
- Rotating Refresh Tokens with reuse detection
- Signing keys from a JWKS file with rotation (`oidc-rbac keygen`)
- Memory, SQLite and Postgres stores; codes and tokens stored as hashes
- CSRF protection, rate limiting and security headers on the sign-in page
- Validated JSON config with `${VAR}` substitution, and the `init`, `start`, `check`, `hash` and `keygen` commands
- Pluggable users, clients, sign-in page and logger when embedded in Express
- `oidc-rbac-express`: `authenticate`, `requirePermission` and `requireRole` middleware
