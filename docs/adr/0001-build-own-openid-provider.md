# Implement the OpenID Provider in-house

We implement the OpenID Provider ourselves (login, authorize, token, JWKS, discovery) instead of wrapping Keycloak, Auth0 or an OIDC framework such as `node-oidc-provider`. Every step of the flow stays in a small, readable codebase that we fully control and can trace hop by hop, and the only cryptographic dependency is `jose` for signing and verifying JWTs. The trade-off is that features those products ship out of the box (federation, MFA, admin UI) are ours to add when needed.
