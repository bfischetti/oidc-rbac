# oidc-rbac

A lightweight OpenID Connect provider with role-based access control: it signs Users in, issues tokens carrying their Roles, and lets each API decide what those Roles allow.

## Language

### Identity

**OpenID Provider (OP)**:
This service: the party that authenticates a **User** and issues tokens about them.
_Avoid_: IdP, auth server, identity server

**User**:
A person who can sign in to the **OP**. Identified in tokens by its subject (`sub`).
_Avoid_: Account, principal, member

**Resource Server**:
An API that accepts **Access Tokens** and decides, from the **Roles** they carry, whether a request is allowed.
_Avoid_: Backend, protected API, audience

**Client**:
An application registered with the **OP** that asks for tokens on behalf of a **User**.
_Avoid_: Relying party, app, consumer

**Confidential Client**:
A **Client** that can keep a secret (runs on a server) and authenticates to the **OP** with it, in addition to PKCE.
_Avoid_: Private client, backend client

**Public Client**:
A **Client** that cannot keep a secret (browser or mobile app) and relies on PKCE alone.
_Avoid_: SPA client, native client

### Tokens

**Authorization Code**:
A short-lived, single-use value the **OP** hands a **Client** after a **User** signs in, bound to a PKCE challenge and exchanged for tokens.
_Avoid_: Auth code, grant

**ID Token**:
A signed JWT telling a **Client** who the **User** is.
_Avoid_: Identity token, user token

**Access Token**:
A signed JWT a **Client** presents to an API to act on behalf of a **User**.
_Avoid_: Bearer token, API token

**Refresh Token**:
A long-lived, opaque value a **Client** exchanges for a new **Access Token** without the **User** signing in again.
_Avoid_: Offline token

**Refresh Token Family**:
The chain of **Refresh Tokens** descended from one sign-in. Each refresh replaces the current member; presenting a replaced member revokes the whole family.
_Avoid_: Token chain, session

### Authorization

**Scope**:
What a **Client** asked the **OP** for in a sign-in request (`openid`, `profile`, `email`, `offline_access`). Scopes shape which claims and tokens are issued; they never grant **Permissions**.
_Avoid_: Permission, access level

**Role**:
A name defined once for the whole **OP**, assigned to **Users** (many-to-many) and carried in **Access Tokens**. The **OP** knows nothing about what a **Role** allows.
_Avoid_: Group, permission set

**Permission**:
A single allowed action on a kind of resource, written `resource:action` (e.g. `documents:write`). Each **Resource Server** owns its own **Role**-to-**Permission** mapping and checks **Permissions**, never **Role** names.
_Avoid_: Scope, privilege, right

## Example dialogue

> **Dev:** Carol is a viewer but needs to edit. Do I add `documents:write` to her in the OP?
> **Domain expert:** No. The OP doesn't know about Permissions. Give Carol the `editor` **Role** in the OP; the documents **Resource Server** already maps `editor` to `documents:write`.
> **Dev:** And she'll see it right away?
> **Domain expert:** Only after her **Client** uses its **Refresh Token**. Her current **Access Token** still says `viewer` until it's replaced.
> **Dev:** Could the Client just ask for a `documents:write` **Scope** instead?
> **Domain expert:** A **Scope** is what the Client asks for, not what Carol is allowed to do. It never grants a **Permission**.
