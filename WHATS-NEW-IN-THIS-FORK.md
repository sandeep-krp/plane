# What's new in this fork

This is a fork of [makeplane/plane](https://github.com/makeplane/plane), maintained at
[sandeep-krp/plane](https://github.com/sandeep-krp/plane). It tracks upstream Plane
release-for-release and adds features on top. Everything not listed below behaves
exactly like upstream Plane — same UI, same data model, same self-hosting docs.

Currently based on upstream **[v1.3.1](https://github.com/makeplane/plane/releases/tag/v1.3.1)**
(see [`.upstream-version`](./.upstream-version) for the exact version this fork is built
against at any given time).

## Added

### OIDC (OpenID Connect) SSO login

A generic OIDC login option, alongside upstream's existing Google/GitHub/GitLab/Gitea
sign-in. Lets you connect Plane to any standards-compliant identity provider — Keycloak,
Okta, Auth0, Azure AD/Entra ID, Authentik, etc.

Unlike upstream's other OAuth providers (which treat the provider's `id_token` as an
opaque string and never verify it), this is a real OIDC implementation:

- Fetches the IdP's `.well-known/openid-configuration` discovery document.
- Verifies the ID token's signature against the IdP's JWKS.
- Validates `iss`, `aud`, `exp`, and a per-login `nonce` (replay protection).
- Cross-checks the userinfo endpoint's `sub` against the verified token.

**Enabling it** — set these instance environment variables, then configure the rest from
the admin console (**God Mode → Authentication → OIDC**):

| Variable                  | Purpose                                                      |
| ------------------------- | ------------------------------------------------------------ |
| `IS_OIDC_ENABLED`         | `1` to turn the provider on                                  |
| `OIDC_ISSUER`             | Your IdP's issuer URL                                        |
| `OIDC_CLIENT_ID`          | Client ID registered with your IdP                           |
| `OIDC_CLIENT_SECRET`      | Client secret                                                |
| `OIDC_DISPLAY_NAME`       | Label shown on the login button (defaults to "SSO")          |
| `ENABLE_OIDC_SYNC`        | Optional: keep user profile fields in sync on every login    |
| `OIDC_GROUPS_CLAIM`       | Claim holding the user's groups/roles (defaults to `groups`) |
| `ENABLE_OIDC_ROLE_SYNC`   | Optional: enable IdP group → workspace role mapping below    |
| `OIDC_GROUP_ROLE_MAPPING` | JSON array mapping IdP groups to workspace roles             |

Works across the main app, the admin console, and the public "spaces" portal.

### OIDC group → workspace role mapping

Grafana-style auto-provisioning: map an IdP group/role claim to a Plane workspace role,
applied on every login. Set `ENABLE_OIDC_ROLE_SYNC=1` and `OIDC_GROUP_ROLE_MAPPING` to a
JSON array of `{group, workspace_slug, role}` entries, e.g.:

```json
[
  { "group": "engineering", "workspace_slug": "acme", "role": "admin" },
  { "group": "support", "workspace_slug": "acme", "role": "guest" }
]
```

- `OIDC_GROUPS_CLAIM` names the userinfo/ID-token claim holding the user's groups (varies
  by IdP — Keycloak, Okta, and Azure AD all name this differently).
- A matching group **auto-joins** the user to the mapped workspace if they aren't already
  a member (this is what makes it useful beyond the existing invite flow).
- The mapping **never downgrades** a role a human admin already set on `WorkspaceMember` —
  it only assigns a role on first join or raises it if the mapped role is higher, so a
  manual admin correction is never silently reverted on the next login.
- All three settings are editable from **God Mode → Authentication → OIDC** — but only
  after they've been seeded once from the matching env vars (the instance-configuration
  API only updates existing settings, it can't create new ones), so set them as env vars
  on your first deploy after upgrading, then manage them from God Mode from then on.
- Invalid JSON or malformed entries are logged and skipped individually; they never block
  login.
- The raw resolved groups list is also stored on `Account.metadata` for auditing.

**Tested against a real IdP** — the automated suite uses real RSA-signed JWTs to exercise
the actual verification logic (valid/tampered/expired/wrong-audience/nonce-mismatch
tokens, etc.), and the full login flow was additionally driven end-to-end against a live
Keycloak instance (no mocking) to confirm the real redirect chain, token verification,
and session creation all work together.

## Fixed

- The members-list "Authentication" column was blank for OIDC users — the display-label
  map for login mediums never had an `oidc` entry, even though the type, the backend, and
  the column renderer all already handled it correctly.
- `ENABLE_OIDC_SYNC` (and its Google/GitHub/GitLab/Gitea equivalents) never actually
  re-synced profile fields on repeat logins — an inverted `is_signup` check meant the sync
  path only ran on first-time account creation, the opposite of "on every login." Fixing
  that also surfaced a related bug where the sync could crash on a `NOT NULL` avatar
  constraint whenever the IdP sends no avatar/picture claim — fixed alongside it.

## Getting it

### Docker images

Prebuilt images for all six components are published to GitHub Container Registry
under one consistent tag, `<upstream-version>-oidc.<n>` (e.g. `v1.3.1-oidc.1`):

- `ghcr.io/sandeep-krp/plane-frontend`
- `ghcr.io/sandeep-krp/plane-admin`
- `ghcr.io/sandeep-krp/plane-space`
- `ghcr.io/sandeep-krp/plane-backend`
- `ghcr.io/sandeep-krp/plane-live`
- `ghcr.io/sandeep-krp/plane-proxy`

Names match upstream's own image naming (per their [Helm chart](https://github.com/makeplane/helm-charts/tree/main/charts/plane-ce)
and CLI deployment config) — `plane-frontend` for `apps/web`, `plane-backend` for
`apps/api`. `plane-backend` also covers the `worker`/`beat-worker`/`migrator` roles,
same as upstream: run the same image with a different startup command
(`./bin/docker-entrypoint-{api,worker,beat,migrator}.sh`) rather than building a
separate image — upstream doesn't publish a distinct "worker" image either.

`live` and `proxy` aren't touched by the OIDC feature, but are built from this fork's
own source (rather than pointing at upstream's images under a different tag) so every
component can be deployed from the same version string.

### Building from source

Same as upstream: see [`docker-compose.yml`](./docker-compose.yml) and
[CONTRIBUTING.md](./CONTRIBUTING.md).

## How this fork stays current

A scheduled workflow checks for new upstream releases, reapplies this fork's changes on
top, runs the OIDC test suite, and opens a PR for review — see
[`.github/workflows/sync-upstream.yml`](./.github/workflows/sync-upstream.yml) and
[`.github/workflows/build-images.yml`](./.github/workflows/build-images.yml).
