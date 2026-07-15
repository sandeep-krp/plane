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

| Variable             | Purpose                                             |
| -------------------- | --------------------------------------------------- |
| `IS_OIDC_ENABLED`    | `1` to turn the provider on                         |
| `OIDC_ISSUER`        | Your IdP's issuer URL                               |
| `OIDC_CLIENT_ID`     | Client ID registered with your IdP                  |
| `OIDC_CLIENT_SECRET` | Client secret                                       |
| `OIDC_DISPLAY_NAME`  | Label shown on the login button (defaults to "SSO") |
| `ENABLE_OIDC_SYNC`   | Optional: keep user profile fields in sync on login |

Works across the main app, the admin console, and the public "spaces" portal.

**Tested against a real IdP** — the automated suite uses real RSA-signed JWTs to exercise
the actual verification logic (valid/tampered/expired/wrong-audience/nonce-mismatch
tokens, etc.), and the full login flow was additionally driven end-to-end against a live
Keycloak instance (no mocking) to confirm the real redirect chain, token verification,
and session creation all work together.

## Getting it

### Docker images

Prebuilt images for all six components are published to GitHub Container Registry
under one consistent tag, `<upstream-version>-oidc.<n>` (e.g. `v1.3.1-oidc.1`):

- `ghcr.io/sandeep-krp/plane-web`
- `ghcr.io/sandeep-krp/plane-admin`
- `ghcr.io/sandeep-krp/plane-space`
- `ghcr.io/sandeep-krp/plane-api`
- `ghcr.io/sandeep-krp/plane-live`
- `ghcr.io/sandeep-krp/plane-proxy`

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
