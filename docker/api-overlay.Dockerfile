# Thin overlay on top of upstream's published API image: reuses their installed
# dependencies and base OS layer, and only overlays the files this fork's OIDC
# feature actually changed or added. Works because Dockerfile.api COPYs plane/
# as plain, uninterpreted Python source (no compile/bundle step) — see
# worklog.md for why this doesn't work for web/admin/space, which are prebuilt
# static bundles.
#
# Build (from repo root):
#   docker build -f docker/api-overlay.Dockerfile \
#     --build-arg PLANE_BACKEND_TAG=v1.3.1 \
#     -t plane-api:v1.3.1-oidc.1 apps/api

ARG PLANE_BACKEND_TAG
FROM makeplane/plane-backend:${PLANE_BACKEND_TAG}

WORKDIR /code

COPY plane/authentication/adapter/base.py plane/authentication/adapter/base.py
COPY plane/authentication/adapter/error.py plane/authentication/adapter/error.py
COPY plane/authentication/adapter/oauth.py plane/authentication/adapter/oauth.py
COPY plane/authentication/provider/oauth/oidc.py plane/authentication/provider/oauth/oidc.py
COPY plane/authentication/urls.py plane/authentication/urls.py
COPY plane/authentication/views/__init__.py plane/authentication/views/__init__.py
COPY plane/authentication/views/app/oidc.py plane/authentication/views/app/oidc.py
COPY plane/authentication/views/space/oidc.py plane/authentication/views/space/oidc.py
COPY plane/db/migrations/0122_account_add_oidc_provider.py plane/db/migrations/0122_account_add_oidc_provider.py
COPY plane/db/models/user.py plane/db/models/user.py
COPY plane/license/api/views/instance.py plane/license/api/views/instance.py
COPY plane/license/management/commands/configure_instance.py plane/license/management/commands/configure_instance.py
COPY plane/utils/instance_config_variables/core.py plane/utils/instance_config_variables/core.py
