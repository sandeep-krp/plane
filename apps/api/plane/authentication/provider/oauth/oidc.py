# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import jwt
import pytz
import requests
from django.core.cache import cache
from jwt import PyJWKClient

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

logger = logging.getLogger("plane.authentication")

DISCOVERY_CACHE_TIMEOUT = 60 * 60  # 1 hour


def _resolve_claim_path(data, path):
    """Resolve a dot-separated claim path against a nested claims dict, e.g.
    "resource_access.plane.roles" for Keycloak-style nested client-role claims.
    A path with no dots is just a plain top-level key lookup."""
    value = data
    for segment in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
        if value is None:
            return None
    return value


def _get_discovery_document(issuer):
    """Fetch (and cache) the OIDC discovery document for the given issuer."""
    cache_key = f"oidc_discovery_document:{issuer}"
    discovery_document = cache.get(cache_key)
    if discovery_document:
        return discovery_document

    try:
        response = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
        response.raise_for_status()
        discovery_document = response.json()
    except (requests.RequestException, ValueError) as e:
        raise AuthenticationException(
            error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
            error_message="OIDC_NOT_CONFIGURED",
        ) from e

    required_endpoints = (
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
    )
    if not all(discovery_document.get(key) for key in required_endpoints):
        raise AuthenticationException(
            error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
            error_message="OIDC_NOT_CONFIGURED",
        )

    cache.set(cache_key, discovery_document, DISCOVERY_CACHE_TIMEOUT)
    return discovery_document


class OidcOAuthProvider(OauthAdapter):
    provider = "oidc"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, nonce=None, callback=None):
        (OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_GROUPS_CLAIM) = get_configuration_value(
            [
                {
                    "key": "OIDC_ISSUER",
                    "default": os.environ.get("OIDC_ISSUER"),
                },
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_GROUPS_CLAIM",
                    "default": os.environ.get("OIDC_GROUPS_CLAIM", "groups"),
                },
            ]
        )
        self.groups_claim = OIDC_GROUPS_CLAIM or "groups"

        if not (OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        # Enforce scheme and normalize trailing slash(es), same treatment as the
        # configurable Gitea/GitLab hosts.
        parsed = urlparse(OIDC_ISSUER)
        if not parsed.scheme or parsed.scheme not in ("https", "http"):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )
        self.issuer = OIDC_ISSUER.rstrip("/")

        discovery_document = _get_discovery_document(self.issuer)
        self.jwks_uri = discovery_document["jwks_uri"]
        self.nonce = nonce

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET

        redirect_uri = f"{'https' if request.is_secure() else 'http'}://{request.get_host()}/auth/oidc/callback/"
        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
        }
        auth_url = f"{discovery_document['authorization_endpoint']}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            discovery_document["token_endpoint"],
            discovery_document["userinfo_endpoint"],
            client_secret,
            code,
            callback=callback,
        )

    def __verify_id_token(self, id_token):
        """Verify the ID token's signature (via the IdP's published JWKS) and its
        iss/aud/exp/nonce claims. This is the part that makes this a real OIDC
        provider rather than an opaque-token OAuth provider like the others."""
        try:
            jwks_client = PyJWKClient(self.jwks_uri, cache_keys=True, lifespan=DISCOVERY_CACHE_TIMEOUT)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_INVALID_ID_TOKEN"],
                error_message="OIDC_INVALID_ID_TOKEN",
            ) from e

        # The nonce ties this token to the specific authorization request this
        # browser session initiated, preventing token replay/injection.
        if not self.nonce or claims.get("nonce") != self.nonce:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_INVALID_ID_TOKEN"],
                error_message="OIDC_INVALID_ID_TOKEN",
            )

        return claims

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {"Accept": "application/json"}
        token_response = self.get_user_token(data=data, headers=headers)

        id_token = token_response.get("id_token")
        if not id_token:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_INVALID_ID_TOKEN"],
                error_message="OIDC_INVALID_ID_TOKEN",
            )
        self.__id_token_claims = self.__verify_id_token(id_token)

        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("refresh_token_expired_at"), tz=pytz.utc)
                    if token_response.get("refresh_token_expired_at")
                    else None
                ),
                "id_token": id_token,
            }
        )

    def __extract_groups(self, user_info_response):
        """Read the configured groups/roles claim from the userinfo response, falling
        back to the verified ID token (some IdPs only include it there depending on
        which scopes were granted to the userinfo endpoint). The claim name may be a
        dot-separated path (e.g. "resource_access.plane.roles") for IdPs like Keycloak
        that nest client roles rather than exposing a top-level claim."""
        raw_groups = _resolve_claim_path(user_info_response, self.groups_claim)
        if raw_groups is None:
            raw_groups = _resolve_claim_path(self.__id_token_claims, self.groups_claim)

        if raw_groups is None:
            return []
        if isinstance(raw_groups, str):
            return [raw_groups]
        if isinstance(raw_groups, list):
            return [str(group) for group in raw_groups]

        logger.warning("OIDC groups claim %r has an unexpected shape, ignoring: %r", self.groups_claim, raw_groups)
        return []

    def set_user_data(self):
        user_info_response = self.get_user_response()

        # The userinfo endpoint's `sub` must match the verified ID token's `sub` —
        # otherwise a compromised/malicious userinfo response could substitute a
        # different user's profile onto this login.
        if user_info_response.get("sub") != self.__id_token_claims.get("sub"):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_INVALID_ID_TOKEN"],
                error_message="OIDC_INVALID_ID_TOKEN",
            )

        # Reject emails explicitly marked unverified (GHSA-7j95-vh8g-f365 pattern). Unlike
        # Google, an absent email_verified claim is *not* treated as unverified: many
        # enterprise IdPs (Okta, Azure AD, generic OIDC) never send this claim at all, and
        # the admin has already made an explicit trust decision by configuring this issuer.
        if user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )

        email = user_info_response.get("email") or self.__id_token_claims.get("email")
        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": str(user_info_response.get("sub")),
                    "email": email,
                    "avatar": user_info_response.get("picture"),
                    "first_name": user_info_response.get("given_name") or user_info_response.get("name") or "",
                    "last_name": user_info_response.get("family_name") or "",
                    "is_password_autoset": True,
                    "groups": self.__extract_groups(user_info_response),
                },
            }
        )
