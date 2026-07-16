# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache
from django.test import RequestFactory

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oauth.oidc import OidcOAuthProvider
from plane.license.models import InstanceConfiguration

ISSUER = "https://idp.example.com"
CLIENT_ID = "plane-client"
CLIENT_SECRET = "plane-secret"

DISCOVERY_DOCUMENT = {
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "jwks_uri": f"{ISSUER}/jwks",
}


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected status {self.status_code}")


@pytest.fixture(autouse=True)
def clear_discovery_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def oidc_config(db):
    for key, value in (
        ("OIDC_ISSUER", ISSUER),
        ("OIDC_CLIENT_ID", CLIENT_ID),
        ("OIDC_CLIENT_SECRET", CLIENT_SECRET),
    ):
        InstanceConfiguration.objects.create(key=key, value=value, is_encrypted=False, category="OIDC")


@pytest.fixture
def django_request():
    return RequestFactory().get("/auth/oidc/callback/", SERVER_NAME="app.plane.so")


@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _signed_id_token(private_key, **claim_overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        "email": "user@example.com",
        "nonce": "test-nonce",
    }
    claims.update(claim_overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def _mock_discovery(mock_get):
    def side_effect(url, *args, **kwargs):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return FakeResponse(DISCOVERY_DOCUMENT)
        raise AssertionError(f"unexpected GET {url}")

    mock_get.side_effect = side_effect


def _mock_jwks(public_key):
    signing_key = MagicMock()
    signing_key.key = public_key
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = signing_key
    return patch("plane.authentication.provider.oauth.oidc.PyJWKClient", return_value=jwks_client)


@pytest.mark.unit
class TestOidcOAuthProviderConfiguration:
    def test_raises_when_not_configured(self, db, django_request):
        with pytest.raises(AuthenticationException) as exc_info:
            OidcOAuthProvider(request=django_request, state="s", nonce="n")
        assert exc_info.value.error_message == "OIDC_NOT_CONFIGURED"

    def test_rejects_issuer_without_scheme(self, db, django_request):
        InstanceConfiguration.objects.create(key="OIDC_ISSUER", value="idp.example.com", category="OIDC")
        InstanceConfiguration.objects.create(key="OIDC_CLIENT_ID", value=CLIENT_ID, category="OIDC")
        InstanceConfiguration.objects.create(key="OIDC_CLIENT_SECRET", value=CLIENT_SECRET, category="OIDC")
        with pytest.raises(AuthenticationException) as exc_info:
            OidcOAuthProvider(request=django_request, state="s", nonce="n")
        assert exc_info.value.error_message == "OIDC_NOT_CONFIGURED"

    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_builds_auth_url_with_state_and_nonce(self, mock_get, oidc_config, django_request):
        _mock_discovery(mock_get)
        provider = OidcOAuthProvider(request=django_request, state="test-state", nonce="test-nonce")
        auth_url = provider.get_auth_url()
        assert auth_url.startswith(f"{ISSUER}/authorize?")
        assert "state=test-state" in auth_url
        assert "nonce=test-nonce" in auth_url
        assert "scope=openid" in auth_url


@pytest.mark.unit
class TestOidcIdTokenVerification:
    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_valid_token_populates_user_data(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key)

        def get_side_effect(url, *args, **kwargs):
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return FakeResponse(DISCOVERY_DOCUMENT)
            if url == f"{ISSUER}/userinfo":
                return FakeResponse(
                    {
                        "sub": "user-123",
                        "email": "user@example.com",
                        "email_verified": True,
                        "given_name": "Test",
                        "family_name": "User",
                        "picture": "https://idp.example.com/avatar.png",
                    }
                )
            raise AssertionError(f"unexpected GET {url}")

        mock_get.side_effect = get_side_effect
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key):
            provider.set_token_data()
            provider.set_user_data()

        assert provider.user_data["email"] == "user@example.com"
        assert provider.user_data["user"]["provider_id"] == "user-123"
        assert provider.user_data["user"]["first_name"] == "Test"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_tampered_signature_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        _, public_key = rsa_keypair
        rogue_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        id_token = _signed_id_token(rogue_private_key)
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key), pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_wrong_audience_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key, aud="some-other-client")
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key), pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_wrong_issuer_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key, iss="https://evil.example.com")
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key), pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_expired_token_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        now = int(time.time())
        id_token = _signed_id_token(private_key, iat=now - 1000, exp=now - 500)
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key), pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_nonce_mismatch_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key, nonce="a-different-nonce")
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key), pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_userinfo_sub_mismatch_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key, sub="user-123")

        def get_side_effect(url, *args, **kwargs):
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return FakeResponse(DISCOVERY_DOCUMENT)
            if url == f"{ISSUER}/userinfo":
                # A different `sub` than the verified ID token — must be rejected.
                return FakeResponse({"sub": "someone-else", "email": "user@example.com", "email_verified": True})
            raise AssertionError(f"unexpected GET {url}")

        mock_get.side_effect = get_side_effect
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key):
            provider.set_token_data()
            with pytest.raises(AuthenticationException) as exc_info:
                provider.set_user_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_explicitly_unverified_email_rejected(self, mock_get, mock_post, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key)

        def get_side_effect(url, *args, **kwargs):
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return FakeResponse(DISCOVERY_DOCUMENT)
            if url == f"{ISSUER}/userinfo":
                return FakeResponse({"sub": "user-123", "email": "user@example.com", "email_verified": False})
            raise AssertionError(f"unexpected GET {url}")

        mock_get.side_effect = get_side_effect
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key):
            provider.set_token_data()
            with pytest.raises(AuthenticationException) as exc_info:
                provider.set_user_data()
        assert exc_info.value.error_message == "OAUTH_PROVIDER_UNVERIFIED_EMAIL"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_absent_email_verified_claim_is_trusted(
        self, mock_get, mock_post, oidc_config, django_request, rsa_keypair
    ):
        """Unlike Google, a missing `email_verified` claim is not treated as unverified —
        many enterprise IdPs never send it, and the admin already trusts this issuer."""
        private_key, public_key = rsa_keypair
        id_token = _signed_id_token(private_key)

        def get_side_effect(url, *args, **kwargs):
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return FakeResponse(DISCOVERY_DOCUMENT)
            if url == f"{ISSUER}/userinfo":
                return FakeResponse({"sub": "user-123", "email": "user@example.com"})
            raise AssertionError(f"unexpected GET {url}")

        mock_get.side_effect = get_side_effect
        mock_post.return_value = FakeResponse(
            {"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}
        )

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with _mock_jwks(public_key):
            provider.set_token_data()
            provider.set_user_data()
        assert provider.user_data["email"] == "user@example.com"

    @patch("plane.authentication.provider.oauth.oidc.requests.post")
    @patch("plane.authentication.provider.oauth.oidc.requests.get")
    def test_missing_id_token_rejected(self, mock_get, mock_post, oidc_config, django_request):
        _mock_discovery(mock_get)
        mock_post.return_value = FakeResponse({"access_token": "test-access-token", "expires_in": 3600})

        provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
        with pytest.raises(AuthenticationException) as exc_info:
            provider.set_token_data()
        assert exc_info.value.error_message == "OIDC_INVALID_ID_TOKEN"


@pytest.mark.unit
class TestOidcGroupsClaimExtraction:
    def _login(self, django_request, private_key, public_key, userinfo, id_token_overrides=None):
        id_token = _signed_id_token(private_key, **(id_token_overrides or {}))

        def get_side_effect(url, *args, **kwargs):
            if url == f"{ISSUER}/.well-known/openid-configuration":
                return FakeResponse(DISCOVERY_DOCUMENT)
            if url == f"{ISSUER}/userinfo":
                return FakeResponse(userinfo)
            raise AssertionError(f"unexpected GET {url}")

        with patch("plane.authentication.provider.oauth.oidc.requests.get", side_effect=get_side_effect), patch(
            "plane.authentication.provider.oauth.oidc.requests.post",
            return_value=FakeResponse({"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}),
        ):
            provider = OidcOAuthProvider(request=django_request, code="test-code", nonce="test-nonce")
            with _mock_jwks(public_key):
                provider.set_token_data()
                provider.set_user_data()
            return provider

    def test_groups_extracted_from_userinfo_default_claim(self, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com", "groups": ["team-a", "team-b"]},
        )
        assert provider.user_data["user"]["groups"] == ["team-a", "team-b"]

    def test_groups_claim_name_configurable(self, db, django_request, rsa_keypair):
        for key, value in (
            ("OIDC_ISSUER", ISSUER),
            ("OIDC_CLIENT_ID", CLIENT_ID),
            ("OIDC_CLIENT_SECRET", CLIENT_SECRET),
            ("OIDC_GROUPS_CLAIM", "roles"),
        ):
            InstanceConfiguration.objects.create(key=key, value=value, is_encrypted=False, category="OIDC")
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com", "roles": ["admin-role"]},
        )
        assert provider.user_data["user"]["groups"] == ["admin-role"]

    def test_groups_claim_supports_nested_dot_path(self, db, django_request, rsa_keypair):
        """Keycloak-style client roles: resource_access.<client>.roles, nested in the ID
        token rather than exposed as a top-level claim."""
        for key, value in (
            ("OIDC_ISSUER", ISSUER),
            ("OIDC_CLIENT_ID", CLIENT_ID),
            ("OIDC_CLIENT_SECRET", CLIENT_SECRET),
            ("OIDC_GROUPS_CLAIM", "resource_access.plane.roles"),
        ):
            InstanceConfiguration.objects.create(key=key, value=value, is_encrypted=False, category="OIDC")
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com"},
            id_token_overrides={"resource_access": {"plane": {"roles": ["admin", "member"]}}},
        )
        assert provider.user_data["user"]["groups"] == ["admin", "member"]

    def test_groups_fallback_to_id_token_claim(self, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com"},
            id_token_overrides={"groups": ["from-id-token"]},
        )
        assert provider.user_data["user"]["groups"] == ["from-id-token"]

    def test_missing_groups_claim_defaults_to_empty_list(self, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request, private_key, public_key, {"sub": "user-123", "email": "user@example.com"}
        )
        assert provider.user_data["user"]["groups"] == []

    def test_string_groups_claim_wrapped_in_list(self, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com", "groups": "solo-group"},
        )
        assert provider.user_data["user"]["groups"] == ["solo-group"]

    def test_non_list_non_string_groups_claim_ignored(self, oidc_config, django_request, rsa_keypair):
        private_key, public_key = rsa_keypair
        provider = self._login(
            django_request,
            private_key,
            public_key,
            {"sub": "user-123", "email": "user@example.com", "groups": {"unexpected": "shape"}},
        )
        assert provider.user_data["user"]["groups"] == []
