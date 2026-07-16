# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import time
import uuid
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from plane.db.models import User
from plane.license.models import Instance, InstanceConfiguration


@pytest.fixture
def setup_instance(db):
    """Create and configure an instance for authentication tests"""
    instance_id = uuid.uuid4() if not Instance.objects.exists() else Instance.objects.first().id

    instance, _ = Instance.objects.update_or_create(
        id=instance_id,
        defaults={
            "instance_name": "Test Instance",
            "instance_id": str(uuid.uuid4()),
            "current_version": "1.0.0",
            "domain": "http://localhost:8000",
            "last_checked_at": timezone.now(),
            "is_setup_done": True,
        },
    )
    return instance


@pytest.fixture
def django_client():
    """Return a Django test client with User-Agent header for handling redirects"""
    return Client(HTTP_USER_AGENT="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1")


@pytest.mark.contract
class TestOIDCOauthInitiateEndpoint:
    @pytest.mark.django_db
    def test_instance_not_configured(self, django_client):
        """No Instance row at all -> redirected with INSTANCE_NOT_CONFIGURED, no provider touched"""
        url = reverse("oidc-initiate")
        response = django_client.get(url, follow=True)
        assert "INSTANCE_NOT_CONFIGURED" in response.redirect_chain[-1][0]

    @pytest.mark.django_db
    def test_oidc_not_configured(self, django_client, setup_instance):
        """Instance is set up but no OIDC issuer/client configured -> OIDC_NOT_CONFIGURED"""
        url = reverse("oidc-initiate")
        response = django_client.get(url, follow=True)
        assert "OIDC_NOT_CONFIGURED" in response.redirect_chain[-1][0]

    @pytest.mark.django_db
    @patch("plane.authentication.views.app.oidc.OidcOAuthProvider")
    def test_redirects_to_authorization_endpoint(self, mock_provider_cls, django_client, setup_instance):
        auth_url = "https://idp.example.com/authorize?client_id=plane-client&state=abc&nonce=def"
        mock_provider = MagicMock()
        mock_provider.get_auth_url.return_value = auth_url
        mock_provider_cls.return_value = mock_provider

        url = reverse("oidc-initiate")
        response = django_client.get(url, follow=False)

        assert response.status_code == 302
        assert response.url == auth_url
        # a fresh state and nonce should have been generated and stashed in the session
        assert django_client.session.get("state")
        assert django_client.session.get("oidc_nonce")
        # the provider should have been constructed with those exact values
        _, kwargs = mock_provider_cls.call_args
        assert kwargs["state"] == django_client.session["state"]
        assert kwargs["nonce"] == django_client.session["oidc_nonce"]


@pytest.mark.contract
class TestOIDCCallbackEndpoint:
    @pytest.mark.django_db
    def test_state_mismatch_rejected(self, django_client, setup_instance):
        session = django_client.session
        session["state"] = "expected-state"
        session.save()

        url = reverse("oidc-callback")
        response = django_client.get(url, {"code": "abc", "state": "wrong-state"}, follow=True)
        assert "OIDC_OAUTH_PROVIDER_ERROR" in response.redirect_chain[-1][0]

    @pytest.mark.django_db
    def test_missing_code_rejected(self, django_client, setup_instance):
        session = django_client.session
        session["state"] = "expected-state"
        session.save()

        url = reverse("oidc-callback")
        response = django_client.get(url, {"state": "expected-state"}, follow=True)
        assert "OIDC_OAUTH_PROVIDER_ERROR" in response.redirect_chain[-1][0]

    @pytest.mark.django_db
    @patch("plane.authentication.views.app.oidc.OidcOAuthProvider")
    def test_successful_login_creates_session(self, mock_provider_cls, django_client, setup_instance):
        user = User.objects.create(email="oidc-user@example.com")
        user.set_password(uuid.uuid4().hex)
        user.is_password_autoset = True
        user.save()

        mock_provider = MagicMock()
        mock_provider.authenticate.return_value = user
        mock_provider_cls.return_value = mock_provider

        session = django_client.session
        session["state"] = "expected-state"
        session["oidc_nonce"] = "expected-nonce"
        session.save()

        url = reverse("oidc-callback")
        response = django_client.get(url, {"code": "test-code", "state": "expected-state"}, follow=False)

        assert response.status_code == 302
        assert "error_code" not in response.url
        assert str(django_client.session["_auth_user_id"]) == str(user.id)
        # the nonce stashed at initiate-time must reach the provider for verification
        _, kwargs = mock_provider_cls.call_args
        assert kwargs["nonce"] == "expected-nonce"


@pytest.mark.contract
class TestOIDCOauthInitiateSpaceEndpoint:
    @pytest.mark.django_db
    def test_instance_not_configured(self, django_client):
        url = reverse("space-oidc-initiate")
        response = django_client.get(url, follow=True)
        assert "INSTANCE_NOT_CONFIGURED" in response.redirect_chain[-1][0]

    @pytest.mark.django_db
    @patch("plane.authentication.views.space.oidc.OidcOAuthProvider")
    def test_redirects_to_authorization_endpoint(self, mock_provider_cls, django_client, setup_instance):
        auth_url = "https://idp.example.com/authorize?client_id=plane-client&state=abc&nonce=def"
        mock_provider = MagicMock()
        mock_provider.get_auth_url.return_value = auth_url
        mock_provider_cls.return_value = mock_provider

        url = reverse("space-oidc-initiate")
        response = django_client.get(url, follow=False)

        assert response.status_code == 302
        assert response.url == auth_url


ISSUER = "https://idp.example.com"
CLIENT_ID = "plane-client"
CLIENT_SECRET = "plane-secret"

DISCOVERY_DOCUMENT = {
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "jwks_uri": f"{ISSUER}/jwks",
}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


def _configure_oidc(enable_profile_sync=True):
    for key, value in (
        ("OIDC_ISSUER", ISSUER),
        ("OIDC_CLIENT_ID", CLIENT_ID),
        ("OIDC_CLIENT_SECRET", CLIENT_SECRET),
        ("ENABLE_OIDC_SYNC", "1" if enable_profile_sync else "0"),
    ):
        InstanceConfiguration.objects.update_or_create(
            key=key, defaults={"value": value, "is_encrypted": False, "category": "OIDC"}
        )


def _run_oidc_login(django_client, email, sub="idp-user-1", given_name=None, family_name=None):
    """Drives the real /auth/oidc/callback/ view end-to-end: real RSA-signed ID token,
    mocked network boundary only (discovery/userinfo/token-exchange HTTP calls and the
    JWKS client), so the full Adapter.complete_login_or_signup() path runs for real
    against the test database."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    now = int(time.time())
    id_token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": sub,
            "iat": now,
            "exp": now + 300,
            "email": email,
            "nonce": "expected-nonce",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    def get_side_effect(url, *args, **kwargs):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return _FakeResponse(DISCOVERY_DOCUMENT)
        if url == f"{ISSUER}/userinfo":
            userinfo = {"sub": sub, "email": email, "email_verified": True}
            if given_name is not None:
                userinfo["given_name"] = given_name
            if family_name is not None:
                userinfo["family_name"] = family_name
            return _FakeResponse(userinfo)
        raise AssertionError(f"unexpected GET {url}")

    signing_key = MagicMock()
    signing_key.key = public_key
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = signing_key

    session = django_client.session
    session["state"] = "expected-state"
    session["oidc_nonce"] = "expected-nonce"
    session.save()

    with patch("plane.authentication.provider.oauth.oidc.requests.get", side_effect=get_side_effect), patch(
        "plane.authentication.provider.oauth.oidc.requests.post",
        return_value=_FakeResponse({"access_token": "test-access-token", "id_token": id_token, "expires_in": 3600}),
    ), patch("plane.authentication.provider.oauth.oidc.PyJWKClient", return_value=jwks_client):
        url = reverse("oidc-callback")
        return django_client.get(url, {"code": "test-code", "state": "expected-state"}, follow=False)


@pytest.mark.contract
class TestOIDCProfileSyncOnRepeatLogin:
    """Regression test for the previously-inverted `is_signup` check in
    Adapter.complete_login_or_signup(): ENABLE_OIDC_SYNC must re-sync profile fields on
    every repeat login, not only (accidentally) at first-time account creation."""

    @pytest.mark.django_db
    def test_repeat_login_resyncs_changed_profile_fields(self, django_client, setup_instance):
        _configure_oidc(enable_profile_sync=True)

        first = _run_oidc_login(
            django_client, "sync-user@example.com", given_name="Old", family_name="Name"
        )
        assert first.status_code == 302
        user = User.objects.get(email="sync-user@example.com")
        assert user.first_name == "Old"
        assert user.last_name == "Name"

        second = _run_oidc_login(
            django_client, "sync-user@example.com", given_name="New", family_name="Person"
        )
        assert second.status_code == 302
        user.refresh_from_db()
        assert user.first_name == "New"
        assert user.last_name == "Person"
