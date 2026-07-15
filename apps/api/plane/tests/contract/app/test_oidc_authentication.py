# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import uuid
from unittest.mock import MagicMock, patch

import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from plane.db.models import User
from plane.license.models import Instance


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
