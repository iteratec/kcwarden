from unittest.mock import Mock

import pytest

from kcwarden.auditors.client.client_authentication_via_mtls_or_jwt_recommended import (
    ClientAuthenticationViaMTLSOrJWTRecommended,
)


class TestClientAuthenticationViaMTLSOrJWTRecommended:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = ClientAuthenticationViaMTLSOrJWTRecommended(database, default_config)
        auditor_instance._DB = Mock()
        return auditor_instance

    @pytest.mark.parametrize(
        "is_oidc,is_public,expected",
        [
            (True, False, True),  # OIDC, confidential client
            (False, False, False),  # Non-OIDC client should be excluded
            (True, True, False),  # Public client should be excluded
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_oidc, is_public, expected):
        mock_client.is_oidc_client.return_value = is_oidc
        mock_client.is_public.return_value = is_public
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "client_authenticator_type, should_alert",
        [
            ("client-secret", True),  # Using client-secret, should alert
            ("unknown-method", True),  # Unknown method, should alert
            ("federated-jwt", False),  # Using Federated JWT, should not alert
            ("client-jwt", False),  # Using signed JWT, should not alert
            ("client-secret-jwt", False),  # Using client-secret JWT, should not alert
            ("client-x509", False),  # Using mTLS (x509), should not alert
        ],
    )
    def test_client_does_not_use_mtls_or_jwt_auth(self, mock_client, auditor, client_authenticator_type, should_alert):
        mock_client.get_client_authenticator_type.return_value = client_authenticator_type
        assert auditor.client_does_not_use_mtls_or_jwt_auth(mock_client) == should_alert

    def test_audit_function_no_findings(self, confidential_client, auditor):
        confidential_client.get_client_authenticator_type.return_value = "federated-jwt"
        auditor._DB.get_all_clients.return_value = [confidential_client]
        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, confidential_client, auditor):
        confidential_client.get_client_authenticator_type.return_value = "client-secret"
        auditor._DB.get_all_clients.return_value = [confidential_client]
        results = list(auditor.audit())
        assert len(results) == 1
        assert results[0].additional_details["client_authenticator_type"] == "client-secret"

    def test_audit_function_multiple_clients(self, confidential_client, auditor):
        # client-secret is returned twice: once for the check, once for additional_details in generate_finding
        confidential_client.get_client_authenticator_type.side_effect = [
            "client-secret",
            "client-secret",
            "federated-jwt",
            "client-x509",
        ]
        auditor._DB.get_all_clients.return_value = [confidential_client, confidential_client, confidential_client]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings from one client
