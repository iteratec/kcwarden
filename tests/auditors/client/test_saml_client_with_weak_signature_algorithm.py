import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_with_weak_signature_algorithm import SamlClientWithWeakSignatureAlgorithm


class TestSamlClientWithWeakSignatureAlgorithm:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWithWeakSignatureAlgorithm(database, default_config)
        auditor_instance._DB = Mock()
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "is_saml, is_ignored, expected",
        [
            (True, False, True),
            (False, False, False),
            (True, True, False),
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, is_saml, is_ignored, expected):
        mock_client.is_saml_client.return_value = is_saml
        auditor.is_not_ignored.return_value = not is_ignored
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "algorithm, expected_findings",
        [
            ("RSA_SHA1", 1),
            ("DSA_SHA1", 1),
            ("RSA_SHA256", 0),
            ("RSA_SHA512", 0),
            (None, 0),
            ("garbage", 0),
        ],
    )
    def test_audit_logic(self, mock_client, auditor, algorithm, expected_findings):
        mock_client.is_saml_client.return_value = True
        mock_client.get_saml_signature_algorithm.return_value = algorithm
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == expected_findings

        if expected_findings > 0:
            assert results[0].additional_details["detected_algorithm"] == algorithm

    def test_audit_mixed_clients(self, auditor, create_mock_client):
        client_oidc = create_mock_client(name="oidc", is_saml_client=False)

        client_strong = create_mock_client(name="strong", is_saml_client=True)
        client_strong.get_saml_signature_algorithm.return_value = "RSA_SHA256"

        client_weak = create_mock_client(name="weak", is_saml_client=True)
        client_weak.get_saml_signature_algorithm.return_value = "RSA_SHA1"

        auditor._DB.get_all_clients.return_value = [client_oidc, client_strong, client_weak]

        results = list(auditor.audit())

        assert len(results) == 1
        assert results[0]._offending_object.get_name() == "weak"
        assert results[0].additional_details["detected_algorithm"] == "RSA_SHA1"
