import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.saml_client_weak_algorithm import SamlClientWeakAlgorithmCheck

class TestSamlClientWeakAlgorithmCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWeakAlgorithmCheck(database, default_config)
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

    def test_audit_mixed_clients(self, auditor):
        client_oidc = Mock()
        client_oidc.name = "oidc"
        client_oidc.__str__ = Mock(return_value="oidc")
        client_oidc.is_saml_client.return_value = False
        client_oidc.get_saml_signature_algorithm.return_value = "RSA_SHA1" 

        client_strong = Mock()
        client_strong.name = "strong"
        client_strong.__str__ = Mock(return_value="strong")
        client_strong.is_saml_client.return_value = True
        client_strong.get_saml_signature_algorithm.return_value = "RSA_SHA256"

        client_weak = Mock()
        client_weak.name = "weak"
        client_weak.__str__ = Mock(return_value="weak")
        client_weak.is_saml_client.return_value = True
        client_weak.get_saml_signature_algorithm.return_value = "RSA_SHA1"

        auditor._DB.get_all_clients.return_value = [client_oidc, client_strong, client_weak]
        
        results = list(auditor.audit())
        
        assert len(results) == 1
        assert results[0]._offending_object.name == "weak"
        assert results[0].additional_details['detected_algorithm'] == "RSA_SHA1"