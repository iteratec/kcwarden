import pytest
from unittest.mock import Mock, MagicMock

from kcwarden.auditors.client.saml_client_weak_algorithm import SamlClientWeakAlgorithmCheck

class TestSamlClientWeakAlgorithmCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWeakAlgorithmCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mock is_not_ignored to return True by default
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, is_ignored, expected",
        [
            ("saml", False, True),      # SAML and not ignored -> Consider
            ("openid-connect", False, False), # OIDC -> Do not consider
            ("saml", True, False),      # SAML but ignored -> Do not consider
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, is_ignored, expected):
        mock_client.get_protocol.return_value = protocol
        auditor.is_not_ignored.return_value = not is_ignored
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "algorithm, expected",
        [
            ("RSA_SHA1", True),         # Weak
            ("DSA_SHA1", True),         # Weak
            ("RSA_SHA256", False),      # Strong
            ("RSA_SHA512", False),      # Strong
            ("", False),                # Empty/Missing
            (None, False),              # None
        ],
    )
    def test_is_vulnerable(self, mock_client, auditor, algorithm, expected):
        attributes = {}
        if algorithm is not None:
            attributes["saml.signature.algorithm"] = algorithm
            
        mock_client.get_attributes.return_value = attributes
        assert auditor.is_vulnerable(mock_client) == expected

    def test_audit_function_no_findings_strong_algo(self, auditor):
        # Use MagicMock to avoid "Mock object has no attribute 'get'" error
        client = MagicMock()
        client.get_protocol.return_value = "saml"
        attributes = {"saml.signature.algorithm": "RSA_SHA256"}
        
        # Setup both property access and method access
        client.get_attributes.return_value = attributes
        client.attributes = attributes
        
        auditor._DB.get_all_clients.return_value = [client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings_weak_algo(self, auditor):
        # Use MagicMock to allow client.get() even if the real Client class doesn't have it
        client = MagicMock()
        client.get_protocol.return_value = "saml"
        attributes = {"saml.signature.algorithm": "RSA_SHA1"}
        
        client.get_attributes.return_value = attributes
        client.attributes = attributes
        
        auditor._DB.get_all_clients.return_value = [client]

        results = list(auditor.audit())
        assert len(results) == 1
        
        finding = results[0]
        assert finding.additional_details["detected_algorithm"] == "RSA_SHA1"

    def test_audit_function_missing_attributes_fallback(self, auditor):
        # Use MagicMock so we can define .get() behavior explicitly
        client = MagicMock()
        client.get_protocol.return_value = "saml"
        attributes = {"saml.signature.algorithm": "RSA_SHA1"}
        
        # 1. is_vulnerable checks get_attributes()
        client.get_attributes.return_value = attributes
        
        # 2. audit checks .attributes (we delete it to force fallback)
        del client.attributes
        
        # 3. audit fallback calls .get("attributes")
        def get_side_effect(key, default=None):
            if key == "attributes":
                return attributes
            return default
        client.get.side_effect = get_side_effect

        auditor._DB.get_all_clients.return_value = [client]

        results = list(auditor.audit())
        assert len(results) == 1
        assert results[0].additional_details["detected_algorithm"] == "RSA_SHA1"

    def test_audit_function_ignores_non_saml(self, auditor):
        client = MagicMock()
        client.get_protocol.return_value = "openid-connect"
        # Even if it has weak algo attributes, it should be ignored
        client.get_attributes.return_value = {"saml.signature.algorithm": "RSA_SHA1"}
        
        auditor._DB.get_all_clients.return_value = [client]
        results = list(auditor.audit())
        assert len(results) == 0