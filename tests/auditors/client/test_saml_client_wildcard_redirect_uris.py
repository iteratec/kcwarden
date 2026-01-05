import pytest
from unittest.mock import Mock

# Adjust the import path to match your project structure
from kcwarden.auditors.client.saml_client_wildcard_redirect_uris import (
    SamlClientWildcardRedirectUriCheck,
)

class TestSamlClientWildcardRedirectUriCheck:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = SamlClientWildcardRedirectUriCheck(database, default_config)
        auditor_instance._DB = Mock()
        # Mocking is_not_ignored to isolate the specific logic of this auditor
        # and avoid dependencies on the base Auditor implementation details.
        auditor_instance.is_not_ignored = Mock(return_value=True)
        return auditor_instance

    @pytest.mark.parametrize(
        "protocol, is_ignored, expected",
        [
            ("saml", False, True),   # SAML client, not ignored -> Consider
            ("oidc", False, False),  # OIDC client -> Do not consider
            ("saml", True, False),   # SAML client but ignored -> Do not consider
            ("openid-connect", False, False), # Specific string check mismatch
        ],
    )
    def test_should_consider_client(self, mock_client, auditor, protocol, is_ignored, expected):
        mock_client.get_protocol.return_value = protocol
        auditor.is_not_ignored.return_value = not is_ignored
        
        assert auditor.should_consider_client(mock_client) == expected

    @pytest.mark.parametrize(
        "uris, expected",
        [
            ([], False),  # Empty list
            (None, False),  # None
            (["https://valid.com"], False),  # Valid URI
            (["https://valid.com/*"], True),  # Wildcard at end
            (["https://valid.com", "https://bad.com/*"], True),  # Mixed valid and invalid
            (["https://valid.com/path*"], True),  # Wildcard on path
            ([" * "], True),  # Wildcard with whitespace (code uses .strip())
            (["https://domain.com/*?query=1"], False),  # Wildcard in middle (not at end)
        ],
    )
    def test_is_vulnerable(self, mock_client, auditor, uris, expected):
        mock_client.get_redirect_uris.return_value = uris
        assert auditor.is_vulnerable(mock_client) == expected

    def test_audit_function_no_findings(self, mock_client, auditor):
        # Setup SAML client with valid URIs
        mock_client.get_protocol.return_value = "saml"
        mock_client.get_redirect_uris.return_value = [
            "https://example.com/callback",
            "https://example.com/saml",
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        # Setup SAML client with a wildcard URI
        mock_client.get_protocol.return_value = "saml"
        bad_uri = "https://example.com/*"
        mock_client.get_redirect_uris.return_value = [
            "https://valid.com",
            bad_uri
        ]
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 1

        finding = results[0]
        # Verify the finding contains the bad URI in additional details
        assert "vulnerable_uris" in finding.additional_details
        assert finding.additional_details["vulnerable_uris"] == [bad_uri]

    def test_audit_function_multiple_clients(self, auditor):
        # 1. Valid SAML Client
        client1 = Mock()
        client1.get_protocol.return_value = "saml"
        client1.get_redirect_uris.return_value = ["https://ok.com"]
        
        # 2. Vulnerable SAML Client
        client2 = Mock()
        client2.get_protocol.return_value = "saml"
        client2.get_redirect_uris.return_value = ["https://bad.com/*"]

        # 3. OIDC Client (Should be ignored even if it has wildcard)
        client3 = Mock()
        client3.get_protocol.return_value = "openid-connect"
        client3.get_redirect_uris.return_value = ["https://bad-oidc.com/*"]

        # 4. Ignored SAML Client (Should be ignored via base class logic)
        client4 = Mock()
        client4.get_protocol.return_value = "saml"
        client4.get_redirect_uris.return_value = ["https://ignored.com/*"]

        auditor._DB.get_all_clients.return_value = [client1, client2, client3, client4]
        
        # We need to make sure is_not_ignored returns False for client4 specifically
        def side_effect_is_not_ignored(client):
            return client != client4
            
        auditor.is_not_ignored.side_effect = side_effect_is_not_ignored

        results = list(auditor.audit())
        
        # Expecting exactly 1 finding (from client2)
        assert len(results) == 1
        assert results[0].additional_details["vulnerable_uris"] == ["https://bad.com/*"]