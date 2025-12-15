import pytest
from unittest.mock import Mock, patch

from kcwarden.auditors.realm.password_hashing_iterations_too_low import PasswordHashingIterationsTooLow


class TestPasswordHashingIterationsTooLow:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return PasswordHashingIterationsTooLow(mock_database, default_config)

    def test_should_consider_realm(self, mock_realm, auditor):
        assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "algorithm, iterations, expected",
        [
            ("argon2", 10, False),  # Argon2 is exempt from this check
            ("pbkdf2-sha512", 200000, True),  # Below minimum (210000)
            ("pbkdf2-sha512", 210000, False),  # Equal to minimum
            ("pbkdf2-sha512", 300000, False),  # Above minimum
            ("pbkdf2-sha256", 500000, True),  # Below minimum (600000)
            ("pbkdf2-sha256", 600000, False),  # Equal to minimum
            ("pbkdf2-sha256", 700000, False),  # Above minimum
            ("pbkdf2", 1000000, True),  # Below minimum (1300000)
            ("pbkdf2", 1300000, False),  # Equal to minimum
            ("pbkdf2", 1500000, False),  # Above minimum
            ("unknown-algorithm", 100000, False),  # Unknown algorithm
        ],
    )
    def test_is_iterations_too_low(self, auditor, mock_realm, algorithm, iterations, expected):
        with patch.object(mock_realm, "get_password_hash_algorithm", return_value=algorithm):
            with patch.object(mock_realm, "get_password_hash_iterations", return_value=iterations):
                assert auditor.is_iterations_too_low(mock_realm) == expected

    def test_audit_function_no_findings(self, auditor, mock_realm):
        # Setup realm with sufficient iterations
        with patch.object(auditor, "is_iterations_too_low", return_value=False):
            auditor._DB.get_all_realms.return_value = [mock_realm]
            results = list(auditor.audit())
            assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_realm):
        # Setup realm with insufficient iterations
        with patch.object(auditor, "is_iterations_too_low", return_value=True):
            with patch.object(mock_realm, "get_password_hash_algorithm", return_value="pbkdf2-sha256"):
                with patch.object(mock_realm, "get_password_hash_iterations", return_value=300000):
                    auditor._DB.get_all_realms.return_value = [mock_realm]
                    results = list(auditor.audit())
                    assert len(results) == 1
                    assert results[0].additional_details["algorithm"] == "pbkdf2-sha256"
                    assert results[0].additional_details["current_iterations"] == 300000
                    assert results[0].additional_details["minimum_recommended_iterations"] == 600000

    def test_audit_function_multiple_realms(self, auditor):
        # Create separate mock realms with distinct settings
        realm1 = Mock()
        realm1.get_password_hash_algorithm.return_value = "pbkdf2"
        realm1.get_password_hash_iterations.return_value = 1000000
        realm1.get_password_policy.return_value = ""

        realm2 = Mock()
        realm2.get_password_hash_algorithm.return_value = "pbkdf2"
        realm2.get_password_hash_iterations.return_value = 1500000
        realm2.get_password_policy.return_value = ""

        realm3 = Mock()
        realm3.get_password_hash_algorithm.return_value = "pbkdf2"
        realm3.get_password_hash_iterations.return_value = 1000000
        realm3.get_password_policy.return_value = ""

        auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
        results = list(auditor.audit())
        assert len(results) == 2  # Expect findings from realm1 and realm3, but not from realm2
