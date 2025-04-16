import pytest
from unittest.mock import Mock

from kcwarden.auditors.realm.realm_brute_force_protection_disabled import RealmBruteForceProtectionDisabled


@pytest.fixture
def auditor(mock_database, default_config):
    return RealmBruteForceProtectionDisabled(mock_database, default_config)


def test_should_consider_realm(mock_realm, auditor):
    assert auditor.should_consider_realm(mock_realm) is True  # Always consider unless specifically ignored


@pytest.mark.parametrize(
    "is_brute_force_protected, expected",
    [
        (True, False),  # Brute-force protection enabled
        (False, True),  # Brute-force protection disabled
    ],
)
def test_realm_has_brute_force_protection_disabled(auditor, is_brute_force_protected, expected, mock_realm):
    mock_realm.is_brute_force_protected.return_value = is_brute_force_protected
    assert auditor.realm_has_brute_force_protection_disabled(mock_realm) == expected


def test_audit_function_no_findings(auditor, mock_realm):
    # Setup realm with brute-force protection enabled
    mock_realm.is_brute_force_protected.return_value = True
    auditor._DB.get_all_realms.return_value = [mock_realm]

    results = list(auditor.audit())
    assert len(results) == 0


def test_audit_function_with_findings(auditor, mock_realm):
    # Setup realm with email verification disabled
    mock_realm.is_brute_force_protected.return_value = False
    auditor._DB.get_all_realms.return_value = [mock_realm]

    results = list(auditor.audit())
    assert len(results) == 1


def test_audit_function_multiple_realms(auditor):
    # Create separate mock realms with distinct settings
    realm1 = Mock()
    realm1.is_brute_force_protected.return_value = False

    realm2 = Mock()
    realm2.is_brute_force_protected.return_value = True

    realm3 = Mock()
    realm3.is_brute_force_protected.return_value = False

    auditor._DB.get_all_realms.return_value = [realm1, realm2, realm3]
    results = list(auditor.audit())
    assert len(results) == 2  # Expect findings from realm1 and realm3, but not from realm2
