from unittest import mock

import pytest

from kcwarden.auditors.realm.keycloak_version_should_be_up_to_date import KeycloakVersionShouldBeUpToDate
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Severity

UUT = "KeycloakVersionShouldBeUpToDate"

KEYCLOAK_VERSION_PATCH_TARGET = (
    "kcwarden.auditors.realm.keycloak_version_should_be_up_to_date.get_latest_keycloak_version"
)


class TestKeycloakVersionShouldBeUpToDate:
    @pytest.fixture
    def auditor(self, mock_database, default_config):
        return KeycloakVersionShouldBeUpToDate(mock_database, default_config)

    def test_audit__given_the_latest_keycloak_version(self, auditor, mock_realm: Realm):
        with mock.patch(KEYCLOAK_VERSION_PATCH_TARGET) as keycloak_version_mock:
            keycloak_version_mock.return_value = "99.9.9"
            # Setup realm with a fictional version that is the latest one
            mock_realm.get_keycloak_version.return_value = "99.9.9"
            auditor._DB.get_all_realms.return_value = [mock_realm]

            results = list(auditor.audit())
            assert len(results) == 0
            keycloak_version_mock.assert_called_once()

    def test_audit__given_an_outdated_keycloak_version(self, auditor, mock_realm: Realm):
        with mock.patch(KEYCLOAK_VERSION_PATCH_TARGET) as keycloak_version_mock:
            keycloak_version_mock.return_value = "99.9.9"
            # Setup realm with a fictional version that is old
            mock_realm.get_keycloak_version.return_value = "20.9.9"
            auditor._DB.get_all_realms.return_value = [mock_realm]

            results = list(auditor.audit())
            assert len(results) == 1
            result = results[0]
            assert result.get_reporting_auditor() == UUT
            assert result.severity == Severity.Medium
            keycloak_version_mock.assert_called_once()

    def test_audit__given_an_outdated_redhat_keycloak_version(self, auditor, mock_realm: Realm):
        with mock.patch(KEYCLOAK_VERSION_PATCH_TARGET) as keycloak_version_mock:
            keycloak_version_mock.return_value = "99.9.9"
            # Setup realm with a fictional RedHat version
            mock_realm.get_keycloak_version.return_value = "20.9.9.redhat-00001"
            auditor._DB.get_all_realms.return_value = [mock_realm]

            results = list(auditor.audit())
            assert len(results) == 1
            result = results[0]
            assert result.get_reporting_auditor() == "KeycloakVersionShouldBeUpToDate"
            assert result.severity == Severity.Low
            keycloak_version_mock.assert_called_once()

    def test_audit__given_an_undetermined_latest_version(self, auditor, mock_realm: Realm):
        with mock.patch(KEYCLOAK_VERSION_PATCH_TARGET) as keycloak_version_mock:
            keycloak_version_mock.return_value = None
            # Setup realm with a fictional version
            mock_realm.get_keycloak_version.return_value = "99.9.9"
            auditor._DB.get_all_realms.return_value = [mock_realm]

            results = list(auditor.audit())
            assert len(results) == 1
            keycloak_version_mock.assert_called_once()
