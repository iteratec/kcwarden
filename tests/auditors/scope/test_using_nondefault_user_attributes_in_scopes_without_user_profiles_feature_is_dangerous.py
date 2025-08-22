from unittest import mock

import pytest
from unittest.mock import Mock

from kcwarden.auditors.scope.using_nondefault_user_attributes_in_scopes_without_user_profiles_feature_is_dangerous import (
    UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous,
)
from kcwarden.custom_types.keycloak_object import Realm


class TestUsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous(
            database, default_config
        )
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_scope(self, mock_scope, auditor):
        assert auditor.should_consider_scope(mock_scope) is True  # Always consider unless specifically ignored

    @pytest.mark.parametrize(
        "mapper_config, expected",
        [
            (
                {"protocol_mapper": "oidc-usermodel-attribute-mapper", "user.attribute": "custom_attribute"},
                True,
            ),  # Non-default attribute
            (
                {"protocol_mapper": "oidc-usermodel-attribute-mapper", "user.attribute": "firstName"},
                False,
            ),  # Default attribute
            ({"protocol_mapper": "other-mapper", "user.attribute": "custom_attribute"}, False),  # Wrong mapper type
        ],
    )
    def test_mapper_references_non_default_user_attribute(self, auditor, mapper_config, expected):
        mapper = Mock()
        mapper.get_protocol_mapper.return_value = mapper_config["protocol_mapper"]
        mapper.get_config.return_value = {"user.attribute": mapper_config["user.attribute"]}
        assert auditor.mapper_references_non_default_user_attribute(mapper) == expected

    def test_audit_function_no_findings(self, auditor, mock_scope):
        # Setup scope in a realm with user profiles enabled
        realm = Mock()
        realm.has_declarative_user_profiles_enabled_legacy_option.return_value = True
        mock_scope.get_realm.return_value = realm
        mock_scope.get_protocol_mappers.return_value = []
        auditor._DB.get_all_scopes.return_value = [mock_scope]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, auditor, mock_scope):
        # Setup scope in a realm without user profiles enabled
        realm = Mock()
        realm.has_declarative_user_profiles_enabled_legacy_option.return_value = False
        mock_scope.get_realm.return_value = realm
        mapper = Mock()
        mapper.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper.get_config.return_value = {"user.attribute": "custom_attribute"}
        mock_scope.get_protocol_mappers.return_value = [mapper]
        mock_scope.get_name.return_value = "mock-scope"
        auditor._DB.get_all_scopes.return_value = [mock_scope]

        # Prepare clients to test the output details
        client_1 = Mock()
        client_1.get_name.return_value = "optional_scope_client"
        client_1.get_default_client_scopes.return_value = ["mock-scope", "other-scope"]
        client_1.get_optional_client_scopes.return_value = []

        client_2 = Mock()
        client_2.get_name.return_value = "default_scope_client"
        client_2.get_default_client_scopes.return_value = ["other-scope"]
        client_2.get_optional_client_scopes.return_value = ["mock-scope"]

        client_3 = Mock()
        client_3.get_name.return_value = "no_scope_client"
        client_3.get_default_client_scopes.return_value = ["other-scope"]
        client_3.get_optional_client_scopes.return_value = ["another-scope"]

        # Prepare database
        auditor._DB.get_all_clients.return_value = [client_1, client_2, client_3]

        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0].to_dict()
        assert finding["additional_details"]["used-attribute"] == "custom_attribute"
        assert finding["additional_details"]["clients-using-scope"] == [client_1.get_name(), client_2.get_name()]

    def test_audit_function_multiple_scopes(self, auditor):
        # Create separate mock scopes with distinct settings in different realms
        scope1, scope2, scope3 = Mock(), Mock(), Mock()
        realm1: Realm = mock.create_autospec(Realm, instance=True)
        realm2: Realm = mock.create_autospec(Realm, instance=True)
        realm1.get_unmanaged_attribute_policy.return_value = "ENABLED"
        realm2.get_unmanaged_attribute_policy.return_value = "DISABLED"
        scope1.get_realm.return_value = realm1
        scope2.get_realm.return_value = realm1
        scope3.get_realm.return_value = realm2
        scope1.get_name.return_value = "scope1"
        scope2.get_name.return_value = "scope2"
        scope3.get_name.return_value = "scope3"
        mapper1 = Mock()
        mapper1.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper1.get_config.return_value = {"user.attribute": "custom_attribute"}
        scope1.get_protocol_mappers.return_value = [mapper1]
        scope2.get_protocol_mappers.return_value = []
        scope3.get_protocol_mappers.return_value = [mapper1]

        auditor._DB.get_all_scopes.return_value = [scope1, scope2, scope3]

        # Prepare clients to test the output details
        client_1 = Mock()
        client_1.get_name.return_value = "optional_scope_client"
        client_1.get_default_client_scopes.return_value = ["scope1", "other-scope"]
        client_1.get_optional_client_scopes.return_value = []

        client_2 = Mock()
        client_2.get_name.return_value = "default_scope_client"
        client_2.get_default_client_scopes.return_value = ["other-scope"]
        client_2.get_optional_client_scopes.return_value = ["scope1"]

        client_3 = Mock()
        client_3.get_name.return_value = "no_scope_client"
        client_3.get_default_client_scopes.return_value = ["other-scope"]
        client_3.get_optional_client_scopes.return_value = ["another-scope"]

        # Prepare database
        auditor._DB.get_all_clients.return_value = [client_1, client_2, client_3]

        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings from scope1 only
        finding = results[0].to_dict()
        assert finding["additional_details"]["used-attribute"] == "custom_attribute"
        assert finding["additional_details"]["clients-using-scope"] == [client_1.get_name(), client_2.get_name()]
