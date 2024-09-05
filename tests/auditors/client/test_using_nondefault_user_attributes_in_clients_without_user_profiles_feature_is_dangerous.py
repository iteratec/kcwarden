import pytest
from unittest.mock import Mock

from kcwarden.auditors.client.using_nondefault_user_attributes_in_clients_without_user_profiles_feature_is_dangerous import (
    UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous,
)

DEFAULT_ATTRIBUTES = [
    "firstName",
    "nickname",
    "zoneinfo",
    "lastName",
    "username",
    "middleName",
    "picture",
    "birthdate",
    "locale",
    "website",
    "gender",
    "updatedAt",
    "profile",
    "phoneNumber",
    "phoneNumberVerified",
    "mobile_number",
    "email",
    "emailVerified",
]


class TestUsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous:
    @pytest.fixture
    def auditor(self, database, default_config):
        auditor_instance = UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous(
            database, default_config
        )
        auditor_instance._DB = Mock()
        return auditor_instance

    def test_should_consider_client(self, mock_client, auditor):
        # Set up mock realm response
        realm = Mock()
        realm.has_declarative_user_profiles_enabled.return_value = False
        mock_client.get_realm.return_value = realm

        assert (
            auditor.should_consider_client(mock_client) is True
        )  # Consider client if user profiles feature is not enabled

    @pytest.mark.parametrize(
        "mapper_config, expected",
        [
            ({"protocol_mapper": "oidc-usermodel-attribute-mapper", "user.attribute": "custom_attribute"}, True),
            (
                {"protocol_mapper": "oidc-usermodel-attribute-mapper", "user.attribute": "email"},
                False,
            ),  # 'email' is a default attribute
            (
                {"protocol_mapper": "other-mapper-type", "user.attribute": "custom_attribute"},
                False,
            ),  # Not the right type of mapper
        ],
    )
    def test_mapper_references_non_default_user_attribute(self, auditor, mapper_config, expected):
        mapper = Mock()
        mapper.get_protocol_mapper.return_value = mapper_config["protocol_mapper"]
        mapper.get_config.return_value = {"user.attribute": mapper_config["user.attribute"]}
        result = auditor.mapper_references_non_default_user_attribute(mapper)
        assert result == expected

    def test_audit_function_no_findings(self, mock_client, auditor):
        # Setup client and mappers
        mock_client.get_realm.return_value.has_declarative_user_profiles_enabled.return_value = True
        mapper = Mock()
        mapper.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper.get_config.return_value = {"user.attribute": "email"}  # 'email' is a default attribute
        mock_client.get_protocol_mappers.return_value = [mapper]
        auditor._DB.get_all_clients.return_value = [mock_client]

        results = list(auditor.audit())
        assert len(results) == 0

    def test_audit_function_with_findings(self, mock_client, auditor):
        # Setup client and mappers
        realm = Mock()
        realm.has_declarative_user_profiles_enabled.return_value = False
        mock_client.get_realm.return_value = realm
        mock_client.is_oidc_client.return_value = True
        mock_client.is_public.return_value = False
        mock_client.has_service_account_enabled.return_value = True

        mapper = Mock()
        mapper.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper.get_config.return_value = {"user.attribute": "custom_attribute"}
        mock_client.get_protocol_mappers.return_value = [mapper]

        auditor._DB.get_all_clients.return_value = [mock_client]
        results = list(auditor.audit())
        assert len(results) == 1
        finding = results[0].to_dict()
        assert finding["additional_details"]["used-attribute"] == "custom_attribute"

    def test_audit_function_multiple_clients(self, auditor):
        # Create separate mock clients with distinct settings
        client1 = Mock()
        realm1 = Mock()
        realm1.has_declarative_user_profiles_enabled.return_value = False
        client1.get_realm.return_value = realm1
        mapper1 = Mock()
        mapper1.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper1.get_config.return_value = {"user.attribute": "custom_attribute"}
        client1.get_protocol_mappers.return_value = [mapper1]

        client2 = Mock()
        realm2 = Mock()
        realm2.has_declarative_user_profiles_enabled.return_value = True
        client2.get_realm.return_value = realm2
        mapper2 = Mock()
        mapper2.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
        mapper2.get_config.return_value = {"user.attribute": "name"}
        client2.get_protocol_mappers.return_value = [mapper2]

        auditor._DB.get_all_clients.return_value = [client1, client2]
        results = list(auditor.audit())
        assert len(results) == 1  # Expect findings from client1 only
