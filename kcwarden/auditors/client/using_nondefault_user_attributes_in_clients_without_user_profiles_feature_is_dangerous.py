from kcwarden.auditors.scope.using_nondefault_user_attributes_in_scopes_without_user_profiles_feature_is_dangerous import (
    UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous,
)
from kcwarden.api import Auditor
from kcwarden.custom_types.result import Severity


# TODO Create versions of the profile auditors for the default attributes


class UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Client uses user attributes, but server does not have User Profiles feature enabled"
    LONG_DESCRIPTION = "Keycloak allows assigning attributes to users. In addition to the default attributes (like name, email, phone number, etc.) you can also add custom attributes. By default, any user is allowed to edit their own attributes when signing up or accessing the default user console. This means that you MUST NOT store sensitive information in the attributes that you rely on in other systems (e.g., a customer number that is used to link their Keycloak account to a customer database). You can prevent the user from editing their own attributes using the experimental User Profiles feature of Keycloak and defining a policy that controls who is allowed to edit specific attributes. See the linked documentation for details."
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#user-profile"

    def should_consider_client(self, client) -> bool:
        # If the client's realm has activated the user profiles feature, the client
        # is not affected no matter which mappers it has.
        return self.is_not_ignored(client) and not client.get_realm().has_declarative_user_profiles_enabled()

    @staticmethod
    def mapper_references_non_default_user_attribute(mapper) -> bool:
        # The mapper type must be oidc-usermodel-attribute-mapper
        # The referenced user attribute must be a non-default user attribute (we will have a separate auditor for default user attributes)
        return (
            mapper.get_protocol_mapper() == "oidc-usermodel-attribute-mapper"
            and mapper.get_config()["user.attribute"]
            not in UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous.DEFAULT_ATTRIBUTES
        )

    def audit(self):
        # First, we need to determine if there are any clients that are actually using
        # user attributes. As far as I know, the only way to use them which can be
        # detected from the Keycloak configuration is using a mapper in a client or scope.
        # Scopes are checked in UsingNonDefaultUserAttributesInScopesWithoutUserAccountsFeatureIsDangerous
        # (It may be possible to also gain access to the attributes using other APIs,
        # but these cannot be identified from looking at the Keycloak configuration alone).
        for client in self._DB.get_all_clients():
            if self.should_consider_client(client):
                # Check the mappers of the client
                for mapper in client.get_protocol_mappers():
                    if self.mapper_references_non_default_user_attribute(mapper):
                        yield self.generate_finding(
                            client, additional_details={"used-attribute": mapper.get_config()["user.attribute"]}
                        )
