from kcwarden.api import Auditor
from kcwarden.auditors.subchecks.realm import users_can_edit_attributes
from kcwarden.custom_types.result import Severity
from kcwarden.database import helper

# TODO Create versions of the profile auditors for the default attributes


class UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous(Auditor):
    DEFAULT_SEVERITY = Severity.High
    SHORT_DESCRIPTION = "Scope uses user attributes, but server does not have User Profiles feature enabled"
    LONG_DESCRIPTION = (
        "Keycloak allows assigning attributes to users. In addition to the default attributes "
        "(like name, email, phone number, etc.) you can also add custom attributes. "
        "By default, any user is allowed to edit their own attributes "
        "when signing up or accessing the default user console. "
        "This means that you MUST NOT store sensitive information in the attributes "
        "that you rely on in other systems (e.g., a customer number "
        "that is used to link their Keycloak account to a customer database). "
        "You can prevent the user from editing their own attributes "
        "using the User Profiles feature of Keycloak and "
        "defining a policy that controls who is allowed to edit specific attributes. "
        "See the linked documentation for details. "
        "Note that this auditor might generate false-positives "
        "when the attribute is imported via LDAP user federation and set to read-only there."
    )
    REFERENCE = "https://www.keycloak.org/docs/latest/server_admin/#user-profile"
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

    def should_consider_scope(self, scope) -> bool:
        return self.is_not_ignored(scope)

    def mapper_references_non_default_user_attribute(self, mapper) -> bool:
        return (
            mapper.get_protocol_mapper() == "oidc-usermodel-attribute-mapper"
            and mapper.get_config()["user.attribute"] not in self.DEFAULT_ATTRIBUTES
        )

    def audit(self):
        # First, we need to determine if there are any scopes that are actually using
        # user attributes. As far as I know, the only way to use them which can be
        # detected from the Keycloak configuration is using a mapper in a client or scope.
        # Clients are checked in a separate auditor (below).
        # (It may be possible to also gain access to the attributes using other APIs,
        # but these cannot be identified from looking at the Keycloak configuration alone).
        for scope in self._DB.get_all_scopes():
            # If the scopes' realm has activated the user profiles feature, the scope
            # is not affected no matter which mappers it has.
            if self.should_consider_scope(scope) and users_can_edit_attributes(scope.get_realm()):
                # Check the mappers of the scope
                for mapper in scope.get_protocol_mappers():
                    if self.mapper_references_non_default_user_attribute(mapper):
                        yield self.generate_finding(
                            scope,
                            additional_details={
                                "used-attribute": mapper.get_config()["user.attribute"],
                                "clients-using-scope": [
                                    client.get_name() for client in helper.get_clients_with_scope(self._DB, scope)
                                ],
                            },
                        )
