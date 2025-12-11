from abc import ABC, abstractmethod
from copy import deepcopy
import json


class Dataclass(ABC):
    def __init__(self, raw_data: dict):
        self._d = raw_data
        super().__init__()

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def get_realm(self) -> "Realm":
        raise NotImplementedError()

    def get_type(self) -> str:
        return self.__class__.__name__

    def __str__(self) -> str:
        return f"<{self.get_type()}: {self.get_name()} in Realm {self.get_realm().get_name()}>"


class Realm(Dataclass):
    """
    Currently _d contains the complete dump once, because there is no defined field
    in the dump that encapsulates the realm properties.
    Therefore, no example data set is stored here.
    """

    def get_name(self) -> str:
        return self._d["realm"]

    def get_realm(self) -> "Realm":
        return self

    def is_self_registration_enabled(self) -> bool:
        return self._d["registrationAllowed"]

    def is_verify_email_enabled(self) -> bool:
        return self._d["verifyEmail"]

    def is_brute_force_protected(self) -> bool:
        return self._d["bruteForceProtected"]

    # Token Handling and Validity
    def has_refresh_token_revocation_enabled(self) -> bool:
        return self._d["revokeRefreshToken"]

    def get_refresh_token_maximum_reuse_count(self) -> int:
        return self._d["refreshTokenMaxReuse"]

    def get_access_token_lifespan(self) -> int:
        """Get access token lifespan in seconds."""
        return self._d["accessTokenLifespan"]

    def get_unmanaged_attribute_policy(self) -> str | None:
        try:
            attribute_config = json.loads(
                self._d["components"]
                .get("org.keycloak.userprofile.UserProfileProvider")[0]
                .get("config")
                .get("kc.user.profile.config")[0]
            )
        except TypeError:  # Will be thrown if the UserProfileProvider wasn't found
            return None
        # Default value in Keycloak 26+ is "DISABLED", which will sometimes be omitted from the config file
        return attribute_config.get("unmanagedAttributePolicy", "DISABLED")

    def has_declarative_user_profiles_enabled_legacy_option(self) -> bool:
        return self._d["attributes"].get("userProfileEnabled", "false") == "true"

    def get_keycloak_version(self) -> str:
        return self._d["keycloakVersion"]

    def get_password_policy(self) -> str:
        return self._d.get("passwordPolicy", "")


class RealmRole(Dataclass):
    """
    Example Payload

        {
            "id": "ff7eefd3-03df-4226-a7de-9e7495120bb0",
            "name": "sensitive_composite_role",
            "description": "",
            "composite": true,
            "composites": {
                "realm": [
                    "normal_role",
                    "sensitive-role"
                ]
            },
            "clientRole": false,
            "containerId": "9b8bf6b3-0cea-44aa-9deb-ddc2d331e3c7",
            "attributes": {}
        },
        {
            "id": "eb8fdce9-75b2-41a5-a91a-3a2a7689d3f7",
            "name": "offline_access",
            "description": "${role_offline-access}",
            "composite": false,
            "clientRole": false,
            "containerId": "9b8bf6b3-0cea-44aa-9deb-ddc2d331e3c7",
            "attributes": {}
        },
    """

    def __init__(self, raw_data: dict, realm: Realm):
        super().__init__(raw_data)
        self._realm: Realm = realm

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def is_client_role(self) -> bool:
        assert self._d["clientRole"] is False, "Client role has been parsed as realm role, wtf?!"
        return self._d["clientRole"]

    def is_composite_role(self) -> bool:
        return self._d["composite"]

    def get_composite_roles(self) -> dict[str, list[str | dict[str, list[str]]]]:
        return self._d.get("composites", {})


class ClientRole(Dataclass):
    """
    Example Payload (information about the client are not contained here,
    but have to be provided separately)

        {
            "id": "0c8d7745-7391-458c-95b7-d8a70c42a6fc",
            "name": "view-users",
            "description": "${role_view-users}",
            "composite": true,
            "composites": {
                "client": {
                    "realm-management": [
                        "query-groups",
                        "query-users"
                    ]
                }
            },
            "clientRole": true,
            "containerId": "c159c414-1fcb-4bd1-95ad-c9b412987c28",
            "attributes": {}
        },
        {
            "id": "fac44c0b-ed3c-487e-8d0d-25a0a249d320",
            "name": "manage-realm",
            "description": "${role_manage-realm}",
            "composite": false,
            "clientRole": true,
            "containerId": "c159c414-1fcb-4bd1-95ad-c9b412987c28",
            "attributes": {}
        },

    """

    def __init__(self, raw_data: dict, realm: Realm, client: str):
        super().__init__(raw_data)
        self._realm: Realm = realm
        self._client: str = client

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def is_client_role(self) -> bool:
        assert self._d["clientRole"] is True, "Realm role has been parsed as client role, wtf?!"
        return self._d["clientRole"]

    def is_composite_role(self) -> bool:
        return self._d["composite"]

    def get_composite_roles(self) -> dict[str, list[str]]:
        return self._d.get("composites", {})

    def get_client_name(self) -> str:
        return self._client

    def __str__(self) -> str:
        return (
            f"<{self.get_type()}: {self.get_client_name()}[{self.get_name()}] in Realm {self.get_realm().get_name()}>"
        )


class ProtocolMapper(Dataclass):
    """
    Example Payload

        {
            "id": "78890c6c-5dfb-4c1c-a469-4f21d170f702",
            "name": "user-id-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "consentRequired": false,
            "config": {
                "userinfo.token.claim": "true",
                "user.attribute": "user-id",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "user-id",
                "jsonType.label": "String"
            }
        }

    """

    def __init__(self, raw_data: dict, realm: Realm):
        super().__init__(raw_data)
        self._realm: Realm = realm

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def get_protocol(self) -> str:
        return self._d["protocol"]

    def get_protocol_mapper(self) -> str:
        return self._d["protocolMapper"]

    def get_config(self) -> dict[str, str]:
        return self._d["config"]


class ClientScope(Dataclass):
    """
    Some examples:

        {
            "id": "b1261941-93bd-4c7c-819f-326b99c8f7f1",
            "name": "roles",
            "description": "OpenID Connect scope for add user roles to the access token",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "false",
                "display.on.consent.screen": "true",
                "consent.screen.text": "${rolesScopeConsentText}"
            },
            "protocolMappers": [
                {
                    "id": "2df747f5-3357-4d84-b648-a6772b386973",
                    "name": "audience resolve",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-resolve-mapper",
                    "consentRequired": false,
                    "config": {}
                },
                {
                    "id": "926f9c0c-69a0-45f1-8e75-42a7987a85c7",
                    "name": "client roles",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-client-role-mapper",
                    "consentRequired": false,
                    "config": {
                        "user.attribute": "foo",
                        "access.token.claim": "true",
                        "claim.name": "resource_access.${client_id}.roles",
                        "jsonType.label": "String",
                        "multivalued": "true"
                    }
                },
                {
                    "id": "0399894e-ff43-42b3-896b-b3df2a3be079",
                    "name": "realm roles",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-realm-role-mapper",
                    "consentRequired": false,
                    "config": {
                        "user.attribute": "foo",
                        "access.token.claim": "true",
                        "claim.name": "realm_access.roles",
                        "jsonType.label": "String",
                        "multivalued": "true"
                    }
                }
            ]
        },
        {
            "id": "6b797a34-a333-4e24-845a-b05ad3d3d926",
            "name": "web-origins",
            "description": "OpenID Connect scope for add allowed web origins to the access token",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "false",
                "display.on.consent.screen": "false",
                "consent.screen.text": ""
            },
            "protocolMappers": [
                {
                    "id": "d5b44d1d-323d-4ee0-962f-b8d6f18b92a7",
                    "name": "allowed web origins",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-allowed-origins-mapper",
                    "consentRequired": false,
                    "config": {}
                }
            ]
        },

    Client Scope Mapping:

        {
            "client-with-client-roles": [
                {
                    "clientScope": "client-scope-with-client-role",
                    "roles": [
                        "sensitive-client-role"
                    ]
                }
            ],
            "account": [
                {
                    "client": "account-console",
                    "roles": [
                        "manage-account",
                        "view-groups"
                    ]
                }
            ]
        },
    """

    def __init__(self, raw_data: dict, scope_mapping: list, client_scope_mapping: dict, realm: Realm):
        super().__init__(raw_data)
        raw_data["roles"] = {"realm": [], "client": {}}

        scope_name = raw_data["name"]
        for scope_map in scope_mapping:
            if scope_map.get("clientScope", None) == scope_name:
                raw_data["roles"]["realm"] = scope_map["roles"]
                break

        for role_client, mapping_scopes in client_scope_mapping.items():
            for mapping_scope in mapping_scopes:
                if mapping_scope.get("clientScope", None) == scope_name:
                    raw_data["roles"]["client"][role_client] = mapping_scope["roles"]

        self._realm: Realm = realm

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def get_realm_roles(self) -> list[str]:
        return self._d["roles"]["realm"]

    def get_client_roles(self) -> dict[str, list[str]]:
        return self._d["roles"]["client"]

    def get_protocol_mappers(self) -> list[ProtocolMapper]:
        protocol_mappers = self._d.get("protocolMappers", [])
        return [ProtocolMapper(data, self._realm) for data in protocol_mappers]


class Client(Dataclass):
    """
    Example Payload:

        {
            "id": "277f1aef-2ca2-4992-92b3-7823941db631",
            "clientId": "client-with-recursive-sensitive-composite-role",
            "name": "",
            "description": "",
            "rootUrl": "",
            "adminUrl": "",
            "baseUrl": "",
            "surrogateAuthRequired": false,
            "enabled": true,
            "alwaysDisplayInConsole": false,
            "clientAuthenticatorType": "client-secret",
            "redirectUris": [
                "/*"
            ],
            "webOrigins": [
                "/*"
            ],
            "notBefore": 0,
            "bearerOnly": false,
            "consentRequired": false,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": false,
            "directAccessGrantsEnabled": false,
            "serviceAccountsEnabled": false,
            "publicClient": true,
            "frontchannelLogout": true,
            "protocol": "openid-connect",
            "attributes": {
                "oidc.ciba.grant.enabled": "false",
                "oauth2.device.authorization.grant.enabled": "false",
                "backchannel.logout.session.required": "true",
                "backchannel.logout.revoke.offline.tokens": "false"
            },
            "authenticationFlowBindingOverrides": {},
            "fullScopeAllowed": true,
            "nodeReRegistrationTimeout": -1,
            "defaultClientScopes": [
                "web-origins",
                "acr",
                "scope-with-recursive-sensitive-composite-role",
                "roles",
                "profile",
                "email"
            ],
            "optionalClientScopes": [
                "address",
                "phone",
                "offline_access",
                "microprofile-jwt"
            ]
        }
    """

    def __init__(self, raw_data: dict, scope_mappings: list, client_scope_mappings: dict, realm: Realm):
        raw_data["directly_assigned_roles"] = {"realm": [], "client": {}}

        client_name = raw_data["clientId"]
        for scope_map in scope_mappings:
            if scope_map.get("client", None) == client_name:
                raw_data["directly_assigned_roles"]["realm"] = scope_map["roles"]
                break

        for role_client, mapping_scopes in client_scope_mappings.items():
            for mapping_scope in mapping_scopes:
                if mapping_scope.get("client", None) == client_name:
                    raw_data["directly_assigned_roles"]["client"][role_client] = mapping_scope["roles"]

        super().__init__(raw_data)
        self._realm: Realm = realm

    def get_client_id(self) -> str:
        return self._d["clientId"]

    def get_name(self) -> str:
        return self.get_client_id()

    def get_realm(self) -> Realm:
        return self._realm

    # Basic Properties
    def is_public(self) -> bool:
        return self._d["publicClient"]

    def is_enabled(self) -> bool:
        return self._d["enabled"]

    # Scopes
    def get_default_client_scopes(self) -> list[str]:
        return self._d["defaultClientScopes"]

    def get_optional_client_scopes(self) -> list[str]:
        return self._d["optionalClientScopes"]

    def has_full_scope_allowed(self) -> bool:
        return self._d["fullScopeAllowed"]

    # Directly assigned roles
    def get_directly_assigned_realm_roles(self) -> list[str]:
        return self._d["directly_assigned_roles"]["realm"]

    def get_directly_assigned_client_roles(self) -> dict[str, list[str]]:
        return self._d["directly_assigned_roles"]["client"]

    # Specific Flows
    def has_standard_flow_enabled(self) -> bool:
        return self._d["standardFlowEnabled"]

    def has_implicit_flow_enabled(self) -> bool:
        return self._d["implicitFlowEnabled"]

    def has_device_authorization_grant_flow_enabled(self) -> bool:
        # For some reason, this flow is encoded as part of the "attributes" dict, where it maps
        # to the string "true" or "false", and this config is not always present. Thus, this
        # check has to look like this.
        if "oauth2.device.authorization.grant.enabled" in self._d["attributes"]:
            return self._d["attributes"]["oauth2.device.authorization.grant.enabled"] == "true"
        # If the config is not present in the attributes, the flow is always disabled
        return False

    def has_direct_access_grants_enabled(self) -> bool:
        return self._d["directAccessGrantsEnabled"]

    def has_service_account_enabled(self) -> bool:
        return self._d["serviceAccountsEnabled"]

    def get_service_account_name(self) -> str | None:
        if not self.has_service_account_enabled():
            return None
        return "service-account-" + self.get_client_id().lower()

    # More Specific Properties
    def is_realm_specific_client(self) -> bool:
        # Each realm in Keycloak will get a realm-specific client created in the
        # master realm. This is used to hold realm-specific roles, like the user
        # management permissions. These clients behave differently from other
        # clients, so we need to exclude them from some of our standard checks.
        return (
            self.get_realm().get_name() == "master" and self.get_name().endswith("-realm") and "protocol" not in self._d
        )

    def get_protocol(self) -> str:
        # Every client should have the "protocol" field set, but the "master-realm"
        # client in the "master" realm for some reason does not include this field.
        # This code works around that by returning openid-connect in that case.
        try:
            return self._d["protocol"]
        except KeyError:
            # If the client is a realm-specific client, it for some reason does not
            # have a "protocol" set. Return openid-connect anyway.
            if self.is_realm_specific_client():
                return "openid-connect"
            # This case should never happen, so instead of blindly returning something,
            # we'd like to know about it. Raise an exception.
            raise RuntimeError("'protocol' field of Client {} is not set, aborting".format(self.get_name()))

    def is_oidc_client(self) -> bool:
        return self.get_protocol() == "openid-connect"

    def get_attributes(self) -> dict[str, str]:
        return self._d["attributes"]

    def get_protocol_mappers(self) -> list[ProtocolMapper]:
        protocol_mappers = self._d.get("protocolMappers", [])
        return [ProtocolMapper(data, self._realm) for data in protocol_mappers]

    def get_client_authenticator_type(self) -> str | None:
        if self.is_public():
            return None
        return self._d["clientAuthenticatorType"]

    def get_root_url(self) -> str | None:
        return self._d.get("rootUrl", None)

    def get_base_url(self) -> str | None:
        return self._d.get("baseUrl", None)

    def get_redirect_uris(self) -> list[str]:
        return self._d["redirectUris"]

    def get_resolved_redirect_uris(self) -> list[str]:
        redirect_uris = self.get_redirect_uris()
        if len(redirect_uris) == 0:
            return redirect_uris
        root_url = self.get_root_url()
        if root_url is None:
            root_url = ""

        rv = []
        for uri in redirect_uris:
            # For relative URIs, we prepend the root URL.
            # See https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java#L54
            # and https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java#L63
            if uri.startswith("/"):
                rv.append(root_url + uri)
            else:
                rv.append(uri)
        return rv

    def is_default_keycloak_client(self) -> bool:
        return self.get_name() in [
            "account",
            "account-console",
            "admin-cli",
            "broker",
            "realm-management",
            "security-admin-console",
        ]

    def allows_user_authentication(self) -> bool:
        return (
            self.has_device_authorization_grant_flow_enabled()
            or self.has_direct_access_grants_enabled()
            or self.has_standard_flow_enabled()
            or self.has_implicit_flow_enabled()
        )

    def use_refresh_tokens(self) -> bool:
        # If the attribute is not present, Keycloak defaults to true for probably legacy reasons
        return self.get_attributes().get("use.refresh.tokens", "true") == "true"

    def get_access_token_lifespan_override(self) -> int | None:
        """Get client-specific access token lifespan override in seconds, if set."""
        lifespan_str = self.get_attributes().get("access.token.lifespan")
        if lifespan_str is None:
            return None
        try:
            return int(lifespan_str)
        except ValueError:
            return None


class Group(Dataclass):
    """
    Example Data:

        {
            "id": "71f4ec07-96c5-4a43-bd2d-3da010cede4a",
            "name": "group-with-sensitive-child-group",
            "path": "/group-with-sensitive-child-group",
            "attributes": {},
            "realmRoles": [
                "sensitive_composite_role"
            ],
            "clientRoles": {},
            "subGroups": [
                {
                    "id": "0f130934-933d-4ac1-8033-2646c4dd6bde",
                    "name": "sensitive-child-group",
                    "path": "/group-with-sensitive-child-group/sensitive-child-group",
                    "attributes": {},
                    "realmRoles": [
                        "sensitive-role"
                    ],
                    "clientRoles": {},
                    "subGroups": []
                },
                {
                    "id": "9f936e3d-8457-4b68-8ce5-f03799e8394e",
                    "name": "composite-sensitive-child-group",
                    "path": "/group-with-sensitive-child-group/composite-sensitive-child-group",
                    "attributes": {},
                    "realmRoles": [
                        "sensitive_composite_role"
                    ],
                    "clientRoles": {},
                    "subGroups": []
                }
            ]
        },

    Note that the list of roles is not necessarily complete here: child groups also implicitly inherit
    the roles and attributes of their parent group(s). So, to get a complete list of attributes or roles,
    the whole inheritance tree needs to be traversed.
    """

    def __init__(self, raw_data: dict, realm: Realm, parent_group: "Group | None" = None):
        super().__init__(raw_data)
        self._realm: Realm = realm
        self._parent: "Group | None" = parent_group

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def get_path(self) -> str:
        return self._d["path"]

    def get_parent(self) -> "Group | None":
        return self._parent

    def get_attributes(self) -> dict[str, str]:
        return self._d["attributes"]

    def get_realm_roles(self) -> list:
        return self._d["realmRoles"]

    def get_client_roles(self) -> dict[str, list[str]]:
        return self._d["clientRoles"]

    def get_effective_realm_roles(self) -> list[str]:
        # If no parent exists, the effective realm roles are the roles of this group only.
        if self._parent is None:
            return self.get_realm_roles()

        # Otherwise, incorporate the parent's roles
        my_realm_roles = set(self._d["realmRoles"])
        my_realm_roles.update(self._parent.get_effective_realm_roles())
        return list(my_realm_roles)

    def get_effective_client_roles(self) -> dict[str, list[str]]:
        if self._parent is None:
            return deepcopy(self._d["clientRoles"])
        parent_client_roles = self._parent.get_effective_client_roles()
        my_client_roles = self.get_client_roles()
        for client in my_client_roles.keys():
            if client in parent_client_roles:
                parent_client_roles[client] += my_client_roles[client]
            else:
                parent_client_roles[client] = my_client_roles[client]
        return parent_client_roles

    def has_subgroups(self) -> bool:
        return self._d["subGroups"] != []

    def get_subgroups(self) -> "list[Group]":
        return [Group(subgroup, self._realm, self) for subgroup in self._d["subGroups"]]


class ServiceAccount(Dataclass):
    """
    Example Payload:

        {
            "id": "8cbc5918-40bf-4be4-b7bd-44500abf8a15",
            "createdTimestamp": 1695986518227,
            "username": "service-account-service-account-client-with-client-role",
            "enabled": true,
            "totp": false,
            "emailVerified": false,
            "serviceAccountClientId": "service-account-client-with-client-role",
            "disableableCredentialTypes": [],
            "requiredActions": [],
            "realmRoles": [
                "default-roles-lint-test"
            ],
            "clientRoles": {
                "client-with-client-roles": [
                    "sensitive-client-role"
                ]
            },
            "notBefore": 0,
            "groups": [
                "/group-with-sensitive-child-group/composite-sensitive-child-group"
            ]
        }

    """

    def __init__(self, raw_data: dict, realm: Realm):
        super().__init__(raw_data)
        self._realm: Realm = realm

    def get_username(self) -> str:
        return self._d["username"]

    def get_name(self) -> str:
        return self.get_username()

    def get_realm(self) -> Realm:
        return self._realm

    def get_client_id(self) -> str:
        return self._d["serviceAccountClientId"]

    def get_realm_roles(self) -> list[str]:
        return self._d.get("realmRoles", [])

    def has_client_roles(self) -> bool:
        return "clientRoles" in self._d

    def get_client_roles(self) -> dict[str, list[str]]:
        if self.has_client_roles():
            return self._d["clientRoles"]
        return {}

    def get_groups(self) -> list[str]:
        return self._d["groups"]


class IdentityProviderMapper(Dataclass):
    """
    Example Payloads:

        {
            "id": "61fbd7df-5b57-4913-8745-6c8f197175fa",
            "name": "Demo Mapper",
            "identityProviderAlias": "openid-connect-provider",
            "identityProviderMapper": "oidc-advanced-group-idp-mapper",
            "config": {
                "syncMode": "INHERIT",
                "claims": "[{\"key\":\"groups\",\"value\":\"test-group\"}]",
                "are.claim.values.regex": "false",
                "group": "/benign-group"
            }
        },
        {
            "id": "c13c8a30-5640-4bd8-ac60-f93eb675c9fe",
            "name": "hardcoded-attr",
            "identityProviderAlias": "openid-connect-provider",
            "identityProviderMapper": "hardcoded-user-session-attribute-idp-mapper",
            "config": {
                "syncMode": "INHERIT",
                "attribute.value": "test-attribute-value",
                "are.claim.values.regex": "false",
                "attribute": "test-attribute-name"
            }
        }

    """

    def __init__(self, raw_data: dict, realm: Realm):
        super().__init__(raw_data)
        self._realm: Realm = realm

    def get_name(self) -> str:
        return self._d["name"]

    def get_realm(self) -> Realm:
        return self._realm

    def get_identity_provider_alias(self) -> str:
        return self._d["identityProviderAlias"]

    def get_identity_provider_mapper_type(self) -> str:
        return self._d["identityProviderMapper"]

    def get_config(self) -> dict:
        return self._d["config"]


class IdentityProvider(Dataclass):
    """
    Example Payload for OIDC client:

        {
            "alias": "openid-connect-provider",
            "displayName": "",
            "internalId": "ebb360e7-61ff-4d5e-a9a0-e06ea3c11a7c",
            "providerId": "oidc",
            "enabled": true,
            "updateProfileFirstLoginMode": "on",
            "trustEmail": false,
            "storeToken": false,
            "addReadTokenRoleOnCreate": false,
            "authenticateByDefault": false,
            "linkOnly": false,
            "firstBrokerLoginFlowAlias": "first broker login",
            "config": {
                "userInfoUrl": "https://other.keycloak.com/auth/realms/users/protocol/openid-connect/userinfo",
                "validateSignature": "true",
                "tokenUrl": "https://other.keycloak.com/auth/realms/users/protocol/openid-connect/token",
                "clientId": "yolo",
                "jwksUrl": "https://other.keycloak.com/auth/realms/users/protocol/openid-connect/certs",
                "issuer": "https://other.keycloak.com/auth/realms/users",
                "useJwksUrl": "true",
                "pkceEnabled": "false",
                "authorizationUrl": "https://other.keycloak.com/auth/realms/users/protocol/openid-connect/auth",
                "clientAuthMethod": "client_secret_post",
                "logoutUrl": "https://other.keycloak.com/auth/realms/users/protocol/openid-connect/logout",
                "clientSecret": "**********"
            }
        }

    Example Payload for Microsoft broker:

        {
            "alias": "microsoft",
            "internalId": "06b17b97-f3a7-492b-9aa2-447cf8354224",
            "providerId": "microsoft",
            "enabled": true,
            "updateProfileFirstLoginMode": "on",
            "trustEmail": false,
            "storeToken": false,
            "addReadTokenRoleOnCreate": false,
            "authenticateByDefault": false,
            "linkOnly": false,
            "firstBrokerLoginFlowAlias": "first broker login",
            "config": {
                "clientSecret": "**********",
                "clientId": "client-id"
            }
        }
    """

    def __init__(self, raw_data: dict, realm: Realm, identity_provider_mappers: list[dict]):
        super().__init__(raw_data)
        self._realm = realm
        # Import all IdentityProviderMappers from the realm that reference this Identity Provider
        self._d["idpMappings"] = [
            IdentityProviderMapper(idpmap, realm)
            for idpmap in identity_provider_mappers
            if idpmap["identityProviderAlias"] == raw_data["alias"]
        ]

    def get_alias(self) -> str:
        return self._d["alias"]

    def get_name(self) -> str:
        return self.get_alias()

    def get_realm(self) -> Realm:
        return self._realm

    def get_provider_id(self) -> str:
        return self._d["providerId"]

    def is_enabled(self) -> bool:
        return self._d["enabled"]

    def get_config(self) -> dict:
        return self._d["config"]

    def get_identity_provider_mappers(self) -> list[IdentityProviderMapper]:
        return self._d["idpMappings"]

    def get_sync_mode(self) -> str | None:
        return self._d["config"].get("syncMode", "LEGACY")
