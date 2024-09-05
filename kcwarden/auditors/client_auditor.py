from kcwarden.auditors.client.client_authentication_via_mtls_or_jwt_recommended import (
    ClientAuthenticationViaMTLSOrJWTRecommended,
)
from kcwarden.auditors.client.client_has_erroneously_configured_wildcard_uri import (
    ClientHasErroneouslyConfiguredWildcardURI,
)
from kcwarden.auditors.client.client_has_undefined_base_domain_and_schema import ClientHasUndefinedBaseDomainAndSchema
from kcwarden.auditors.client.client_must_not_use_unencrypted_nonlocal_redirect_uri import (
    ClientMustNotUseUnencryptedNonlocalRedirectUri,
)
from kcwarden.auditors.client.client_should_not_use_wildcard_redirect_uri import ClientShouldNotUseWildcardRedirectURI
from kcwarden.auditors.client.client_uses_custom_redirect_uri_scheme import ClientUsesCustomRedirectUriScheme
from kcwarden.auditors.client.client_with_default_offline_access_scope import ClientWithDefaultOfflineAccessScope
from kcwarden.auditors.client.client_with_full_scope_allowed import ClientWithFullScopeAllowed
from kcwarden.auditors.client.client_with_optional_offline_access_scope import ClientWithOptionalOfflineAccessScope
from kcwarden.auditors.client.client_with_service_account_and_other_flow_enabled import (
    ClientWithServiceAccountAndOtherFlowEnabled,
)
from kcwarden.auditors.client.client_should_disable_implicit_grant_flow import ClientShouldDisableImplicitGrantFlow
from kcwarden.auditors.client.confidential_client_should_disable_direct_access_grants import (
    ConfidentialClientShouldDisableDirectAccessGrants,
)
from kcwarden.auditors.client.confidential_client_should_enforce_pkce import ConfidentialClientShouldEnforcePKCE
from kcwarden.auditors.client.public_client_should_disable_direct_access_grants import (
    PublicClientShouldDisableDirectAccessGrants,
)
from kcwarden.auditors.client.using_nondefault_user_attributes_in_clients_without_user_profiles_feature_is_dangerous import (
    UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous,
)
from kcwarden.auditors.client.public_clients_must_enforce_pkce import PublicClientsMustEnforcePKCE

# TODO Refactor this bit out of here to get rid of this file.
# Idea: Rely on the auto-import logic that will be the basis for the plugin infrastructure?

AUDITORS = [
    PublicClientsMustEnforcePKCE,
    ConfidentialClientShouldEnforcePKCE,
    ClientShouldDisableImplicitGrantFlow,
    PublicClientShouldDisableDirectAccessGrants,
    ConfidentialClientShouldDisableDirectAccessGrants,
    ClientAuthenticationViaMTLSOrJWTRecommended,
    ClientMustNotUseUnencryptedNonlocalRedirectUri,
    ClientUsesCustomRedirectUriScheme,
    ClientHasUndefinedBaseDomainAndSchema,
    ClientShouldNotUseWildcardRedirectURI,
    ClientHasErroneouslyConfiguredWildcardURI,
    ClientWithServiceAccountAndOtherFlowEnabled,
    UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous,
    ClientWithDefaultOfflineAccessScope,
    ClientWithOptionalOfflineAccessScope,
    ClientWithFullScopeAllowed,
]
