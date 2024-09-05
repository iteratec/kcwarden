from kcwarden.auditors.idp.identity_provider_with_mappers_without_force_sync_mode import (
    IdentityProviderWithMappersWithoutForceSyncMode,
)
from kcwarden.auditors.idp.identity_provider_with_one_time_sync import IdentityProviderWithOneTimeSync
from kcwarden.auditors.idp.oidc_identity_provider_without_pkce import OIDCIdentityProviderWithoutPKCE

# TODO Refactor this bit out of here to get rid of this file.
# Idea: Rely on the auto-import logic that will be the basis for the plugin infrastructure?


AUDITORS = [
    OIDCIdentityProviderWithoutPKCE,
    IdentityProviderWithOneTimeSync,
    IdentityProviderWithMappersWithoutForceSyncMode,
]
