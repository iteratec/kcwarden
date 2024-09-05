from kcwarden.auditors.realm.realm_email_verification_disabled import RealmEmailVerificationDisabled
from kcwarden.auditors.realm.realm_self_registration_enabled import RealmSelfRegistrationEnabled
from kcwarden.auditors.realm.refresh_token_reuse_count_should_be_zero import RefreshTokenReuseCountShouldBeZero
from kcwarden.auditors.realm.refresh_tokens_should_be_revoked_after_use import RefreshTokensShouldBeRevokedAfterUse

# TODO Refactor this bit out of here to get rid of this file.
# Idea: Rely on the auto-import logic that will be the basis for the plugin infrastructure?

AUDITORS = [
    RefreshTokensShouldBeRevokedAfterUse,
    RefreshTokenReuseCountShouldBeZero,
    RealmSelfRegistrationEnabled,
    RealmEmailVerificationDisabled,
]
