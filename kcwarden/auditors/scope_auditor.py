from kcwarden.auditors.scope.using_nondefault_user_attributes_in_scopes_without_user_profiles_feature_is_dangerous import (
    UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous,
)


# TODO Refactor this bit out of here to get rid of this file.
# Idea: Rely on the auto-import logic that will be the basis for the plugin infrastructure?


AUDITORS = [UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous]
