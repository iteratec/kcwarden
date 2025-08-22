from kcwarden.custom_types.keycloak_object import Realm


def users_can_edit_attributes(realm: Realm) -> bool:
    """
    Whether end users can edit their attributes that might be a risk under certain conditions.
    """
    unmanaged_attribute_policy = realm.get_unmanaged_attribute_policy()
    if unmanaged_attribute_policy is None:
        return not realm.has_declarative_user_profiles_enabled_legacy_option()

    return unmanaged_attribute_policy not in ("DISABLED", "ADMIN_EDIT", "ADMIN_VIEW")
