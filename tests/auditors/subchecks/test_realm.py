from unittest import mock

import pytest

from kcwarden.auditors.subchecks.realm import users_can_edit_attributes
from kcwarden.custom_types.keycloak_object import Realm


@pytest.mark.parametrize(
    ("unmanaged_attribute_policy", "expected"),
    [
        ("ADMIN_EDIT", False),
        ("ADMIN_VIEW", False),
        ("DISABLED", False),
        ("ENABLED", True),
        ("UNEXPECTED", True),
    ],
)
def test_users_can_edit_attributes(unmanaged_attribute_policy: str, expected: bool):
    realm = mock.create_autospec(spec=Realm, instance=True)
    realm.get_unmanaged_attribute_policy.return_value = unmanaged_attribute_policy

    assert users_can_edit_attributes(realm) == expected
    realm.has_declarative_user_profiles_enabled_legacy_option.assert_not_called()


@pytest.mark.parametrize(
    ("has_declarative_user_profiles_enabled_legacy_option", "expected"),
    [
        (False, True),
        (True, False),
    ],
)
def test_users_can_edit_attributes__given_legacy_option(
    has_declarative_user_profiles_enabled_legacy_option: bool, expected: bool
):
    realm = mock.create_autospec(spec=Realm, instance=True)
    realm.get_unmanaged_attribute_policy.return_value = None
    realm.has_declarative_user_profiles_enabled_legacy_option.return_value = (
        has_declarative_user_profiles_enabled_legacy_option
    )
    assert users_can_edit_attributes(realm) == expected
    realm.get_unmanaged_attribute_policy.assert_called_once()
