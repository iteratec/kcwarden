import re
import sys

from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import RealmRole, ClientRole, ClientScope, Client, Group, ServiceAccount


### Internal helper functions
def _role_contains_role(contained_role: RealmRole | ClientRole, container_role: RealmRole | ClientRole) -> bool:
    if contained_role.is_client_role():
        return contained_role.get_name() in container_role.get_composite_roles().get("client", {}).get(
            contained_role.get_client_name(), []
        )  # type: ignore - can only be a ClientRole here
    return contained_role.get_name() in container_role.get_composite_roles().get("realm", [])


def _scope_contains_role(role: RealmRole | ClientRole, scope: ClientScope) -> bool:
    if role.is_client_role():
        return role.get_name() in scope.get_client_roles().get(role.get_client_name(), [])  # type: ignore - can only be a ClientRole here
    return role.get_name() in scope.get_realm_roles()


def _client_contains_directly_assigned_role(role: RealmRole | ClientRole, client: Client) -> bool:
    if role.is_client_role():
        return role.get_name() in client.get_directly_assigned_client_roles().get(role.get_client_name(), [])  # type: ignore - can only be a ClientRole here
    return role.get_name() in client.get_directly_assigned_realm_roles()


def _group_contains_role(role: RealmRole | ClientRole, group: Group) -> bool:
    if role.is_client_role():
        effective_client_roles = group.get_effective_client_roles()
        return (
            role.get_client_name() in effective_client_roles
            and role.get_name() in effective_client_roles[role.get_client_name()]
        )  # type: ignore - can only be a ClientRole here
    return role.get_name() in group.get_effective_realm_roles()


def _service_account_has_role(role: RealmRole | ClientRole, account: ServiceAccount) -> bool:
    if role.is_client_role():
        client_roles = account.get_client_roles()
        return role.get_client_name() in client_roles and role.get_name() in client_roles[role.get_client_name()]  # type: ignore - can only be a ClientRole here
    return role.get_name() in account.get_realm_roles()


def _merge_role_dict(existing, new):
    existing["realm"] = list(set(existing["realm"]) | set(new["realm"]))
    for client in new["client"]:
        if client not in existing["client"]:
            existing["client"][client] = []
        existing["client"][client] = list(set(existing["client"][client]) | set(new["client"][client]))
    return existing


def matches_as_string_or_regex(input_string: str, string_or_regex: str) -> bool:
    if input_string == string_or_regex:
        return True
    try:
        # We aren't sure if the string should be interpreted as a regular expression.
        # Regex matching will interpret the (non)-regex "some-string" to match
        # "some-string-that-is-not-the-same". This is unexpected if I don't explicitly
        # ask for regular expression matching, and means that we may false-positive match
        # some strings.
        # The workaround is to check if the string contains one of a number of common
        # regular expression control characters. If so, we will activate regex matching.
        # This has a small chance of false negatives if the user provides a string that
        # does not contain any of the control characters listed below. However, in practice,
        # I would expect this to be extremely rare.
        # It may also introduce false positive matching if someone has these characters
        # as part of the normal (non-regex) name for a resource. However, once again,
        # I would expect this to be a rare occurrence (I am not even sure if these characters
        # are allowed by Keycloak).
        if any(re_control in string_or_regex for re_control in ["?", "!", "+", "*"]):
            return re.match(re.compile(string_or_regex), input_string) is not None
        return False
    except re.error as e:
        print(
            f"Interpreting input '{string_or_regex}' as regular expression resulted in an error."
            f" Treated as not matching. Error: {e}",
            file=sys.stderr,
        )
        return False


def matches_list_of_regexes(input_string: str, re_list: list[str]) -> bool:
    """Checks if the provided string matches at least one entry in the provided
    list of strings or patterns. First considers exact string matches, then interprets
    the list entries as regular expressions and sees if the provided input string
    matches the regex. If the re_list entry isn't a valid regular expression, it is
    interpreted as not matching in the regular expression matching step (but can still
    match on an exact-string basis).
    """
    return any([matches_as_string_or_regex(input_string, pattern_entry) for pattern_entry in re_list])


def regex_matches_list_entry(pattern_string: str, string_list: list[str]) -> bool:
    """Checks if the provided pattern string matches at least one entry in the
    provided list. First considers exact string matches, then interprets the
    pattern string as a regular expression and sees if it matches at least one
    entry of the list. If the pattern_string isn't a valid regular expression, it is
    interpreted as not matching in the regular expression matching step (but can
    still match on an exact-string basis)
    """
    return any([matches_as_string_or_regex(list_entry, pattern_string) for list_entry in string_list])


def retrieve_roles_from_db_with_regex(
    db: Database, role_client: str, role_name: str
) -> list[RealmRole] | list[ClientRole]:
    if role_client is None or role_client.lower() == "realm":
        return [role for role in db.get_all_realm_roles() if matches_as_string_or_regex(role.get_name(), role_name)]
    return [
        role
        for role in db.get_all_client_roles()[role_client].values()
        if matches_as_string_or_regex(role.get_name(), role_name)
    ]


def get_roles_containing_role(db: Database, role: ClientRole | RealmRole) -> list[RealmRole | ClientRole]:
    """Get roles containing a specified role

    In Keycloak, roles can contain other roles. In some situations, you may want to know
    which other roles contain a specific role, through however many layers of recursion
    are necessary to enumerate them. This function encapsulates this logic.

    The output list will always contain the role itself.
    """
    matching_roles = [role]
    for realm_role in db.get_all_realm_roles():
        if realm_role.is_composite_role():
            if _role_contains_role(role, realm_role):
                matching_roles += get_roles_containing_role(db, realm_role)

    all_client_roles = db.get_all_client_roles()
    for client in all_client_roles:
        for client_role in all_client_roles[client].values():
            if client_role.is_composite_role():
                if _role_contains_role(role, client_role):
                    matching_roles += get_roles_containing_role(db, client_role)

    return matching_roles


def get_scopes_containing_role(db: Database, role: ClientRole | RealmRole) -> list[ClientScope]:
    """Get all scopes containing a specific role

    In Keycloak, scopes can contain one or more roles. This helper finds all scopes that
    contain a specific client- or realm role.
    """
    return [scope for scope in db.get_all_scopes() if _scope_contains_role(role, scope)]


def get_clients_with_scope(db: Database, scope: ClientScope) -> list[Client]:
    matching_clients = []
    for client in db.get_all_clients():
        if (
            scope.get_name() in client.get_default_client_scopes()
            or scope.get_name() in client.get_optional_client_scopes()
        ):
            matching_clients.append(client)

    return matching_clients


def get_clients_with_directly_assigned_role(db: Database, role: RealmRole | ClientRole) -> list[Client]:
    return [client for client in db.get_all_clients() if _client_contains_directly_assigned_role(role, client)]


def get_groups_containing_role(db: Database, role: RealmRole | ClientRole) -> list[Group]:
    return [group for group in db.get_all_groups() if _group_contains_role(role, group)]


def get_service_accounts_with_role(db: Database, role: RealmRole | ClientRole) -> list[ServiceAccount]:
    return [account for account in db.get_all_service_accounts() if _service_account_has_role(role, account)]


def get_service_accounts_in_group(db: Database, group: Group) -> list[ServiceAccount]:
    return [account for account in db.get_all_service_accounts() if group.get_path() in account.get_groups()]


def get_effective_roles(db: Database, role: RealmRole | ClientRole) -> dict:
    rv = {"realm": [], "client": {}}
    if role.is_client_role():
        rv["client"][role.get_client_name()] = [role.get_name()]  # type: ignore
    else:
        rv["realm"].append(role.get_name())

    if role.is_composite_role():
        for client_or_realm in role.get_composite_roles().keys():
            if client_or_realm == "realm":
                # We are dealing with the "realm roles" block of the composite roles
                for realm_role_name in role.get_composite_roles()[client_or_realm]:
                    realm_role = db.get_realm_role(realm_role_name)
                    rv = _merge_role_dict(rv, get_effective_roles(db, realm_role))
            else:
                assert client_or_realm == "client"
                client_composite_roles = role.get_composite_roles()["client"]
                assert isinstance(client_composite_roles, dict)
                for client, role_names in client_composite_roles.items():
                    for client_role_name in role_names:
                        client_role = db.get_client_role(client_role_name, client)
                        rv = _merge_role_dict(rv, get_effective_roles(db, client_role))
    return rv


def get_effective_roles_for_service_account(db: Database, saccount: ServiceAccount) -> dict:
    roles = {"realm": [], "client": {}}

    for role_name in saccount.get_realm_roles():
        role = db.get_realm_role(role_name)
        roles = _merge_role_dict(roles, get_effective_roles(db, role))

    for client in saccount.get_client_roles():
        for role_name in saccount.get_client_roles()[client]:
            role = db.get_client_role(role_name, client)
            roles = _merge_role_dict(roles, get_effective_roles(db, role))
    return roles
