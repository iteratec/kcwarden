import json
from io import TextIOBase

from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import (
    Realm,
    Client,
    ClientScope,
    ServiceAccount,
    Group,
    RealmRole,
    ClientRole,
    IdentityProvider,
)


def add_realm(realm: dict, db: Database) -> Realm:
    r = Realm(realm)
    db.add_realm(r)
    return r


def add_group(group: dict, realm: Realm, db: Database) -> None:
    def recursive_add_to_database(g: Group) -> None:
        db.add_group(g)

        # Recursively add subgroups
        for subgroup in g.get_subgroups():
            recursive_add_to_database(subgroup)

    recursive_add_to_database(Group(group, realm))


def load_realm_dump(input_file: TextIOBase, db: Database) -> None:
    data = json.load(input_file)

    ### Start loading the data into our own structure
    # Realm
    realm = add_realm(data, db)

    # Load scope and client scope mappings
    scope_mappings = data["scopeMappings"]
    client_scope_mappings = data["clientScopeMappings"]

    # Client
    for client in data["clients"]:
        db.add_client(Client(client, scope_mappings, client_scope_mappings, realm))

    # Scope
    for scope in data.get("clientScopes", []):
        db.add_scope(ClientScope(scope, scope_mappings, client_scope_mappings, realm))

    # Service Accounts
    for saccount in data.get("users", []):
        db.add_service_account(ServiceAccount(saccount, realm))

    # Realm Roles
    for role in data["roles"]["realm"]:
        db.add_realm_role(RealmRole(role, realm))

    # Client Roles
    for client in data["roles"]["client"]:
        for role in data["roles"]["client"][client]:
            db.add_client_role(ClientRole(role, realm, client))

    # Groups (including subgroups through recursive calls)
    for group in data.get("groups", []):
        add_group(group, realm, db)

    # Identity Providers
    idp_mappers = data["identityProviderMappers"]
    for idp in data.get("identityProviders", []):
        db.add_identity_provider(IdentityProvider(idp, realm, idp_mappers))
