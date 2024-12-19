from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import (
    Client,
    ClientScope,
    IdentityProvider,
    ServiceAccount,
    Group,
    Realm,
    ClientRole,
    RealmRole,
)


class InMemoryDatabase(Database):
    def __init__(self):
        self.CLIENTS = {}
        self.SCOPES = {}
        self.SERVICE_ACCOUNTS = {}
        self.GROUPS = {}
        self.REALMS = {}
        self.REALM_ROLES = {}
        self.CLIENT_ROLES = {}
        self.IDENTITY_PROVIDERS = {}

    ### "Adders"
    def add_realm(self, realm: Realm):
        self.REALMS[realm.get_name()] = realm

    def add_client(self, client: Client):
        self.CLIENTS[client.get_client_id()] = client

    def add_scope(self, scope: ClientScope):
        self.SCOPES[scope.get_name()] = scope

    def add_service_account(self, saccount: ServiceAccount):
        self.SERVICE_ACCOUNTS[saccount.get_username()] = saccount

    def add_group(self, group: Group):
        self.GROUPS[group.get_name()] = group

    def add_realm_role(self, role: RealmRole):
        self.REALM_ROLES[role.get_name()] = role

    def add_client_role(self, role: ClientRole):
        if role.get_client_name() not in self.CLIENT_ROLES:
            self.CLIENT_ROLES[role.get_client_name()] = {}
        self.CLIENT_ROLES[role.get_client_name()][role.get_name()] = role

    def add_identity_provider(self, idp: IdentityProvider):
        self.IDENTITY_PROVIDERS[idp.get_alias()] = idp

    ### Full list getters
    def get_all_realms(self):
        return self.REALMS.values()

    def get_all_clients(self):
        return self.CLIENTS.values()

    def get_all_scopes(self):
        return self.SCOPES.values()

    def get_all_service_accounts(self):
        return self.SERVICE_ACCOUNTS.values()

    def get_all_groups(self):
        return self.GROUPS.values()

    def get_all_realm_roles(self):
        return self.REALM_ROLES.values()

    def get_all_client_roles(self):
        return self.CLIENT_ROLES

    def get_all_identity_providers(self):
        return self.IDENTITY_PROVIDERS.values()

    ### Specific getters
    def get_realm(self, realm_name):
        return self.REALMS[realm_name]

    def get_client(self, client_id):
        return self.CLIENTS[client_id]

    def get_scope(self, scope):
        return self.SCOPES[scope]

    def get_service_account(self, saccount):
        return self.SERVICE_ACCOUNTS[saccount]

    def get_group(self, group):
        return self.GROUPS[group]

    def get_realm_role(self, role):
        return self.REALM_ROLES[role]

    def get_client_role(self, role, client):
        return self.CLIENT_ROLES[client][role]

    def get_identity_provider(self, alias):
        return self.IDENTITY_PROVIDERS[alias]
