from abc import ABC, abstractmethod
from collections.abc import Iterable

from kcwarden.custom_types.keycloak_object import (
    Client,
    ClientScope,
    ServiceAccount,
    Realm,
    Group,
    RealmRole,
    ClientRole,
    IdentityProvider,
)


class Database(ABC):
    ### "Adders"
    @abstractmethod
    def add_realm(self, realm: Realm) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_client(self, client: Client) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_scope(self, scope: ClientScope) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_service_account(self, saccount: ServiceAccount) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_group(self, group: Group) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_realm_role(self, role: RealmRole) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_client_role(self, role: ClientRole) -> None:
        raise NotImplementedError()

    @abstractmethod
    def add_identity_provider(self, idp: IdentityProvider) -> None:
        raise NotImplementedError()

    ### Full list getters
    @abstractmethod
    def get_all_realms(self) -> Iterable[Realm]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_clients(self) -> Iterable[Client]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_scopes(self) -> Iterable[ClientScope]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_service_accounts(self) -> Iterable[ServiceAccount]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_groups(self) -> Iterable[Group]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_realm_roles(self) -> Iterable[RealmRole]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_client_roles(self) -> dict[str, dict[str, ClientRole]]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_identity_providers(self) -> Iterable[IdentityProvider]:
        raise NotImplementedError()

    ### Specific getters
    @abstractmethod
    def get_realm(self, realm_name: str) -> Realm:
        raise NotImplementedError()

    @abstractmethod
    def get_client(self, client_id: str) -> Client:
        raise NotImplementedError()

    @abstractmethod
    def get_scope(self, scope: str) -> ClientScope:
        raise NotImplementedError()

    @abstractmethod
    def get_service_account(self, saccount: str) -> ServiceAccount:
        raise NotImplementedError()

    @abstractmethod
    def get_group(self, group: str) -> Group:
        raise NotImplementedError()

    @abstractmethod
    def get_realm_role(self, role: str) -> RealmRole:
        raise NotImplementedError()

    @abstractmethod
    def get_client_role(self, role: str, client: str) -> ClientRole:
        raise NotImplementedError()

    @abstractmethod
    def get_identity_provider(self, alias: str) -> IdentityProvider:
        raise NotImplementedError()
