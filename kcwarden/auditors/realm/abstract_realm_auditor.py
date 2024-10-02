import abc
from typing import Generator

from kcwarden.api import Auditor
from kcwarden.custom_types.keycloak_object import Realm
from kcwarden.custom_types.result import Result


class AbstractRealmAuditor(Auditor, abc.ABC):
    def should_consider_realm(self, realm: Realm) -> bool:
        return self.is_not_ignored(realm)

    def audit(self) -> Generator[Result, None, None]:
        for realm in self._DB.get_all_realms():
            if self.should_consider_realm(realm):
                yield from self.audit_realm(realm)

    @abc.abstractmethod
    def audit_realm(self, realm: Realm) -> Generator[Result, None, None]:
        raise NotImplementedError()
