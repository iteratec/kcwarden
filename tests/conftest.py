from unittest import mock
from unittest.mock import Mock

import pytest
import os

from kcwarden.custom_types.database import Database
from kcwarden.custom_types.keycloak_object import (
    Realm,
    Client,
    RealmRole,
    ClientRole,
    ProtocolMapper,
    ClientScope,
    Group,
    ServiceAccount,
)
from kcwarden.database.in_memory_db import InMemoryDatabase
from kcwarden.custom_types.config_keys import AUDITOR_CONFIG
from kcwarden.database.importer import load_realm_dump

# Adapted from
# https://docs.pytest.org/en/latest/example/simple.html#control-skipping-of-tests-according-to-command-line-option
OPTION_INTEGRATION = "--integration"
MARKER_INTEGRATION_TEST = "integration"


def pytest_addoption(parser):
    parser.addoption(
        OPTION_INTEGRATION,
        action="store_true",
        default=False,
        help="Run integration tests that leverage a Docker container for Keycloak",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", f"{MARKER_INTEGRATION_TEST}: mark test as integration test")


def pytest_collection_modifyitems(config, items):
    if len(items) == 1:
        return  # ignore options if a single test is executed

    int_test_enabled = config.getoption(OPTION_INTEGRATION)

    skip_regular = pytest.mark.skip(reason="only integration tests are executed")
    skip_int_test = pytest.mark.skip(reason=f"need {OPTION_INTEGRATION} option to run")

    # If the whole execution contains only integration tests, execute them
    if all(MARKER_INTEGRATION_TEST in item.keywords for item in items):
        return

    for item in items:
        is_int_test = MARKER_INTEGRATION_TEST in item.keywords
        if int_test_enabled and not is_int_test:
            item.add_marker(skip_regular)
        elif is_int_test and not int_test_enabled:
            item.add_marker(skip_int_test)


# Fixtures


# Configuration
@pytest.fixture
def default_config():
    return {AUDITOR_CONFIG: {"PublicClientMustEnforcePKCE": []}}


# Input for generating Dataclass instances
@pytest.fixture
def realm_role_json():
    return {
        "id": "eb8fdce9-75b2-41a5-a91a-3a2a7689d3f7",
        "name": "offline_access",
        "description": "${role_offline-access}",
        "composite": False,
        "clientRole": False,
        "containerId": "9b8bf6b3-0cea-44aa-9deb-ddc2d331e3c7",
        "attributes": {},
    }


@pytest.fixture
def composite_realm_role_json(realm_role_json):
    realm_role_json["composite"] = True
    realm_role_json["composites"] = {}  # To be filled by testing code
    return realm_role_json


@pytest.fixture
def client_role_json():
    return {
        "id": "fac44c0b-ed3c-487e-8d0d-25a0a249d320",
        "name": "manage-realm",
        "description": "${role_manage-realm}",
        "composite": False,
        "clientRole": True,
        "containerId": "c159c414-1fcb-4bd1-95ad-c9b412987c28",
        "attributes": {},
    }


@pytest.fixture
def composite_client_role_json(client_role_json):
    client_role_json["composite"] = True
    client_role_json["composites"] = {}  # To be filled by testing code
    return client_role_json


@pytest.fixture
def realm_json():
    return {}


# Data storage
@pytest.fixture
def database():
    return InMemoryDatabase()


@pytest.fixture
def mock_database():
    return mock.create_autospec(spec=InMemoryDatabase, instance=True)


# Mocked data objects
@pytest.fixture
def mock_idp():
    idp = Mock()
    return idp


@pytest.fixture
def mock_realm():
    realm = mock.create_autospec(spec=Realm, instance=True)
    realm.get_name.return_value = "mock-realm"
    return realm


@pytest.fixture
def mock_scope(create_mock_scope):
    return create_mock_scope(name="sensitive-scope")


@pytest.fixture
def create_mock_scope():
    def _create_mock_scope(name="sensitive-scope", protocol_mappers=[]):
        scope = Mock(spec=ClientScope)
        scope.get_name.return_value = name
        scope.get_protocol_mappers.return_value = protocol_mappers
        return scope
    
    return _create_mock_scope


@pytest.fixture
def mock_client(mock_realm):
    client = Mock(spec=Client)
    client.get_name.return_value = "mock-test-client"
    client.is_enabled.return_value = True
    client.get_realm.return_value = mock_realm
    client.get_default_client_scopes.return_value = []
    client.get_optional_client_scopes.return_value = []
    client.is_oidc_client.return_value = True
    client.is_realm_specific_client.return_value = False
    client.get_protocol_mappers.return_value = []
    client.has_service_account_enabled.return_value = False
    return client


@pytest.fixture
def public_client(mock_client):
    mock_client.is_public.return_value = True
    return mock_client


@pytest.fixture
def confidential_client(mock_client):
    mock_client.is_public.return_value = False
    return mock_client


@pytest.fixture
def mock_service_account():
    service_account = Mock(spec=ServiceAccount)
    service_account.get_username.return_value = "test-service-account"
    service_account.get_client_id.return_value = "test-client-id"
    service_account.get_realm_roles.return_value = ["test-realm-role"]
    service_account.get_client_roles.return_value = {"test-client": ["test-client-role"]}
    service_account.get_groups.return_value = ["test-group"]
    return service_account


@pytest.fixture
def mock_role(create_mock_role):
    return create_mock_role(role_name="mock-role", client="realm")


@pytest.fixture
def create_mock_role(mock_realm):
    # Fixture factory pattern, so we can create more than one role in our tests
    def _create_mock_role(role_name, client="realm", composite=[]):
        if client == "realm":
            role = Mock(spec=RealmRole)
            role.is_client_role.return_value = False
        else:
            role = Mock(spec=ClientRole)
            role.is_client_role.return_value = True
            role.get_client_name.return_value = client
        if len(composite) > 0:
            role.is_composite_role.return_value = True
            comp_map = {}
            for c_role in composite:
                if c_role.is_client_role():
                    if c_role.get_client_name() not in comp_map:
                        comp_map[c_role.get_client_name()] = []
                    comp_map[c_role.get_client_name()].append(c_role.get_name())
                else:
                    if "realm" not in comp_map:
                        comp_map["realm"] = []
                    comp_map["realm"].append(c_role.get_name())
            role.get_composite_roles.return_value = comp_map
        else:
            role.is_composite_role.return_value = False
            role.get_composite_roles.return_value = {}
        role.get_name.return_value = role_name
        role.get_realm.return_value = mock_realm
        return role

    return _create_mock_role


@pytest.fixture
def mock_client_role(mock_role):
    mock_role.is_client_role.return_value = True
    mock_role.get_client_name.return_value = "mock_client"
    return mock_role


@pytest.fixture
def mock_composite_role(mock_role):
    mock_role.is_composite_role.return_value = True
    return mock_role


@pytest.fixture
def mock_protocol_mapper(create_mock_protocol_mapper):
    return create_mock_protocol_mapper(mapper_type="oidc-usermodel-attribute-mapper", config={"userinfo.token.claim": "true", "user.attribute": "email"})

@pytest.fixture
def create_mock_protocol_mapper():
    def _create_mock_protocol_mapper(mapper_type="oidc-usermodel-attribute-mapper", config={"userinfo.token.claim": "true", "user.attribute": "email"}):
        mapper = Mock(spec=ProtocolMapper)
        mapper.get_protocol_mapper.return_value = mapper_type
        mapper.get_config.return_value = config
        return mapper
    
    return _create_mock_protocol_mapper

@pytest.fixture
def mock_group(mock_realm):
    group = Mock(spec=Group)
    group.get_path.return_value = "/test-group"
    group.get_name.return_value = "test-group"
    group.get_realm_roles.return_value = []
    group.get_client_roles.return_value = {}
    group.get_effective_realm_roles.return_value = []
    group.get_effective_client_roles.return_value = {}
    group.get_realm.return_value = mock_realm
    return group


# Loader for example realm dump
@pytest.fixture
def example_db():
    # Load example realm file from disk
    current_dir = os.path.dirname(os.path.abspath(__file__))
    test_json_path = os.path.normpath(os.path.join(current_dir, "fixtures", "test-realm-with-client.json"))

    # Create database and import realm into it
    db = InMemoryDatabase()
    load_realm_dump(test_json_path, db)
    return db
