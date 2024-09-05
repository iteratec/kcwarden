from unittest.mock import Mock

import pytest

from kcwarden.database.in_memory_db import InMemoryDatabase
from kcwarden.custom_types.config_keys import AUDITOR_CONFIG

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


# Mocked data objects
@pytest.fixture
def mock_idp():
    idp = Mock()
    return idp


@pytest.fixture
def mock_realm():
    realm = Mock()
    realm.get_name.return_value = "mock-realm"
    return realm


@pytest.fixture
def mock_scope():
    scope = Mock()
    return scope


@pytest.fixture
def mock_client(mock_realm):
    client = Mock()
    client.get_name.return_value = "mock-test-client"
    client.is_enabled.return_value = True
    client.get_realm.return_value = mock_realm
    client.get_default_client_scopes.return_value = []
    client.get_optional_client_scopes.return_value = []
    client.is_oidc_client.return_value = True
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
def mock_role():
    role = Mock()
    role.is_client_role.return_value = False
    role.is_composite_role.return_value = False
    role.get_composite_roles.return_value = {}
    role.get_client_name.return_value = "realm"
    return role


@pytest.fixture
def mock_client_role(mock_role):
    mock_role.is_client_role.return_value = True
    mock_role.get_client_name.return_value = "mock_client"
    return mock_role


@pytest.fixture
def mock_composite_role(mock_role):
    mock_role.is_composite_role.return_value = True
    return mock_role
