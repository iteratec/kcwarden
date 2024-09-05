import logging
import os

import pytest
from testcontainers.keycloak import KeycloakContainer

KEYCLOAK_VERSIONS_ENV_VARIABLE = "INTEGRATION_TEST_KEYCLOAK_VERSIONS"
KEYCLOAK_VERSIONS_ENV_VALUE = os.environ.get(KEYCLOAK_VERSIONS_ENV_VARIABLE)
KEYCLOAK_VERSIONS_TO_TEST = (
    KEYCLOAK_VERSIONS_ENV_VALUE.split(" ") if KEYCLOAK_VERSIONS_ENV_VALUE is not None else ["latest", "22.0", "18.0"]
)


@pytest.fixture(scope="module", params=KEYCLOAK_VERSIONS_TO_TEST)
def keycloak(request):
    """
    This fixture provides a KeycloakAdmin instance for testing purposes.
    It automatically creates instances of the consuming tests for multiple Keycloak versions.
    Currently, we use the latest version, the base version of Red Hat Build of Keycloak and
    the base version of Red Hat Single Sign-On.
    """
    logging.getLogger("testcontainers.core.waiting_utils").setLevel(logging.WARNING)
    with KeycloakContainer(image=f"quay.io/keycloak/keycloak:{request.param}") as kc:
        yield kc.get_client()
