import requests

from kcwarden.utils.plugins import logger

GITHUB_API_PATH_LATEST_KEYCLOAK_RELEASE = "https://api.github.com/repos/keycloak/keycloak/releases/latest"


def get_latest_keycloak_version() -> str | None:
    try:
        response = requests.get(GITHUB_API_PATH_LATEST_KEYCLOAK_RELEASE, timeout=10).json()
        return response.get("tag_name", None)
    except requests.exceptions.RequestException as e:
        logger.warning("Latest Keycloak version cannot be fetched from GitHub due to: %s", e)
        return None
