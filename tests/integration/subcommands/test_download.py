import json
import os
from pathlib import Path

import pytest
from keycloak import KeycloakAdmin

from kcwarden import cli


@pytest.mark.integration
def test_download_config(keycloak: KeycloakAdmin, tmp_path: Path):
    output_path = tmp_path / "config.json"
    test_args = [
        "download",
        "--auth-method",
        "password",
        keycloak.connection.server_url,
        "--user",
        keycloak.connection.username,
        "--output",
        str(output_path),
        "--realm",
        "master",
    ]
    os.environ["KCWARDEN_KEYCLOAK_PASSWORD"] = keycloak.connection.password
    cli.main(test_args)

    with output_path.open() as f:
        config = json.load(f)

    assert config["realm"] == "master"
    assert len(config["clients"]) == 6
