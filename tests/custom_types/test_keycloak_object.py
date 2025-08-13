from unittest.mock import Mock

import pytest

from kcwarden.custom_types.keycloak_object import Client


class TestClient:
    @pytest.mark.parametrize(
        ["attributes", "expected"],
        [
            ({}, True),
            ({"use.refresh.tokens": "true"}, True),
            ({"use.refresh.tokens": "false"}, False),
        ],
    )
    def test_use_refresh_tokens(self, attributes: dict, expected: bool):
        client = Client(
            {
                "clientId": "TEST_CLIENT_ID",
                "attributes": attributes,
            },
            [],
            {},
            realm=Mock(),
        )
        assert client.use_refresh_tokens() == expected
