import pytest
from unittest.mock import Mock

from kcwarden.custom_types.keycloak_object import ProtocolMapper
from kcwarden.monitors.subchecks.protocol_mapper import protocol_mapper_matches_config


@pytest.fixture
def mock_mapper():
    mapper = Mock(spec=ProtocolMapper)
    mapper.get_protocol_mapper.return_value = "oidc-usermodel-attribute-mapper"
    mapper.get_config.return_value = {"userinfo.token.claim": "true", "user.attribute": "email"}
    return mapper


def test_type_and_config_match(mock_mapper):
    assert protocol_mapper_matches_config(
        mock_mapper,
        "oidc-usermodel-attribute-mapper",
        {"userinfo.token.claim": "true", "user.attribute": "email"},
    )


def test_type_matches_config_does_not(mock_mapper):
    assert not protocol_mapper_matches_config(
        mock_mapper,
        "oidc-usermodel-attribute-mapper",
        {"userinfo.token.claim": "false"},
    )


def test_type_does_not_match(mock_mapper):
    assert not protocol_mapper_matches_config(mock_mapper, "oidc-audience-mapper", {})


def test_regex_in_type(mock_mapper):
    assert protocol_mapper_matches_config(mock_mapper, "oidc-.*-mapper", {"userinfo.token.claim": "true"})


def test_regex_in_config(mock_mapper):
    assert protocol_mapper_matches_config(
        mock_mapper,
        "oidc-usermodel-attribute-mapper",
        {"userinfo.token.claim": "tr.*", "user.attribute": "em.*"},
    )


def test_empty_config_matches_any_mapper_of_type(mock_mapper):
    assert protocol_mapper_matches_config(mock_mapper, "oidc-usermodel-attribute-mapper", {})


def test_config_key_not_present_in_mapper(mock_mapper):
    assert not protocol_mapper_matches_config(
        mock_mapper,
        "oidc-usermodel-attribute-mapper",
        {"nonexistent.key": "value"},
    )
