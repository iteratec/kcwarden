from kcwarden.custom_types.keycloak_object import ProtocolMapper
from kcwarden.database import helper


def protocol_mapper_matches_config(
    mapper: ProtocolMapper, target_mapper_type: str, target_mapper_config: dict[str, str]
) -> bool:
    if not helper.matches_as_string_or_regex(mapper.get_protocol_mapper(), target_mapper_type):
        return False

    mapper_config = mapper.get_config()
    for cfg_key, cfg_value in target_mapper_config.items():
        if cfg_key not in mapper_config:
            return False
        if not helper.matches_as_string_or_regex(mapper_config[cfg_key], cfg_value):
            return False
    return True
