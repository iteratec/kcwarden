MAX_ACCESS_TOKEN_LIFESPAN_SECONDS = 600  # 10 minutes


def access_token_lifespan_is_too_long(lifespan: int) -> bool:
    # 0 means unlimited
    return lifespan <= 0 or lifespan > MAX_ACCESS_TOKEN_LIFESPAN_SECONDS
