MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS = 3600  # 1 hour


def long_sso_session_idle_timeout_is_not_capped(sso_idle: int, client_idle: int) -> bool:
    """
    Whether a long SSO session idle timeout is not capped by a shorter client session idle timeout.
    A client session idle timeout of 0 means it is not set, so the SSO session idle timeout applies.
    """
    return sso_idle > MAX_SSO_SESSION_IDLE_TIMEOUT_SECONDS and (client_idle == 0 or client_idle >= sso_idle)
