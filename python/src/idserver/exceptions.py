"""Exception hierarchy for IdServer client."""


class IdServerError(Exception):
    """Base exception for all IdServer client errors."""


class DiscoveryError(IdServerError):
    """Raised when the OIDC discovery document or JWKS cannot be fetched."""


class TokenExchangeError(IdServerError):
    """Raised when an authorization code / refresh token exchange fails.

    Attributes
    ----------
    error : str
        The OAuth2 `error` code from the server (e.g. ``invalid_grant``).
    description : str | None
        The human-readable `error_description` from the server, if any.
    status_code : int
        The HTTP status code returned by the token endpoint.
    """

    def __init__(self, error: str, description: str | None, status_code: int):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(f"{error}: {description}" if description else error)


class InvalidTokenError(IdServerError):
    """Raised when a token fails signature or claim validation."""


class UserInfoError(IdServerError):
    """Raised when the userinfo endpoint returns an error."""
