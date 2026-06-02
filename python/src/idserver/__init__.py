"""
IdServer — Python client SDK for Signward Identity Server.

Basic usage:

    from idserver import IdServerClient

    client = IdServerClient(
        authority="https://mytenant.signward.com",
        client_id="my-app",
        client_secret="...",
    )

    # Build authorize URL
    url = await client.authorize_url(redirect_uri="https://myapp.com/callback")

    # Exchange authorization code
    tokens = await client.exchange_code(code, redirect_uri="https://myapp.com/callback")

    # Validate access token → User
    user = await client.validate_token(tokens.access_token)
    print(user.email, user.roles)
"""

from idserver.client import IdServerClient, IdServerOptions
from idserver.exceptions import (
    IdServerError,
    InvalidTokenError,
    TokenExchangeError,
    DiscoveryError,
)
from idserver.models import TokenResponse, User

__all__ = [
    "IdServerClient",
    "IdServerOptions",
    "User",
    "TokenResponse",
    "IdServerError",
    "InvalidTokenError",
    "TokenExchangeError",
    "DiscoveryError",
]

__version__ = "0.11.1"
