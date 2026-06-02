"""Async IdServer OIDC client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import get_default_algorithms

from idserver.exceptions import (
    DiscoveryError,
    InvalidTokenError,
    TokenExchangeError,
    UserInfoError,
)
from idserver.models import TokenResponse, User


@dataclass
class IdServerOptions:
    """Configuration for :class:`IdServerClient`."""

    authority: str
    """Base URL of the IdServer instance, e.g. ``https://mytenant.signward.com``."""

    client_id: str
    """OIDC client identifier registered in IdServer."""

    client_secret: str | None = None
    """OIDC client secret (for confidential clients)."""

    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    """Default scopes requested when building an authorize URL."""

    audience: str | None = None
    """Expected ``aud`` claim for validated tokens (default: ``idserver-api``)."""

    issuer: str | None = None
    """Expected ``iss`` claim. If ``None``, derived from the discovery document."""

    timeout: float = 10.0
    """HTTP request timeout in seconds."""

    verify_ssl: bool = True
    """Whether to verify the TLS certificate of the IdServer."""

    web_base_url: str | None = None
    """Optional web base URL used by :meth:`IdServerClient.get_privacy_center_url`.
    If ``None``, the privacy center URL is derived from ``authority``."""


class IdServerClient:
    """Async OIDC client for Signward Identity Server.

    Implements the Authorization Code + PKCE flow, token exchange, userinfo,
    and local JWT validation using the server's JWKS.

    The discovery document and JWKS are fetched lazily and cached for the
    lifetime of the client. Call :meth:`refresh_metadata` to force a reload
    (e.g. after a key rotation).

    Usage
    -----
    >>> async with IdServerClient(authority="...", client_id="...", client_secret="...") as client:
    ...     url, verifier = client.authorize_url_with_pkce(redirect_uri="https://app/callback")
    ...     # redirect user to `url`, then after callback:
    ...     tokens = await client.exchange_code(code, redirect_uri="...", code_verifier=verifier)
    ...     user = await client.validate_token(tokens.access_token)
    """

    def __init__(
        self,
        authority: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        *,
        options: IdServerOptions | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        if options is None:
            if authority is None or client_id is None:
                raise ValueError("authority and client_id are required")
            options = IdServerOptions(
                authority=authority,
                client_id=client_id,
                client_secret=client_secret,
            )
        self.options = options
        self._authority = options.authority.rstrip("/")
        self._http = http_client
        self._owns_http = http_client is None
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._metadata_lock = asyncio.Lock()

    # --- Context manager ------------------------------------------------------

    async def __aenter__(self) -> "IdServerClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client (if this instance owns it)."""
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    def _get_http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=self.options.timeout,
                verify=self.options.verify_ssl,
            )
        return self._http

    # --- Discovery / JWKS -----------------------------------------------------

    async def discovery(self) -> dict[str, Any]:
        """Return the cached OIDC discovery document (fetching it if needed)."""
        if self._discovery is None:
            async with self._metadata_lock:
                if self._discovery is None:
                    await self._load_metadata()
        assert self._discovery is not None
        return self._discovery

    async def jwks(self) -> dict[str, Any]:
        """Return the cached JWKS (fetching it if needed)."""
        if self._jwks is None:
            async with self._metadata_lock:
                if self._jwks is None:
                    await self._load_metadata()
        assert self._jwks is not None
        return self._jwks

    async def refresh_metadata(self) -> None:
        """Force a reload of the discovery document and JWKS."""
        async with self._metadata_lock:
            await self._load_metadata()

    async def _load_metadata(self) -> None:
        http = self._get_http()
        try:
            disc_resp = await http.get(f"{self._authority}/.well-known/openid-configuration")
            disc_resp.raise_for_status()
            self._discovery = disc_resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DiscoveryError(f"Failed to fetch OIDC discovery document: {exc}") from exc

        jwks_uri = self._discovery.get("jwks_uri")
        if not jwks_uri:
            raise DiscoveryError("Discovery document missing jwks_uri")

        try:
            jwks_resp = await http.get(jwks_uri)
            jwks_resp.raise_for_status()
            self._jwks = jwks_resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DiscoveryError(f"Failed to fetch JWKS: {exc}") from exc

    # --- Authorization URL ----------------------------------------------------

    def authorize_url(
        self,
        *,
        redirect_uri: str,
        scope: str | list[str] | None = None,
        state: str | None = None,
        nonce: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> str:
        """Build an authorization URL for the Authorization Code flow.

        This method does not hit the network. If you want PKCE, prefer
        :meth:`authorize_url_with_pkce` which generates the code verifier for you.
        """
        if isinstance(scope, list):
            scope_str = " ".join(scope)
        elif scope is None:
            scope_str = " ".join(self.options.scopes)
        else:
            scope_str = scope

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.options.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope_str,
        }
        if state:
            params["state"] = state
        if nonce:
            params["nonce"] = nonce
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"
        if extra_params:
            params.update(extra_params)

        return f"{self._authority}/connect/authorize?{urlencode(params)}"

    def get_privacy_center_url(self) -> str:
        """Return the URL of the Signward privacy self-service center for the end user.

        Use this for "Manage your privacy" / "Withdraw consent" footer links in
        your app. The user must be logged in via Signward to access it.

        Defaults to ``<authority>/Auth/MyPrivacy``. Override via
        :attr:`IdServerOptions.web_base_url` if the web frontend is on a different
        host than the API.
        """
        base = (self.options.web_base_url or self._authority).rstrip("/")
        return f"{base}/Auth/MyPrivacy"

    def authorize_url_with_pkce(
        self,
        *,
        redirect_uri: str,
        scope: str | list[str] | None = None,
        state: str | None = None,
        nonce: str | None = None,
    ) -> tuple[str, str]:
        """Build an authorization URL with a freshly generated PKCE verifier.

        Returns
        -------
        tuple[str, str]
            ``(authorize_url, code_verifier)`` — store the verifier in the
            session and pass it back to :meth:`exchange_code`.
        """
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        url = self.authorize_url(
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        return url, verifier

    # --- Token endpoint -------------------------------------------------------

    async def exchange_code(
        self,
        code: str,
        *,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.options.client_id,
        }
        if self.options.client_secret:
            data["client_secret"] = self.options.client_secret
        if code_verifier:
            data["code_verifier"] = code_verifier

        return await self._post_token(data)

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """Exchange a refresh token for a new access token."""
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.options.client_id,
        }
        if self.options.client_secret:
            data["client_secret"] = self.options.client_secret
        return await self._post_token(data)

    async def _post_token(self, data: dict[str, str]) -> TokenResponse:
        discovery = await self.discovery()
        token_endpoint = discovery.get("token_endpoint") or f"{self._authority}/connect/token"

        http = self._get_http()
        resp = await http.post(token_endpoint, data=data)

        if resp.status_code >= 400:
            payload: dict[str, Any] = {}
            try:
                payload = resp.json()
            except ValueError:
                pass
            raise TokenExchangeError(
                error=payload.get("error", "token_error"),
                description=payload.get("error_description"),
                status_code=resp.status_code,
            )
        return TokenResponse.model_validate(resp.json())

    # --- Userinfo -------------------------------------------------------------

    async def userinfo(self, access_token: str) -> User:
        """Fetch the userinfo endpoint and return a :class:`User`."""
        discovery = await self.discovery()
        endpoint = discovery.get("userinfo_endpoint") or f"{self._authority}/connect/userinfo"

        http = self._get_http()
        resp = await http.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
        if resp.status_code >= 400:
            raise UserInfoError(f"userinfo returned {resp.status_code}: {resp.text}")
        return User.from_claims(resp.json())

    # --- Token validation -----------------------------------------------------

    async def validate_token(
        self,
        token: str,
        *,
        audience: str | None = None,
        leeway: int = 10,
    ) -> User:
        """Validate a JWT locally using the server's JWKS and return the user.

        Parameters
        ----------
        token : str
            The JWT to validate (access_token or id_token).
        audience : str | None
            Expected audience claim. Defaults to :attr:`IdServerOptions.audience`
            or ``"idserver-api"``.
        leeway : int
            Clock skew tolerance in seconds.

        Raises
        ------
        InvalidTokenError
            If the signature, issuer, audience, or expiry is invalid.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(f"Malformed token: {exc}") from exc

        key = await self._get_signing_key(unverified_header.get("kid"))

        discovery = await self.discovery()
        issuer = self.options.issuer or discovery.get("issuer") or self._authority
        expected_audience = audience or self.options.audience or "idserver-api"
        algorithm = unverified_header.get("alg") or "HS256"

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                audience=expected_audience,
                issuer=issuer,
                leeway=leeway,
                options={"require": ["exp", "iat"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc

        return User.from_claims(claims)

    async def _get_signing_key(self, kid: str | None) -> Any:
        jwks = await self.jwks()
        keys = jwks.get("keys", [])
        if not keys:
            raise InvalidTokenError("JWKS contains no keys")

        matching: dict[str, Any] | None = None
        if kid:
            matching = next((k for k in keys if k.get("kid") == kid), None)
        if matching is None:
            # Fall back to the first key (single-key JWKS is the common case)
            matching = keys[0]

        kty = matching.get("kty")
        algs = get_default_algorithms()
        alg_name = matching.get("alg") or ("HS256" if kty == "oct" else "RS256")
        try:
            return algs[alg_name].from_jwk(matching)
        except KeyError as exc:
            raise InvalidTokenError(f"Unsupported JWK alg: {alg_name}") from exc

    # --- Logout URL -----------------------------------------------------------

    async def end_session_url(
        self,
        *,
        id_token_hint: str | None = None,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str:
        """Build the end-session (logout) URL."""
        discovery = await self.discovery()
        endpoint = discovery.get("end_session_endpoint") or f"{self._authority}/connect/endsession"

        params: dict[str, str] = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state

        if not params:
            return endpoint
        return f"{endpoint}?{urlencode(params)}"
