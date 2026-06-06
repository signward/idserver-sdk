"""FastAPI integration for IdServer.

Install with the ``fastapi`` extra::

    pip install "signward-idserver-client[fastapi]"

Basic usage::

    from fastapi import FastAPI, Depends
    from idserver import IdServerClient
    from idserver.fastapi import IdServerAuth, CurrentUser

    app = FastAPI()

    idserver = IdServerClient(
        authority="https://mytenant.signward.com",
        client_id="my-api",
        client_secret="...",
    )
    auth = IdServerAuth(idserver)

    @app.get("/me")
    async def me(user: CurrentUser = Depends(auth.current_user)):
        return {"email": user.email, "roles": user.roles}

    @app.get("/admin")
    async def admin(user: CurrentUser = Depends(auth.require_role("admin"))):
        return {"ok": True}
"""

from __future__ import annotations

from typing import Annotated, Callable

try:
    from fastapi import Depends, HTTPException, Request, status
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "FastAPI is not installed. Install it with: pip install 'signward-idserver-client[fastapi]'"
    ) from exc

from idserver.client import IdServerClient
from idserver.exceptions import InvalidTokenError
from idserver.models import User

CurrentUser = User
"""Alias for :class:`idserver.models.User` — use as a type annotation."""


class IdServerAuth:
    """FastAPI helper that produces auth dependencies bound to an :class:`IdServerClient`."""

    def __init__(
        self,
        client: IdServerClient,
        *,
        scheme_name: str = "IdServer",
        auto_error: bool = True,
    ):
        self.client = client
        self._bearer = HTTPBearer(scheme_name=scheme_name, auto_error=auto_error)

    async def current_user(
        self,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer(auto_error=True))],
    ) -> User:
        """FastAPI dependency that validates the bearer token and returns a User."""
        token = credentials.credentials
        try:
            user = await self.client.validate_token(token)
        except InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from exc

        # Attach to request.state for downstream access
        request.state.idserver_user = user
        return user

    def require_role(
        self,
        *roles: str,
        require_all: bool = False,
        include_custom: bool = True,
    ) -> Callable[..., User]:
        """Return a dependency that enforces role membership.

        Parameters
        ----------
        *roles : str
            One or more roles. The user must have at least one (or all, if
            ``require_all=True``).
        require_all : bool
            If ``True``, require ALL listed roles.
        include_custom : bool
            If ``True`` (default), also check per-tenant custom RBAC roles.
        """

        async def dependency(user: User = Depends(self.current_user)) -> User:
            check = user.has_all_roles if require_all else user.has_any_role
            if not check(*roles, include_custom=include_custom):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient role",
                )
            return user

        return dependency
