"""Pydantic models for IdServer responses."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TokenResponse(BaseModel):
    """OAuth2 / OIDC token response from /connect/token."""

    model_config = ConfigDict(extra="allow")

    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


class User(BaseModel):
    """Authenticated user extracted from an IdServer JWT or userinfo response.

    Built-in roles (``admin``, ``member`` …) live in :attr:`roles`. Per-tenant
    custom RBAC roles live in :attr:`custom_roles`.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    user_id: UUID | None = Field(default=None, alias="sub")
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    tenant_id: UUID | None = None
    roles: list[str] = Field(default_factory=list)
    custom_roles: list[str] = Field(default_factory=list)

    # Preserve original claims for advanced use cases
    claims: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "User":
        """Build a User from a flat claims dict (JWT payload or userinfo JSON)."""
        def _as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [str(v) for v in value]
            return []

        display_name = claims.get("name")
        if not display_name:
            given = claims.get("given_name")
            family = claims.get("family_name")
            if given or family:
                display_name = " ".join(p for p in (given, family) if p).strip()

        return cls(
            sub=claims.get("sub"),
            email=claims.get("email"),
            email_verified=claims.get("email_verified"),
            name=display_name,
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            tenant_id=claims.get("tenant_id"),
            roles=_as_list(claims.get("roles")),
            custom_roles=_as_list(claims.get("custom_roles")),
            claims=claims,
        )

    # --- Convenience helpers ---------------------------------------------------

    def has_role(self, role: str) -> bool:
        """Check whether the user has a built-in role (case-insensitive)."""
        return role.lower() in (r.lower() for r in self.roles)

    def has_custom_role(self, role: str) -> bool:
        """Check whether the user has a per-tenant custom RBAC role (case-insensitive)."""
        return role.lower() in (r.lower() for r in self.custom_roles)

    def has_any_role(self, *roles: str, include_custom: bool = True) -> bool:
        """Check whether the user has any of the listed roles."""
        return any(
            self.has_role(r) or (include_custom and self.has_custom_role(r))
            for r in roles
        )

    def has_all_roles(self, *roles: str, include_custom: bool = True) -> bool:
        """Check whether the user has all of the listed roles."""
        return all(
            self.has_role(r) or (include_custom and self.has_custom_role(r))
            for r in roles
        )
