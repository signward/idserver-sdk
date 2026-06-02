"""Smoke tests for the User model — no network required."""

from uuid import UUID

from idserver.models import User


def test_from_claims_basic():
    claims = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "email": "alice@example.com",
        "email_verified": True,
        "given_name": "Alice",
        "family_name": "Smith",
        "tenant_id": "22222222-2222-2222-2222-222222222222",
        "roles": ["admin", "member"],
        "custom_roles": ["billing"],
        "exp": 1234567890,
    }
    user = User.from_claims(claims)

    assert user.user_id == UUID("11111111-1111-1111-1111-111111111111")
    assert user.email == "alice@example.com"
    assert user.email_verified is True
    assert user.name == "Alice Smith"
    assert user.tenant_id == UUID("22222222-2222-2222-2222-222222222222")
    assert user.roles == ["admin", "member"]
    assert user.custom_roles == ["billing"]
    assert user.claims["exp"] == 1234567890


def test_role_helpers():
    user = User.from_claims({
        "sub": "11111111-1111-1111-1111-111111111111",
        "roles": ["Admin"],
        "custom_roles": ["Billing"],
    })

    assert user.has_role("admin")               # case-insensitive
    assert not user.has_role("editor")
    assert user.has_custom_role("BILLING")
    assert user.has_any_role("editor", "admin")
    assert user.has_any_role("editor", "billing")  # custom role matches
    assert not user.has_any_role("editor", "billing", include_custom=False)
    assert user.has_all_roles("admin", "billing")
    assert not user.has_all_roles("admin", "editor")


def test_name_fallback_to_name_claim():
    user = User.from_claims({
        "sub": "11111111-1111-1111-1111-111111111111",
        "name": "Bob Jones",
    })
    assert user.name == "Bob Jones"


def test_roles_single_string():
    # Some IdPs return a single role as a string instead of a list
    user = User.from_claims({
        "sub": "11111111-1111-1111-1111-111111111111",
        "roles": "admin",
    })
    assert user.roles == ["admin"]


def test_missing_roles():
    user = User.from_claims({"sub": "11111111-1111-1111-1111-111111111111"})
    assert user.roles == []
    assert user.custom_roles == []
