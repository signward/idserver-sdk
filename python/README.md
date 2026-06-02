# idserver-client

Python client SDK for [Signward Identity Server](https://signward.com) — OIDC
authentication for **FastAPI** and other Python apps. Open source, no
Microsoft-stack dependency.

## Features

- OIDC Authorization Code flow (with optional PKCE)
- Local JWT validation via the server's JWKS (`HS256` today, algorithm-agnostic)
- Discovery + JWKS caching
- Typed Pydantic v2 user model with built-in and per-tenant custom roles
- Async-first (`httpx.AsyncClient`)
- First-class **FastAPI** integration (`Depends`-friendly auth helpers)
- MIT licensed

## Install

```bash
pip install "idserver-client[fastapi]"
```

Core-only (no framework integration):

```bash
pip install idserver-client
```

Python 3.10+.

## Quickstart — FastAPI (protecting an API)

```python
from fastapi import FastAPI, Depends
from idserver import IdServerClient
from idserver.fastapi import IdServerAuth, CurrentUser

app = FastAPI()

idserver = IdServerClient(
    authority="https://mytenant.signward.com",
    client_id="my-api",
    client_secret="...",          # if confidential
    options=None,
)
auth = IdServerAuth(idserver)


@app.get("/me")
async def me(user: CurrentUser = Depends(auth.current_user)):
    return {
        "id": user.user_id,
        "email": user.email,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "custom_roles": user.custom_roles,
    }


@app.get("/admin")
async def admin(user: CurrentUser = Depends(auth.require_role("admin"))):
    return {"ok": True}


@app.get("/editors-or-admins")
async def editors(
    user: CurrentUser = Depends(auth.require_role("admin", "editor")),
):
    return {"ok": True}


@app.get("/billing-admin-only")
async def billing(
    user: CurrentUser = Depends(
        auth.require_role("admin", "billing", require_all=True)
    ),
):
    return {"ok": True}
```

Clients call your API with a bearer token obtained from Signward:

```
GET /me
Authorization: Bearer eyJhbGciOi...
```

## Quickstart — Server-side login flow

For a Python web app that wants to perform the full OIDC login flow itself:

```python
from idserver import IdServerClient

client = IdServerClient(
    authority="https://mytenant.signward.com",
    client_id="my-webapp",
    client_secret="...",
)

# 1) Redirect the user to the login page:
url, verifier = client.authorize_url_with_pkce(
    redirect_uri="https://myapp.com/callback",
    state="random-state",
)
# Store `verifier` and `state` in the session, redirect to `url`.

# 2) On callback (?code=...&state=...):
tokens = await client.exchange_code(
    code,
    redirect_uri="https://myapp.com/callback",
    code_verifier=verifier,
)

# 3) Validate the access token locally:
user = await client.validate_token(tokens.access_token)
print(user.email, user.roles)

# 4) Or fetch userinfo remotely:
user = await client.userinfo(tokens.access_token)

# 5) Later, refresh:
new_tokens = await client.refresh_token(tokens.refresh_token)

# 6) Logout URL:
logout = await client.end_session_url(
    id_token_hint=tokens.id_token,
    post_logout_redirect_uri="https://myapp.com/",
)
```

## User model

```python
class User:
    user_id: UUID | None         # "sub" claim
    email: str | None
    email_verified: bool | None
    name: str | None
    given_name: str | None
    family_name: str | None
    tenant_id: UUID | None
    roles: list[str]             # built-in roles
    custom_roles: list[str]      # per-tenant RBAC roles
    claims: dict                 # raw JWT / userinfo payload

    def has_role(self, role: str) -> bool: ...
    def has_custom_role(self, role: str) -> bool: ...
    def has_any_role(self, *roles: str, include_custom: bool = True) -> bool: ...
    def has_all_roles(self, *roles: str, include_custom: bool = True) -> bool: ...
```

## Configuration

Pass values directly to `IdServerClient` or use an `IdServerOptions` dataclass
for more control:

```python
from idserver import IdServerClient, IdServerOptions

client = IdServerClient(options=IdServerOptions(
    authority="https://mytenant.signward.com",
    client_id="my-app",
    client_secret="...",
    scopes=["openid", "profile", "email", "roles"],
    audience="idserver-api",     # expected JWT aud claim
    issuer=None,                 # default: discovery.issuer
    timeout=10.0,
    verify_ssl=True,             # set False for localhost dev
))
```

## Using your own HTTP client

If you want to share an `httpx.AsyncClient` with the rest of your app:

```python
import httpx
from idserver import IdServerClient

shared_http = httpx.AsyncClient(timeout=20.0)
client = IdServerClient(
    authority="...",
    client_id="...",
    http_client=shared_http,
)
# When constructed this way, IdServerClient will NOT close shared_http.
```

## Error handling

All exceptions derive from `idserver.IdServerError`:

```python
from idserver import IdServerError, InvalidTokenError, TokenExchangeError

try:
    user = await client.validate_token(token)
except InvalidTokenError as e:
    ...
except TokenExchangeError as e:
    print(e.error, e.description, e.status_code)
except IdServerError as e:
    ...
```

## License

MIT
