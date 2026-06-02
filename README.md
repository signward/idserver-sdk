# Signward SDKs

Official client SDKs for [Signward](https://signward.com) — white-label OIDC
authentication you can drop into your apps in minutes. Open source (MIT), no
Microsoft-stack dependency.

| Language | Package | Install | Docs |
| --- | --- | --- | --- |
| Python | `idserver-client` | `pip install "idserver-client[fastapi]"` | [Python SDK](https://developer.signward.com/sdks/python) |
| JavaScript / TypeScript | `@signward/idserver-client` | `npm install @signward/idserver-client` | [JS/TS SDK](https://developer.signward.com/sdks/javascript) |
| .NET | `IdServer.Client` | `dotnet add package IdServer.Client` | [.NET SDK](https://developer.signward.com/sdks/dotnet) |

## What's in this repo

- [`python/`](python/) — Python SDK for FastAPI, Flask, and other Python apps
- [`js/`](js/) — JavaScript / TypeScript SDK for Node.js, Express, and the browser

The .NET SDK (`IdServer.Client`) ships via NuGet; its source lives in the main
Signward server repository.

## What the SDKs do

- OIDC Authorization Code flow with PKCE
- Local JWT validation via the server's JWKS, with discovery + JWKS caching
- Typed user model with built-in and per-tenant custom roles
- Framework integrations: FastAPI / Flask (Python), Express (JS/TS), ASP.NET Core (.NET)

## Quickstart

**Python (FastAPI):**

```python
from idserver import IdServerClient
from idserver.fastapi import IdServerAuth, CurrentUser
from fastapi import FastAPI, Depends

app = FastAPI()
idserver = IdServerClient(authority="https://mytenant.signward.com", client_id="my-api")
auth = IdServerAuth(idserver)

@app.get("/me")
async def me(user: CurrentUser = Depends(auth.current_user)):
    return {"email": user.email, "roles": user.roles}
```

**JavaScript / TypeScript (Express):**

```ts
import { IdServerClient } from '@signward/idserver-client';
import { requireAuth } from '@signward/idserver-client/express';

const idserver = new IdServerClient({ authority: 'https://mytenant.signward.com', clientId: 'my-api' });
app.get('/me', requireAuth(idserver), (req, res) => res.json({ email: req.user!.email }));
```

See each package's own README for the full guide.

## Documentation

Full guides, API reference, and per-SDK docs: **[developer.signward.com](https://developer.signward.com)**

## License

MIT — see [`python/LICENSE`](python/LICENSE) and [`js/LICENSE`](js/LICENSE).
