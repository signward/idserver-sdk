# @signward/idserver-client

JavaScript / TypeScript client SDK for [Signward Identity Server](https://signward.com) —
OIDC authentication for Node.js, Express, and the browser. Open source, no
Microsoft-stack dependency.

## Features

- OIDC Authorization Code flow with PKCE (S256)
- Local JWT validation via the server's JWKS (HS256/RS256/ES256 — algorithm-agnostic)
- Discovery + JWKS caching
- Typed user model with built-in and per-tenant custom roles
- Universal: works in Node 18+ and modern browsers (uses native `fetch` + Web Crypto)
- First-class **Express** middleware
- MIT licensed

## Install

```bash
npm install @signward/idserver-client
```

Peer dependency for the Express middleware: `express >= 4.18`.

## Quickstart — Express (protecting an API)

```ts
import express from 'express';
import { IdServerClient } from '@signward/idserver-client';
import { requireAuth, requireRole } from '@signward/idserver-client/express';

const app = express();

const idserver = new IdServerClient({
  authority: 'https://mytenant.signward.com',
  clientId: 'my-api',
  clientSecret: process.env.IDSERVER_CLIENT_SECRET,
});

// Build auth middleware once, reuse on any route
const auth = requireAuth(idserver);

app.get('/me', auth, (req, res) => {
  res.json({
    id: req.user!.userId,
    email: req.user!.email,
    tenantId: req.user!.tenantId,
    roles: req.user!.roles,
    customRoles: req.user!.customRoles,
  });
});

app.get('/admin', auth, requireRole('admin'), (req, res) => {
  res.json({ ok: true });
});

app.get('/editors', auth, requireRole('admin', 'editor'), (req, res) => {
  res.json({ ok: true });
});

app.get(
  '/billing-admin',
  auth,
  requireRole('admin', 'billing', { requireAll: true }),
  (req, res) => {
    res.json({ ok: true });
  },
);

app.listen(3000);
```

Clients call your API with a bearer token obtained from Signward:

```
GET /me
Authorization: Bearer eyJhbGciOi...
```

## Quickstart — Server-side login flow (Express / Node)

```ts
import { IdServerClient } from '@signward/idserver-client';

const client = new IdServerClient({
  authority: 'https://mytenant.signward.com',
  clientId: 'my-webapp',
  clientSecret: process.env.IDSERVER_CLIENT_SECRET,
});

// 1) Build the login URL (with PKCE) and redirect
app.get('/login', async (req, res) => {
  const { url, verifier } = await client.authorizeUrlWithPkce({
    redirectUri: 'https://myapp.com/callback',
    state: req.query.returnTo as string ?? '/',
  });
  // Store the verifier in the session so you can pass it back later
  req.session!.pkceVerifier = verifier;
  res.redirect(url);
});

// 2) Handle the callback
app.get('/callback', async (req, res) => {
  const code = req.query.code as string;
  const tokens = await client.exchangeCode(code, {
    redirectUri: 'https://myapp.com/callback',
    codeVerifier: req.session!.pkceVerifier,
  });

  // Validate locally to get the user
  const user = await client.validateToken(tokens.access_token);

  req.session!.user = {
    email: user.email,
    roles: user.roles,
  };
  req.session!.tokens = tokens;

  res.redirect((req.query.state as string) ?? '/');
});

// 3) Refresh an expired access token
app.get('/refresh', async (req, res) => {
  const fresh = await client.refreshToken(req.session!.tokens.refresh_token);
  req.session!.tokens = fresh;
  res.json({ ok: true });
});

// 4) Logout
app.get('/logout', async (req, res) => {
  const url = await client.endSessionUrl({
    idTokenHint: req.session!.tokens?.id_token,
    postLogoutRedirectUri: 'https://myapp.com/',
  });
  req.session!.destroy?.(() => res.redirect(url));
});
```

## Quickstart — Browser (SPA)

The same `IdServerClient` works in the browser using native `fetch` + Web Crypto:

```ts
import { IdServerClient } from '@signward/idserver-client';

const client = new IdServerClient({
  authority: 'https://mytenant.signward.com',
  clientId: 'my-spa',
  // No clientSecret in the browser — use PKCE
});

// Login button handler
async function login() {
  const { url, verifier } = await client.authorizeUrlWithPkce({
    redirectUri: window.location.origin + '/callback',
  });
  sessionStorage.setItem('pkce', verifier);
  window.location.href = url;
}

// Callback page
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code')!;
  const verifier = sessionStorage.getItem('pkce')!;
  sessionStorage.removeItem('pkce');

  const tokens = await client.exchangeCode(code, {
    redirectUri: window.location.origin + '/callback',
    codeVerifier: verifier,
  });

  const user = await client.validateToken(tokens.access_token);
  console.log('Logged in as', user.email, user.roles);

  // Store tokens — consider using HttpOnly cookies via your backend instead
  sessionStorage.setItem('access_token', tokens.access_token);
}
```

> **Security tip:** for browser apps, prefer storing tokens in HttpOnly cookies
> set by your backend rather than in `sessionStorage` / `localStorage`. Never
> embed a client secret in browser code.

## User model

```ts
interface User {
  userId: string | null;        // sub claim
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  givenName: string | null;
  familyName: string | null;
  tenantId: string | null;
  roles: string[];              // built-in roles
  customRoles: string[];        // per-tenant RBAC roles
  claims: Record<string, unknown>;

  hasRole(role: string): boolean;
  hasCustomRole(role: string): boolean;
  hasAnyRole(...roles: string[]): boolean;
  hasAllRoles(...roles: string[]): boolean;
}
```

Role checks are case-insensitive.

## Error handling

All errors derive from `IdServerError`:

```ts
import {
  IdServerError,
  InvalidTokenError,
  TokenExchangeError,
  DiscoveryError,
  UserInfoError,
} from '@signward/idserver-client';

try {
  const user = await client.validateToken(token);
} catch (err) {
  if (err instanceof InvalidTokenError) { /* 401 */ }
  else if (err instanceof TokenExchangeError) { console.log(err.error, err.description, err.statusCode); }
  else if (err instanceof DiscoveryError) { /* can't reach IdServer */ }
}
```

## License

MIT
