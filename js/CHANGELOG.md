# Changelog — @signward/idserver-client (JavaScript / TypeScript)

All notable changes to the JavaScript / TypeScript SDK are documented in this file.

## [1.0.0] — 2026-06-02

First public release. OIDC authentication client for Node.js, Express, and the browser.

### Features
- OIDC Authorization Code flow with PKCE (S256)
- Local JWT validation via the server's JWKS, with discovery + JWKS caching
- Typed user model with built-in and per-tenant custom roles
- Universal: works in Node 18+ and modern browsers (native `fetch` + Web Crypto)
- First-class Express middleware
- MIT licensed

### Tested platforms
- Node.js 18, 20, 22
- Express ≥ 4.18 (peer dependency, optional)
- `jose` ≥ 5.9 for JWKS / JWT verification
