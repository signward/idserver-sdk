# Changelog — @signward/idserver-client (JavaScript / TypeScript)

All notable changes to the JavaScript / TypeScript SDK are documented in this file.

From v0.19.4 onwards, the JS SDK is **synchronised with the Signward Identity Server backend release** for consistency with the C# (NuGet) and Python (PyPI) SDKs.

## [0.19.4] — 2026-05-26

### Changed
- **Versioning strategy** — the SDK now follows the backend version (was a separate `0.11.x` track until this release). The 0.11.1 → 0.19.4 jump is a one-time synchronisation, not a breaking change.
- **Tested against Signward backend v0.19.4** (signup + recurring billing verified end-to-end).

### Compatibility notes
- **No breaking change** vs 0.11.1. The same `Client`, `userFromClaims`, Express middleware surface is preserved.
- ESM-only (was already in 0.11.x). Requires Node ≥ 18.
- The Signward backend now emits an additional `tenant_subdomain` claim from `/connect/userinfo` (v0.19.x). The SDK passes it through in the raw `claims` object on the user — application code can access it via `user.claims.tenant_subdomain`. No typed property is added in this release to avoid the breaking export surface change.

### Tested platforms
- Node.js 18, 20, 22
- Express ≥ 4.18 (peer dependency, optional)
- `jose` ≥ 5.9 for JWKS / JWT verification

---

## [0.11.x] (historical)
Pre-synchronisation track. Last release was 0.11.1 — feature-complete OIDC flow for Node.js + Express + browser SPA, PKCE, JWKS caching, token refresh.
