# Changelog — idserver-client (Python)

All notable changes to the Python SDK are documented in this file.

## [1.0.0] — 2026-06-02

First public release. OIDC authentication client for FastAPI, Flask, and other Python apps.

### Features
- OIDC Authorization Code flow with optional PKCE
- Local JWT validation via the server's JWKS, with discovery + JWKS caching
- Typed Pydantic v2 user model with built-in and per-tenant custom roles
- Async-first (`httpx.AsyncClient`)
- First-class FastAPI integration; Flask helpers
- MIT licensed

### Tested platforms
- Python 3.10, 3.11, 3.12, 3.13
- FastAPI ≥ 0.100, Flask ≥ 2.0
- httpx ≥ 0.27, PyJWT[crypto] ≥ 2.8, Pydantic ≥ 2.5
