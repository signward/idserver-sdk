# Changelog — idserver-client (Python)

All notable changes to the Python SDK are documented in this file.

From v0.19.4 onwards, the Python SDK is **synchronised with the Signward Identity Server backend release** for consistency with the C# (NuGet) and JavaScript (npm) SDKs.

## [1.0.0] — 2026-06-02

First public release on PyPI, aligned with the Signward 1.0.0 GA launch.

### Changed
- Synchronised to the Signward backend **1.0.0** release.

### Added
- Bundled `LICENSE` file (MIT) in the source and wheel distributions.

### Compatibility notes
- **No API change** vs 0.19.4 — the `User`, `IdServerClient`, and FastAPI / Flask integration surface is unchanged. Existing code keeps working after upgrading.

---

## [0.19.4] — 2026-05-26

### Changed
- **Versioning strategy** — the SDK now follows the backend version (was a separate `0.11.x` track until this release). The 0.11.1 → 0.19.4 jump is a one-time synchronisation, not a breaking change.
- **Development status** — `Development Status :: 5 - Production/Stable` (was Beta).
- **Tested against Signward backend v0.19.4** (signup + recurring billing verified end-to-end).

### Compatibility notes
- **No breaking change** vs 0.11.1. The same `User`, `Client`, FastAPI / Flask integration surface is preserved.
- The Signward backend now emits an additional `tenant_subdomain` claim from `/connect/userinfo` (v0.19.x). The SDK reads it into the raw `claims` dict on the `User` model — application code can access it via `user.claims.get("tenant_subdomain")`. No typed property is added in this release to avoid the breaking import surface change.

### Tested platforms
- Python 3.10, 3.11, 3.12, 3.13
- FastAPI ≥ 0.100, Flask ≥ 2.0
- httpx ≥ 0.27, PyJWT[crypto] ≥ 2.8, Pydantic ≥ 2.5

---

## [0.11.x] (historical)
Pre-synchronisation track. Last release was 0.11.1 — feature-complete OIDC flow for FastAPI/Flask, PKCE, JWKS caching, `/.well-known/openid-configuration` discovery.
