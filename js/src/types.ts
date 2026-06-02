/**
 * OIDC discovery document (subset we care about).
 */
export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  jwks_uri: string;
  [key: string]: unknown;
}

/**
 * OAuth2 / OIDC token response from /connect/token.
 */
export interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  [key: string]: unknown;
}

/**
 * Raw claims payload from a JWT or userinfo response.
 */
export type Claims = Record<string, unknown>;

/**
 * Authenticated user extracted from an IdServer JWT or userinfo response.
 *
 * Built-in roles (admin, member …) live in `roles`. Per-tenant custom RBAC
 * roles live in `customRoles`.
 */
export interface User {
  userId: string | null;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  givenName: string | null;
  familyName: string | null;
  tenantId: string | null;
  roles: string[];
  customRoles: string[];
  claims: Claims;

  hasRole(role: string): boolean;
  hasCustomRole(role: string): boolean;
  hasAnyRole(...roles: string[]): boolean;
  hasAllRoles(...roles: string[]): boolean;
}

export interface RoleCheckOptions {
  /** Also consider per-tenant custom roles (default: true). */
  includeCustom?: boolean;
}

export interface IdServerOptions {
  /** Base URL of the IdServer instance, e.g. `https://mytenant.signward.com`. */
  authority: string;
  /** OIDC client identifier registered in IdServer. */
  clientId: string;
  /** OIDC client secret (for confidential clients). */
  clientSecret?: string;
  /** Default scopes requested when building an authorize URL. */
  scopes?: string[];
  /** Expected `aud` claim for validated tokens (default: `idserver-api`). */
  audience?: string;
  /** Expected `iss` claim. If not set, derived from the discovery document. */
  issuer?: string;
  /** HTTP request timeout in milliseconds (default: 10000). */
  timeoutMs?: number;
  /** Custom fetch implementation (default: global `fetch`). */
  fetch?: typeof fetch;
  /**
   * Optional web base URL used by {@link SignwardClient.getPrivacyCenterUrl}.
   * If omitted, the privacy center URL is derived from `authority` (the same host).
   * Example: `https://mytenant.signward.com`.
   */
  webBaseUrl?: string;
}

export interface AuthorizeUrlParams {
  redirectUri: string;
  scope?: string | string[];
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
  extraParams?: Record<string, string>;
}

export interface ExchangeCodeParams {
  redirectUri: string;
  codeVerifier?: string;
}

export interface ValidateTokenOptions {
  audience?: string;
  /** Clock skew tolerance in seconds (default: 10). */
  leeway?: number;
}

export interface EndSessionParams {
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}
