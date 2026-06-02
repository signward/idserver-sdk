import {
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type KeyLike,
} from 'jose';

import {
  DiscoveryError,
  InvalidTokenError,
  TokenExchangeError,
  UserInfoError,
} from './errors.js';
import { generatePkcePair } from './pkce.js';
import {
  type AuthorizeUrlParams,
  type Claims,
  type DiscoveryDocument,
  type EndSessionParams,
  type ExchangeCodeParams,
  type IdServerOptions,
  type TokenResponse,
  type User,
  type ValidateTokenOptions,
} from './types.js';

interface JwksDocument {
  keys: JWK[];
}

/**
 * Build a {@link User} from a flat claims payload.
 */
export function userFromClaims(claims: Claims): User {
  const asList = (value: unknown): string[] => {
    if (value == null) return [];
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.map((v) => String(v));
    return [];
  };

  let name = (claims.name as string | undefined) ?? null;
  if (!name) {
    const given = claims.given_name as string | undefined;
    const family = claims.family_name as string | undefined;
    if (given || family) {
      name = [given, family].filter(Boolean).join(' ').trim();
    }
  }

  const roles = asList(claims.roles);
  const customRoles = asList(claims.custom_roles);

  const hasRole = (role: string): boolean =>
    roles.some((r) => r.toLowerCase() === role.toLowerCase());
  const hasCustomRole = (role: string): boolean =>
    customRoles.some((r) => r.toLowerCase() === role.toLowerCase());

  return {
    userId: (claims.sub as string | undefined) ?? null,
    email: (claims.email as string | undefined) ?? null,
    emailVerified: (claims.email_verified as boolean | undefined) ?? null,
    name,
    givenName: (claims.given_name as string | undefined) ?? null,
    familyName: (claims.family_name as string | undefined) ?? null,
    tenantId: (claims.tenant_id as string | undefined) ?? null,
    roles,
    customRoles,
    claims,
    hasRole,
    hasCustomRole,
    hasAnyRole: (...rs: string[]) => rs.some((r) => hasRole(r) || hasCustomRole(r)),
    hasAllRoles: (...rs: string[]) => rs.every((r) => hasRole(r) || hasCustomRole(r)),
  };
}

/**
 * OIDC client for Signward Identity Server.
 *
 * Implements the Authorization Code + PKCE flow, token exchange, userinfo,
 * and local JWT validation via the server's JWKS. Works in Node 18+ and
 * modern browsers (uses native `fetch` and Web Crypto).
 */
export class IdServerClient {
  private readonly authority: string;
  private readonly options: Required<Omit<IdServerOptions, 'clientSecret' | 'issuer' | 'fetch' | 'scopes' | 'audience'>> &
    Pick<IdServerOptions, 'clientSecret' | 'issuer'> & {
      scopes: string[];
      audience: string;
      fetchFn: typeof fetch;
    };

  private discoveryCache: DiscoveryDocument | null = null;
  private jwksCache: JwksDocument | null = null;
  private jwksKeyCache = new Map<string, KeyLike | Uint8Array>();
  private metadataPromise: Promise<void> | null = null;

  constructor(options: IdServerOptions) {
    if (!options.authority) throw new Error('authority is required');
    if (!options.clientId) throw new Error('clientId is required');

    this.authority = options.authority.replace(/\/+$/, '');
    this.options = {
      authority: this.authority,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      scopes: options.scopes ?? ['openid', 'profile', 'email'],
      audience: options.audience ?? 'idserver-api',
      issuer: options.issuer,
      timeoutMs: options.timeoutMs ?? 10_000,
      fetchFn: options.fetch ?? fetch,
      webBaseUrl: options.webBaseUrl ?? this.authority,
    };
  }

  // --- Discovery / JWKS -----------------------------------------------------

  async discovery(): Promise<DiscoveryDocument> {
    if (this.discoveryCache) return this.discoveryCache;
    await this.loadMetadata();
    return this.discoveryCache!;
  }

  async jwks(): Promise<JwksDocument> {
    if (this.jwksCache) return this.jwksCache;
    await this.loadMetadata();
    return this.jwksCache!;
  }

  async refreshMetadata(): Promise<void> {
    this.discoveryCache = null;
    this.jwksCache = null;
    this.jwksKeyCache.clear();
    this.metadataPromise = null;
    await this.loadMetadata();
  }

  private async loadMetadata(): Promise<void> {
    if (this.metadataPromise) return this.metadataPromise;
    this.metadataPromise = (async () => {
      try {
        const discResp = await this.fetchWithTimeout(
          `${this.authority}/.well-known/openid-configuration`,
        );
        if (!discResp.ok) {
          throw new DiscoveryError(`Discovery HTTP ${discResp.status}`);
        }
        this.discoveryCache = (await discResp.json()) as DiscoveryDocument;
      } catch (err) {
        this.metadataPromise = null;
        throw err instanceof DiscoveryError
          ? err
          : new DiscoveryError(`Failed to fetch discovery document: ${(err as Error).message}`, { cause: err });
      }

      const jwksUri = this.discoveryCache.jwks_uri;
      if (!jwksUri) {
        this.metadataPromise = null;
        throw new DiscoveryError('Discovery document missing jwks_uri');
      }

      try {
        const jwksResp = await this.fetchWithTimeout(jwksUri);
        if (!jwksResp.ok) {
          throw new DiscoveryError(`JWKS HTTP ${jwksResp.status}`);
        }
        this.jwksCache = (await jwksResp.json()) as JwksDocument;
      } catch (err) {
        this.metadataPromise = null;
        throw err instanceof DiscoveryError
          ? err
          : new DiscoveryError(`Failed to fetch JWKS: ${(err as Error).message}`, { cause: err });
      }
    })();
    return this.metadataPromise;
  }

  private async fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs);
    try {
      return await this.options.fetchFn(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  // --- Authorization URL ----------------------------------------------------

  authorizeUrl(params: AuthorizeUrlParams): string {
    const scopeStr = Array.isArray(params.scope)
      ? params.scope.join(' ')
      : params.scope ?? this.options.scopes.join(' ');

    const query = new URLSearchParams({
      response_type: 'code',
      client_id: this.options.clientId,
      redirect_uri: params.redirectUri,
      scope: scopeStr,
    });
    if (params.state) query.set('state', params.state);
    if (params.nonce) query.set('nonce', params.nonce);
    if (params.codeChallenge) {
      query.set('code_challenge', params.codeChallenge);
      query.set('code_challenge_method', params.codeChallengeMethod ?? 'S256');
    }
    if (params.extraParams) {
      for (const [k, v] of Object.entries(params.extraParams)) query.set(k, v);
    }

    return `${this.authority}/connect/authorize?${query.toString()}`;
  }

  /**
   * Returns the URL of the Signward privacy self-service center for the end user.
   * Use this for "Manage your privacy" / "Withdraw consent" footer links in your app.
   * The user must be logged in via Signward to access it (their bearer token is
   * stored in localStorage on the Signward domain).
   *
   * Defaults to `<authority>/Auth/MyPrivacy` — override with `options.webBaseUrl`
   * if your web frontend is on a different host than the API (e.g. api.* vs app.*).
   */
  getPrivacyCenterUrl(): string {
    const base = (this.options.webBaseUrl ?? this.authority).replace(/\/+$/, '');
    return `${base}/Auth/MyPrivacy`;
  }

  /**
   * Build an authorize URL with a freshly generated PKCE verifier.
   * Returns both the URL (to redirect to) and the verifier (store in session
   * and pass back to {@link exchangeCode}).
   */
  async authorizeUrlWithPkce(
    params: Omit<AuthorizeUrlParams, 'codeChallenge' | 'codeChallengeMethod'>,
  ): Promise<{ url: string; verifier: string }> {
    const { verifier, challenge } = await generatePkcePair();
    const url = this.authorizeUrl({
      ...params,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    });
    return { url, verifier };
  }

  // --- Token endpoint -------------------------------------------------------

  async exchangeCode(code: string, params: ExchangeCodeParams): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: params.redirectUri,
      client_id: this.options.clientId,
    };
    if (this.options.clientSecret) body.client_secret = this.options.clientSecret;
    if (params.codeVerifier) body.code_verifier = params.codeVerifier;
    return this.postToken(body);
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.options.clientId,
    };
    if (this.options.clientSecret) body.client_secret = this.options.clientSecret;
    return this.postToken(body);
  }

  private async postToken(body: Record<string, string>): Promise<TokenResponse> {
    const disc = await this.discovery();
    const endpoint = disc.token_endpoint ?? `${this.authority}/connect/token`;

    const resp = await this.fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

    if (!resp.ok) {
      let payload: Record<string, unknown> = {};
      try {
        payload = (await resp.json()) as Record<string, unknown>;
      } catch {
        // ignore
      }
      throw new TokenExchangeError(
        (payload.error as string) ?? 'token_error',
        payload.error_description as string | undefined,
        resp.status,
      );
    }

    return (await resp.json()) as TokenResponse;
  }

  // --- Userinfo -------------------------------------------------------------

  async userinfo(accessToken: string): Promise<User> {
    const disc = await this.discovery();
    const endpoint = disc.userinfo_endpoint ?? `${this.authority}/connect/userinfo`;
    const resp = await this.fetchWithTimeout(endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!resp.ok) {
      throw new UserInfoError(`userinfo returned ${resp.status}: ${await resp.text()}`);
    }
    return userFromClaims((await resp.json()) as Claims);
  }

  // --- Token validation -----------------------------------------------------

  async validateToken(token: string, options: ValidateTokenOptions = {}): Promise<User> {
    const disc = await this.discovery();
    const issuer = this.options.issuer ?? disc.issuer ?? this.authority;
    const audience = options.audience ?? this.options.audience;
    const leeway = options.leeway ?? 10;

    let header: { kid?: string; alg?: string };
    try {
      header = this.decodeHeader(token);
    } catch (err) {
      throw new InvalidTokenError(`Malformed token: ${(err as Error).message}`, { cause: err });
    }

    const key = await this.getSigningKey(header.kid);

    let payload: JWTPayload;
    try {
      const result = await jwtVerify(token, key, {
        issuer,
        audience,
        clockTolerance: leeway,
        requiredClaims: ['exp', 'iat'],
      });
      payload = result.payload;
    } catch (err) {
      throw new InvalidTokenError((err as Error).message, { cause: err });
    }

    return userFromClaims(payload as Claims);
  }

  private decodeHeader(token: string): { kid?: string; alg?: string } {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('JWT must have 3 segments');
    const headerB64 = parts[0]!;
    const json = Buffer.from(headerB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json) as { kid?: string; alg?: string };
  }

  private async getSigningKey(kid: string | undefined): Promise<KeyLike | Uint8Array> {
    const cacheKey = kid ?? '__default__';
    const cached = this.jwksKeyCache.get(cacheKey);
    if (cached) return cached;

    const jwks = await this.jwks();
    const keys = jwks.keys ?? [];
    if (keys.length === 0) throw new InvalidTokenError('JWKS contains no keys');

    let match: JWK | undefined;
    if (kid) match = keys.find((k) => k.kid === kid);
    if (!match) match = keys[0];
    if (!match) throw new InvalidTokenError('No matching JWK found');

    const alg = match.alg ?? (match.kty === 'oct' ? 'HS256' : 'RS256');
    const imported = (await importJWK(match, alg)) as KeyLike | Uint8Array;
    this.jwksKeyCache.set(cacheKey, imported);
    return imported;
  }

  // --- End session ----------------------------------------------------------

  async endSessionUrl(params: EndSessionParams = {}): Promise<string> {
    const disc = await this.discovery();
    const endpoint = disc.end_session_endpoint ?? `${this.authority}/connect/endsession`;

    const query = new URLSearchParams();
    if (params.idTokenHint) query.set('id_token_hint', params.idTokenHint);
    if (params.postLogoutRedirectUri) query.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
    if (params.state) query.set('state', params.state);

    const qs = query.toString();
    return qs ? `${endpoint}?${qs}` : endpoint;
  }
}
